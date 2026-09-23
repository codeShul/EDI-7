"""Produces raw mesh packets for the ingestion pipeline.

Two sources are supported behind the same `TelemetrySource` interface:

- `SerialSource`  — reads newline-delimited JSON from a real gateway ESP32
  over USB serial (per docs/mesh_base_plan.md Step 3: `{"src":1,"dst":5,
  "seq":105,"type":"DATA","ttl":4,"rssi":-52}`).
- `SimulatedSource` — generates plausible mesh traffic so the backend and
  dashboard are fully testable before hardware/firmware is ready.

`get_source()` picks the real serial link when `SECUREMESH_SIMULATE=0` and the
configured port is actually reachable, and falls back to the simulator
otherwise — the rest of the app never needs to know which one is active.
"""
from __future__ import annotations

import asyncio
import json
import logging
import random
from typing import AsyncIterator

from .. import config

logger = logging.getLogger("securemesh.telemetry")

PACKET_TYPES = ["DATA", "DATA", "DATA", "HEARTBEAT", "ROUTE_SYNC"]


class TelemetrySource:
    async def packets(self) -> AsyncIterator[dict]:
        raise NotImplementedError
        yield  # pragma: no cover - makes this an async generator signature


class SimulatedSource(TelemetrySource):
    def __init__(self, node_ids: list[int]):
        self.node_ids = node_ids
        self._seq: dict[tuple[int, int], int] = {}
        self._rssi: dict[tuple[int, int], float] = {}

    def _next_rssi(self, key: tuple[int, int]) -> int:
        # Real RSSI drifts slowly on a stable link; a fresh independent random
        # value per packet would look like constant spoofing to the decision
        # engine. Model it as a small random walk instead.
        current = self._rssi.get(key, random.uniform(-70, -45))
        current = max(-85.0, min(-40.0, current + random.uniform(-2.5, 2.5)))
        self._rssi[key] = current
        return round(current)

    async def packets(self) -> AsyncIterator[dict]:
        logger.warning("No ESP32 gateway configured — running in SIMULATED telemetry mode")
        while True:
            await asyncio.sleep(random.uniform(0.15, 0.45))
            src = random.choice(self.node_ids)
            dst = random.choice([n for n in self.node_ids if n != src])
            key = (src, dst)
            self._seq[key] = self._seq.get(key, 0) + 1
            yield {
                "src": src,
                "dst": dst,
                "seq": self._seq[key],
                "type": random.choice(PACKET_TYPES),
                "ttl": random.randint(2, 4),
                "rssi": self._next_rssi(key),
            }


class SerialSource(TelemetrySource):
    def __init__(self, port: str, baudrate: int):
        self.port = port
        self.baudrate = baudrate

    async def packets(self) -> AsyncIterator[dict]:
        import serial  # pyserial — imported lazily so it stays optional in simulate mode

        ser = await asyncio.to_thread(serial.Serial, self.port, self.baudrate, timeout=1)
        logger.info("Connected to gateway ESP32 on %s @ %d baud", self.port, self.baudrate)
        try:
            while True:
                raw = await asyncio.to_thread(ser.readline)
                line = raw.decode("utf-8", errors="ignore").strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    logger.debug("Ignoring malformed serial line: %s", line)
        finally:
            await asyncio.to_thread(ser.close)


def get_source() -> TelemetrySource:
    if config.SIMULATE:
        return SimulatedSource(config.NODE_IDS)

    try:
        import serial
    except ImportError:
        logger.warning("pyserial not installed — falling back to simulated telemetry")
        return SimulatedSource(config.NODE_IDS)

    try:
        probe = serial.Serial(config.SERIAL_PORT, config.SERIAL_BAUDRATE, timeout=0.1)
        probe.close()
    except Exception as exc:
        logger.warning(
            "Serial port %s unavailable (%s) — falling back to simulated telemetry",
            config.SERIAL_PORT, exc,
        )
        return SimulatedSource(config.NODE_IDS)

    return SerialSource(config.SERIAL_PORT, config.SERIAL_BAUDRATE)
