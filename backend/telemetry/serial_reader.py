"""Produces raw mesh packets for the ingestion pipeline.

Two sources are supported behind the same `TelemetrySource` interface:

- `SerialSource`  — reads newline-delimited JSON from a real gateway ESP32
  over USB serial (per docs/mesh_base_plan.md Step 3: `{"src":1,"dst":5,
  "seq":105,"type":"DATA","ttl":4,"rssi":-52}`).
- `SimulatedSource` — generates plausible mesh traffic so the backend and
  dashboard are fully testable before hardware/firmware is ready. It can also
  inject the three attack patterns the decision engine looks for (DoS flood,
  replay, RSSI spoofing) so the detect -> isolate -> reroute flow can be
  demonstrated on demand.

`get_source()` picks the real serial link when `SECUREMESH_SIMULATE=0` and the
configured port is actually reachable, and falls back to the simulator
otherwise — the rest of the app never needs to know which one is active.
"""
from __future__ import annotations

import asyncio
import json
import logging
import random
import time
from collections import deque
from typing import AsyncIterator

from .. import config

logger = logging.getLogger("securemesh.telemetry")

PACKET_TYPES = ["DATA", "DATA", "DATA", "HEARTBEAT", "ROUTE_SYNC"]
ATTACKS = ("DOS", "REPLAY", "SPOOFING")


class TelemetrySource:
    supports_attacks = False

    def set_isolated(self, nodes: set[int]) -> None:
        """Called whenever the isolated-node set changes. Real hardware needs
        no help here; the simulator uses it to stop talking to isolated peers."""

    async def packets(self) -> AsyncIterator[dict]:
        raise NotImplementedError
        yield  # pragma: no cover - makes this an async generator signature


class SimulatedSource(TelemetrySource):
    supports_attacks = True

    def __init__(self, node_ids: list[int]):
        self.node_ids = node_ids
        self.enabled = True
        self._seq: dict[int, int] = {}
        self._rssi: dict[tuple[int, int], float] = {}
        self._isolated: set[int] = set()
        self._dos: dict[int, int] = {}          # attacker -> victim, flooding until reset
        self._pending: deque[dict] = deque()     # queued one-shot attack packets

    def set_isolated(self, nodes: set[int]) -> None:
        self._isolated = set(nodes)

    def _next_rssi(self, key: tuple[int, int]) -> int:
        # Real RSSI drifts slowly on a stable link; a fresh independent random
        # value per packet would look like constant spoofing to the decision
        # engine. Model it as a small random walk instead.
        current = self._rssi.get(key, random.uniform(-70, -45))
        current = max(-85.0, min(-40.0, current + random.uniform(-2.5, 2.5)))
        self._rssi[key] = current
        return round(current)

    def _packet(self, src: int, dst: int, ptype: str | None = None) -> dict:
        # Like the firmware, one sequence counter per sending node (shared by
        # all destinations); only the RSSI baseline is per link.
        self._seq[src] = self._seq.get(src, 0) + 1
        return {
            "src": src,
            "dst": dst,
            "seq": self._seq[src],
            "type": ptype or random.choice(PACKET_TYPES),
            "ttl": random.randint(2, 4),
            "rssi": self._next_rssi((src, dst)),
        }

    # ---- attack injection ---------------------------------------------------
    def start_attack(self, attack: str, node: int) -> str:
        peers = [n for n in self.node_ids if n != node and n not in self._isolated]
        if not peers:
            raise ValueError("No reachable peers to attack")
        peer = random.choice(peers)

        if attack == "DOS":
            self._dos[node] = peer
            return f"DoS flood from N{node} towards N{peer}"

        if attack == "REPLAY":
            frame = self._packet(node, peer, "DATA")
            self._pending.append(frame)
            for _ in range(4):
                self._pending.append(dict(frame))  # exact copies: same sequence number and TTL
            return f"Replay of frame #{frame['seq']} from N{node} to N{peer}"

        if attack == "SPOOFING":
            baseline = self._packet(node, peer, "DATA")
            spoofed = self._packet(node, peer, "DATA")
            spoofed["rssi"] = baseline["rssi"] + (-30 if baseline["rssi"] > -62 else 30)
            self._pending.append(baseline)
            self._pending.append(spoofed)
            return f"Spoofed frame on link N{node}->N{peer} ({baseline['rssi']} -> {spoofed['rssi']} dBm)"

        raise ValueError(f"Unknown attack {attack}")

    def reset(self) -> None:
        self._dos.clear()
        self._pending.clear()

    # ---- packet stream -------------------------------------------------------
    async def packets(self) -> AsyncIterator[dict]:
        logger.warning("No ESP32 gateway configured — running in SIMULATED telemetry mode")
        next_normal = 0.0  # background traffic is scheduled by time so a flood keeps its pace
        while True:
            if not self.enabled:
                await asyncio.sleep(0.25)
                continue

            if self._pending:
                await asyncio.sleep(0.2)
                if self._pending:
                    yield self._pending.popleft()
                continue

            now = time.monotonic()
            if self._dos and now < next_normal:
                await asyncio.sleep(0.01)
                if not self._dos:  # a reset can land while we were sleeping
                    continue
                attacker, victim = random.choice(list(self._dos.items()))
                yield self._packet(attacker, victim, "DATA")
                continue

            if next_normal > now:
                await asyncio.sleep(next_normal - now)
            next_normal = time.monotonic() + random.uniform(0.15, 0.45)

            active = [n for n in self.node_ids if n not in self._isolated]
            if len(active) < 2:
                continue
            src = random.choice(active)
            dst = random.choice([n for n in active if n != src])
            yield self._packet(src, dst)


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
