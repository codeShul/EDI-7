"""Produces the gateway's JSON lines for the ingestion pipeline.

Two sources are supported behind the same `TelemetrySource` interface; both
yield dicts in the flat schema of docs/serial_json_schema.md (RX / TX /
TELEMETRY / ALERT):

- `SerialSource`  — reads newline-delimited JSON from a real gateway ESP32
  over USB serial.
- `SimulatedSource` — generates mesh traffic in the same schema, mirroring the
  firmware (one sequence counter per sender, relays re-sending at TTL-1, a
  1 s TELEMETRY summary per peer), so the backend and dashboard are fully
  testable before hardware is attached. It can also inject the attack
  patterns the decision engine looks for (DoS flood, replay, RSSI spoofing) so
  detect -> isolate -> reroute can be demonstrated on demand.

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


def flat(kind: str, **fields) -> dict:
    """A message with every key the firmware's `print_json` always prints."""
    message = {
        "type": kind, "src": 0, "dst": 0, "seq": 0, "pkt_type": "", "ttl": 0, "rssi": 0,
        "receiver": 0, "hop": 0, "action": "", "delivery": "", "rate": 0, "avg_rssi": 0,
        "drops": 0, "threat": "",
    }
    message.update(fields)
    return message


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
        self._seq: dict[int, int] = {}                     # one counter per sending node
        self._rssi: dict[tuple[int, int], float] = {}      # per radio link
        self._isolated: set[int] = set()
        self._dos: dict[int, int] = {}                     # attacker -> victim, flooding until reset
        self._pending: deque[dict] = deque()               # paced attack frames
        self._out: deque[dict] = deque()                   # frames to send back to back
        self._rx_log: deque[tuple[float, int, int, int]] = deque()   # (t, peer, reporter, rssi)
        self._last_seq: dict[tuple[int, int], int] = {}
        self._drops: dict[tuple[int, int], int] = {}

    def set_isolated(self, nodes: set[int]) -> None:
        self._isolated = set(nodes)

    # ---- frame construction ---------------------------------------------------
    def _next_rssi(self, key: tuple[int, int]) -> int:
        # Real RSSI drifts slowly on a stable link; a fresh independent random
        # value per packet would look like constant spoofing to the decision
        # engine. Model it as a small random walk instead.
        current = self._rssi.get(key, random.uniform(-70, -45))
        current = max(-85.0, min(-40.0, current + random.uniform(-2.5, 2.5)))
        self._rssi[key] = current
        return round(current)

    def _new_frame(self, src: int, dst: int, ptype: str | None = None) -> dict:
        self._seq[src] = self._seq.get(src, 0) + 1
        return {"src": src, "dst": dst, "seq": self._seq[src],
                "pkt_type": ptype or random.choice(PACKET_TYPES), "ttl": config.INITIAL_TTL}

    @staticmethod
    def _rx(frame: dict, receiver: int, action: str, rssi: int, ttl: int | None = None) -> dict:
        return flat("RX", src=frame["src"], dst=frame["dst"], seq=frame["seq"],
                    pkt_type=frame["pkt_type"], ttl=frame["ttl"] if ttl is None else ttl,
                    rssi=rssi, receiver=receiver, action=action)

    def _traffic(self, src: int, dst: int) -> list[dict]:
        """Everything the mesh prints for one frame: usually a single RX at the
        destination; sometimes a relay chain (RX RELAYING, TX at TTL-1, RX)."""
        frame = self._new_frame(src, dst)
        relays = [n for n in self.node_ids if n not in self._isolated and n not in (src, dst)]
        if relays and random.random() < 0.15:
            relay = random.choice(relays)
            ttl = frame["ttl"] - 1
            return [
                self._rx(frame, relay, "RELAYING", self._next_rssi((src, relay))),
                flat("TX", src=relay, dst=dst, seq=frame["seq"], pkt_type="DATA", ttl=ttl,
                     receiver=relay, hop=dst, action="SENT",
                     delivery="FAIL" if random.random() < 0.03 else "SUCCESS"),
                self._rx(frame, dst, "CONSUMED", self._next_rssi((relay, dst)), ttl=ttl),
            ]
        return [self._rx(frame, dst, "CONSUMED", self._next_rssi((src, dst)))]

    # ---- per-second TELEMETRY -------------------------------------------------
    def _emit(self, message: dict) -> dict:
        if message["type"] == "RX":
            peer, reporter = message["src"], message["receiver"]
            self._rx_log.append((time.monotonic(), peer, reporter, message["rssi"]))
            key = (peer, reporter)
            last = self._last_seq.get(key)
            if last is not None and message["seq"] > last + 1:
                self._drops[key] = self._drops.get(key, 0) + message["seq"] - last - 1
            self._last_seq[key] = max(message["seq"], last or 0)
        return message

    def _telemetry_messages(self) -> list[dict]:
        cutoff = time.monotonic() - 1.0
        while self._rx_log and self._rx_log[0][0] < cutoff:
            self._rx_log.popleft()
        groups: dict[tuple[int, int], list[int]] = {}
        for _, peer, reporter, rssi in self._rx_log:
            groups.setdefault((peer, reporter), []).append(rssi)
        return [
            flat("TELEMETRY", src=peer, dst=reporter, receiver=reporter,
                 rssi=round(sum(rssis) / len(rssis)), rate=len(rssis),
                 avg_rssi=round(sum(rssis) / len(rssis)), drops=self._drops.get((peer, reporter), 0))
            for (peer, reporter), rssis in groups.items()
        ]

    # ---- attack injection -----------------------------------------------------
    def start_attack(self, attack: str, node: int) -> str:
        # Exclude Node 5 (offline) and the attacker itself
        peers = [n for n in self.node_ids if n != node and n != 5 and n not in self._isolated]
        if not peers:
            raise ValueError("No reachable peers to attack")
        peer = random.choice(peers)

        if attack == "DOS":
            self._dos[node] = peer
            return f"DoS flood from N{node} towards N{peer}"

        if attack == "REPLAY":
            frame = self._new_frame(node, peer, "DATA")
            message = self._rx(frame, peer, "CONSUMED", self._next_rssi((node, peer)))
            self._pending.append(message)
            for _ in range(4):
                self._pending.append(dict(message))  # exact copies: same sequence number and TTL
            return f"Replay of frame #{frame['seq']} from N{node} to N{peer}"

        if attack == "SPOOFING":
            baseline = self._rx(self._new_frame(node, peer, "DATA"), peer, "CONSUMED",
                                self._next_rssi((node, peer)))
            spoofed = self._rx(self._new_frame(node, peer, "DATA"), peer, "CONSUMED",
                               self._next_rssi((node, peer)))
            spoofed["rssi"] = baseline["rssi"] + (-30 if baseline["rssi"] > -62 else 30)
            self._pending.append(baseline)
            self._pending.append(spoofed)
            return f"Spoofed frame on link N{node}->N{peer} ({baseline['rssi']} -> {spoofed['rssi']} dBm)"

        raise ValueError(f"Unknown attack {attack}")

    def reset(self) -> None:
        self._dos.clear()
        self._pending.clear()
        self._out.clear()
        self._rx_log.clear()   # otherwise the next TELEMETRY still reports the flood that just stopped

    # ---- message stream -------------------------------------------------------
    async def packets(self) -> AsyncIterator[dict]:
        logger.warning("No ESP32 gateway configured — running in SIMULATED telemetry mode")
        next_normal = 0.0       # background traffic is scheduled by time so a flood keeps its pace
        next_telemetry = time.monotonic() + 1.0
        while True:
            if not self.enabled:
                await asyncio.sleep(0.25)
                continue

            if self._out:
                yield self._emit(self._out.popleft())
                continue

            if self._pending:
                await asyncio.sleep(0.2)
                if self._pending:
                    yield self._emit(self._pending.popleft())
                continue

            now = time.monotonic()
            if now >= next_telemetry:
                next_telemetry = now + 1.0
                self._out.extend(self._telemetry_messages())
                continue

            if self._dos and now < next_normal:
                await asyncio.sleep(0.01)
                if not self._dos:  # a reset can land while we were sleeping
                    continue
                attacker, victim = random.choice(list(self._dos.items()))
                frame = self._new_frame(attacker, victim, "DATA")
                yield self._emit(self._rx(frame, victim, "CONSUMED", self._next_rssi((attacker, victim))))
                continue

            if now < next_normal:
                await asyncio.sleep(max(0.0, min(next_normal, next_telemetry) - now))
                continue

            next_normal = now + random.uniform(0.15, 0.45)
            active = [n for n in self.node_ids if n not in self._isolated]
            if len(active) < 2:
                continue
            src = random.choice(active)
            dst = random.choice([n for n in active if n != src])
            self._out.extend(self._traffic(src, dst))


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
