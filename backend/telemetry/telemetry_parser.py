"""Parses raw ESP-NOW gateway packets and maintains rolling per-link telemetry.

Input is an `RX` line of docs/serial_json_schema.md, already normalised by
`gateway_schema.to_packet` (`src`, `dst`, `seq`, `type`, `ttl`, `rssi`, ...). The firmware-side
`TelemetryEngine` will eventually report window stats itself; until then this
module computes the equivalent on the backend so the rest of the pipeline
(decision engine, database, dashboard) works end to end.

Facts about the firmware that shape the logic here (firmware/mesh_node):
- `seq` is ONE counter per sending node, shared by every destination, so
  sequence continuity can only be judged per *sender*, never per link.
- Relays re-send a frame with a lower TTL, so the same (src, seq) legitimately
  shows up more than once. Only an exact repeat (same seq AND same ttl) is a
  duplicate.
- The gateway's own outbound packets are logged with `rssi: 0`, meaning "no
  radio reception"; that is missing data, not a signal strength.
"""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

RECENT_FRAMES_PER_SENDER = 64  # how many (seq, ttl) pairs are remembered for repeat detection


@dataclass
class _LinkWindow:
    # Each sample: (timestamp, rssi, is_duplicate, is_gap)
    samples: deque = field(default_factory=deque)


@dataclass
class _SenderState:
    max_seq: Optional[int] = None
    recent: deque = field(default_factory=lambda: deque(maxlen=RECENT_FRAMES_PER_SENDER))


class PacketAggregator:
    """Maintains a rolling time window per (source, destination) link and
    turns raw ESP-NOW packets into telemetry rows shaped for the DB schema."""

    def __init__(self, window_seconds: float = 2.0):
        self.window_seconds = window_seconds
        self._links: dict[tuple[int, int], _LinkWindow] = {}
        self._senders: dict[int, _SenderState] = {}

    def ingest(self, packet: dict) -> Optional[dict]:
        if "src" not in packet or "dst" not in packet:
            return None

        src, dst = int(packet["src"]), int(packet["dst"])
        seq = packet.get("seq")
        ttl = packet.get("ttl")
        rssi = packet.get("rssi")
        if rssi == 0:  # gateway-originated packet: no reception, so no RSSI
            rssi = None
        now = time.time()

        is_dup = False
        is_gap = False
        if seq is not None:
            sender = self._senders.setdefault(src, _SenderState())
            if (seq, ttl) in sender.recent:
                is_dup = True
            elif sender.max_seq is not None and seq > sender.max_seq + 1:
                is_gap = True  # informational: unicast frames to other nodes are never heard here
            sender.recent.append((seq, ttl))
            sender.max_seq = seq if sender.max_seq is None else max(sender.max_seq, seq)

        link = self._links.setdefault((src, dst), _LinkWindow())
        link.samples.append((now, rssi, is_dup, is_gap))
        cutoff = now - self.window_seconds
        while link.samples and link.samples[0][0] < cutoff:
            link.samples.popleft()

        window = link.samples
        rssi_values = [s[1] for s in window if s[1] is not None]
        avg_rssi = sum(rssi_values) / len(rssi_values) if rssi_values else None

        return {
            "timestamp": now,
            "source": str(src),
            "destination": str(dst),
            "packet_rate": round(len(window) / self.window_seconds, 2),
            # Not derivable here: seq is per sender and unicast frames to other
            # nodes are never heard by the gateway, so gaps are not losses.
            "packet_loss": None,
            "latency": packet.get("latency_ms"),
            "rssi": round(avg_rssi, 1) if avg_rssi is not None else None,
            "rssi_instant": rssi,
            "retransmissions": packet.get("retransmissions", 0),
            "sequence_number": seq,
            "duplicate_count": sum(1 for s in window if s[2]),
            "sequence_anomalies": sum(1 for s in window if s[3]),
            "type": packet.get("type", "DATA"),
            "ttl": ttl,
            "direction": packet.get("direction", "RX"),
            "receiver": packet.get("receiver"),
            "hop": packet.get("hop"),
            "action": packet.get("action"),
            "delivery": packet.get("delivery"),
            "checksum": packet.get("checksum"),
            "payload": packet.get("payload"),
            "packet_status": "DUP" if is_dup else ("GAP" if is_gap else "OK"),
        }
