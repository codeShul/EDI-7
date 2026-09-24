"""Parses raw ESP-NOW gateway packets and maintains rolling per-link telemetry.

The firmware-side `TelemetryEngine` (see firmware/common/TelemetryEngine.h) is
meant to eventually compute these same rolling-window stats on the ESP32
gateway itself and ship a ready-made `TelemetryReport`. Until that firmware
exists, this module computes the equivalent stats on the backend from raw
per-packet JSON (`{"src", "dst", "seq", "type", "ttl", "rssi"}`), so the rest
of the pipeline (decision engine, database, dashboard) works end to end today.
"""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class _LinkWindow:
    # Each sample: (timestamp, seq, rssi, is_duplicate, is_gap)
    samples: deque = field(default_factory=deque)
    last_seq: Optional[int] = None


class PacketAggregator:
    """Maintains a rolling time window per (source, destination) link and
    turns raw ESP-NOW packets into telemetry rows shaped for the DB schema."""

    def __init__(self, window_seconds: float = 2.0):
        self.window_seconds = window_seconds
        self._links: dict[tuple[int, int], _LinkWindow] = {}

    def ingest(self, packet: dict) -> Optional[dict]:
        if "src" not in packet or "dst" not in packet:
            return None

        src, dst = int(packet["src"]), int(packet["dst"])
        seq = packet.get("seq")
        rssi = packet.get("rssi")
        now = time.time()

        link = self._links.setdefault((src, dst), _LinkWindow())

        is_dup = False
        is_gap = False
        if seq is not None and link.last_seq is not None:
            if seq <= link.last_seq:
                is_dup = True
            elif seq - link.last_seq > 1:
                is_gap = True
        if seq is not None:
            link.last_seq = max(seq, link.last_seq) if link.last_seq is not None else seq

        link.samples.append((now, seq, rssi, is_dup, is_gap))
        cutoff = now - self.window_seconds
        while link.samples and link.samples[0][0] < cutoff:
            link.samples.popleft()

        window = link.samples
        packet_rate = len(window) / self.window_seconds
        rssi_values = [s[2] for s in window if s[2] is not None]
        avg_rssi = sum(rssi_values) / len(rssi_values) if rssi_values else None
        duplicate_count = sum(1 for s in window if s[3])
        sequence_anomalies = sum(1 for s in window if s[4])

        seqs = [s[1] for s in window if s[1] is not None]
        packet_loss = 0.0
        if len(seqs) >= 2:
            expected = max(seqs) - min(seqs) + 1
            packet_loss = max(0.0, (expected - len(seqs)) / expected) * 100.0

        return {
            "timestamp": now,
            "source": str(src),
            "destination": str(dst),
            "packet_rate": round(packet_rate, 2),
            "packet_loss": round(packet_loss, 2),
            "latency": packet.get("latency_ms"),
            "rssi": round(avg_rssi, 1) if avg_rssi is not None else None,
            "rssi_instant": rssi,
            "retransmissions": packet.get("retransmissions", 0),
            "sequence_number": seq,
            "duplicate_count": duplicate_count,
            "sequence_anomalies": sequence_anomalies,
            "type": packet.get("type", "DATA"),
            "ttl": packet.get("ttl"),
            "checksum": packet.get("checksum"),
            "payload": packet.get("payload"),
            "packet_status": "DUP" if is_dup else ("GAP" if is_gap else "OK"),
        }
