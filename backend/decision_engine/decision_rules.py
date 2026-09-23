"""Threshold-based Intrusion Detection rules.

This is a stand-in for the ML-based IDS (a separate teammate's responsibility
per docs/project.md.txt section 14). It converts rolling telemetry into a
security verdict using the same features the project spec calls out for each
attack class, so the decision engine, database, and recovery pipeline are
fully wired end to end before the trained model exists. Swapping this for a
real classifier later means implementing the same `evaluate()` contract.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class Verdict:
    node_id: str
    attack_type: str
    confidence: float
    detail: str


class DecisionEngine:
    def __init__(self, dos_threshold: float, rssi_jump_dbm: float, known_nodes: set[int]):
        self.dos_threshold = dos_threshold
        self.rssi_jump_dbm = rssi_jump_dbm
        self.known_nodes = known_nodes
        self._last_rssi: dict[str, float] = {}

    def evaluate(self, telemetry: dict) -> Optional[Verdict]:
        source = telemetry["source"]

        if int(source) not in self.known_nodes:
            return Verdict(source, "ROGUE_NODE", 0.95,
                            f"Unregistered node {source} transmitting on the mesh")

        if telemetry.get("packet_rate", 0) > self.dos_threshold:
            confidence = min(0.99, telemetry["packet_rate"] / (self.dos_threshold * 2))
            return Verdict(source, "DOS", round(confidence, 2),
                            f"Packet rate {telemetry['packet_rate']:.1f} pkts/s exceeds "
                            f"{self.dos_threshold:.0f} pkts/s threshold")

        if telemetry.get("duplicate_count", 0) > 0:
            return Verdict(source, "REPLAY", 0.9,
                            f"{telemetry['duplicate_count']} duplicate sequence number(s) "
                            f"detected in the current window")

        if telemetry.get("sequence_anomalies", 0) > 2:
            return Verdict(source, "REPLAY", 0.6, "Repeated out-of-order sequence numbers")

        # Baseline RSSI per *link* (source+destination), not per source node:
        # a node's signal strength naturally differs across its several peers,
        # so comparing against the wrong peer's baseline reads as a false jump.
        link_key = source + "->" + telemetry["destination"]
        rssi = telemetry.get("rssi")
        prev_rssi = self._last_rssi.get(link_key)
        if rssi is not None:
            if prev_rssi is not None and abs(rssi - prev_rssi) >= self.rssi_jump_dbm:
                self._last_rssi[link_key] = rssi
                return Verdict(source, "SPOOFING", 0.7,
                                f"RSSI on link {source}->{telemetry['destination']} jumped "
                                f"{prev_rssi:.0f} -> {rssi:.0f} dBm, inconsistent with the "
                                f"node's known radio identity")
            self._last_rssi[link_key] = rssi

        return None
