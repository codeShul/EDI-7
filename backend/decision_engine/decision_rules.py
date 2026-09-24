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
    def __init__(self, dos_threshold: float, rssi_jump_dbm: float, known_nodes: set[int],
                 replay_dup_threshold: int = 3):
        self.dos_threshold = dos_threshold
        self.rssi_jump_dbm = rssi_jump_dbm
        self.known_nodes = known_nodes
        self.replay_dup_threshold = replay_dup_threshold
        self._rssi_baseline: dict[str, float] = {}

    def evaluate(self, telemetry: dict) -> Optional[Verdict]:
        source = telemetry["source"]

        if int(source) not in self.known_nodes:
            return Verdict(source, "ROGUE_NODE", 0.95,
                            f"Unregistered node {source} transmitting on the mesh")

        if telemetry.get("packet_rate", 0) > self.dos_threshold:
            # Rule-based verdicts have no model probability. Any breach is a firm
            # hit (0.7); confidence then grows with how far the rate exceeds the limit.
            excess = (telemetry["packet_rate"] - self.dos_threshold) / self.dos_threshold
            confidence = 0.7 + 0.29 * min(1.0, excess)
            return Verdict(source, "DOS", round(confidence, 2),
                            f"Packet rate {telemetry['packet_rate']:.1f} pkts/s exceeds "
                            f"{self.dos_threshold:.0f} pkts/s threshold")

        # A lone repeated frame is normal on a real radio (ESP-NOW retries after a
        # lost ACK), so replay needs several exact repeats inside the window.
        # Sequence gaps are deliberately not a replay signal: they indicate loss.
        duplicates = telemetry.get("duplicate_count", 0)
        if duplicates >= self.replay_dup_threshold:
            return Verdict(source, "REPLAY", 0.9,
                            f"{duplicates} repeated frames (same sequence number and TTL) "
                            f"in the current window")

        # Baseline RSSI per *link* (source+destination), not per source node:
        # a node's signal strength naturally differs across its several peers,
        # so comparing against the wrong peer's baseline reads as a false jump.
        # The instantaneous sample is compared against a smoothed baseline so a
        # single spoofed frame is not diluted by the rolling-window average.
        link_key = source + "->" + telemetry["destination"]
        rssi = telemetry.get("rssi_instant", telemetry.get("rssi"))
        baseline = self._rssi_baseline.get(link_key)
        if rssi is not None:
            if baseline is not None and abs(rssi - baseline) >= self.rssi_jump_dbm:
                return Verdict(source, "SPOOFING", 0.7,
                                f"RSSI on link {source}->{telemetry['destination']} jumped "
                                f"{baseline:.0f} -> {rssi:.0f} dBm, inconsistent with the "
                                f"node's known radio identity")
            self._rssi_baseline[link_key] = rssi if baseline is None else 0.7 * baseline + 0.3 * rssi

        return None
