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
    confidence: Optional[float]   # None when the verdict comes from a device that reports no score
    detail: str


class DecisionEngine:
    def __init__(self, dos_threshold: float, rssi_jump_dbm: float, known_nodes: set[int],
                 replay_dup_threshold: int = 3, initial_ttl: int = 4):
        self.dos_threshold = dos_threshold
        self.rssi_jump_dbm = rssi_jump_dbm
        self.known_nodes = known_nodes
        self.replay_dup_threshold = replay_dup_threshold
        self.initial_ttl = initial_ttl
        self._rssi_baseline: dict[str, float] = {}

    def evaluate_peer(self, peer: int, reporter: int, rate: float) -> Optional[Verdict]:
        """Judge a per-peer 1 s statistic reported by a node (TELEMETRY line).

        Only the packet rate is used. `drops` counts sequence gaps, which in a
        random-target mesh are mostly frames addressed to other nodes, and the
        reported average RSSI mixes several radio hops, so neither is a safe
        isolation trigger."""
        if peer not in self.known_nodes:
            return Verdict(str(peer), "ROGUE_NODE", 0.95,
                            f"Unregistered node {peer} heard by N{reporter}")
        if rate > self.dos_threshold:
            excess = (rate - self.dos_threshold) / self.dos_threshold
            return Verdict(str(peer), "DOS", round(0.7 + 0.29 * min(1.0, excess), 2),
                            f"N{reporter} receives {rate} pkts/s from N{peer} in a 1 s window "
                            f"(limit {self.dos_threshold:.0f})")
        return None

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

        # RSSI describes the last radio hop. A relayed frame (ttl already
        # decremented) was heard from the relay, not from `source`, so only
        # direct frames say anything about the sender's own signal.
        ttl = telemetry.get("ttl")
        if ttl is not None and ttl < self.initial_ttl:
            return None

        # Baseline per *link* (sender -> the node that heard it), not per
        # sender: one node has a different signal strength to each peer. The
        # instantaneous sample is compared against a smoothed baseline so a
        # single spoofed frame is not diluted by the rolling-window average.
        heard_by = str(telemetry.get("receiver") or telemetry["destination"])
        link_key = source + "->" + heard_by
        rssi = telemetry.get("rssi_instant", telemetry.get("rssi"))
        baseline = self._rssi_baseline.get(link_key)
        if rssi is not None:
            if baseline is not None and abs(rssi - baseline) >= self.rssi_jump_dbm:
                return Verdict(source, "SPOOFING", 0.7,
                                f"RSSI on link {source}->{heard_by} jumped "
                                f"{baseline:.0f} -> {rssi:.0f} dBm, inconsistent with the "
                                f"node's known radio identity")
            self._rssi_baseline[link_key] = rssi if baseline is None else 0.7 * baseline + 0.3 * rssi

        return None
