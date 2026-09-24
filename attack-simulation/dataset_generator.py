#!/usr/bin/env python3
"""Telemetry logger and ground-truth dataset generator for SecureMesh AI.

Collects mesh telemetry from the gateway ESP32 via serial (or simulated stream),
calculates rolling metrics, syncs with attack_controller.py, and outputs labeled CSV.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import random
import signal
import sys
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional, Tuple

logger = logging.getLogger("DatasetGenerator")

# Fixed schema required by ML pipeline
CSV_COLUMNS = [
    "timestamp",
    "source_node_id",
    "destination_node_id",
    "packet_rate",
    "packet_loss",
    "latency_ms",
    "rssi",
    "retransmissions",
    "sequence_number",
    "duplicate_packets",
    "node_identity_status",
    "label",
]

# Authorized nodes in the mesh
AUTHORIZED_NODES = {1, 2, 3, 4, 5, "1", "2", "3", "4", "5", "NODE_01", "NODE_02", "NODE_03", "NODE_04", "NODE_05"}


@dataclass
class _LinkWindow:
    samples: deque = field(default_factory=deque)
    last_seq: Optional[int] = None


class RollingMetricsAggregator:
    """Calculates link-level metrics over a sliding window."""

    def __init__(self, window_seconds: float = 2.0):
        self.window_seconds = window_seconds
        self._links: Dict[Tuple[str, str], _LinkWindow] = {}

    def ingest(self, packet: dict) -> Optional[dict]:
        src = str(packet.get("src", packet.get("source", "")))
        dst = str(packet.get("dst", packet.get("destination", "")))
        if not src or not dst:
            return None

        now = float(packet.get("timestamp", time.time()))
        seq = packet.get("seq", packet.get("sequence_number"))
        rssi = packet.get("rssi")
        latency = float(packet.get("latency_ms", packet.get("latency", 15.0)))
        retries = int(packet.get("retransmissions", 0))

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

        link.samples.append((now, seq, rssi, is_dup, is_gap, latency, retries))

        # Drop old entries outside window
        cutoff = now - self.window_seconds
        while link.samples and link.samples[0][0] < cutoff:
            link.samples.popleft()

        window = link.samples
        if not window:
            return None

        packet_rate = len(window) / self.window_seconds

        rssi_vals = [s[2] for s in window if s[2] is not None]
        avg_rssi = round(sum(rssi_vals) / len(rssi_vals)) if rssi_vals else -55

        dup_count = sum(1 for s in window if s[3])

        seqs = [s[1] for s in window if s[1] is not None]
        packet_loss = 0.0
        if len(seqs) >= 2:
            expected = max(seqs) - min(seqs) + 1
            if expected > 0:
                packet_loss = max(0.0, (expected - len(seqs)) / expected) * 100.0

        latencies = [s[5] for s in window]
        avg_latency = sum(latencies) / len(latencies) if latencies else 15.0
        total_retries = sum(s[6] for s in window)

        node_identity_status = 0 if src in AUTHORIZED_NODES else 1

        return {
            "timestamp": round(now, 4),
            "source_node_id": src,
            "destination_node_id": dst,
            "packet_rate": round(packet_rate, 2),
            "packet_loss": round(packet_loss, 2),
            "latency_ms": round(avg_latency, 2),
            "rssi": int(avg_rssi),
            "retransmissions": total_retries,
            "sequence_number": seq if seq is not None else 0,
            "duplicate_packets": dup_count,
            "node_identity_status": node_identity_status,
        }


class GroundTruthReader:
    """Reads state from controller and discards transition boundary rows."""

    def __init__(self, state_file: Path, transition_buffer_s: float = 1.5):
        self.state_file = state_file
        self.transition_buffer_s = transition_buffer_s

        self.last_state = "NORMAL"
        self.last_transition_time = 0.0
        self.cached_payload: Dict = {}
        self.last_read_time = 0.0

    def get_ground_truth(self, current_time: float) -> Tuple[str, bool]:
        if current_time - self.last_read_time > 0.2:
            self._read_file()
            self.last_read_time = current_time

        mode = self.cached_payload.get("active_state", "NORMAL").upper()
        start_t = float(self.cached_payload.get("start_time", 0.0))
        end_t = float(self.cached_payload.get("end_time", 0.0))

        if mode not in ["NORMAL", "IDLE"]:
            if current_time < start_t or current_time > end_t:
                mode = "NORMAL"

        if mode != self.last_state:
            logger.info("Ground truth transition: %s -> %s", self.last_state, mode)
            self.last_state = mode
            self.last_transition_time = current_time

        is_transitional = (current_time - self.last_transition_time) < self.transition_buffer_s

        label_map = {
            "DOS": "DoS",
            "REPLAY": "Replay",
            "SPOOFING": "Spoofing",
            "ROGUE_NODE": "Rogue_Node",
            "NORMAL": "Normal",
            "IDLE": "Normal",
        }
        return label_map.get(mode, "Normal"), is_transitional

    def _read_file(self):
        if not self.state_file.exists():
            return
        try:
            with open(self.state_file, "r", encoding="utf-8") as f:
                self.cached_payload = json.load(f)
        except Exception:
            pass


class SimulatedGatewayStream:
    """Generates synthetic mesh traffic matching active ground truth."""

    def __init__(self, ground_truth_reader: GroundTruthReader):
        self.gt_reader = ground_truth_reader
        self.node_ids = [1, 2, 3, 4, 5]
        self._seq: Dict[Tuple[int, int], int] = {}
        self._rssi: Dict[Tuple[int, int], float] = {}

    def get_next_packet(self) -> dict:
        now = time.time()
        label, _ = self.gt_reader.get_ground_truth(now)

        delay = random.uniform(0.12, 0.25)
        src = random.choice(self.node_ids)
        dst = random.choice([n for n in self.node_ids if n != src])
        retries = 0
        latency = random.uniform(8.0, 22.0)
        packet_type = "DATA"

        key = (src, dst)
        self._seq[key] = self._seq.get(key, 0) + 1
        seq = self._seq[key]

        cur_rssi = self._rssi.get(key, random.uniform(-65, -48))
        cur_rssi = max(-85.0, min(-40.0, cur_rssi + random.uniform(-2.0, 2.0)))
        self._rssi[key] = cur_rssi

        if label == "DoS":
            src = 4
            dst = random.choice([1, 2, 3, 5])
            delay = random.uniform(0.02, 0.04)
            retries = random.choice([1, 2, 4, 6])
            latency = random.uniform(70.0, 160.0)
            key = (src, dst)
            self._seq[key] = self._seq.get(key, 0) + 1
            seq = self._seq[key]
        elif label == "Replay":
            if random.random() < 0.65:
                seq = max(1, self._seq.get(key, 10) - random.randint(2, 8))
        elif label == "Spoofing":
            src = 2
            dst = random.choice([1, 3, 4, 5])
            retries = 1
            latency = random.uniform(15.0, 35.0)
            cur_rssi = -78 if random.random() < 0.55 else -48
        elif label == "Rogue_Node":
            src = 99
            dst = random.choice(self.node_ids)
            retries = 0
            latency = random.uniform(20.0, 40.0)

        time.sleep(delay)

        return {
            "src": src,
            "dst": dst,
            "seq": seq,
            "type": packet_type,
            "ttl": 3,
            "rssi": round(cur_rssi),
            "latency_ms": latency,
            "retransmissions": retries,
            "timestamp": now,
        }


class DatasetGenerator:
    def __init__(
        self,
        output_file: Path,
        serial_port: Optional[str] = None,
        baudrate: int = 115200,
        simulate: bool = False,
        ipc_file: str = ".ground_truth_state.json",
        transition_buffer_s: float = 1.5,
        window_seconds: float = 2.0,
    ):
        self.output_file = Path(output_file).resolve()
        self.serial_port = serial_port
        self.baudrate = baudrate
        self.simulate = simulate
        self.running = True

        self.gt_reader = GroundTruthReader(Path(ipc_file).resolve(), transition_buffer_s=transition_buffer_s)
        self.aggregator = RollingMetricsAggregator(window_seconds=window_seconds)

        self.rows_written = 0
        self.rows_discarded = 0
        self.label_counts: Dict[str, int] = {}

        self._init_csv()

    def _init_csv(self):
        write_header = not self.output_file.exists() or self.output_file.stat().st_size == 0
        if write_header:
            with open(self.output_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(CSV_COLUMNS)
            logger.info("Initialized CSV at: %s", self.output_file)

    def write_row(self, metrics: dict, label: str):
        row = [
            metrics["timestamp"],
            metrics["source_node_id"],
            metrics["destination_node_id"],
            metrics["packet_rate"],
            metrics["packet_loss"],
            metrics["latency_ms"],
            metrics["rssi"],
            metrics["retransmissions"],
            metrics["sequence_number"],
            metrics["duplicate_packets"],
            metrics["node_identity_status"],
            label,
        ]

        with open(self.output_file, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(row)

        self.rows_written += 1
        self.label_counts[label] = self.label_counts.get(label, 0) + 1

    def run_serial_stream(self):
        import serial
        logger.info("Reading gateway serial on %s @ %d baud...", self.serial_port, self.baudrate)
        ser = serial.Serial(self.serial_port, self.baudrate, timeout=1.0)
        try:
            while self.running:
                raw = ser.readline()
                line = raw.decode("utf-8", errors="ignore").strip()
                if not line:
                    continue
                try:
                    packet = json.loads(line)
                    self._process_packet(packet)
                except json.JSONDecodeError:
                    pass
        finally:
            ser.close()

    def run_simulated_stream(self, row_limit: Optional[int] = None):
        logger.info("Running simulated gateway stream...")
        stream = SimulatedGatewayStream(self.gt_reader)
        while self.running:
            packet = stream.get_next_packet()
            self._process_packet(packet)
            if row_limit and self.rows_written >= row_limit:
                break

    def _process_packet(self, packet: dict):
        now = time.time()
        metrics = self.aggregator.ingest(packet)
        if not metrics:
            return

        label, is_transitional = self.gt_reader.get_ground_truth(now)

        if is_transitional:
            self.rows_discarded += 1
            return

        self.write_row(metrics, label)

        if self.rows_written % 25 == 0 or self.rows_written == 1:
            logger.info("[%d rows] Label: %-10s | Link: %s->%s | Rate: %.1f pkts/s",
                        self.rows_written, label, metrics["source_node_id"], metrics["destination_node_id"], metrics["packet_rate"])

    def shutdown(self):
        self.running = False
        print(f"\nCaptured {self.rows_written} rows ({self.rows_discarded} transition rows dropped).")
        for lbl, count in sorted(self.label_counts.items()):
            pct = (count / self.rows_written * 100) if self.rows_written > 0 else 0
            print(f"  {lbl:12s}: {count:5d} ({pct:5.1f}%)")
        print(f"Saved to: {self.output_file}")


def main():
    parser = argparse.ArgumentParser(description="Dataset Generator & Auto-Labeler")
    parser.add_argument("--port", "-p", type=str, default=None, help="Gateway serial port")
    parser.add_argument("--baud", "-b", type=int, default=115200, help="Gateway baudrate")
    parser.add_argument("--output", "-o", type=str, default="securemesh_dataset.csv", help="Output CSV path")
    parser.add_argument("--simulate", "-s", action="store_true", help="Use simulated gateway stream")
    parser.add_argument("--ipc-file", type=str, default=".ground_truth_state.json", help="Ground truth state file")
    parser.add_argument("--transition-buffer", type=float, default=1.5, help="Transition discard window in seconds")
    parser.add_argument("--limit", type=int, default=None, help="Row limit")

    args = parser.parse_args()

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S"))
    logger.addHandler(console)
    logger.setLevel(logging.INFO)

    generator = DatasetGenerator(
        output_file=Path(args.output),
        serial_port=args.port,
        baudrate=args.baud,
        simulate=args.simulate or (args.port is None),
        ipc_file=args.ipc_file,
        transition_buffer_s=args.transition_buffer,
    )

    def handle_exit(signum, frame):
        generator.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)

    if args.port and not args.simulate:
        try:
            generator.run_serial_stream()
        except Exception as exc:
            logger.error("Serial connection failed: %s. Switching to simulation.", exc)
            generator.run_simulated_stream(row_limit=args.limit)
    else:
        generator.run_simulated_stream(row_limit=args.limit)

    generator.shutdown()


if __name__ == "__main__":
    main()
