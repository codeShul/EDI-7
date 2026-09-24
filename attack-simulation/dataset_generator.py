#!/usr/bin/env python3
"""Telemetry logger and ground-truth dataset generator for SecureMesh AI.

Reads the gateway ESP32's serial output (Node 3 running firmware/mesh_node),
which prints one flat JSON object per event (docs/serial_json_schema.md):
RX, TX, TELEMETRY and ALERT. It syncs with attack_controller.py to know which
attack is active and writes a labeled CSV.

Two CSV formats are supported (--format):

  telemetry (default)  One row per TELEMETRY line, exactly the columns of
                       docs/integration_steps.md Phase A plus the label:
                       timestamp, reporter, target, rate, avg_rssi, drops, label.
                       These are the features the on-device model sees.

  features             The original 12-column schema derived from RX lines with
                       a rolling window (see attack_characteristics.md).

Limits worth knowing (see INSTRUCTIONS.md): TELEMETRY only covers node IDs 1-5,
so a rogue node never appears in the `telemetry` format, and a replay is
invisible in it (the firmware ignores backwards sequence numbers there).
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

FORMAT_TELEMETRY = "telemetry"
FORMAT_FEATURES = "features"

# integration_steps.md Phase A columns + ground-truth label
TELEMETRY_COLUMNS = ["timestamp", "reporter", "target", "rate", "avg_rssi", "drops", "label"]

# Original schema (12 columns) used by the ML feature-engineering guide
FEATURE_COLUMNS = [
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
CSV_COLUMNS = FEATURE_COLUMNS  # backwards-compatible name

# Authorized nodes in the mesh
AUTHORIZED_NODES = {1, 2, 3, 4, 5, "1", "2", "3", "4", "5", "NODE_01", "NODE_02", "NODE_03", "NODE_04", "NODE_05"}

GATEWAY_ID = 3     # the node whose serial port is logged (firmware/common/MeshConfig.h GATEWAY_ID)
ATTACKER_ID = 4    # docs/attacker_node_requirements.md

LABEL_MAP = {
    "DOS": "DoS",
    "REPLAY": "Replay",
    "SPOOFING": "Spoofing",
    "BLACKHOLE": "Blackhole",
    "ROGUE_NODE": "Rogue_Node",
    "NORMAL": "Normal",
    "IDLE": "Normal",
}


def classify(msg: dict) -> Optional[str]:
    """RX / TX / TELEMETRY / ALERT for a gateway line, else None.

    Lines of the earlier schema draft still work: `telemetry: true` is
    TELEMETRY, and a bare packet line (src + dst, type DATA/HEARTBEAT/ROUTE_SYNC)
    is RX."""
    kind = msg.get("type")
    if kind in ("RX", "TX", "TELEMETRY", "ALERT"):
        return kind
    if msg.get("telemetry") is True:
        return "TELEMETRY"
    if "src" in msg and "dst" in msg and kind in (None, "DATA", "HEARTBEAT", "ROUTE_SYNC"):
        return "RX"
    return None


def flat(kind: str, **fields) -> dict:
    """A message with every key the firmware's `print_json` always prints."""
    message = {
        "type": kind, "src": 0, "dst": 0, "seq": 0, "pkt_type": "", "ttl": 0, "rssi": 0,
        "receiver": 0, "hop": 0, "action": "", "delivery": "", "rate": 0, "avg_rssi": 0,
        "drops": 0, "threat": "",
    }
    message.update(fields)
    return message


@dataclass
class _SenderState:
    max_seq: Optional[int] = None
    recent: deque = field(default_factory=lambda: deque(maxlen=64))


@dataclass
class _LinkWindow:
    samples: deque = field(default_factory=deque)


class RollingMetricsAggregator:
    """Calculates link-level metrics over a sliding window from RX lines.

    The firmware numbers frames with ONE counter per sending node, and relays
    re-send a frame with a lower TTL, so sequence checks are made per sender:
    a duplicate is an exact repeat (same seq and TTL) or a backwards jump, and
    a relayed copy (same seq, lower TTL) is not a duplicate. The gateway only
    hears frames addressed to it, so sequence gaps include frames sent to other
    nodes; `packet_loss` is the share of missing sequence numbers, the same
    quantity as the firmware's `drops`."""

    def __init__(self, window_seconds: float = 2.0):
        self.window_seconds = window_seconds
        self._links: Dict[Tuple[str, str], _LinkWindow] = {}
        self._senders: Dict[str, _SenderState] = {}

    def ingest(self, packet: dict) -> Optional[dict]:
        src = str(packet.get("src", packet.get("source", "")))
        dst = str(packet.get("dst", packet.get("destination", "")))
        if not src or not dst:
            return None

        now = float(packet.get("timestamp", time.time()))
        seq = packet.get("seq", packet.get("sequence_number"))
        ttl = packet.get("ttl")
        rssi = packet.get("rssi")
        if rssi == 0:  # rssi 0 = "no reception" (gateway-originated), not a signal strength
            rssi = None
        latency = float(packet.get("latency_ms", packet.get("latency", 15.0)))
        retries = int(packet.get("retransmissions", 0))

        is_dup = False
        gap = 0
        if seq is not None:
            sender = self._senders.setdefault(src, _SenderState())
            if (seq, ttl) in sender.recent or (sender.max_seq is not None and seq < sender.max_seq):
                is_dup = True
            elif sender.max_seq is not None and seq > sender.max_seq + 1:
                gap = seq - sender.max_seq - 1
            sender.recent.append((seq, ttl))
            sender.max_seq = seq if sender.max_seq is None else max(sender.max_seq, seq)

        link = self._links.setdefault((src, dst), _LinkWindow())
        link.samples.append((now, seq, rssi, is_dup, gap, latency, retries))

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

        missing = sum(s[4] for s in window)
        packet_loss = missing / (missing + len(window)) * 100.0

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
        return LABEL_MAP.get(mode, "Normal"), is_transitional

    def parameters(self) -> Dict:
        """Parameters of the running attack phase (from the scenario)."""
        params = self.cached_payload.get("parameters")
        return params if isinstance(params, dict) else {}

    def _read_file(self):
        if not self.state_file.exists():
            return
        try:
            with open(self.state_file, "r", encoding="utf-8") as f:
                self.cached_payload = json.load(f)
        except Exception:
            pass


class SimulatedGatewayStream:
    """Emulates the serial output of the gateway (Node 3) during the test bed:
    normal nodes 1 and 2 plus the attacker (Node 4), in the unified schema.

    Per-peer statistics follow firmware/common/TelemetryEngine.h exactly (window
    counters reset every second, `drops` counts sequence gaps, senders outside
    1-5 are ignored) so the simulated `TELEMETRY` rows have the same quirks as
    the real ones. The gateway only hears frames addressed to it, so attacks
    target Node 3."""

    NORMAL_PEERS = (1, 2)
    RSSI_BASE = {1: -52.0, 2: -60.0, ATTACKER_ID: -45.0}
    SPOOF_RSSI = -75.0   # the attacker's own signal, different from the node it impersonates
    REPLAY_PATTERN = (0, 1, 2, 0, 1, 0)   # seq 100, 101, 102, then old numbers again
    REPLAY_BASE = 100

    def __init__(self, ground_truth_reader: GroundTruthReader):
        self.gt_reader = ground_truth_reader
        self._seq: Dict[int, int] = {}
        self._table = {n: {"packets": 0, "rssi_sum": 0, "last_seq": 0, "drops": 0} for n in range(1, 6)}
        self._queue: deque = deque()
        now = time.time()
        self._next_tick = now + 1.0
        self._next_normal = now
        self._next_attack = now
        self._replay_step = 0

    # ---- what the gateway firmware does on every received frame -------------
    def _update_table(self, sender: int, seq: int, rssi: int) -> None:
        if sender < 1 or sender > 5:
            return
        row = self._table[sender]
        row["packets"] += 1
        row["rssi_sum"] += rssi
        if row["last_seq"] > 0 and seq > row["last_seq"] + 1:
            row["drops"] += seq - row["last_seq"] - 1
        if seq > row["last_seq"]:
            row["last_seq"] = seq

    def _rx(self, src: int, seq: int, rssi: int, dst: int = GATEWAY_ID) -> dict:
        self._update_table(src, seq, rssi)
        return flat("RX", src=src, dst=dst, seq=seq, pkt_type="DATA", ttl=4, rssi=rssi,
                    receiver=GATEWAY_ID, action="CONSUMED" if dst == GATEWAY_ID else "RELAYING")

    def _telemetry_messages(self) -> list:
        messages = []
        for peer in sorted(self._table):
            row = self._table[peer]
            if row["packets"] > 0:
                avg = int(row["rssi_sum"] / row["packets"])
                messages.append(flat("TELEMETRY", src=peer, dst=GATEWAY_ID, rssi=avg, receiver=GATEWAY_ID,
                                     rate=row["packets"], avg_rssi=avg, drops=row["drops"]))
                row["packets"] = 0
                row["rssi_sum"] = 0
        return messages

    def _rssi(self, node: float, base: Optional[float] = None) -> int:
        centre = self.RSSI_BASE.get(node, -60.0) if base is None else base
        return round(centre + random.uniform(-2.0, 2.0))

    # ---- traffic generation --------------------------------------------------
    def _normal_frame(self, blackhole: bool) -> None:
        peer = random.choice(self.NORMAL_PEERS)
        # One counter per sender; frames it sent to other nodes are never heard here.
        skipped = 0
        if random.random() < 0.5:
            skipped = random.randint(3, 6) if blackhole else random.randint(1, 2)
        self._seq[peer] = self._seq.get(peer, 0) + 1 + skipped
        dst = GATEWAY_ID if random.random() < 0.85 else random.choice([n for n in (1, 2, ATTACKER_ID) if n != peer])
        self._queue.append(self._rx(peer, self._seq[peer], self._rssi(peer), dst))

    def _attack_frame(self, label: str) -> float:
        """Queue one frame for the active attack; returns the delay to the next."""
        params = self.gt_reader.parameters()
        if label == "DoS":
            self._seq[ATTACKER_ID] = self._seq.get(ATTACKER_ID, 0) + 1
            self._queue.append(self._rx(ATTACKER_ID, self._seq[ATTACKER_ID], self._rssi(ATTACKER_ID)))
            return random.uniform(0.015, 0.03)
        if label == "Replay":
            seq = self.REPLAY_BASE + self.REPLAY_PATTERN[self._replay_step % len(self.REPLAY_PATTERN)]
            self._replay_step += 1
            self._queue.append(self._rx(ATTACKER_ID, seq, self._rssi(ATTACKER_ID)))
            return 0.2
        if label == "Spoofing":
            spoofed = int(params.get("target_node_id", 2))
            self._seq[-spoofed] = self._seq.get(-spoofed, 0) + 1   # the attacker's own counter
            self._queue.append(self._rx(spoofed, self._seq[-spoofed], self._rssi(spoofed, self.SPOOF_RSSI)))
            return 0.2
        if label == "Rogue_Node":
            rogue = int(params.get("unauthorized_id", 99))
            self._seq[rogue] = self._seq.get(rogue, 0) + 1
            self._queue.append(self._rx(rogue, self._seq[rogue], self._rssi(rogue, -70.0)))
            return 0.3
        return 1.0

    def get_next_message(self) -> dict:
        while True:
            if self._queue:
                return self._queue.popleft()

            now = time.time()
            label, _ = self.gt_reader.get_ground_truth(now)
            attacking = label in ("DoS", "Replay", "Spoofing", "Rogue_Node")

            if now >= self._next_tick:
                self._next_tick = max(self._next_tick + 1.0, now + 0.5)
                self._queue.extend(self._telemetry_messages())
            elif attacking and now >= self._next_attack:
                self._next_attack = now + self._attack_frame(label)
            elif now >= self._next_normal:
                blackhole = label == "Blackhole"
                self._normal_frame(blackhole)
                self._next_normal = now + random.uniform(0.25, 0.6) * (1.6 if blackhole else 1.0)
            else:
                time.sleep(0.002)


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
        output_format: str = FORMAT_TELEMETRY,
    ):
        if output_format not in (FORMAT_TELEMETRY, FORMAT_FEATURES):
            raise ValueError(f"Unknown format {output_format!r}")
        self.output_file = Path(output_file).resolve()
        self.serial_port = serial_port
        self.baudrate = baudrate
        self.simulate = simulate
        self.output_format = output_format
        self.running = True

        self.gt_reader = GroundTruthReader(Path(ipc_file).resolve(), transition_buffer_s=transition_buffer_s)
        self.aggregator = RollingMetricsAggregator(window_seconds=window_seconds)

        self.rows_written = 0
        self.rows_discarded = 0
        self.rows_unobservable = 0
        self.lines_ignored = 0
        self.label_counts: Dict[str, int] = {}

        self._init_csv()

    @property
    def columns(self):
        return TELEMETRY_COLUMNS if self.output_format == FORMAT_TELEMETRY else FEATURE_COLUMNS

    def _init_csv(self):
        write_header = not self.output_file.exists() or self.output_file.stat().st_size == 0
        if write_header:
            with open(self.output_file, "w", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow(self.columns)
            logger.info("Initialized %s CSV at: %s", self.output_format, self.output_file)

    def _append_row(self, row: list, label: str):
        with open(self.output_file, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(row)
        self.rows_written += 1
        self.label_counts[label] = self.label_counts.get(label, 0) + 1

    def write_row(self, metrics: dict, label: str):
        """One row of the 12-column `features` format."""
        self._append_row([metrics[c] for c in FEATURE_COLUMNS[:-1]] + [label], label)

    def write_telemetry_row(self, message: dict, label: str):
        """One row of the `telemetry` format from a TELEMETRY line."""
        target = message.get("target", message.get("src"))
        reporter = message.get("reporter", message.get("receiver", message.get("dst")))
        self._append_row([
            round(time.time(), 4), reporter, target,
            message.get("rate", 0), message.get("avg_rssi", 0), message.get("drops", 0), label,
        ], label)

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
                    message = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(message, dict):
                    self._process_message(message)
        finally:
            ser.close()

    def run_simulated_stream(self, row_limit: Optional[int] = None):
        logger.info("Running simulated gateway stream (%s format)...", self.output_format)
        stream = SimulatedGatewayStream(self.gt_reader)
        while self.running:
            self._process_message(stream.get_next_message())
            if row_limit and self.rows_written >= row_limit:
                break

    def _process_message(self, message: dict):
        kind = classify(message)
        wanted = "TELEMETRY" if self.output_format == FORMAT_TELEMETRY else "RX"
        if kind != wanted:
            self.lines_ignored += 1   # TX / ALERT lines, or the other format's input
            return

        metrics = None
        if kind == "RX":
            metrics = self.aggregator.ingest(message)
            if not metrics:
                return

        label, is_transitional = self.gt_reader.get_ground_truth(time.time())
        if is_transitional:
            self.rows_discarded += 1
            return

        # TELEMETRY only covers node IDs 1-5, so during a rogue-node phase it shows
        # nothing but normal traffic; labeling those rows Rogue_Node would teach a
        # model the wrong thing. Only the `features` format (RX lines) can see it.
        if kind == "TELEMETRY" and label == "Rogue_Node":
            self.rows_unobservable += 1
            return

        if kind == "RX":
            self.write_row(metrics, label)
            detail = "Link: %s->%s | Rate: %.1f pkts/s" % (
                metrics["source_node_id"], metrics["destination_node_id"], metrics["packet_rate"])
        else:
            self.write_telemetry_row(message, label)
            detail = "Peer N%s | rate %s pps | avg_rssi %s | drops %s" % (
                message.get("target", message.get("src")), message.get("rate"),
                message.get("avg_rssi"), message.get("drops"))

        if self.rows_written % 25 == 0 or self.rows_written == 1:
            logger.info("[%d rows] Label: %-10s | %s", self.rows_written, label, detail)

    def shutdown(self):
        self.running = False
        print(f"\nCaptured {self.rows_written} rows ({self.rows_discarded} transition rows dropped, "
              f"{self.rows_unobservable} rogue-phase rows skipped, {self.lines_ignored} other lines ignored).")
        for lbl, count in sorted(self.label_counts.items()):
            pct = (count / self.rows_written * 100) if self.rows_written > 0 else 0
            print(f"  {lbl:12s}: {count:5d} ({pct:5.1f}%)")
        print(f"Saved to: {self.output_file}")


def main():
    parser = argparse.ArgumentParser(description="Dataset Generator & Auto-Labeler")
    parser.add_argument("--port", "-p", type=str, default=None, help="Gateway (Node 3) serial port")
    parser.add_argument("--baud", "-b", type=int, default=115200, help="Gateway baudrate")
    parser.add_argument("--output", "-o", type=str, default="securemesh_dataset.csv", help="Output CSV path")
    parser.add_argument("--format", "-f", choices=[FORMAT_TELEMETRY, FORMAT_FEATURES], default=FORMAT_TELEMETRY,
                        help="telemetry: one row per TELEMETRY line (integration_steps.md); "
                             "features: 12-column schema from RX lines")
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
        output_format=args.format,
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
