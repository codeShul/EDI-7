#!/usr/bin/env python3
"""End-to-end integration test for the attack simulation and dataset generation suite.

Runs the controller (mock attacker) against the dataset generator (simulated
gateway) once per CSV format and checks columns, row counts and labels.
"""

from __future__ import annotations

import csv
import subprocess
import sys
import tempfile
import time
from pathlib import Path

FEATURE_COLUMNS = [
    "timestamp", "source_node_id", "destination_node_id", "packet_rate", "packet_loss",
    "latency_ms", "rssi", "retransmissions", "sequence_number", "duplicate_packets",
    "node_identity_status", "label",
]
TELEMETRY_COLUMNS = ["timestamp", "reporter", "target", "rate", "avg_rssi", "drops", "label"]

# A rogue node ID (99) is outside the 1-5 range the firmware's TELEMETRY covers,
# so it can only be captured in the `features` format (built from RX lines).
FORMATS = {
    "telemetry": (TELEMETRY_COLUMNS, {"Normal", "DoS", "Replay", "Spoofing", "Blackhole"}),
    "features": (FEATURE_COLUMNS, {"Normal", "DoS", "Replay", "Spoofing", "Blackhole", "Rogue_Node"}),
}


def run_format(root: Path, workdir: Path, fmt: str) -> None:
    columns, expected_labels = FORMATS[fmt]
    scenario = root / "scenarios" / "fast_test_scenario.json"
    ipc_file = workdir / f".{fmt}_ground_truth.json"
    log_file = workdir / f"{fmt}_attack_controller.log"
    csv_file = workdir / f"{fmt}_dataset.csv"

    print(f"[{fmt}] running...")

    gen_proc = subprocess.Popen(
        [sys.executable, str(root / "dataset_generator.py"), "--output", str(csv_file),
         "--ipc-file", str(ipc_file), "--simulate", "--format", fmt, "--transition-buffer", "1.0"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(1.0)

    ctrl_proc = subprocess.Popen(
        [sys.executable, str(root / "attack_controller.py"), "--scenario", str(scenario),
         "--ipc-file", str(ipc_file), "--log-file", str(log_file), "--mock"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    ctrl_proc.communicate()

    # Let the generator capture trailing normal traffic, then stop it
    time.sleep(1.5)
    gen_proc.terminate()
    try:
        gen_proc.wait(timeout=3.0)
    except subprocess.TimeoutExpired:
        gen_proc.kill()

    assert csv_file.exists(), f"[{fmt}] missing {csv_file}"
    assert log_file.exists(), f"[{fmt}] missing {log_file}"

    with open(csv_file, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)
        rows = list(reader)
    assert header == columns, f"[{fmt}] header mismatch: {header}"

    print(f"[{fmt}] rows logged: {len(rows)}")
    assert len(rows) > 30, f"[{fmt}] too few rows: {len(rows)}"

    labels_seen = set()
    for row in rows:
        assert len(row) == len(columns), f"[{fmt}] bad row width: {row}"
        labels_seen.add(row[-1])

    missing = expected_labels - labels_seen
    assert not missing, f"[{fmt}] missing labels: {missing}"
    unexpected = labels_seen - expected_labels
    assert not unexpected, f"[{fmt}] unexpected labels: {unexpected}"
    print(f"[{fmt}] classes captured: {sorted(labels_seen)}")


def run_auto_cycle(root: Path, workdir: Path) -> None:
    """Node 4 is autonomous now; check the controller-free labeling path
    directly (no attack_controller.py process involved)."""
    print("[auto-cycle] running...")
    csv_file = workdir / "auto_cycle_dataset.csv"

    proc = subprocess.Popen(
        [sys.executable, str(root / "dataset_generator.py"), "--output", str(csv_file),
         "--simulate", "--auto-cycle", "--cycle-phase-s", "2", "--transition-buffer", "0.3"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(10.0)   # >1 full cycle (4 phases x 2s) so every label appears
    proc.terminate()
    try:
        proc.wait(timeout=3.0)
    except subprocess.TimeoutExpired:
        proc.kill()

    assert csv_file.exists(), f"[auto-cycle] missing {csv_file}"
    with open(csv_file, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)
        rows = list(reader)
    assert header == TELEMETRY_COLUMNS, f"[auto-cycle] header mismatch: {header}"
    assert len(rows) > 5, f"[auto-cycle] too few rows: {len(rows)}"

    labels_seen = [row[-1] for row in rows]
    order_seen = []
    for label in labels_seen:
        if not order_seen or order_seen[-1] != label:
            order_seen.append(label)

    expected_cycle = ["DoS", "Replay", "Spoofing", "Drop_Anomaly"]
    assert order_seen[0] == "DoS", f"[auto-cycle] must start with DoS immediately: {order_seen}"
    # order_seen should be a slice of the repeating cycle (allow wrap-around)
    doubled = expected_cycle * 3
    joined = ",".join(order_seen)
    assert joined in ",".join(doubled), f"[auto-cycle] wrong cycle order: {order_seen}"
    print(f"[auto-cycle] label order: {order_seen}")


def check_schema_parsing() -> None:
    """The generator must understand the gateway's unified JSON lines."""
    sys.path.insert(0, str(Path(__file__).parent.resolve()))
    from dataset_generator import RollingMetricsAggregator, classify

    tx = {"type": "TX", "src": 1, "dst": 3, "seq": 105, "pkt_type": "DATA", "ttl": 4, "rssi": 0,
          "receiver": 1, "hop": 2, "action": "SENT", "delivery": "SUCCESS", "rate": 0,
          "avg_rssi": 0, "drops": 0, "threat": ""}
    rx = dict(tx, type="RX", rssi=-52, receiver=3, hop=0, action="CONSUMED", delivery="")
    telemetry = dict(tx, type="TELEMETRY", rate=12, avg_rssi=-48, drops=2, receiver=3)
    assert [classify(m) for m in (tx, rx, telemetry)] == ["TX", "RX", "TELEMETRY"]
    assert classify({"type": "ALERT", "src": 1}) == "ALERT"
    assert classify({"src": 1, "dst": 2, "seq": 5, "type": "DATA"}) == "RX"          # earlier draft
    assert classify({"telemetry": True, "reporter": 3, "target": 1}) == "TELEMETRY"  # earlier draft
    assert classify({"type": "DELIVERY", "node": 1}) is None

    # Per-sender sequence rules: a relayed copy (same seq, lower TTL) is not a duplicate,
    # an exact repeat and a backwards jump are, and rssi 0 is "no reception".
    agg = RollingMetricsAggregator()
    first = agg.ingest(dict(rx, seq=10))
    relayed = agg.ingest(dict(rx, seq=10, ttl=3))
    repeat = agg.ingest(dict(rx, seq=10, ttl=3))
    backwards = agg.ingest(dict(rx, seq=4))
    assert first["duplicate_packets"] == 0 and relayed["duplicate_packets"] == 0
    assert repeat["duplicate_packets"] == 1 and backwards["duplicate_packets"] == 2
    assert agg.ingest(dict(rx, src=2, seq=1, rssi=0))["rssi"] == -55   # only sample is "no reception": fallback
    print("[schema] parsing checks passed")


def run_test():
    root = Path(__file__).parent.resolve()
    print("Running integration test...")
    check_schema_parsing()
    with tempfile.TemporaryDirectory() as tmp:
        for fmt in FORMATS:
            run_format(root, Path(tmp), fmt)
        run_auto_cycle(root, Path(tmp))
    print("Test passed successfully.")


if __name__ == "__main__":
    run_test()
