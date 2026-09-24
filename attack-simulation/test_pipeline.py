#!/usr/bin/env python3
"""End-to-end integration test for the attack simulation and dataset generation suite."""

from __future__ import annotations

import csv
import subprocess
import sys
import time
from pathlib import Path

EXPECTED_COLUMNS = [
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

EXPECTED_LABELS = {"Normal", "DoS", "Replay", "Spoofing", "Rogue_Node"}


def run_test():
    root = Path(__file__).parent.resolve()
    scenario = root / "scenarios" / "fast_test_scenario.json"
    ipc_file = root / ".test_ground_truth.json"
    log_file = root / "test_attack_controller.log"
    csv_file = root / "test_dataset.csv"

    # Remove old test files
    for f in [ipc_file, log_file, csv_file]:
        if f.exists():
            f.unlink()

    print("Running integration test...")

    # Start dataset generator
    gen_cmd = [
        sys.executable,
        str(root / "dataset_generator.py"),
        "--output", str(csv_file),
        "--ipc-file", str(ipc_file),
        "--simulate",
        "--transition-buffer", "1.0",
    ]
    gen_proc = subprocess.Popen(gen_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.0)

    # Start controller with fast scenario
    ctrl_cmd = [
        sys.executable,
        str(root / "attack_controller.py"),
        "--scenario", str(scenario),
        "--ipc-file", str(ipc_file),
        "--log-file", str(log_file),
        "--mock",
    ]
    ctrl_proc = subprocess.Popen(ctrl_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    ctrl_proc.communicate()

    # Let generator capture trailing normal traffic then terminate
    time.sleep(1.5)
    gen_proc.terminate()
    try:
        gen_proc.wait(timeout=3.0)
    except subprocess.TimeoutExpired:
        gen_proc.kill()

    # Verify CSV file
    assert csv_file.exists(), f"Missing {csv_file}"
    assert log_file.exists(), f"Missing {log_file}"

    rows = []
    with open(csv_file, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)
        assert header == EXPECTED_COLUMNS, f"Header mismatch: {header}"
        for row in reader:
            rows.append(row)

    print(f"Total rows logged: {len(rows)}")
    assert len(rows) > 30, f"Too few rows: {len(rows)}"

    labels_seen = set()
    for r in rows:
        assert len(r) == 12
        labels_seen.add(r[11])

    missing = EXPECTED_LABELS - labels_seen
    assert not missing, f"Missing labels: {missing}"

    print(f"All classes captured: {sorted(labels_seen)}")
    print("Test passed successfully.")


if __name__ == "__main__":
    run_test()
