# SecureMesh AI — Attack Simulation Suite Manual

This folder contains the complete attack orchestration and dataset generation toolkit for Member 2 of the SecureMesh AI project.

It generates labeled CSV datasets (DoS, Replay, Spoofing, Blackhole, Rogue Node) from the ESP32 mesh testbed for Member 3's ML intrusion detection pipeline.

Node 4, the attacker, is **autonomous**: not a mesh member, not commanded from the PC, and it starts cycling through its attacks the instant it boots (see `docs/attacker_node_requirements.md` "Autonomous Operation Model"). `dataset_generator.py --auto-cycle` is the primary way to label data against it; `attack_controller.py` remains for the older controller-driven workflow.

---

## 1. File Overview

| File | Description |
|---|---|
| `dataset_generator.py` | Listens to the gateway's unified JSON output (`docs/serial_json_schema.md`) and writes labeled CSV rows (`--format telemetry` by default, `--format features` for the 12-column schema). `--auto-cycle` labels from Node 4's fixed autonomous schedule; without it, labels come from `attack_controller.py`'s broadcast (or default to `Normal` if nothing is broadcasting). |
| `esp32_attacker.ino` | Firmware for the attacker ESP32 (Node 4): boot-time random target selection and the autonomous attack-cycle scheduler are done; the four attack payload functions are still stubs (see `docs/attacker_node_requirements.md`). |
| `attack_controller.py` | CLI orchestrator for the older, PC-commanded attacker model. Sends attack mode commands over serial and broadcasts ground-truth state for `dataset_generator.py`'s `--ipc-file` mode. Not needed for the current autonomous Node 4 firmware. |
| `attack_characteristics.md` | Reference guide describing expected telemetry signatures for each attack class. |
| `scenarios/` | JSON files defining multi-phase attack schedules (`default_scenario.json`, `fast_test_scenario.json`). |
| `mock_attacker.py` | Standalone serial emulator for testing without physical hardware. |
| `test_pipeline.py` | End-to-end automated integration test. |

---

## 2. Requirements & Setup

### Prerequisites
- Python 3.9+ (Python 3.11–3.14 supported)
- `pyserial` (required only when connecting to real hardware)

### Installation
Open a terminal in this folder and install dependencies:
```bash
pip install pyserial
```

---

## 3. Quick Start: Testing Without Hardware (Simulation Mode)

You can run and test the entire system on your laptop without any ESP32 boards plugged in.

> Node 4 (`esp32_attacker.ino`) is autonomous — it is not a mesh member, is not
> commanded from the PC, and starts cycling `DoS -> Replay -> Spoofing ->
> Blackhole -> DoS -> ...` (30s each) the instant it boots. There is nothing to
> control from a second terminal for it, so labeling comes from
> `--auto-cycle` instead of `attack_controller.py`.

### Step 1: Run the Dataset Generator with the autonomous schedule
```bash
python dataset_generator.py --simulate --auto-cycle --output dataset.csv
```
This is one command, one terminal — the built-in simulator behaves like the autonomous firmware, and `--auto-cycle` labels rows from the same fixed schedule described above (starting from the moment this command runs).

### Step 2: View the Generated Dataset
Open `dataset.csv` in Excel or VS Code. Each row is one `TELEMETRY` sample (`timestamp, reporter, target, rate, avg_rssi, drops`) plus its label (`Normal`, `DoS`, `Replay`, `Spoofing`, `Blackhole`). Add `--format features` to get the 12-column schema instead, which also captures `Rogue_Node`.

### Alternative: scripted scenarios via the controller

`attack_controller.py` still works against the older, controller-driven ground-truth mode (`--ipc-file`, the default when `--auto-cycle` is not passed) — useful for testing the `features` pipeline or a `ROGUE_NODE` phase, neither of which the autonomous cycle covers:
```bash
# Terminal 1
python dataset_generator.py --simulate --output dataset.csv
# Terminal 2
python attack_controller.py --mock --scenario scenarios/default_scenario.json
```

---

## 4. Running With Physical Hardware (ESP32 Boards)

### Step 1: Flash the Attacker Board
1. Open the Arduino IDE.
2. Open `esp32_attacker.ino`.
3. Select your ESP32 board (`Tools > Board > ESP32 Arduino > ESP32 Dev Module`).
4. Connect your designated attacker ESP32 via USB and select its COM port (e.g. `COM10`).
5. Click **Upload**.

Node 4 needs no further setup after this — leave it powered off until Step 4.

### Step 2: Flash the Gateway Board
Flash `firmware/mesh_node/mesh_node.ino` onto the gateway ESP32 with `NODE_ID 3` in `firmware/common/MeshConfig.h` (e.g. `COM9`). It prints one JSON line per event (`RX`, `TX`, `TELEMETRY`, `ALERT`) over USB serial. Nodes 1 and 2 run the same firmware with their own `NODE_ID`.

> **Important:** the gateway only hears frames addressed to it, and it is the only node whose serial port is logged. Node 4 targets a random node among 1-3 by itself; if it happens to pick a node other than 3, that phase's frames will not show up in the dataset (a real limitation of the current design, not a bug).

Node 4 is autonomous now, so there is no attack controller step. Capture the dataset in two passes instead — a clean baseline with Node 4 off, then an attack capture from the moment it is powered on:

### Step 3: Capture a clean baseline (Node 4 still powered off)
```bash
python dataset_generator.py --port COM9 --baud 115200 --output baseline.csv
```
Let it run for a few minutes, then stop it (Ctrl+C). Every row is labeled `Normal` (no `--auto-cycle`, so it defaults to the plain "no attack active" reader).

### Step 4: Capture the attack cycle
Start this the same moment you power on Node 4, so its logged schedule lines up with when Node 4 actually starts attacking:
```bash
python dataset_generator.py --port COM9 --baud 115200 --output attack.csv --auto-cycle
```
It labels rows `DoS -> Replay -> Spoofing -> Blackhole -> DoS -> ...` (30s each, matching the firmware's `ATTACK_PHASE_DURATION_MS`) starting from the moment this command runs. Let it run for a few full cycles, then stop it.

Merge `baseline.csv` and `attack.csv` (same columns, just concatenate the rows) for training.

---

## 5. Telemetry Schema Reference

### `--format telemetry` (default, `docs/integration_steps.md` Phase A)

| Column | Description |
|---|---|
| `timestamp` | Epoch seconds when the line was logged |
| `reporter` | Node that computed the statistic (the gateway, 3) |
| `target` | Peer being profiled |
| `rate` | Packets received from that peer in the last second |
| `avg_rssi` | Average signal strength from that peer (dBm) |
| `drops` | Cumulative missing sequence numbers (includes frames sent to other nodes, so it is not pure loss) |
| `label` | Ground truth: `Normal`, `DoS`, `Replay`, `Spoofing`, `Blackhole` |

Known limits of this format: the firmware's `TELEMETRY` only covers node IDs 1-5, so a rogue node is invisible (rogue-phase rows are skipped rather than mislabeled), and replayed frames with old sequence numbers are ignored by it, so a replay only shows as a small rate bump. Use `--format features` if you need those.

### `--format features` (12 columns, built from `RX` lines)

The fixed 12-column schema used by the ML feature-engineering guide:

| Column | Type | Description |
|---|---|---|
| `timestamp` | Float | Unix epoch timestamp of window evaluation |
| `source_node_id` | String / Int | Originating node ID (e.g. `1`, `2`, `4`, `99`) |
| `destination_node_id` | String / Int | Target node ID |
| `packet_rate` | Float | Rolling packets/second over a 2.0-second window |
| `packet_loss` | Float | Calculated packet loss percentage (0.0 to 100.0) |
| `latency_ms` | Float | Packet transit latency in milliseconds |
| `rssi` | Int | Received signal strength in dBm (-90 to -30) |
| `retransmissions` | Int | Count of packet retransmission attempts |
| `sequence_number` | Int | Current packet sequence number |
| `duplicate_packets` | Int | Number of duplicate/backward sequence packets |
| `node_identity_status` | Int | `0` = Known / Valid node, `1` = Suspicious / Foreign node |
| `label` | String | Ground truth: `Normal`, `DoS`, `Replay`, `Spoofing`, `Rogue_Node` |

---

## 6. How Transition Filtering Works

When switching attack modes (e.g. Normal $\to$ DoS), the radio channel takes 1–2 seconds to transition.

To avoid recording ambiguous transitional packets that confuse the ML training pipeline:
- `dataset_generator.py` discards telemetry evaluated within `--transition-buffer` seconds (default: `1.5s`) of any mode switch.
- Only stable, steady-state packets are written to the CSV file.

---

## 7. Creating Custom Attack Scenarios

Create a JSON file in `scenarios/` with the following structure:

```json
{
  "name": "Custom Test",
  "attacker_id": 4,
  "phases": [
    {
      "mode": "NORMAL",
      "duration_s": 30,
      "description": "Baseline traffic"
    },
    {
      "mode": "DOS",
      "duration_s": 45,
      "parameters": {
        "packet_rate_ms": 10
      },
      "description": "Flooding test"
    },
    {
      "mode": "NORMAL",
      "duration_s": 20,
      "description": "Recovery"
    }
  ]
}
```

Run it with:
```bash
python attack_controller.py --scenario scenarios/my_custom_scenario.json
```

---

## 8. Automated Self-Test

To verify that the entire pipeline functions correctly:
```bash
python test_pipeline.py
```
This script launches mock firmware, runs a fast multi-phase scenario, and verifies that the output CSV contains valid data across all 5 classes with exact schema compliance.

---

## 9. Troubleshooting

- **`PermissionError: [Errno 13] Permission denied: 'COM...'`**: Ensure no other program (such as the Arduino Serial Monitor or another script) has the COM port open.
- **`ModuleNotFoundError: No module named 'serial'`**: Run `pip install pyserial` (make sure it is `pyserial`, not `serial`).
- **Generator shows 0 rows recorded**: Verify that the gateway ESP32 is outputting valid JSON lines, or use `--simulate` if testing without hardware.
