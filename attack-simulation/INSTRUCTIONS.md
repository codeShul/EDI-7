# SecureMesh AI — Attack Simulation Suite Manual

This folder contains the complete attack orchestration and dataset generation toolkit for Member 2 of the SecureMesh AI project.

It allows you to run controlled attack scenarios (DoS, Replay, Spoofing, Rogue Node) against the ESP32 mesh testbed and generate labeled CSV datasets for Member 3's ML intrusion detection pipeline.

---

## 1. File Overview

| File | Description |
|---|---|
| `attack_controller.py` | CLI orchestrator. Sends attack mode commands to the attacker ESP32 and broadcasts ground-truth state. |
| `dataset_generator.py` | Listens to the gateway's unified JSON output (`docs/serial_json_schema.md`) and writes labeled CSV rows (`--format telemetry` by default, `--format features` for the 12-column schema). |
| `esp32_attacker.ino` | Firmware skeleton for the attacker ESP32 (Node 4): state machine and serial parser are done; the attack payload functions are still stubs (see `docs/attacker_node_requirements.md`). |
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

### Step 1: Start the Dataset Generator
Open Terminal 1:
```bash
python dataset_generator.py --simulate --output dataset.csv
```
The generator starts listening for synthetic mesh telemetry.

### Step 2: Run an Attack Scenario
Open Terminal 2:
```bash
python attack_controller.py --mock --scenario scenarios/default_scenario.json
```
The controller will execute the scenario phases:
`Normal (25s) -> DoS (20s) -> Normal (15s) -> Replay (20s) -> Normal (15s) -> Spoofing (20s) -> Normal (15s) -> Blackhole (20s) -> Normal (15s) -> Rogue Node (20s) -> Normal (20s)`

As the controller switches modes, `dataset_generator.py` reads the active state and automatically labels every recorded row.

### Step 3: View the Generated Dataset
Open `dataset.csv` in Excel or VS Code. Each row is one `TELEMETRY` sample (`timestamp, reporter, target, rate, avg_rssi, drops`) plus its label (`Normal`, `DoS`, `Replay`, `Spoofing`, `Blackhole`). Add `--format features` to get the 12-column schema instead, which also captures `Rogue_Node`.

---

## 4. Running With Physical Hardware (ESP32 Boards)

### Step 1: Flash the Attacker Board
1. Open the Arduino IDE.
2. Open `esp32_attacker.ino`.
3. Select your ESP32 board (`Tools > Board > ESP32 Arduino > ESP32 Dev Module`).
4. Connect your designated attacker ESP32 via USB and select its COM port (e.g. `COM10`).
5. Click **Upload**.

### Step 2: Flash the Gateway Board
Flash `firmware/mesh_node/mesh_node.ino` onto the gateway ESP32 with `NODE_ID 3` in `firmware/common/MeshConfig.h` (e.g. `COM9`). It prints one JSON line per event (`RX`, `TX`, `TELEMETRY`, `ALERT`) over USB serial. Nodes 1 and 2 run the same firmware with their own `NODE_ID`.

> **Important:** the gateway only hears frames addressed to it, and it is the only node whose serial port is logged. Aim attacks at Node 3 (the controller's default for DoS) or they will not show up in the dataset.

### Step 3: Start the Dataset Generator
In your terminal, connect `dataset_generator.py` to your gateway COM port:
```bash
python dataset_generator.py --port COM9 --baud 115200 --output testbed_dataset.csv
```

### Step 4: Run the Attack Controller
In a second terminal, connect `attack_controller.py` to your attacker board COM port:

**Option A: Interactive Menu**
```bash
python attack_controller.py --port COM10 --interactive
```
You will see a menu:
```text
=== SecureMesh Attack Controller CLI ===
1. Set NORMAL (Baseline)
2. Trigger DOS (Packet Flood)
3. Trigger REPLAY (Old Sequence Numbers)
4. Trigger SPOOFING (Impersonate a Node)
5. Trigger BLACKHOLE (Drop Relayed Packets)
6. Trigger ROGUE_NODE (Unregistered Node ID)
7. Stop / Return to Idle
0. Exit
```
Enter a number to trigger the attack for a chosen duration.

**Option B: Automated Scenario**
```bash
python attack_controller.py --port COM10 --scenario scenarios/default_scenario.json
```

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
