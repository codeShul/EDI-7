# SecureMesh AI — Attack Simulation Suite Manual

This folder contains the complete attack orchestration and dataset generation toolkit for Member 2 of the SecureMesh AI project.

It allows you to run controlled attack scenarios (DoS, Replay, Spoofing, Rogue Node) against the ESP32 mesh testbed and generate labeled CSV datasets for Member 3's ML intrusion detection pipeline.

---

## 1. File Overview

| File | Description |
|---|---|
| `attack_controller.py` | CLI orchestrator. Sends attack mode commands to the attacker ESP32 and broadcasts ground-truth state. |
| `dataset_generator.py` | Listens to gateway telemetry, computes rolling link metrics, and outputs labeled CSV rows. |
| `esp32_attacker.ino` | Firmware skeleton for the attacker ESP32 (state machine, serial parser, and attack stubs). |
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
`Normal (25s) -> DoS (20s) -> Normal (15s) -> Replay (20s) -> Normal (15s) -> Spoofing (20s) -> Normal (15s) -> Rogue Node (20s) -> Normal (20s)`

As the controller switches modes, `dataset_generator.py` reads the active state and automatically labels every recorded row.

### Step 3: View the Generated Dataset
Open `dataset.csv` in Excel or VS Code. Each row will have all 12 telemetry features and the corresponding label (`Normal`, `DoS`, `Replay`, `Spoofing`, `Rogue_Node`).

---

## 4. Running With Physical Hardware (ESP32 Boards)

### Step 1: Flash the Attacker Board
1. Open the Arduino IDE.
2. Open `esp32_attacker.ino`.
3. Select your ESP32 board (`Tools > Board > ESP32 Arduino > ESP32 Dev Module`).
4. Connect your designated attacker ESP32 via USB and select its COM port (e.g. `COM10`).
5. Click **Upload**.

### Step 2: Flash the Gateway Board
Flash `firmware/gateway_node/gateway_node.ino` onto your gateway ESP32 (e.g. `COM9`). This board listens to mesh radio packets and prints JSON lines over USB serial.

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
3. Trigger REPLAY (Sequence Injection)
4. Trigger SPOOFING (MAC / Identity)
5. Trigger ROGUE_NODE (Unregistered Node)
6. Stop / Return to Idle
0. Exit
```
Enter a number to trigger the attack for a chosen duration.

**Option B: Automated Scenario**
```bash
python attack_controller.py --port COM10 --scenario scenarios/default_scenario.json
```

---

## 5. Telemetry Schema Reference

The CSV output follows the fixed 12-column schema required by Member 3's ML models:

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
