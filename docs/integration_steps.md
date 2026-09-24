# System Integration Guide

This guide details how to integrate the hardware mesh network with the software backend (dataset generation, ML training, and website dashboard).

## Phase A: Baseline Dataset Generation (Normal Traffic)

Before the AI can detect attacks, it needs a dataset of normal mesh behavior.

1.  **Hardware Setup:**
    *   Flash `firmware/mesh_node/mesh_node.ino` to Nodes 1, 2, and 3 (ensure `NODE_ID` is set correctly in `MeshConfig.h` before each flash).
    *   Power on Nodes 1 and 2 (e.g., using a battery bank or USB wall charger).
    *   Plug Node 3 (The Gateway) into the PC via USB.
2.  **Data Capture Script:**
    *   The software team needs to write a simple Python script (`dataset_logger.py`) using the `pyserial` library.
    *   The script must connect to Node 3's COM port at `115200` baud.
    *   It should listen for lines starting with `{"type":"TELEMETRY"`.
    *   It should parse these JSON objects and append them as rows to a CSV file (e.g., `normal_baseline.csv`) with columns: `timestamp, reporter, target, rate, avg_rssi, drops`.
3.  **Execution:**
    *   Run the script and let the mesh operate normally for 15-30 minutes to collect thousands of rows of baseline data.

## Phase B: Attack Dataset Generation

Once the normal baseline is captured, you need to capture how the telemetry changes under attack.

1.  **Hardware Setup:**
    *   Keep Nodes 1, 2, and 3 running as before.
    *   Flash the custom attacker firmware to Node 4.
    *   Power on Node 4.
2.  **Execution (DoS):**
    *   Start a new CSV log (e.g., `attack_dos.csv`).
    *   Trigger the DoS flood from Node 4 targeting Node 1 or 2.
    *   Capture 5-10 minutes of data.
3.  **Execution (Other Attacks):**
    *   Repeat the process, triggering MAC Spoofing, Replay, and Blackhole attacks one by one, saving them to distinct CSV files.

## Phase C: Machine Learning Training

1.  **Merge Data:** The software team merges the `normal_baseline.csv` and the various attack CSVs into one master dataset. Add a label column (e.g., `0` for normal, `1` for DoS, `2` for Spoof, etc.).
2.  **Train Model:** Train a lightweight model like a Decision Tree or Random Forest on this dataset.
3.  **Export to C++:** Use a tool like `m2cgen` (Model 2 C Code Generator) to convert the trained Python Decision Tree into raw C++ `if/else` statements.
4.  **Embed in Firmware:** Paste this C++ code back into the ESP32 firmware so the nodes can run the AI locally without needing the PC.

## Phase D: Website Dashboard Integration

1.  **WebSerial API:** The frontend team should use the HTML5 WebSerial API in their JavaScript to connect directly to Node 3's COM port from the browser.
2.  **Parsing:**
    *   Listen for `{"type":"TX"}` and `{"type":"RX"}` to draw animated lines on the network graph showing real-time traffic bouncing between nodes.
    *   Listen for `{"type":"TELEMETRY"}` to update the health gauges (packets/sec, RSSI) on the dashboard.
    *   Listen for `{"type":"ALERT"}` to flash the screen red and mark a node as isolated.
3.  **Command & Control:** Add buttons on the website that send Serial commands back to the Gateway (e.g., `ISOLATE_NODE_4`), which the Gateway will then broadcast over ESP-NOW to force the mesh to heal.
