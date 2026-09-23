# SecureMesh AI: Master Engineering Blueprint & Implementation Plan

> **Project Title**: SecureMesh AI — An Edge-AI-Based Intrusion Detection and Self-Healing Framework for ESP32 IoT Mesh Networks  
> **Lead Architecture Document**: System blueprint, technology trade-offs, 15-phase roadmap, and Phase 1 execution plan.

---

## 1. Current Workspace Analysis

An inspection of the workspace (`c:\Camputer\Projects\EDI`) reveals the following existing assets:

| Asset / Directory | Status | Description / Purpose |
|---|---|---|
| [project.md.txt](file:///c:/Camputer/Projects/EDI/project.md.txt) | Available | Master project build specification covering end-to-end flow from mesh to ML and dashboard. |
| [myrole.txt](file:///c:/Camputer/Projects/EDI/myrole.txt) | Available | Detailed specification focusing on networking telemetry, protocol abstraction, and gateway ingestion. |
| [dashboard_plan.md](file:///c:/Camputer/Projects/EDI/dashboard_plan.md) | Available | Comprehensive tentative UI/UX plan with 10-link topology, packet inspector, and multi-tier logs. |
| [ApplicationPacket.h](file:///c:/Camputer/Projects/EDI/esp32_firmware/include/ApplicationPacket.h) | Available | C++ header defining packet structures, telemetry report frames, and command types. |
| [MeshNetworkInterface.h](file:///c:/Camputer/Projects/EDI/esp32_firmware/include/MeshNetworkInterface.h) | Available | Pure abstract C++ interface for mesh implementations (`initialize`, `sendPacket`, `isolateNode`). |
| [TelemetryEngine.h](file:///c:/Camputer/Projects/EDI/esp32_firmware/include/TelemetryEngine.h) | Available | Header for windowed calculation of packet rate, loss %, RSSI, latency, and sequence anomalies. |
| [sender.ino](file:///c:/Camputer/Projects/EDI/esp32_firmware/esp_now_2node_test/sender/sender.ino) | Available | ESP-NOW test transmitter with Core 3.x / IDF 5.x compatible callbacks. |
| [receiver.ino](file:///c:/Camputer/Projects/EDI/esp32_firmware/esp_now_2node_test/receiver/receiver.ino) | Available | ESP-NOW test receiver with RSSI and payload logging. |
| [read_mac.py](file:///c:/Camputer/Projects/EDI/gateway_pc/read_mac.py) | Available | Serial utility for reading ESP32 bootloader logs and extracting hardware MAC addresses. |
| **Hardware State** | Verified | **ESP32 Node 1 connected on COM9** (Silicon Labs CP210x, STA MAC: `68:09:47:86:31:D0`). |

---

## 2. Required Technologies

- **Embedded Firmware**: C++17, Arduino ESP32 Core (v3.x / ESP-IDF v5.x), ESP-NOW Protocol, FreeRTOS.
- **Edge Gateway PC Backend**: Python 3.13, FastAPI, Uvicorn, PySerial, NetworkX (Graph routing), SQLite (Database storage).
- **AI / Intrusion Detection System**: Scikit-Learn, NumPy, Pandas, Joblib (Models: Decision Tree, Random Forest, SVM).
- **Monitoring Web Dashboard**: HTML5, Modern CSS3 (Dark NOC Theme), Vanilla JavaScript (ES6+), SVG / Canvas Graph Engine, Native WebSockets, WebSerial API.

---

## 3. Decentralized Three-Layer Modular Architecture Diagram

```text
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│ LAYER 3 — WEB DASHBOARD (Passive Presentation & Real-Time Observability)                        │
│ ├── 10-Link Topology Graph (SVG)    ├── Live Node Status Matrix    ├── Deep Packet Inspector    │
│ ├── Rolling Telemetry Charts        ├── Security Incident Audit Log ├── Self-Healing Trace Log  │
└───────────────────────────────────────────────▲─────────────────────────────────────────────────┘
                                                │ REST API / WebSocket Stream (JSON)
┌───────────────────────────────────────────────┴─────────────────────────────────────────────────┐
│ LAYER 2 — GATEWAY BRIDGE (Passive Ingestion & PC Serial Link)                                   │
│ ├── Telemetry Ingestion Receiver    ├── JSON Serializer (USB Serial 115200 baud)                │
└───────────────────────────────────────────────▲─────────────────────────────────────────────────┘
                                                │ Physical Gateway Radio Link (Sniffer)
┌───────────────────────────────────────────────┴─────────────────────────────────────────────────┐
│ LAYER 1 — ESP32 HARDWARE, MESH & TINYML (Autonomous Nodes)                                      │
│ ├── Node 1 (Booted COM9)  ├── Node 2                 ├── Node 3                                 │
│ ├── Node 4                ├── Node 5                 ├── ESP-NOW Redundant 10-Link Full Mesh    │
│ ├── Rolling Telemetry Engine ├── Peer Link Blacklist ├── TinyML Decision Tree (Local Execution) │
└─────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Component List

### Layer 1: Hardware & Mesh
1. **`ApplicationPacket`**: Unified 32-byte network frame (Headers, Sequence, TTL, Hop Count, Payload Hash, Checksum).
2. **`MeshNetworkInterface`**: Abstract C++ interface decoupling radio hardware from routing logic.
3. **`ESPNowMesh`**: Implementation handling peer discovery, unicast/broadcast framing, and blacklisting.
4. **`TelemetryEngine`**: Computes rolling 1-second window stats (`packet_rate`, `loss_pct`, `avg_rssi`, `seq_anomalies`).
5. **`IsolationController`**: Hardware executor that unregisters peers and updates local routing tables upon command.

### Layer 2: Edge Gateway
1. **`TelemetryReceiver`**: Serial/UDP ingestion daemon reading incoming mesh telemetry frames.
2. **`DatabaseEngine`**: SQLite manager maintaining `nodes`, `telemetry`, `security_events`, and `routes`.
3. **`RouteManager`**: Graph-theory solver (`NetworkX`) calculating shortest alternate paths when nodes are isolated.
4. **`ControlDispatcher`**: Formats and transmits network control packets (`ISOLATE`, `RESTORE`) back to the mesh.

### Layer 3: AI & Security
1. **`FeaturePipeline`**: Normalizes raw metrics into ML-ready feature vectors.
2. **`IDSClassifier`**: Multi-class model (`NORMAL`, `DOS`, `REPLAY`, `SPOOFING`, `ROGUE_NODE`).
3. **`DecisionEngine`**: State machine converting classifications into security actions.

### Layer 4: Web Dashboard
1. **`TopologyVisualizer`**: Interactive 5-node, 10-link SVG canvas with animated traffic pulses and link states.
2. **`PacketInspector`**: Live packet-by-packet capture stream with hex and JSON inspection modals.
3. **`TelemetryCards`**: Real-time throughput, RSSI, and error rate gauges.
4. **`AuditLogger`**: Multi-tab searchable and exportable event log.

---

## 5. Communication & Data Flow Diagram

```text
[ ESP32 Sensor Nodes N1..N5 ]
             │
             │ (1) Application Packets (ESP-NOW Mesh Radio)
             ▼
[ Monitoring / Gateway Node ]
             │
             │ (2) Structured Telemetry JSON (USB Serial / UDP)
             ▼
[ Gateway Telemetry Ingestor ] ────────► [ SQLite Database ]
             │
             │ (3) Feature Vector
             ▼
[ Feature Extraction Pipeline ]
             │
             │ (4) Normalized Telemetry
             ▼
[ ML Intrusion Detection Engine ]
             │
             │ (5) Prediction & Confidence Score (e.g. Node 2 -> DOS 96%)
             ▼
[ Security Decision Engine ]
       │                      │
       │ (6a) Alert JSON      │ (6b) ISOLATE Command Packet
       ▼                      ▼
[ Web Dashboard WebSocket ] [ Control Command Dispatcher ]
       │                      │
       │                      │ (7) Radio Control Command
       ▼                      ▼
[ Live UI Render ]          [ ESP32 Mesh Network ]
(Red Link, Alert Log)       (Node 2 Unregistered, Links Severed, Traffic Rerouted)
```

---

## 6. Recommended Project Structure

```text
securemesh-ai/
├── firmware/
│   ├── common/
│   │   ├── ApplicationPacket.h
│   │   ├── MeshNetworkInterface.h
│   │   └── TelemetryEngine.h
│   ├── node/
│   │   ├── ESPNowMesh.cpp
│   │   ├── TelemetryEngine.cpp
│   │   └── main.cpp
│   ├── gateway_node/
│   │   └── gateway_main.cpp
│   └── attacker/
│       ├── dos_flooder.ino
│       ├── replay_injector.ino
│       └── mac_spoofer.ino
│
├── backend/
│   ├── api/
│   │   ├── routes_api.py
│   │   └── websocket_hub.py
│   ├── telemetry/
│   │   ├── serial_reader.py
│   │   └── telemetry_parser.py
│   ├── database/
│   │   ├── db_manager.py
│   │   └── schema.sql
│   ├── decision_engine/
│   │   ├── decision_rules.py
│   │   └── recovery_controller.py
│   └── server.py
│
├── ml/
│   ├── data/
│   │   ├── raw_telemetry.csv
│   │   └── labeled_dataset.csv
│   ├── training/
│   │   ├── train_models.py
│   │   └── evaluate_metrics.py
│   └── inference/
│       ├── ids_engine.py
│       └── model_export_c.py
│
├── dashboard/
│   ├── index.html
│   ├── css/style.css
│   └── js/
│       ├── topology.js
│       ├── packet_inspector.js
│       └── app.js
│
├── docs/
│   ├── architecture.md
│   └── api_spec.md
│
└── README.md
```

---

## 7. Technology Decisions and Alternatives

### Decision 1: Wireless Protocol — ESP-NOW
- **Why Needed**: Provides direct peer-to-peer MAC-level communication without router overhead, sub-millisecond transmission, accurate hardware RSSI, and low memory consumption.
- **Alternatives**: ESP-MESH (Wi-Fi tree mesh), BLE Mesh, Standard Wi-Fi UDP.
- **Advantages**: Fast, zero association delay, direct broadcast and unicast support, lightweight frame size.
- **Limitations**: Max 250-byte payload (sufficient for telemetry frames); max 20 direct peers (we only need 4 peers per node).
- **Timing**: **Implemented in Phase 1**.

### Decision 2: Edge Gateway Compute — Local Edge PC
- **Why Needed**: Allows running rich Python ML models (Random Forest, SVM), real-time database logging, and web services without constraining ESP32 RAM.
- **Alternatives**: Running all ML directly on microcontrollers via tiny C trees.
- **Advantages**: Full visibility, rich dashboard hosting, rapid model retraining and hyperparameter tuning.
- **Limitations**: Requires one ESP32 connected via USB/Wi-Fi to the PC.
- **Timing**: **Implemented in Phase 5**.

### Decision 3: Machine Learning Model Selection
- **Why Needed**: To accurately classify multi-feature telemetry into normal vs attack categories with high explainability and low inference latency.
- **Alternatives**: Deep Neural Networks (MLP), Decision Tree, Random Forest, Support Vector Machine (SVM).
- **Advantages**: Random Forest / Decision Trees offer high accuracy, fast CPU inference ($< 2\text{ ms}$), and clean C-export capabilities (`m2cgen`).
- **Limitations**: Requires representative training datasets for all 4 attack classes.
- **Timing**: **Implemented in Phase 9**.

### Decision 4: Database — SQLite
- **Why Needed**: Zero-configuration, serverless, single-file relational database suitable for prototype telemetry and event logging.
- **Alternatives**: PostgreSQL, In-Memory Dict, MongoDB.
- **Advantages**: Embedded in Python standard library, zero setup overhead, full SQL query capability.
- **Limitations**: Concurrency limits under extreme multi-threaded writes (mitigated via background write queue).
- **Timing**: **Implemented in Phase 6**.

---

## 8. Hardware Requirements

- **5 $\times$ ESP32 Development Boards** (ESP32-WROOM-32 / NodeMCU-32S).
- **5 $\times$ Micro-USB / USB-C Cables**.
- **1 $\times$ Host PC** (Windows, running Python 3.13 and Arduino IDE / PlatformIO).
- **Optional**: 1 $\times$ DHT11/DHT22 or LDR for sensor payload simulation.
- **Power**: 5V USB Hub or independent power banks for distributed nodes.

---

## 9. Software Requirements

- **Python Environment**: Python 3.13.7, `pip install fastapi uvicorn pyserial scikit-learn pandas numpy networkx aiosqlite`.
- **Arduino IDE / PlatformIO**: ESP32 Board Package v3.x (`esp32 by Espressif Systems`).
- **Web Browser**: Chrome, Edge, or Firefox (supporting WebSockets and SVG rendering).

---

## 10. 15 Structured Development Phases

```text
Phase 1: ESP32 Basic Communication (P2P Handshake & ACK)
   ↓
Phase 2: Multi-Node Mesh (4–5 Nodes Discovery & Topology Table)
   ↓
Phase 3: Redundant Routing Paths (Path A vs Path B Multi-Hop Forwarding)
   ↓
Phase 4: Telemetry Collection Engine (Windowed Feature Tracker on Nodes)
   ↓
Phase 5: Gateway Communication Bridge (ESP32 Gateway Node -> PC Serial/UDP)
   ↓
Phase 6: Database & Persistence Layer (SQLite Nodes, Telemetry, Events Schema)
   ↓
Phase 7: Normal Baseline Dataset Generation (Continuous Clean Traffic Capture)
   ↓
Phase 8: Controlled Attack Simulation (DoS, Replay, Spoofing, Rogue Node)
   ↓
Phase 9: ML Model Training & Evaluation (Decision Tree, Random Forest, SVM)
   ↓
Phase 10: Real-Time IDS Inference Engine (Live Feature Extraction -> Model Output)
   ↓
Phase 11: Security Decision Engine (Threshold Checks, State Machine, Action Triggers)
   ↓
Phase 12: Node Isolation Execution (Gateway -> Mesh Control Command Dispatch)
   ↓
Phase 13: Dynamic Route Recovery (Path Recalculation & Verified Traffic Continuation)
   ↓
Phase 14: Web Monitoring Dashboard (SVG Topology, Packet Inspector, Multi-Tier Logs)
   ↓
Phase 15: Full End-to-End System Integration & Demonstration
```

---

## 11. Dependencies Between Phases

| Phase | Direct Prerequisites | Output Produced / Consumed By |
|---|---|---|
| **Phase 1** | Hardware Booted (COM9) | Stable 2-node radio link $\to$ Prerequisite for Phase 2. |
| **Phase 2–3** | Phase 1 | Active 5-node topology & multi-hop paths $\to$ Consumed by Phase 4. |
| **Phase 4–5** | Phase 2, 3 | Streaming telemetry data over USB $\to$ Consumed by Phase 6 & 7. |
| **Phase 6–8** | Phase 4, 5 | Labeled dataset (`raw_telemetry.csv`) $\to$ Consumed by Phase 9. |
| **Phase 9–10** | Phase 8 | Trained ML Classifier $\to$ Consumed by Phase 11. |
| **Phase 11–13**| Phase 3, 10 | Autonomous Isolation & Rerouting $\to$ Verified in Phase 15. |
| **Phase 14** | Phase 5, 6, 11 | Complete UI visualization $\to$ Consumed by Phase 15. |
| **Phase 15** | All previous phases | Final working prototype demonstration. |

---

## 12. Testing Strategy

1. **Link-Level Unit Tests (Phases 1–3)**: Verify packet delivery ratios, round-trip latency, and sequence continuity over ESP-NOW.
2. **Telemetry Validation Tests (Phase 4)**: Ensure calculated rolling window metrics (`packet_rate`, `loss_pct`, `rssi`) accurately reflect network conditions.
3. **Attack Generation Tests (Phase 8)**: Verify attacker nodes produce measurable parameter shifts ($> 20\text{ pkts/s}$ for DoS, non-increasing sequence numbers for Replay).
4. **ML Benchmark Tests (Phase 9)**: 5-Fold cross-validation measuring Accuracy, Precision, Recall, F1-Score, and Confusion Matrix across all candidate models.
5. **Self-Healing Verification Tests (Phases 12–13)**: Assert that when Node 2 is isolated, Node 1 successfully transmits to Node 3 via Node 4/5 with $0\%$ ongoing packet loss.

---

## 13. Risks and Blockers

| Risk / Challenge | Severity | Mitigation Strategy |
|---|---|---|
| **Radio Channel Saturation during DoS Flood** | Medium | Implement local node rate-limiting and prioritize control packets over data packets. |
| **ESP-NOW Peer Table Memory Limits** | Low | Network has 5 nodes; ESP-NOW supports up to 20 peers. Table overhead is $< 1\text{ KB}$. |
| **Model False Positives on Transient Link Drops** | Medium | Decision engine uses a rolling 3-window confirmation filter before triggering hard isolation. |
| **ESP32 Core 3.x Callback Signature Shifts** | Low | Used universal preprocessor macros (`#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5,0,0)`). |

---

## 14. Resolved Architectural Decisions

> [!NOTE]
> **`DECISION 1: Gateway Physical Transport — USB Serial (Option 1A)`**
> The Edge Gateway ESP32 will communicate with the Edge PC via **USB Serial (115200 baud)**. The Web Dashboard will use the modern HTML5 WebSerial API to read this telemetry directly from the USB port. This ensures zero network latency, 100% offline reliability, and removes the need for an external Wi-Fi router.

> [!NOTE]
> **`DECISION 2: Attack Triggering Mechanism — Software/Serial Command (Option 2A)`**
> Attack scenarios will be activated via **serial commands** sent directly from the Web Dashboard's UI. When a user clicks an attack button on the website, a command (e.g., `CMD:ATTACK:DOS:N2`) travels via WebSerial to the Gateway ESP32, which then silently broadcasts the trigger to the target node over the ESP-NOW mesh. This turns the dashboard into a true Command & Control (C2) center.

---

## 15. Concrete Phase 1 Implementation Plan

### Goal
Establish, verify, and document **bidirectional point-to-point ESP-NOW communication** between 2 physical ESP32 boards with sequence numbering, latency tracking, delivery status verification, and clean serial telemetry output.

### Tasks for Phase 1:
1. **Node 1 (Sender / Transceiver)**:
   - Configure Wi-Fi in Station Mode (`WIFI_STA`).
   - Register peer MAC address.
   - Transmit structured `ApplicationPacket` (Source ID: 1, Dest ID: 2, Sequence #, Timestamp, Payload Hash).
   - Capture `esp_now_send_cb` delivery confirmations (`SUCCESS` / `FAIL`).
2. **Node 2 (Receiver / Responder)**:
   - Configure Wi-Fi in Station Mode (`WIFI_STA`).
   - Listen for incoming frames via `esp_now_recv_cb`.
   - Calculate packet RSSI, verify sequence delta, and transmit an immediate ACK / echo response.
3. **Verification**:
   - Upload firmware to Node 1 (`COM9`) and Node 2.
   - Run verification script to confirm $> 99\%$ delivery rate and $< 10\text{ ms}$ latency over 100 packets.
