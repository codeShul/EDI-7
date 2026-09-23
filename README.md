# SecureMesh AI
An Edge-AI-Based Intrusion Detection and Self-Healing Framework for ESP32 IoT Mesh Networks.

**Team:** [Team name / batch] | **Guide:** [Name] | **Institute:** [Name]

---

## 1. Problem Definition, Related Work, and Complexity

### 1.1 Problem Statement
Modern IoT mesh networks are increasingly deployed in critical infrastructure, but they are highly vulnerable to cyberattacks such as Denial of Service (DoS), Replay attacks, and MAC Spoofing. Traditional Intrusion Detection Systems (IDS) rely on cloud connectivity (introducing latency and offline risks) or heavy local compute (which microcontrollers lack). There is a critical need for an offline, edge-based security framework that can detect attacks using machine learning and autonomously self-heal without cloud dependency.

### 1.2 Related Work
| Existing System / Product | What It Does | Limitation |
|---|---|---|
| Cloud-based IoT Security | Routes all IoT traffic to AWS/Azure for ML analysis | High latency, requires constant internet access, high bandwidth costs. |
| Threshold-based Micro-IDS | Uses hardcoded limits (e.g., >50 pkts/s) on microcontrollers | High false-positive rate, unable to detect complex patterns like Replay or Spoofing. |

### 1.3 Complexity of the Problem
- **Resource Constraints**: ESP32 microcontrollers have limited RAM (~520KB) and CPU speed, making on-device deep learning difficult.
- **Network Topology**: In a decentralized 5-node full mesh (10 links), isolating a node requires distributed consensus and dynamic route recalculation.
- **Latency**: Detecting an attack and severing the physical radio link must happen in under a few seconds to prevent network collapse.

---

## 2. Literature Review, Proposed Solution, Technical Approach, and Feasibility

### 2.1 Literature Review
| Ref | Title / Source | Key Finding | Gap Identified |
|---|---|---|---|
| [1] | [Placeholder Author, 2023] | ESP-NOW provides sub-millisecond P2P communication for IoT. | Lacks native encryption and built-in spoofing protection. |
| [2] | [Placeholder Author, 2024] | Random Forest models can classify IoT attack vectors with 98% accuracy. | Models are rarely integrated with automated radio-level isolation mechanisms. |

### 2.2 Proposed Solution
SecureMesh AI is a fully decentralized, 3-layer architecture combining an ESP-NOW wireless mesh, an On-Device ML-based IDS (TinyML Decision Trees), and a WebSerial passive monitoring dashboard. Instead of relying on an external Edge PC to make security decisions, every individual ESP32 runs a highly optimized Machine Learning classifier directly in its firmware. Each node independently extracts live telemetry from its peers, classifies malicious traffic (DoS, Replay, Spoofing) in real-time, and autonomously severs links with rogue nodes to dynamically reroute traffic, achieving true Edge-AI independence.

### 2.3 Technical Approach
- **Mesh Protocol**: ESP-NOW (for offline, router-less, ultra-low latency MAC-to-MAC communication).
- **AI/ML Engine**: Scikit-Learn in Python (trained on a PC), then exported to raw C++ using `m2cgen` (Model to C Generator) to run natively on the ESP32 microcontrollers.
- **Gateway Link**: USB WebSerial API (passively bridges mesh telemetry to the dashboard without acting as a master node).
- **Visualization**: HTML5/Vanilla JS with SVG canvas for 60fps topology rendering.

### 2.4 Feasibility
- **Technical:** High. Decision Trees compiled via `m2cgen` consume $<2\text{ KB}$ of Flash/RAM, fitting easily alongside the ESP-NOW networking stack on the ESP32.
- **Economic:** Highly affordable; the entire hardware footprint costs under $30.
- **Operational:** Works completely offline without needing a Wi-Fi router or an Edge PC to function, making it ideal for remote or harsh environments.
- **Schedule:** Divided into concrete, iterative phases ensuring steady progress from basic P2P links to full TinyML integration.

---

## 3. Cost, Resources, Environmental Relevance, and Sustainability

### 3.1 Cost (Bill of Materials)
| Item | Qty | Unit Cost | Total |
|---|---|---|---|
| ESP32 Development Board (WROOM-32) | 5 | $5.00 | $25.00 |
| Micro-USB / USB-C Cables | 5 | $2.00 | $10.00 |
| Edge Gateway PC (Laptop) | 1 | Existing | $0.00 |
| **Total** | | | **$35.00** |

### 3.2 Resources
- **Hardware**: 5 ESP32 nodes, 1 PC.
- **Software**: Arduino IDE (ESP-IDF v5.x core), Python 3.13, Scikit-learn, HTML/JS/CSS.
- **Tools**: Git/GitHub, Serial Plotter.

### 3.3 Environmental Relevance
By moving AI to the edge and utilizing low-power ESP-NOW radios, the project drastically reduces the cloud computing energy footprint and transmission power typically required for IoT security monitoring.

### 3.4 Sustainability
The system is highly reusable as a foundational security layer for *any* ESP-NOW deployment (smart agriculture, industrial monitoring). Failed or compromised nodes are isolated logically rather than physically, extending the network's operational lifespan.

---

## 4. Group Formation and Individual Responsibilities

| Member | ID / Roll No. | Role | Responsibilities |
|---|---|---|---|
| [Your Name] | [ID] | Lead Mesh & Gateway Engineer | Implement ESP-NOW mesh, telemetry engine, packet formats, and USB WebSerial ingestion. |
| [Member 2] | [ID] | Security & ML Engineer | Generate attack datasets, train ML classifier, build Decision Engine. |
| [Member 3] | [ID] | Frontend / UI Developer | Build the interactive Web Dashboard, SVG topology, and log inspector. |

*(Update names, IDs, and roles as necessary)*

---

## 5. Objectives of the Project

1. **Mesh Infrastructure**: Establish a robust 5-node, 10-link wireless mesh network using ESP-NOW.
2. **Telemetry Collection**: Extract and process live network metrics (RSSI, packet rate, sequence anomalies) in a rolling window.
3. **Intrusion Detection**: Train and deploy an ML classifier to accurately identify DoS, Replay, and Spoofing attacks.
4. **Self-Healing**: Autonomously isolate compromised nodes and seamlessly reroute traffic to maintain network integrity.
5. **Real-time C2**: Provide a single-pane-of-glass Web Dashboard for live monitoring and attack simulation.

---

## 6. System Architecture

### 6.1 Overall Architecture
![Architecture Diagram](docs/architecture.png) *(Placeholder for diagram)*

### 6.2 Component / Module Description
| Module | Function | Interacts With |
|---|---|---|
| **Layer 1: Autonomous Mesh Nodes** | Physical ESP-NOW communication & local telemetry calculation. | Layer 2 |
| **Layer 2: On-Device TinyML IDS** | Embedded C++ Decision Tree running inside *every* node to classify attacks and execute isolation locally. | Layer 1 |
| **Layer 3: Gateway Bridge & Dashboard** | A single node passively bridges the network state via WebSerial to an HTML5 Dashboard for visual monitoring. | Layer 1 |

### 6.3 Data Flow
1. **Nodes** exchange `network_packet` frames over the radio.
2. **Local Telemetry Engine** inside each receiving node calculates the RSSI, Packet Rate, and Sequence Continuity.
3. **Local ML Engine** (Decision Tree) evaluates the telemetry. If an attack is detected, the node independently drops the peer.
4. **Gateway Node** passively overhears the traffic and formats it as JSON telemetry.
5. **Dashboard** reads the JSON via USB WebSerial to visually animate the 10-link topology and network health.

---

## 7. Methodology
1. **Requirement analysis**: Define hardware limits, packet structures, and attack vectors.
2. **Design**: Draft the 4-layer architecture, DB schemas, and UI wireframes.
3. **Implementation**: Execute the 15-phase build (starting with P2P links, ending with ML integration).
4. **Testing**: Simulate DoS and Replay attacks; measure latency and model accuracy.
5. **Evaluation**: Benchmark network recovery time after node isolation.
6. **Documentation**: Compile APIs, architecture diagrams, and academic reports.

---

## 8. Knowledge of the Domain, Technology, and Tools

### 8.1 Domain Knowledge
- **Mesh Networking**: Graph theory, redundant multi-hop routing, MAC-layer addressing.
- **Cybersecurity**: Understanding attack vectors (Denial of Service, MAC Spoofing, Replay attacks).
- **Machine Learning**: Supervised classification, feature scaling, model inference.

### 8.2 Technologies Used
| Technology | Purpose |
|---|---|
| **ESP-NOW (C++)** | Protocol for ultra-low latency, routerless IoT communication. |
| **Python / m2cgen** | Training the ML models on PC and compiling them into raw C++ for the microcontrollers. |
| **HTML5 WebSerial API** | Bridging physical hardware directly to the browser UI without a server. |

### 8.3 Tools
- **Arduino IDE / PlatformIO**: Firmware compilation and flashing.
- **Git / GitHub**: Source control and team collaboration.
- **Wireshark (Mini)**: Custom built packet inspector for the dashboard.

---

## Installation and Usage

*(To be updated as implementation progresses)*
```bash
# 1. Clone the repository
git clone https://github.com/codeShul/EDI-7.git

# 2. Flash Firmware
# Open firmware/tests/esp_now_2node_test/sender/sender.ino in Arduino IDE
# Upload to ESP32 Node 1

# 3. Launch Dashboard
# Open dashboard/index.html in a WebSerial-compatible browser (Chrome/Edge)
# Click "Connect USB WebSerial"
```

## Results
*(Screenshots of the dashboard, ML confusion matrices, and physical hardware setup will be added here post-implementation).*

## Future Scope
- Scaling the mesh from 5 nodes to 50 nodes.
- Adding OTA (Over-The-Air) firmware updates via the mesh.

## References
[1] Espressif Systems, "ESP-NOW User Guide", 2024.  
[2] Scikit-Learn Documentation, "Random Forest Classifier", 2024.  

## License
Private — Academic Project
