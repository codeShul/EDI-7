# SecureMesh AI

**An Edge-AI-Based Intrusion Detection and Self-Healing Framework for ESP32 IoT Mesh Networks.**

## Overview

SecureMesh AI is a cybersecurity prototype consisting of 5 ESP32 IoT nodes forming a wireless mesh network (10-link full mesh). The system collects network telemetry, detects intrusions using ML-based classification, autonomously isolates compromised nodes, and recovers communication through alternative routes.

## Architecture

```
LAYER 4 — Web Dashboard (Real-Time Observability)
LAYER 3 — AI & Security Decision Engine
LAYER 2 — Edge Gateway (Ingestion, Persistence, Coordination)
LAYER 1 — ESP32 Hardware & Mesh Network (5 Nodes, 10 Links)
```

## Project Structure

```
securemesh-ai/
├── firmware/          # ESP32 C++ firmware (common headers, node, gateway, attacker)
├── backend/           # Python Edge Gateway (FastAPI, SQLite, Decision Engine)
├── ml/                # ML pipeline (training, evaluation, inference)
├── dashboard/         # Web monitoring dashboard (HTML/CSS/JS)
├── docs/              # Architecture and API documentation
└── README.md
```

## Development Phases

1. ESP32 Basic Communication (ESP-NOW P2P)
2. Multi-Node Mesh (4–5 Nodes)
3. Redundant Routing Paths
4. Telemetry Collection Engine
5. Gateway Communication Bridge
6. Database & Persistence Layer
7. Normal Baseline Dataset Generation
8. Controlled Attack Simulation (DoS, Replay, Spoofing, Rogue)
9. ML Model Training & Evaluation
10. Real-Time IDS Inference Engine
11. Security Decision Engine
12. Node Isolation Execution
13. Dynamic Route Recovery
14. Web Monitoring Dashboard
15. Full End-to-End Integration

## Hardware

- 5 × ESP32 Development Boards (ESP32-WROOM-32)
- USB Cables for flashing and serial communication
- Edge Gateway PC (Windows)

## License

Private — Academic Project
