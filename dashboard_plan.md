# SecureMesh AI: Comprehensive Monitoring Website Architecture & Plan

> [!IMPORTANT]
> **Core Objective**: Real-time visual monitoring for **all 5 ESP32 nodes** ($N_1, N_2, N_3, N_4, N_5$), all **10 physical mesh links**, **Deep Network Packet Inspection (Live Packet Stream)**, and **Multi-Tier Incident & System Logs**.
> 
> - **All 5 Nodes Active & Responding**: Every node independently transmits real network packets, tracks its 4 direct peer connections, makes local attack-severing decisions, and streams live telemetry to the dashboard.
> - **Pure Network Focus**: Zero temperature/weather data. Tracks actual network packets, sequence counters, TTL/hops, throughput rates, and CRC16 checksums.

---

## 1. Tentative UI/UX Layout & Wireframe

> [!NOTE]
> This layout is **tentative** and serves as the architectural blueprint for the monitoring interface. Components and styling can be refined during implementation.

```text
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│  🛡️ SECUREMESH AI — 5-NODE / 10-LINK DECENTRALIZED MESH MONITOR                  [● LIVE STREAM] │
├─────────────────────────────────────────────────────────────────────────────────────────────────┤
│  STATUS: 🟢 ALL 5 NODES ACTIVE  │  ACTIVE LINKS: 10/10  │  NET TX RATE: 18.2 pkts/s  │  LOGS: 1,420 │
├───────────────────────────────────────────────────┬─────────────────────────────────────────────┤
│                                                   │                                             │
│   🌐 10-LINK INTERACTIVE TOPOLOGY GRAPH           │   📊 ALL 5 NODES LIVE TELEMETRY MATRIX      │
│                     [ Node 1 ]                    │  ┌──────┬────────┬────────┬──────┬────────┐ │
│                    /    |     \                   │  │ Node │ Status │ Rate   │ RSSI │ Pkts Tx│ │
│           [ Node 5 ]────┼────[ Node 2 ]           │  ├──────┼────────┼────────┼──────┼────────┤ │
│             \   \───[Node 3]───/   /              │  │ N1   │ 🟢 OK  │ 2.1/s  │ -52  │ 420    │ │
│              \       /     \      /               │  │ N2   │ 🔴 DOS │ 44.0/s │ -58  │ 1,890  │ │
│              [ Node 4 ]───────────                │  │ N3   │ 🟢 OK  │ 1.9/s  │ -61  │ 390    │ │
│                                                   │  │ N4   │ 🟢 OK  │ 2.0/s  │ -55  │ 410    │ │
│   Legend: ── Active  ┄┄ Severed Link              │  │ N5   │ 🟢 OK  │ 2.2/s  │ -54  │ 430    │ │
│                                                   │  └──────┴────────┴────────┴──────┴────────┘ │
├───────────────────────────────────────────────────┴─────────────────────────────────────────────┤
│ 📦 LIVE NETWORK PACKET STREAM & DEEP PACKET INSPECTOR (Mini-Wireshark for ESP-NOW)              │
│ ┌─────┬──────────┬────────┬────────┬─────────┬──────┬─────┬───────────────────────┬───────────┐ │
│ │ #   │ Time     │ Source │ Target │ Type    │ Size │ TTL │ Payload Hash / Hex    │ Checksum  │ │
│ ├─────┼──────────┼────────┼────────┼─────────┼──────┼─────┼───────────────────────┼───────────┤ │
│ │ 104 │ 22:45:11 │ Node 1 │ Node 2 │ DATA    │ 32 B │ 4   │ 0x4E65745F44617461    │ 0xA4F2 OK │ │
│ │ 105 │ 22:45:11 │ Node 2 │ Node 3 │ ROUTE   │ 24 B │ 3   │ 0x526F7574655F5379    │ 0x8C11 OK │ │
│ │ 106 │ 22:45:12 │ Node 2 │ Node 1 │ FLOOD   │ 32 B │ 4   │ 0x4E65745F44617461    │ 0x8C11 DUP│ │
│ └─────┴──────────┴────────┴────────┴─────────┴──────┴─────┴───────────────────────┴───────────┘ │
│ 🔍 Selected Packet #106 Details: [Hex Dump] [Raw JSON] [Sequence Gap: 0 (DUPLICATE DETECTED!)]  │
├─────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 📜 MULTI-TIER SYSTEM & SECURITY LOGS                                                            │
│ Tabs: [🚨 Security Alerts (3)]  [⚙️ System Events (28)]  [🔁 Self-Healing Routing (4)]  [📥 Export] │
│ ┌──────────┬──────────┬───────────┬───────────────────────────────────────────┬───────────────┐ │
│ │ Timestamp│ Level    │ Source    │ Log Message / Rule Violation Detail       │ Action Taken  │ │
│ ├──────────┼──────────┼───────────┼───────────────────────────────────────────┼───────────────┤ │
│ │ 22:45:10 │ 🟡 WARN  │ Node 2    │ Rate spike detected: 14.5 pkts/sec        │ Watchlist     │ │
│ │ 22:45:12 │ 🔴 CRIT  │ Node 2    │ Rule DOS_FLOOD triggered (> 20 pkts/sec)  │ LINK SEVERED  │ │
│ │ 22:45:12 │ 🔵 INFO  │ Node 1    │ esp_now_del_peer(Node 2 MAC) executed     │ Peer Blacklist│ │
│ │ 22:45:12 │ 🟢 HEAL  │ Node 3    │ esp_now_del_peer(Node 2 MAC) executed     │ Peer Blacklist│ │
│ │ 22:45:12 │ 🟢 HEAL  │ Router    │ Recalculated mesh routes. 6 links healthy │ Traffic Normal│ │
│ └──────────┴──────────┴───────────┴───────────────────────────────────────────┴───────────────┘ │
├─────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 🛠️ DEMO CONTROLS: [⚡ DoS Attack (N2)]  [🔁 Replay Attack (N3)]  [🎭 Spoofing (N4)]  [🔄 Reset All]  │
└─────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. How the Dashboard Links to Real ESP32 Data (WebSerial C2 Architecture)

The dashboard operates as a true **Command and Control (C2) Center** using the modern HTML5 WebSerial API. This means zero Python backend, zero external routers, and 100% offline reliability. 

```text
  ┌─────────────────────────────────────────────────────────────┐
  │                 WEB BROWSER (Dashboard App)                 │
  │  1. Receives streaming JSON Telemetry                       │
  │  2. Renders 10-link SVG graph, packet inspector & logs      │
  │  3. Sends Attack Commands (e.g., `CMD:ATTACK:DOS:N2`)       │
  └──────────────────────────┬───────────────────────▲──────────┘
             [Attack Trigger]│                       │ [JSON Telemetry]
                             ▼ (USB WebSerial 115200)│
  ┌──────────────────────────┴───────────────────────┴──────────┐
  │                 ESP32 EDGE GATEWAY (COM Port)               │
  │  - Plugs directly into laptop via USB                       │
  │  - Bridges WebSerial commands to radio broadcasts           │
  │  - Listens to radio mesh and forwards JSON to PC            │
  └──────────────────────────┬───────────────────────▲──────────┘
             [ESP-NOW Broadcast]│                    │ [ESP-NOW Telemetry]
                                ▼                    │
  ┌─────────────────────────────┴────────────────────┴──────────┐
  │                 ALL 5 ESP32 NODES (N1 - N5)                 │
  │  - Execute attack commands instantly upon receipt           │
  │  - Transmit real network frames and metrics continuously    │
  └─────────────────────────────────────────────────────────────┘
```

### Connection Flow:
1. **Plug in Gateway**: Plug one ESP32 into your laptop via USB.
2. **Open Dashboard**: Double-click `index.html` in Chrome or Edge.
3. **Connect**: Click the **"Connect USB"** button on the webpage and select the COM port. 
4. **Command & Control**: The browser instantly reads the live mesh telemetry for the UI, and the **Demo Control Panel** buttons send serial triggers down the USB cable to execute attacks on the remote nodes.

---

## 3. All 5 Nodes Active Response & Metrics Matrix

Every single node ($N_1, N_2, N_3, N_4, N_5$) continuously reports:
1. **Node Health & Role**: `Node ID`, `MAC Address`, `Uptime`, `Status (HEALTHY / ISOLATED)`.
2. **4 Peer Link Metrics**: For each of its 4 direct connections:
   - **Throughput Rate**: Instantaneous packets/second sent & received.
   - **Signal Strength (RSSI)**: Radio reception quality in dBm.
   - **Sequence Continuity**: Sequence delta and duplicate counter.
   - **Link State**: `ACTIVE` (Green), `DEGRADED` (Yellow), `SEVERED` (Red/Dotted).
3. **Decentralized Decision Broadcast**:
   - When Node 2 floods the network, Node 1, Node 3, Node 4, and Node 5 each independently sever their respective link to Node 2.
   - The dashboard shows all 4 sever actions in real-time as each node independently acts.

---

## 4. Deep Network Packet Inspector (Live Packet Stream)

Functions like a **mini-Wireshark** tailored for ESP32 mesh networks:

```text
┌─────┬──────────┬────────┬────────┬─────────┬──────┬─────┬───────────────────────┬───────────┐
│ #   │ Time     │ Source │ Target │ Type    │ Size │ TTL │ Payload Hash / Hex    │ Checksum  │
├─────┼──────────┼────────┼────────┼─────────┼──────┼─────┼───────────────────────┼───────────┤
│ 104 │ 22:45:11 │ Node 1 │ Node 2 │ DATA    │ 32 B │ 4   │ 0x4E65745F44617461    │ 0xA4F2 OK │
│ 105 │ 22:45:11 │ Node 2 │ Node 3 │ ROUTE   │ 24 B │ 3   │ 0x526F7574655F5379    │ 0x8C11 OK │
│ 106 │ 22:45:12 │ Node 2 │ Node 1 │ FLOOD   │ 32 B │ 4   │ 0x4E65745F44617461    │ 0x8C11 DUP│
└─────┴──────────┴────────┴────────┴─────────┴──────┴─────┴───────────────────────┴───────────┘
```
- **Packet Breakdown**: Monotonic index `#`, timestamp, source/target nodes & MACs, packet type (`DATA`, `HEARTBEAT`, `ROUTE_SYNC`, `ISOLATE_CMD`), payload bytes, TTL/hop count, and checksum.
- **Deep Inspection Click**: Clicking any packet row opens an inspector showing the **Raw Hex Dump**, **JSON serialization**, and **Sequence Gap status** (detects duplicates/replays instantly).

---

## 5. Multi-Tier Logging Center

Organized into 4 categorized tabs:
1. 🚨 **Security Alerts Tab**:
   - Time-stamped logs of all rule triggers (`[DOS_FLOOD]`, `[REPLAY_ATTACK]`, `[MAC_SPOOFING]`, `[ROGUE_NODE]`).
2. ⚙️ **System & Hardware Logs Tab**:
   - Internal ESP32 logs: Free Heap memory, radio buffer utilization, Wi-Fi channel switches.
3. 🔁 **Self-Healing & Routing Logs Tab**:
   - Traces autonomous actions across all nodes: `esp_now_del_peer(Node 2)` executed, peer blacklisted, and alternate mesh routes updated.
4. 📥 **Search, Filter & Log Export**:
   - Live search bar and **Download CSV** / **Download JSON** export buttons for project reports.

---

## 6. Technical Implementation Blueprint

- **Single-File Zero-Dependency Architecture**: Entire website lives in a single, high-performance `index.html` file (containing embedded CSS and JS).
- **Local Storage Buffer**: Retains the last 500 packets and 200 log entries in circular browser memory for smooth 60fps rendering without lag.
- **Embedded Web Server**: Stored in ESP32 `PROGMEM` / LittleFS to be hosted directly from `http://192.168.4.1` on the ESP32 Wi-Fi Access Point.
