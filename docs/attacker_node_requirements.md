# Attacker Node (Node 4) - Requirements & Context

This document provides the necessary context and requirements for developing the firmware for **Node 4**, which will act as the designated **Attacker Node** in our SecureMesh AI network.

## System Context

We have a decentralized ESP32 mesh network using ESP-NOW.
- **Node IDs:** 1, 2, 3 are normal nodes and only talk to each other (`firmware/mesh_node/mesh_node.ino` picks targets/next-hops from `random(1, 4)`, i.e. never 4). **Node 4 is not a mesh member** — it does not receive normal traffic and is not treated as trusted.
- **Gateway:** Node 3 acts as the gateway, logging telemetry to the PC via Serial. It only sees frames addressed to it, so an attack must target Node 3 (or a node relaying through it) to be visible in the captured data at all.
- **Normal Behavior:** Nodes 1-3 randomly send packets to each other at a low rate (1-5 packets per second). The `TelemetryEngine` tracks packet rate, RSSI, and dropped packets (sequence gaps).
- **Communication:** All nodes share a common `network_packet` struct and hardcoded MAC address table (`MeshConfig.h`).

## The Goal

Your goal is to write custom firmware for Node 4 (`esp32_attacker.ino`) that deliberately violates the normal network behavior to trigger the Intrusion Detection System (IDS). You will simulate four distinct types of attacks.

## Autonomous Operation Model

Unlike the earlier design, Node 4 is **not commanded from the PC**. There is no baseline/idle period to wait for a serial command in normal operation:

1. **On boot**, after ESP-NOW init (register peers exactly like a normal node, per "Required Includes & Setup" below), pick **one random target** from the known mesh MAC table (`mesh_macs[1..3]`, i.e. any of nodes 1, 2 or 3 — never itself). Keep that same target for the whole session; do not re-pick per attack phase.
2. **Immediately** begin the attack cycle — no waiting, no idle state.
3. **Cycle through all four attacks automatically**, one after another, looping forever:
   `DoS -> Replay -> Spoofing -> Blackhole -> DoS -> ...`
   Each phase runs for a fixed dwell time (`ATTACK_PHASE_DURATION_MS`, suggested default 30000 = 30s) before advancing to the next. There is no gap or "NORMAL" phase between them — Node 4 is always attacking once it has booted.
4. The existing serial `STOP` / `STATUS` commands (see `parseJsonCommand`) may still be kept as an optional manual override/debugging aid, but nothing needs to send `{"mode": ...}` to start it — that handshake from `attack_controller.py` is no longer required for Node 4's own state machine.

### Why this changes the dataset workflow

`attack_controller.py`'s original job — commanding the attacker and broadcasting which attack is active so `dataset_generator.py` can label rows — no longer has anything to synchronize with, since nothing on the PC decides when Node 4 switches modes. Instead:

- Capture a **clean baseline** with Node 4 powered off (or physically disconnected).
- Then power Node 4 on and start `dataset_generator.py --auto-cycle` (see `attack-simulation/INSTRUCTIONS.md`), which labels rows purely from elapsed time against the same fixed 4-phase schedule described above — no IPC file, no controller process needed.
- Keep the firmware's dwell time and the generator's `--cycle-phase-s` in sync (both default to 30s).

## Required Includes & Setup

Your `attacker_node.ino` must include the shared configuration so it can interact with the mesh:

```cpp
#include <WiFi.h>
#include <esp_now.h>
#include "../common/MeshConfig.h" // Gives you access to NODE_ID (set to 4) and mesh_macs array
```

You must initialize ESP-NOW and add peers exactly like a normal node so your packets are accepted by the radio hardware.

## Attack Scenarios to Implement

You need to implement functions to trigger the following attacks, likely controlled via Serial input or a hardware button on Node 4.

### 1. Denial of Service (DoS) Flood
**Concept:** Overwhelm a target node with excessive traffic.
**Implementation:**
- Bypass the normal `delay(1000, 3000)`.
- Rapidly call `esp_now_send` in a tight loop targeting a specific node (e.g., Node 1).
- **Expected IDS Trigger:** The target node's `TelemetryEngine` will see the `rate` spike from ~3 pps to 50+ pps.

### 2. Replay Attack
**Concept:** Send valid, but old, packets to confuse the system.
**Implementation:**
- Instead of strictly incrementing `pkt.seq_num` for every packet, intentionally send packets with older sequence numbers (e.g., send seq 100, 101, 102, then send 100 again).
- **Expected IDS Trigger:** The target node tracks the highest sequence number seen. Receiving older numbers indicates a replay.

### 3. MAC Spoofing (Impersonation)
**Concept:** Pretend to be another trusted node.
**Implementation:**
- Modify the `pkt.sender_id` in your outgoing packet struct. Instead of setting it to `4`, set it to `1` or `2`.
- Send the packet to Node 3 (Gateway).
- **Expected IDS Trigger:** Node 3 will see a packet claiming to be from Node 1. However, Node 4 is physically located somewhere else, so the `avg_rssi` (signal strength) received will suddenly jump or drop significantly compared to the real Node 1's historical RSSI.

### 4. Blackhole / Selective Forwarding (Rogue Router)
**Concept:** Accept packets intended for relaying, but drop them instead.
**Implementation:**
- Implement the `OnDataRecv` callback.
- If a packet is received where `pkt.target_id != NODE_ID` (meaning you are supposed to relay it), **do not** call `esp_now_send` to forward it. Simply drop it.
- **Expected IDS Trigger:** If Node 1 sends packets to Node 3 via Node 4, Node 3 will never receive them. Node 3's telemetry will show a massive spike in `drops` (missing sequence numbers from Node 1) because the packets disappeared mid-flight.

## Development Workflow

1.  **Create the Firmware:** Finish `attack-simulation/esp32_attacker.ino` implementing these behaviors (the state machine, boot-time target selection, and cycle scheduler are already there — the four `run*Mode()` attack payload functions are still TODO stubs).
2.  **Flash Node 4:** Upload the firmware to the ESP32 designated as Node 4.
3.  **Observe:** Power on Nodes 1-3 and the gateway first, then power on Node 4. It attacks immediately, no PC command needed. Watch the Serial Monitor on the Gateway (Node 3) — you should see the telemetry JSON reflecting the anomalous behavior (e.g., massive rate spikes, sequence errors, or RSSI shifts) within one dwell period (30s) of Node 4 powering on.
