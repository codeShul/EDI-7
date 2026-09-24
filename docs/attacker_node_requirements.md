# Attacker Node (Node 4) - Requirements & Context

This document provides the necessary context and requirements for developing the firmware for **Node 4**, which will act as the designated **Attacker Node** in our SecureMesh AI network.

## System Context

We have a decentralized ESP32 mesh network using ESP-NOW.
- **Node IDs:** 1, 2, 3 are normal nodes. 4 is the attacker.
- **Gateway:** Node 3 acts as the gateway, logging telemetry to the PC via Serial.
- **Normal Behavior:** Nodes randomly send packets to each other at a low rate (1-5 packets per second). The `TelemetryEngine` tracks packet rate, RSSI, and dropped packets (sequence gaps).
- **Communication:** All nodes share a common `network_packet` struct and hardcoded MAC address table (`MeshConfig.h`).

## The Goal

Your goal is to write custom firmware for Node 4 (e.g., `attacker_node.ino`) that deliberately violates the normal network behavior to trigger the Intrusion Detection System (IDS). You will simulate four distinct types of attacks.

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

1.  **Create the Firmware:** Write `attacker_node.ino` implementing these behaviors.
2.  **Flash Node 4:** Upload the firmware to the ESP32 designated as Node 4.
3.  **Coordinate with Gateway:** Run the mesh. Trigger an attack on Node 4 and observe the Serial Monitor on the Gateway (Node 3). You should see the telemetry JSON reflecting the anomalous behavior (e.g., massive rate spikes, sequence errors, or RSSI shifts).
