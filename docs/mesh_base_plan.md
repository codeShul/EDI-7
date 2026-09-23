# ESP-NOW Mesh & Random Data Implementation Plan

Since the Attack Simulator, ML, and Website are being handled separately by your teammate, your core responsibility is exclusively building the **Network Infrastructure** and **Data Generation Pipeline**. 

This plan focuses purely on hardcoded ESP-NOW mesh networking, generating random payloads, and formatting the output for your teammate's system to consume.

---

## 1. Scope of Work
- **Hardcoded Topology**: All 5 ESP32 MAC addresses will be hardcoded into the firmware.
- **Random Data Generation**: Each node will generate random simulated data (e.g., temperature, humidity, battery level) to represent real IoT traffic.
- **ESP-NOW Mesh**: Nodes will broadcast or unicast this data to each other and the Gateway.
- **Gateway Serial Dump**: One designated Gateway ESP32 will receive all packets from the mesh and print them over the USB Serial port in JSON format. Your teammate's website can then easily read this COM port.

---

## 2. Node Roles

| Node ID | Role | Behavior |
|---|---|---|
| **Nodes 1, 2, 3, 4** | Sensor Nodes | Wakes up, generates random data every 1-2 seconds, packages it, and sends it to the Gateway via ESP-NOW. |
| **Node 5** | Gateway Node | Plugs into the laptop. Listens for ESP-NOW packets from Nodes 1-4. Converts received packets into a JSON string and runs `Serial.println(json)`. |

---

## 3. Hardcoded Packet Structure

We will define a simple, unified C++ `struct` that all nodes share:

```cpp
typedef struct network_packet {
    uint8_t sender_id;      // Hardcoded Node ID (1 to 5)
    uint8_t target_id;      // Intended recipient Node ID
    uint32_t seq_num;       // Monotonic sequence number (prevents replays)
    uint8_t packet_type;    // 0: DATA, 1: HEARTBEAT, 2: ROUTE_SYNC
    uint8_t ttl;            // Time-to-Live (Hop count limit)
    uint16_t checksum;      // Data integrity verification
    uint8_t dummy_payload[16]; // Random bytes simulating real network payload
} network_packet;
```

---

## 4. Development Steps

### Step 1: MAC Address Hardcoding
- We will write a quick script to extract the exact MAC addresses of your 5 physical ESP32 boards.
- These MAC addresses will be hardcoded into an array in the firmware so they all know exactly who to talk to.

### Step 2: Write Sensor Node Firmware (`sensor_node.ino`)
- Initialize Wi-Fi in Station mode.
- Initialize ESP-NOW and register the Gateway's hardcoded MAC address as a peer.
- In the `loop()`, increment the `seq_num`, populate `dummy_payload` with random bytes, and calculate the `checksum`.
- Send the `network_packet` struct via `esp_now_send()`.
- Add a random `delay()` to generate a realistic, variable packet rate.

### Step 3: Write Gateway Firmware (`gateway_node.ino`)
- Initialize Wi-Fi in Station mode.
- Initialize ESP-NOW and register a receive callback (`OnDataRecv`).
- When a packet hits the antenna, instantly extract the `sender_id`, `seq_num`, `packet_type`, etc.
- Also pull the hardware RSSI (signal strength) from the `esp_now_recv_info` struct.
- Format everything into a clean JSON string: 
  `{"src": 1, "dst": 5, "seq": 105, "type": "DATA", "ttl": 4, "rssi": -52}`
- Print it to the Serial Monitor at `115200` baud.

### Step 4: Integration
- Flash Nodes 1-4 with the Sensor firmware.
- Flash Node 5 with the Gateway firmware and plug it into the PC.
- Hand over the COM port to your teammate so their website can read the JSON stream and run the simulated attacks!

---

## 5. Next Actions
Once you approve this plan, I will generate the exact `.ino` code for the **Sensor Node** and the **Gateway Node**. We will then compile and flash them to your boards.
