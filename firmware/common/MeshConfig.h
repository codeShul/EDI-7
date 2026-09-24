#ifndef MESH_CONFIG_H
#define MESH_CONFIG_H

#include <Arduino.h>

// ---------------------------------------------------------
// 1. Network Packet Structure
// ---------------------------------------------------------
// This is the exact structure that will be transmitted over the air.
typedef struct __attribute__((packed)) network_packet {
    uint8_t sender_id;         // Node ID (1 to 5)
    uint8_t target_id;         // Intended recipient Node ID (5 = Gateway)
    uint32_t seq_num;          // Monotonic sequence number (prevents replays)
    uint8_t packet_type;       // 0: DATA, 1: HEARTBEAT, 2: ROUTE_SYNC
    uint8_t ttl;               // Time-to-Live (Hop count limit)
    uint16_t checksum;         // Data integrity verification
    uint8_t dummy_payload[16]; // Random bytes simulating real network payload
} network_packet;

// ---------------------------------------------------------
// 2. Hardcoded Node Configuration
// ---------------------------------------------------------
#define NODE_ID 1              // CHANGE THIS FOR EACH NODE (1-4 for sensors, 5 for gateway)
#define GATEWAY_ID 5

// For Phase 1, we use the Broadcast MAC address so nodes can find each other 
// without needing hardcoded physical MACs immediately. 
// In Phase 2, we will replace this with the exact MAC arrays.
const uint8_t broadcast_mac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

#endif // MESH_CONFIG_H
