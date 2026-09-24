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
#define NODE_ID 1              // CHANGE THIS FOR EACH BOARD YOU FLASH (1, 2, or 3)
#define GATEWAY_ID 3           // Let's use Node 3 as the Gateway for now since we have 3 MACs

// Array of known MAC addresses in the mesh (Index corresponds to NODE_ID)
// Index 0 is empty. Index 1 = ESP 1, Index 2 = ESP 2, etc.
const uint8_t mesh_macs[6][6] = {
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // Node 0 (Null)
    {0x68, 0x09, 0x47, 0x86, 0x31, 0xD0}, // Node 1 (ESP 1)
    {0x1C, 0xC3, 0xAB, 0xB3, 0xC4, 0xA8}, // Node 2 (ESP 2)
    {0x8C, 0x94, 0xDF, 0x7C, 0xCC, 0x84}, // Node 3 (ESP 3 - Acting as Gateway)
    {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, // Node 4 (Placeholder)
    {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}  // Node 5 (Placeholder)
};

#endif // MESH_CONFIG_H
