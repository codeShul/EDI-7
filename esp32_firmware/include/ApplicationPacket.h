#ifndef APPLICATION_PACKET_H
#define APPLICATION_PACKET_H

#include <stdint.h>

// Packet Message Types
enum MessageType : uint8_t {
    MSG_TYPE_DATA = 1,          // Sensor payload packet
    MSG_TYPE_HEARTBEAT = 2,     // Node status heartbeat
    MSG_TYPE_TELEMETRY = 3,     // Telemetry report sent to gateway
    MSG_TYPE_ISOLATE_CMD = 4,   // Command from gateway to isolate node
    MSG_TYPE_RESTORE_CMD = 5,   // Command from gateway to restore isolated node
    MSG_TYPE_ROUTE_UPDATE = 6   // Routing table sync packet
};

// Node Status Flags
enum NodeStatus : uint8_t {
    NODE_STATUS_HEALTHY = 0,
    NODE_STATUS_SUSPICIOUS = 1,
    NODE_STATUS_ISOLATED = 2
};

// Primary Application Packet Structure (exchanged over mesh)
#pragma pack(push, 1)
struct ApplicationPacket {
    uint8_t  source_id;         // Unique integer ID of sending node (1, 2, 3...)
    uint8_t  destination_id;    // Unique ID of target node (0 = Broadcast/Gateway)
    uint32_t sequence_num;      // Incremental packet sequence number
    uint32_t timestamp_ms;      // Milliseconds since boot or epoch timestamp
    uint8_t  msg_type;          // Enum MessageType
    
    // Payload Data (e.g. sensor readings)
    float    temperature;       // Sensor value (e.g. DHT11)
    float    humidity;          // Sensor value
    uint16_t checksum;          // Simple packet integrity check
};

// Telemetry Report Packet Structure (sent from ESP32 nodes to Gateway PC)
struct TelemetryReport {
    uint8_t  node_id;
    uint32_t timestamp_s;
    float    packet_rate;       // Packets per second
    float    packet_loss_pct;   // Packet loss percentage (0.0 to 100.0)
    int16_t  avg_rssi;          // Average Received Signal Strength Indicator (dBm)
    uint16_t avg_latency_ms;    // Round-trip or hop latency in ms
    uint16_t retransmissions;   // Total retransmission attempts in window
    uint16_t sequence_anomalies;// Duplicate or out-of-order sequence count
    uint16_t duplicate_count;   // Exact duplicate packet count
    uint8_t  status;            // Enum NodeStatus
};

// Control Command Packet (Gateway -> Node)
struct ControlCommandPacket {
    uint8_t  target_node_id;
    uint8_t  command_type;     // MSG_TYPE_ISOLATE_CMD or MSG_TYPE_RESTORE_CMD
    uint32_t command_id;
};
#pragma pack(pop)

#endif // APPLICATION_PACKET_H
