#ifndef TELEMETRY_ENGINE_H
#define TELEMETRY_ENGINE_H

#include <Arduino.h>

// Structure to hold rolling telemetry data for a specific peer
struct PeerTelemetry {
    uint32_t packets_received; // Count of packets in the last 1 second
    int32_t  rssi_sum;         // Sum of RSSI for averaging
    uint32_t last_seq_num;     // The last sequence number we saw
    uint32_t dropped_packets;  // Running total of missing sequence numbers
};

// Global telemetry table (Indexes 1 to 5 correspond to Node IDs)
PeerTelemetry telemetry_table[6];

// Call this in setup() to ensure RAM is cleanly zeroed
void init_telemetry() {
    memset(telemetry_table, 0, sizeof(telemetry_table));
}

// Call this inside OnDataRecv to update the running stats
void update_telemetry(uint8_t sender_id, uint32_t seq_num, int rssi) {
    if (sender_id < 1 || sender_id > 5) return; // Ignore invalid IDs

    telemetry_table[sender_id].packets_received++;
    telemetry_table[sender_id].rssi_sum += rssi;

    // Detect missing sequence numbers (Packet Drops / Blackhole)
    if (telemetry_table[sender_id].last_seq_num > 0 && seq_num > telemetry_table[sender_id].last_seq_num + 1) {
        telemetry_table[sender_id].dropped_packets += (seq_num - telemetry_table[sender_id].last_seq_num - 1);
    }
    
    // Detect Replay Attacks (Sequence number went backwards)
    // Note: In a real system, we might flag this immediately. 
    // Here we just record the highest sequence number seen.
    if (seq_num > telemetry_table[sender_id].last_seq_num) {
        telemetry_table[sender_id].last_seq_num = seq_num;
    }
}

// Call this every 1000ms in the main loop to dump and reset the rolling window
void process_telemetry_window(uint8_t my_node_id, bool is_gateway) {
    for (int i = 1; i <= 5; i++) {
        if (telemetry_table[i].packets_received > 0) {
            
            // Calculate features for the ML model
            int avg_rssi = telemetry_table[i].rssi_sum / telemetry_table[i].packets_received;
            uint32_t rate = telemetry_table[i].packets_received; // Packets Per Second
            uint32_t drops = telemetry_table[i].dropped_packets;

            // If we are the Gateway, output this clean telemetry JSON for the teammate's website/AI
            if (is_gateway) {
                Serial.printf("{\"telemetry\": true, \"reporter\": %d, \"target\": %d, \"rate\": %d, \"avg_rssi\": %d, \"drops\": %d}\n",
                              my_node_id, i, rate, avg_rssi, drops);
            }

            // Reset the 1-second rolling window counters
            telemetry_table[i].packets_received = 0;
            telemetry_table[i].rssi_sum = 0;
            // Note: We DO NOT reset last_seq_num or dropped_packets, as those span across windows.
        }
    }
}

#endif // TELEMETRY_ENGINE_H
