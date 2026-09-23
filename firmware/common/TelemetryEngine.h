#ifndef TELEMETRY_ENGINE_H
#define TELEMETRY_ENGINE_H

#include "ApplicationPacket.h"

class TelemetryEngine {
private:
    uint8_t  m_node_id;
    uint32_t m_window_start_ms;
    uint32_t m_window_duration_ms;
    
    // Window metrics tracking
    uint32_t m_packets_sent;
    uint32_t m_packets_received;
    uint32_t m_packets_expected;
    uint32_t m_retransmissions;
    uint32_t m_sequence_anomalies;
    uint32_t m_duplicate_count;
    
    int32_t  m_total_rssi;
    uint32_t m_rssi_samples;
    uint32_t m_total_latency_ms;
    uint32_t m_latency_samples;
    
    uint32_t m_last_sequence_num;
    NodeStatus m_status;

public:
    TelemetryEngine(uint8_t node_id, uint32_t window_duration_ms = 2000);
    
    void recordPacketSent();
    void recordPacketReceived(const ApplicationPacket& packet, int16_t rssi, uint32_t latency_ms);
    void recordRetransmission();
    
    bool isWindowComplete() const;
    TelemetryReport generateReport();
    void resetWindow();
    
    void setStatus(NodeStatus status) { m_status = status; }
    NodeStatus getStatus() const { return m_status; }
};

#endif // TELEMETRY_ENGINE_H
