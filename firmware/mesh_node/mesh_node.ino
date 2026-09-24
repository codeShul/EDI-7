#include <WiFi.h>
#include <esp_now.h>
#include "../common/MeshConfig.h"
#include "../common/TelemetryEngine.h"

uint32_t current_seq_num = 1;
unsigned long last_telemetry_time = 0;

// ---------------------------------------------------------
// CALLBACK: When data is sent
// ---------------------------------------------------------
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 0, 0)
void OnDataSent(const wifi_tx_info_t *mac_addr, esp_now_send_status_t status) {
#else
void OnDataSent(const uint8_t *mac_addr, esp_now_send_status_t status) {
#endif
    const char* result = (status == ESP_NOW_SEND_SUCCESS) ? "SUCCESS" : "FAIL";
    Serial.printf("{\"type\": \"DELIVERY\", \"node\": %d, \"status\": \"%s\"}\n", NODE_ID, result);
}

// ---------------------------------------------------------
// CALLBACK: When data is received
// ---------------------------------------------------------
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 0, 0)
void OnDataRecv(const esp_now_recv_info_t *recv_info, const uint8_t *incomingData, int len) {
    int rssi = recv_info->rx_ctrl->rssi;
#else
void OnDataRecv(const uint8_t * mac_addr, const uint8_t *incomingData, int len) {
    int rssi = -50; // Mock for older cores
#endif

    network_packet pkt;
    memcpy(&pkt, incomingData, sizeof(pkt));
    
    // 1. Feed the data into the Local Telemetry Engine (For the AI)
    update_telemetry(pkt.sender_id, pkt.seq_num, rssi);

    // 2. If I am the Gateway, output raw packet JSON to the Laptop
    if (NODE_ID == GATEWAY_ID) {
        String type_str = (pkt.packet_type == 0) ? "DATA" : "UNKNOWN";
        Serial.printf("{\"src\": %d, \"dst\": %d, \"seq\": %d, \"type\": \"%s\", \"ttl\": %d, \"rssi\": %d}\n", 
                      pkt.sender_id, pkt.target_id, pkt.seq_num, type_str.c_str(), pkt.ttl, rssi);
    } 
    
    // 3. If the packet is NOT for me, I need to act as a Router (A -> B -> C)
    if (pkt.target_id != NODE_ID && pkt.ttl > 0) {
        pkt.ttl--;
        esp_now_send(mesh_macs[pkt.target_id], (uint8_t *) &pkt, sizeof(pkt));
    } 
}

// ---------------------------------------------------------
// SETUP
// ---------------------------------------------------------
void setup() {
    Serial.begin(115200);
    WiFi.mode(WIFI_STA);
    
    init_telemetry(); // Clear garbage RAM values for the math engine

    if (esp_now_init() != ESP_OK) return;

    #if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 0, 0)
        esp_now_register_send_cb(OnDataSent);
    #else
        esp_now_register_send_cb(OnDataSent);
    #endif
    
    esp_now_register_recv_cb(OnDataRecv);

    for (int i = 1; i <= 5; i++) {
        if (i == NODE_ID || mesh_macs[i][0] == 0xFF || mesh_macs[i][0] == 0x00) continue; 
        esp_now_peer_info_t peerInfo = {};
        memcpy(peerInfo.peer_addr, mesh_macs[i], 6);
        peerInfo.channel = 0;  
        peerInfo.encrypt = false;
        esp_now_add_peer(&peerInfo);
    }
}

// ---------------------------------------------------------
// MAIN LOOP
// ---------------------------------------------------------
void loop() {
    unsigned long current_time = millis();
    
    // PROCESS TELEMETRY EVERY 1000ms (1 Second Rolling Window)
    if (current_time - last_telemetry_time >= 1000) {
        last_telemetry_time = current_time;
        // This will calculate stats and print JSON for the AI website
        process_telemetry_window(NODE_ID, NODE_ID == GATEWAY_ID); 
    }

    // OCCASIONALLY GENERATE MESH TRAFFIC
    // We only generate a packet 1% of the loop cycles to allow time for processing
    if (random(0, 100) < 5) {
        int target = random(1, 5); 
        while(target == NODE_ID) target = random(1, 5);
        
        int next_hop_mac = random(1, 5);
        while(next_hop_mac == NODE_ID) next_hop_mac = random(1, 5);

        network_packet pkt;
        pkt.sender_id = NODE_ID;
        pkt.target_id = target;
        pkt.seq_num = current_seq_num++;
        pkt.packet_type = 0;
        pkt.ttl = 4;
        
        for(int i = 0; i < 16; i++) pkt.dummy_payload[i] = random(0, 255);
        pkt.checksum = pkt.sender_id + pkt.target_id + pkt.seq_num;
        
        // If I am the gateway generating my own packet, print it so the website sees it!
        if (NODE_ID == GATEWAY_ID) {
            Serial.printf("{\"src\": %d, \"dst\": %d, \"seq\": %d, \"type\": \"DATA\", \"ttl\": %d, \"rssi\": 0}\n", 
                          pkt.sender_id, pkt.target_id, pkt.seq_num, pkt.ttl);
        }

        esp_now_send(mesh_macs[next_hop_mac], (uint8_t *) &pkt, sizeof(pkt));
    }
    
    delay(50); // Small non-blocking delay for stability
}
