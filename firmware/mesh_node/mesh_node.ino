#include <WiFi.h>
#include <esp_now.h>
#include "../common/MeshConfig.h"
#include "../common/TelemetryEngine.h"

uint32_t current_seq_num = 1;
unsigned long last_telemetry_time = 0;

// Store last sent packet info so OnDataSent can merge it into one JSON
volatile uint8_t last_sent_target = 0;
volatile uint8_t last_sent_dst = 0;
volatile uint32_t last_sent_seq = 0;
volatile uint8_t last_sent_ttl = 0;

// ---------------------------------------------------------
// CALLBACK: When data is sent (merges delivery status into the packet JSON)
// ---------------------------------------------------------
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 0, 0)
void OnDataSent(const wifi_tx_info_t *mac_addr, esp_now_send_status_t status) {
#else
void OnDataSent(const uint8_t *mac_addr, esp_now_send_status_t status) {
#endif
    const char* result = (status == ESP_NOW_SEND_SUCCESS) ? "SUCCESS" : "FAIL";
    Serial.printf("{\"type\": \"TX\", \"src\": %d, \"dst\": %d, \"seq\": %d, \"ttl\": %d, \"hop\": %d, \"delivery\": \"%s\"}\n",
                  NODE_ID, last_sent_dst, last_sent_seq, last_sent_ttl, last_sent_target, result);
}

// ---------------------------------------------------------
// CALLBACK: When data is received (single unified JSON per event)
// ---------------------------------------------------------
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 0, 0)
void OnDataRecv(const esp_now_recv_info_t *recv_info, const uint8_t *incomingData, int len) {
    int rssi = recv_info->rx_ctrl->rssi;
#else
void OnDataRecv(const uint8_t * mac_addr, const uint8_t *incomingData, int len) {
    int rssi = -50;
#endif

    network_packet pkt;
    memcpy(&pkt, incomingData, sizeof(pkt));
    
    // Feed the data into the Local Telemetry Engine
    update_telemetry(pkt.sender_id, pkt.seq_num, rssi);

    // Determine if this packet reached its final destination or needs relaying
    bool is_final = (pkt.target_id == NODE_ID);
    const char* action = is_final ? "CONSUMED" : (pkt.ttl > 0 ? "RELAYING" : "TTL_EXPIRED");
    
    String pkt_type = (pkt.packet_type == 0) ? "DATA" : "UNKNOWN";

    // Print ONE unified JSON for the received packet
    Serial.printf("{\"type\": \"RX\", \"src\": %d, \"dst\": %d, \"seq\": %d, \"pkt_type\": \"%s\", \"ttl\": %d, \"rssi\": %d, \"receiver\": %d, \"action\": \"%s\"}\n", 
                  pkt.sender_id, pkt.target_id, pkt.seq_num, pkt_type.c_str(), pkt.ttl, rssi, NODE_ID, action);

    // If the packet is NOT for me, relay it
    if (!is_final && pkt.ttl > 0) {
        pkt.ttl--;
        last_sent_target = pkt.target_id;
        last_sent_dst = pkt.target_id;
        last_sent_seq = pkt.seq_num;
        last_sent_ttl = pkt.ttl;
        esp_now_send(mesh_macs[pkt.target_id], (uint8_t *) &pkt, sizeof(pkt));
    } 
}

// ---------------------------------------------------------
// SETUP
// ---------------------------------------------------------
void setup() {
    Serial.begin(115200);
    WiFi.mode(WIFI_STA);
    
    init_telemetry();

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
    
    // PROCESS TELEMETRY EVERY 1000ms
    if (current_time - last_telemetry_time >= 1000) {
        last_telemetry_time = current_time;
        process_telemetry_window(NODE_ID, NODE_ID == GATEWAY_ID); 
    }

    // OCCASIONALLY GENERATE MESH TRAFFIC
    if (random(0, 100) < 5) {
        int target = random(1, 5); 
        while(target == NODE_ID) target = random(1, 5);
        
        int next_hop = random(1, 5);
        while(next_hop == NODE_ID) next_hop = random(1, 5);

        network_packet pkt;
        pkt.sender_id = NODE_ID;
        pkt.target_id = target;
        pkt.seq_num = current_seq_num++;
        pkt.packet_type = 0;
        pkt.ttl = 4;
        
        for(int i = 0; i < 16; i++) pkt.dummy_payload[i] = random(0, 255);
        pkt.checksum = pkt.sender_id + pkt.target_id + pkt.seq_num;

        // Store packet info so OnDataSent can include it in one JSON
        last_sent_target = next_hop;
        last_sent_dst = target;
        last_sent_seq = pkt.seq_num;
        last_sent_ttl = pkt.ttl;

        esp_now_send(mesh_macs[next_hop], (uint8_t *) &pkt, sizeof(pkt));
    }
    
    delay(50);
}
