#include <WiFi.h>
#include <esp_now.h>
#include "../common/MeshConfig.h"
#include "../common/TelemetryEngine.h"

uint32_t current_seq_num = 1;
unsigned long last_telemetry_time = 0;

// Store last sent packet info so OnDataSent can print the unified JSON
volatile uint8_t last_sent_hop = 0;
volatile uint8_t last_sent_dst = 0;
volatile uint32_t last_sent_seq = 0;
volatile uint8_t last_sent_ttl = 0;

// The ONE universal JSON print function
void print_json(const char* type, int src, int dst, int seq, const char* pkt_type, 
                int ttl, int rssi, int receiver, int hop, const char* action, 
                const char* delivery, int rate, int avg_rssi, int drops, const char* threat) {
    Serial.printf("{\"type\":\"%s\",\"src\":%d,\"dst\":%d,\"seq\":%d,\"pkt_type\":\"%s\","
                  "\"ttl\":%d,\"rssi\":%d,\"receiver\":%d,\"hop\":%d,\"action\":\"%s\","
                  "\"delivery\":\"%s\",\"rate\":%d,\"avg_rssi\":%d,\"drops\":%d,\"threat\":\"%s\"}\n",
                  type, src, dst, seq, pkt_type, ttl, rssi, receiver, hop, action, delivery, rate, avg_rssi, drops, threat);
}

// ---------------------------------------------------------
// CALLBACK: When data is sent
// ---------------------------------------------------------
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 0, 0)
void OnDataSent(const wifi_tx_info_t *mac_addr, esp_now_send_status_t status) {
#else
void OnDataSent(const uint8_t *mac_addr, esp_now_send_status_t status) {
#endif
    const char* result = (status == ESP_NOW_SEND_SUCCESS) ? "SUCCESS" : "FAIL";
    print_json("TX", NODE_ID, last_sent_dst, last_sent_seq, "DATA", 
               last_sent_ttl, 0, NODE_ID, last_sent_hop, "SENT", result, 0, 0, 0, "");
}

// ---------------------------------------------------------
// CALLBACK: When data is received
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
    
    update_telemetry(pkt.sender_id, pkt.seq_num, rssi);

    bool is_final = (pkt.target_id == NODE_ID);
    const char* action = is_final ? "CONSUMED" : (pkt.ttl > 0 ? "RELAYING" : "TTL_EXPIRED");
    const char* pkt_type = (pkt.packet_type == 0) ? "DATA" : (pkt.packet_type == 1) ? "HEARTBEAT" : "ROUTE_SYNC";

    print_json("RX", pkt.sender_id, pkt.target_id, pkt.seq_num, pkt_type, 
               pkt.ttl, rssi, NODE_ID, 0, action, "", 0, 0, 0, "");

    if (!is_final && pkt.ttl > 0) {
        pkt.ttl--;
        last_sent_hop = pkt.target_id;
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
    
    if (current_time - last_telemetry_time >= 1000) {
        last_telemetry_time = current_time;
        // Print telemetry using the same unified JSON schema
        for (int i = 1; i <= 5; i++) {
            if (telemetry_table[i].packets_received > 0) {
                int avg_rssi = telemetry_table[i].rssi_sum / telemetry_table[i].packets_received;
                uint32_t rate = telemetry_table[i].packets_received;
                uint32_t drops = telemetry_table[i].dropped_packets;
                
                print_json("TELEMETRY", i, NODE_ID, 0, "", 
                           0, avg_rssi, NODE_ID, 0, "", "", rate, avg_rssi, drops, "");

                telemetry_table[i].packets_received = 0;
                telemetry_table[i].rssi_sum = 0;
            }
        }
    }

    if (random(0, 100) < 5) {
        int target = random(1, 4); 
        while(target == NODE_ID) target = random(1, 4);
        
        int next_hop = random(1, 4);
        while(next_hop == NODE_ID) next_hop = random(1, 4);

        network_packet pkt;
        pkt.sender_id = NODE_ID;
        pkt.target_id = target;
        pkt.seq_num = current_seq_num++;
        pkt.packet_type = 0;
        pkt.ttl = 4;
        
        for(int i = 0; i < 16; i++) pkt.dummy_payload[i] = random(0, 255);
        pkt.checksum = pkt.sender_id + pkt.target_id + pkt.seq_num;

        last_sent_hop = next_hop;
        last_sent_dst = target;
        last_sent_seq = pkt.seq_num;
        last_sent_ttl = pkt.ttl;

        esp_now_send(mesh_macs[next_hop], (uint8_t *) &pkt, sizeof(pkt));
    }
    
    delay(50);
}
