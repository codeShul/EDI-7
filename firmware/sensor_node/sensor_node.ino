#include <WiFi.h>
#include <esp_now.h>
#include "../common/MeshConfig.h"

// Note: For Phase 1, we assume this is Node 1. 
// Before flashing other nodes, you would change NODE_ID in MeshConfig.h
uint32_t current_seq_num = 1;
esp_now_peer_info_t peerInfo;

// Callback when data is sent (Core 3.x / IDF 5.x compatible)
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 0, 0)
void OnDataSent(const wifi_tx_info_t *mac_addr, esp_now_send_status_t status) {
    Serial.print("Last Packet Send Status: ");
    Serial.println(status == ESP_NOW_SEND_SUCCESS ? "Delivery Success" : "Delivery Fail");
}
#else
void OnDataSent(const uint8_t *mac_addr, esp_now_send_status_t status) {
    Serial.print("Last Packet Send Status: ");
    Serial.println(status == ESP_NOW_SEND_SUCCESS ? "Delivery Success" : "Delivery Fail");
}
#endif

void setup() {
    Serial.begin(115200);
    
    // Set device as a Wi-Fi Station
    WiFi.mode(WIFI_STA);

    // Initialize ESP-NOW
    if (esp_now_init() != ESP_OK) {
        Serial.println("Error initializing ESP-NOW");
        return;
    }

    // Register Send Callback
    #if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 0, 0)
        esp_now_register_send_cb(OnDataSent);
    #else
        esp_now_register_send_cb(OnDataSent);
    #endif
    
    // Register peer (Gateway / Broadcast)
    memcpy(peerInfo.peer_addr, broadcast_mac, 6);
    peerInfo.channel = 0;  
    peerInfo.encrypt = false;
    
    if (esp_now_add_peer(&peerInfo) != ESP_OK){
        Serial.println("Failed to add peer");
        return;
    }
    
    Serial.println("Sensor Node Initialized. Sending data...");
}

void loop() {
    network_packet pkt;
    pkt.sender_id = NODE_ID;
    pkt.target_id = GATEWAY_ID;
    pkt.seq_num = current_seq_num++;
    pkt.packet_type = 0; // DATA
    pkt.ttl = 4;
    
    // Fill dummy payload with random network-like data
    for(int i = 0; i < 16; i++) {
        pkt.dummy_payload[i] = random(0, 255);
    }
    
    // Simple mock checksum (Sum of bytes)
    pkt.checksum = pkt.sender_id + pkt.target_id + pkt.seq_num;

    // Send message via ESP-NOW
    esp_err_t result = esp_now_send(broadcast_mac, (uint8_t *) &pkt, sizeof(pkt));
   
    if (result == ESP_OK) {
        Serial.printf("Sent packet Seq: %d\n", pkt.seq_num);
    } else {
        Serial.println("Error sending the data");
    }
    
    // Random delay between 1 and 3 seconds to simulate variable IoT traffic
    delay(random(1000, 3000));
}
