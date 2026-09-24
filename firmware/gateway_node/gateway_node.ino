#include <WiFi.h>
#include <esp_now.h>
#include "../common/MeshConfig.h"

// Callback when data is received (Core 3.x / IDF 5.x compatible)
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 0, 0)
void OnDataRecv(const esp_now_recv_info_t *recv_info, const uint8_t *incomingData, int len) {
    // Extract RSSI from the hardware callback
    int rssi = recv_info->rx_ctrl->rssi;
#else
void OnDataRecv(const uint8_t * mac_addr, const uint8_t *incomingData, int len) {
    // In older ESP-IDF, getting precise per-packet RSSI in the callback requires promiscuous mode tricks.
    // For this prototype, we'll mock it if compiling on an extremely old core, but Core 3.x uses the above block.
    int rssi = -50; 
#endif

    network_packet pkt;
    memcpy(&pkt, incomingData, sizeof(pkt));
    
    // Convert packet type to string
    String type_str = "UNKNOWN";
    if (pkt.packet_type == 0) type_str = "DATA";
    else if (pkt.packet_type == 1) type_str = "HEARTBEAT";
    else if (pkt.packet_type == 2) type_str = "ROUTE_SYNC";

    // Format as JSON and print to Serial (for the Web Dashboard to read via WebSerial)
    Serial.printf("{\"src\": %d, \"dst\": %d, \"seq\": %d, \"type\": \"%s\", \"ttl\": %d, \"rssi\": %d}\n", 
                  pkt.sender_id, pkt.target_id, pkt.seq_num, type_str.c_str(), pkt.ttl, rssi);
}

void setup() {
    // Initialize Serial Monitor at 115200 baud
    Serial.begin(115200);
    
    // Set device as a Wi-Fi Station
    WiFi.mode(WIFI_STA);

    // Initialize ESP-NOW
    if (esp_now_init() != ESP_OK) {
        Serial.println("{\"error\": \"Error initializing ESP-NOW\"}");
        return;
    }
    
    // Register the receive callback
    esp_now_register_recv_cb(OnDataRecv);
    
    Serial.println("{\"status\": \"Gateway Node Initialized. Listening for mesh traffic...\"}");
}

void loop() {
    // The Gateway node just passively listens and prints incoming JSON.
    // We can add a small delay to prevent watchdog timeout.
    delay(100);
}
