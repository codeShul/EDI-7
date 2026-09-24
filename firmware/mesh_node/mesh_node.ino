#include <WiFi.h>
#include <esp_now.h>
#include "../common/MeshConfig.h"

uint32_t current_seq_num = 1;

// ---------------------------------------------------------
// CALLBACK: When data is sent
// ---------------------------------------------------------
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 0, 0)
void OnDataSent(const wifi_tx_info_t *mac_addr, esp_now_send_status_t status) {
#else
void OnDataSent(const uint8_t *mac_addr, esp_now_send_status_t status) {
#endif
    if (NODE_ID != GATEWAY_ID) {
        // Only print debug on non-gateway nodes to keep the Gateway's JSON stream clean
        Serial.print("Packet Send Status: ");
        Serial.println(status == ESP_NOW_SEND_SUCCESS ? "Success" : "Fail");
    }
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
    
    // 1. If I am the Gateway, output clean JSON to the Laptop
    if (NODE_ID == GATEWAY_ID) {
        String type_str = (pkt.packet_type == 0) ? "DATA" : "UNKNOWN";
        Serial.printf("{\"src\": %d, \"dst\": %d, \"seq\": %d, \"type\": \"%s\", \"ttl\": %d, \"rssi\": %d}\n", 
                      pkt.sender_id, pkt.target_id, pkt.seq_num, type_str.c_str(), pkt.ttl, rssi);
    } 
    
    // 2. If the packet is NOT for me, I need to act as a Router (A -> B -> C)
    if (pkt.target_id != NODE_ID && pkt.ttl > 0) {
        Serial.printf("Relaying packet from Node %d to Node %d (TTL: %d)\n", pkt.sender_id, pkt.target_id, pkt.ttl);
        
        // Decrement TTL (Time to Live) to prevent infinite loops
        pkt.ttl--;
        
        // Forward it to the next hop (Directly to the target for now)
        esp_now_send(mesh_macs[pkt.target_id], (uint8_t *) &pkt, sizeof(pkt));
    } 
    // 3. If it IS for me (and I'm a normal node), consume it
    else if (pkt.target_id == NODE_ID && NODE_ID != GATEWAY_ID) {
        Serial.printf("Received final packet from Node %d! (RSSI: %d)\n", pkt.sender_id, rssi);
    }
}

// ---------------------------------------------------------
// SETUP
// ---------------------------------------------------------
void setup() {
    Serial.begin(115200);
    WiFi.mode(WIFI_STA);

    if (esp_now_init() != ESP_OK) {
        Serial.println("Error initializing ESP-NOW");
        return;
    }

    // Register BOTH send and receive callbacks (making it fully bidirectional)
    #if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 0, 0)
        esp_now_register_send_cb(OnDataSent);
    #else
        esp_now_register_send_cb(OnDataSent);
    #endif
    
    esp_now_register_recv_cb(OnDataRecv);

    // Register ALL other valid nodes in the mesh as peers
    for (int i = 1; i <= 5; i++) {
        // Skip ourselves and skip empty placeholders (0xFF or 0x00)
        if (i == NODE_ID || mesh_macs[i][0] == 0xFF || mesh_macs[i][0] == 0x00) {
            continue; 
        }

        esp_now_peer_info_t peerInfo = {};
        memcpy(peerInfo.peer_addr, mesh_macs[i], 6);
        peerInfo.channel = 0;  
        peerInfo.encrypt = false;
        
        if (esp_now_add_peer(&peerInfo) != ESP_OK) {
            Serial.printf("Failed to add Node %d as peer\n", i);
        } else {
            Serial.printf("Successfully registered Node %d as peer\n", i);
        }
    }
    
    Serial.printf("Node %d Initialized in Full Mesh Mode.\n", NODE_ID);
}

// ---------------------------------------------------------
// MAIN LOOP
// ---------------------------------------------------------
void loop() {
    // 1. Pick a random FINAL destination (1, 2, or 3)
    int target = random(1, 4); 
    while(target == NODE_ID) { // Don't send to ourselves
        target = random(1, 4);
    }
    
    // 2. Pick a random NEXT HOP physical MAC (1, 2, or 3)
    // This allows packets to take random paths through the mesh!
    int next_hop_mac = random(1, 4);
    while(next_hop_mac == NODE_ID) { 
        next_hop_mac = random(1, 4);
    }

    network_packet pkt;
    pkt.sender_id = NODE_ID;
    pkt.target_id = target;
    pkt.seq_num = current_seq_num++;
    pkt.packet_type = 0; // DATA
    pkt.ttl = 4;
    
    for(int i = 0; i < 16; i++) pkt.dummy_payload[i] = random(0, 255);
    pkt.checksum = pkt.sender_id + pkt.target_id + pkt.seq_num;

    // Send the radio wave to the random next hop
    esp_now_send(mesh_macs[next_hop_mac], (uint8_t *) &pkt, sizeof(pkt));
    
    // Random delay so packets constantly bounce around the mesh asynchronously
    delay(random(1000, 3000));
}
