/*
 * ESP-NOW Receiver Node
 * Compatible with ESP32 Arduino Core v2.x and v3.x
 * Receives ESP-NOW messages from Sender and prints to Serial Monitor (115200 baud).
 */

#include <esp_now.h>
#include <WiFi.h>
#include <esp_idf_version.h>

// Structure of incoming test message (must match Sender)
typedef struct struct_message {
    char text[32];
    uint32_t counter;
} struct_message;

struct_message incomingData;

// Callback function executed when data is received via ESP-NOW
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 0, 0)
void OnDataRecv(const esp_now_recv_info_t *recv_info, const uint8_t *incomingDataBytes, int len) {
    memcpy(&incomingData, incomingDataBytes, sizeof(incomingData));
    
    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
             recv_info->src_addr[0], recv_info->src_addr[1], recv_info->src_addr[2],
             recv_info->src_addr[3], recv_info->src_addr[4], recv_info->src_addr[5]);

    int rssi = (recv_info->rx_ctrl != NULL) ? recv_info->rx_ctrl->rssi : 0;

    Serial.println("-----------------------------------------");
    Serial.printf("📥 [RECEIVED PACKET #%u]\n", incomingData.counter);
    Serial.printf("   From MAC : %s\n", macStr);
    Serial.printf("   Message  : \"%s\"\n", incomingData.text);
    Serial.printf("   RSSI     : %d dBm\n", rssi);
    Serial.printf("   Bytes    : %d bytes\n", len);
    Serial.println("-----------------------------------------");
}
#else
void OnDataRecv(const uint8_t *mac_addr, const uint8_t *incomingDataBytes, int len) {
    memcpy(&incomingData, incomingDataBytes, sizeof(incomingData));
    
    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac_addr[0], mac_addr[1], mac_addr[2],
             mac_addr[3], mac_addr[4], mac_addr[5]);

    Serial.println("-----------------------------------------");
    Serial.printf("📥 [RECEIVED PACKET #%u]\n", incomingData.counter);
    Serial.printf("   From MAC : %s\n", macStr);
    Serial.printf("   Message  : \"%s\"\n", incomingData.text);
    Serial.printf("   Bytes    : %d bytes\n", len);
    Serial.println("-----------------------------------------");
}
#endif

void setup() {
    Serial.begin(115200);
    delay(1000);

    Serial.println("=========================================");
    Serial.println("   ESP-NOW RECEIVER NODE INITIALIZING    ");
    Serial.println("=========================================");

    // Set device as Wi-Fi Station
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();

    Serial.print("Receiver MAC Address: ");
    Serial.println(WiFi.macAddress());

    // Init ESP-NOW
    if (esp_now_init() != ESP_OK) {
        Serial.println("Error initializing ESP-NOW ❌");
        return;
    }
    Serial.println("ESP-NOW Initialized Successfully ✅");

    // Register callback for receiving data
    esp_now_register_recv_cb(OnDataRecv);

    Serial.println("Listening for incoming ESP-NOW messages...\n");
}

void loop() {
    delay(100);
}
