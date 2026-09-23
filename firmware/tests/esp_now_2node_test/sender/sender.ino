/*
 * ESP-NOW Sender Node
 * Compatible with ESP32 Arduino Core v2.x and v3.x
 * Sends "Hello from ESP32 #1" every 2 seconds via ESP-NOW.
 */

#include <esp_now.h>
#include <WiFi.h>
#include <esp_idf_version.h>

// Structure of the test message
typedef struct struct_message {
    char text[32];
    uint32_t counter;
} struct_message;

struct_message myData;
esp_now_peer_info_t peerInfo;

// Broadcast MAC address (sends to any ESP-NOW receiver nearby)
uint8_t broadcastAddress[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// Callback when data is sent (Compatible with Core 3.x and Core 2.x)
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 0, 0)
void OnDataSent(const wifi_tx_info_t *info, esp_now_send_status_t status) {
    Serial.print("Send Status: ");
    Serial.println(status == ESP_NOW_SEND_SUCCESS ? "Delivery Success ✅" : "Delivery Fail ❌");
}
#else
void OnDataSent(const uint8_t *mac_addr, esp_now_send_status_t status) {
    Serial.print("Send Status: ");
    Serial.println(status == ESP_NOW_SEND_SUCCESS ? "Delivery Success ✅" : "Delivery Fail ❌");
}
#endif

void setup() {
    Serial.begin(115200);
    delay(1000);

    Serial.println("=========================================");
    Serial.println("   ESP-NOW SENDER NODE INITIALIZING      ");
    Serial.println("=========================================");

    // Set device as a Wi-Fi Station
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();

    Serial.print("Sender MAC Address: ");
    Serial.println(WiFi.macAddress());

    // Init ESP-NOW
    if (esp_now_init() != ESP_OK) {
        Serial.println("Error initializing ESP-NOW ❌");
        return;
    }
    Serial.println("ESP-NOW Initialized Successfully ✅");

    // Register Send Callback
    esp_now_register_send_cb(OnDataSent);

    // Register peer (Broadcast)
    memset(&peerInfo, 0, sizeof(peerInfo));
    memcpy(peerInfo.peer_addr, broadcastAddress, 6);
    peerInfo.channel = 0;  // pick current channel
    peerInfo.encrypt = false;

    if (esp_now_add_peer(&peerInfo) != ESP_OK) {
        Serial.println("Failed to add peer ❌");
        return;
    }
    Serial.println("Broadcast Peer Added Successfully ✅");
    Serial.println("Starting transmission loop...\n");
}

void loop() {
    static uint32_t count = 0;
    
    // Prepare message payload
    snprintf(myData.text, sizeof(myData.text), "Hello from ESP32 #1");
    myData.counter = ++count;

    Serial.printf("[Packet #%u] Sending: \"%s\" ... ", myData.counter, myData.text);

    // Send message via ESP-NOW
    esp_err_t result = esp_now_send(broadcastAddress, (uint8_t *) &myData, sizeof(myData));

    if (result == ESP_OK) {
        Serial.println("Sent to radio buffer.");
    } else {
        Serial.println("Error sending packet.");
    }

    delay(2000); // Send every 2 seconds
}
