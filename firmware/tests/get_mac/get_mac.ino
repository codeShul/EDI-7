#include <WiFi.h>

void setup() {
    Serial.begin(115200);
    // Put Wi-Fi into Station mode to get the correct STA MAC address
    WiFi.mode(WIFI_STA);
    
    Serial.println();
    Serial.println("=========================================");
    Serial.print("THIS BOARD'S MAC ADDRESS: ");
    Serial.println(WiFi.macAddress());
    Serial.println("=========================================");
}

void loop() {
    // Do nothing
}
