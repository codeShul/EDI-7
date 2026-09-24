#include <Arduino.h>
#include <WiFi.h>
#include <esp_now.h>
// Re-declare the struct and MACs here to avoid Arduino IDE relative path issues across top-level folders
#define NODE_ID 4

typedef struct network_packet {
    uint8_t sender_id;      
    uint8_t target_id;      
    uint32_t seq_num;       
    uint8_t packet_type;    
    uint8_t ttl;            
    uint16_t checksum;      
    uint8_t dummy_payload[16]; 
} network_packet;

const uint8_t mesh_macs[6][6] = {
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x68, 0x09, 0x47, 0x86, 0x31, 0xD0}, // 1
    {0x1C, 0xC3, 0xAB, 0xB3, 0xC4, 0xA8}, // 2
    {0x8C, 0x94, 0xDF, 0x7C, 0xCC, 0x84}, // 3 (Gateway)
    {0x70, 0x4B, 0xCA, 0x46, 0x79, 0xF4}, // 4 (Attacker)
    {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
};

enum AttackMode {
    MODE_DOS,
    MODE_REPLAY,
    MODE_SPOOFING,
    MODE_ROGUE_NODE,
    MODE_COUNT // used for cycling
};

AttackMode currentMode = MODE_DOS;
unsigned long modeStartTimeMs = 0;
const unsigned long ATTACK_PHASE_DURATION_MS = 30000; // 30 seconds per attack
unsigned long lastHeartbeatMs = 0;
const unsigned long HEARTBEAT_INTERVAL_MS = 1000;

uint32_t current_seq_num = 1;
int attackTarget = 1; // Picked randomly on boot

// ---------------------------------------------------------
// Attack Implementations
// ---------------------------------------------------------
void runDosMode() {
    network_packet pkt;
    pkt.sender_id = NODE_ID; // 4
    pkt.target_id = attackTarget;
    pkt.seq_num = current_seq_num++;
    pkt.packet_type = 0;
    pkt.ttl = 4;
    esp_now_send(mesh_macs[attackTarget], (uint8_t *) &pkt, sizeof(pkt));
    // No delay! This will flood the target as fast as the loop runs.
}

void runReplayMode() {
    network_packet pkt;
    pkt.sender_id = NODE_ID; // 4
    pkt.target_id = attackTarget;
    // Intentional replay: freeze the sequence number to trigger REPLAY detection
    pkt.seq_num = current_seq_num; // Do NOT increment!
    pkt.packet_type = 0;
    pkt.ttl = 4;
    esp_now_send(mesh_macs[attackTarget], (uint8_t *) &pkt, sizeof(pkt));
    delay(50); // Burst it out fast enough to trip the 2-second window
}

void runSpoofingMode() {
    network_packet pkt;
    // SPOOFING: Pretend to be someone else!
    // If target is 1, pretend to be 2. If target is 2, pretend to be 1.
    uint8_t spoofed_sender = (attackTarget == 1) ? 2 : 1;
    
    pkt.sender_id = spoofed_sender;
    pkt.target_id = attackTarget;
    pkt.seq_num = current_seq_num++;
    pkt.packet_type = 0;
    pkt.ttl = 4;
    esp_now_send(mesh_macs[attackTarget], (uint8_t *) &pkt, sizeof(pkt));
    delay(100); // Normal rate
}

void runRogueNodeMode() {
    network_packet pkt;
    pkt.sender_id = NODE_ID; // 4
    pkt.target_id = attackTarget;
    // ROGUE / DROPS: Skip sequence numbers wildly to trigger the "drops" telemetry on the target
    pkt.seq_num = current_seq_num;
    current_seq_num += 10; // Skip 9 packets every time!
    pkt.packet_type = 0;
    pkt.ttl = 4;
    esp_now_send(mesh_macs[attackTarget], (uint8_t *) &pkt, sizeof(pkt));
    delay(100); // Normal rate
}

String modeToString(AttackMode mode) {
    switch (mode) {
        case MODE_DOS: return "DOS";
        case MODE_REPLAY: return "REPLAY";
        case MODE_SPOOFING: return "SPOOFING";
        case MODE_ROGUE_NODE: return "ROGUE_NODE";
        default: return "NONE";
    }
}

void setup() {
    Serial.begin(115200);
    WiFi.mode(WIFI_STA);

    if (esp_now_init() != ESP_OK) {
        Serial.println("ESP-NOW Init Failed");
        return;
    }

    // Register Nodes 1, 2, 3 as peers
    for (int i = 1; i <= 3; i++) {
        esp_now_peer_info_t peerInfo = {};
        memcpy(peerInfo.peer_addr, mesh_macs[i], 6);
        peerInfo.channel = 0;  
        peerInfo.encrypt = false;
        esp_now_add_peer(&peerInfo);
    }

    // Always target Node 3 (the Gateway) so the PC dashboard can actually receive and display the attack traffic!
    attackTarget = 3;
    
    modeStartTimeMs = millis();
    Serial.println("{\"type\":\"INIT\",\"status\":\"Attacker Autonomous Mode Ready\"}");
}

void loop() {
    unsigned long now = millis();

    // Check if it's time to cycle to the next attack mode
    if (now - modeStartTimeMs >= ATTACK_PHASE_DURATION_MS) {
        modeStartTimeMs = now;
        currentMode = (AttackMode)((currentMode + 1) % MODE_COUNT);
    }

    // Execute the current attack payload
    switch (currentMode) {
        case MODE_DOS:
            runDosMode();
            break;
        case MODE_REPLAY:
            runReplayMode();
            break;
        case MODE_SPOOFING:
            runSpoofingMode();
            break;
        case MODE_ROGUE_NODE:
            runRogueNodeMode();
            break;
        default:
            break;
    }

    // Optional Heartbeat to Serial Monitor
    if (now - lastHeartbeatMs >= HEARTBEAT_INTERVAL_MS) {
        lastHeartbeatMs = now;
        long remainingMs = (long)ATTACK_PHASE_DURATION_MS - (now - modeStartTimeMs);
        Serial.print("{\"type\":\"STATE_REPORT\",\"state\":\"ATTACKING\",\"mode\":\"");
        Serial.print(modeToString(currentMode));
        Serial.print("\",\"target\":");
        Serial.print(attackTarget);
        Serial.print(",\"time_remaining_s\":");
        Serial.print(remainingMs / 1000.0, 1);
        Serial.println("}");
    }
}
