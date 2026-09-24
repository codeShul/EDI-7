#include <Arduino.h>

enum AttackerState {
    STATE_IDLE,
    STATE_MODE_ENTERED,
    STATE_MODE_ACTIVE,
    STATE_MODE_TIMEOUT
};

enum AttackMode {
    MODE_NONE,
    MODE_DOS,
    MODE_REPLAY,
    MODE_SPOOFING,
    MODE_ROGUE_NODE
};

AttackerState currentState = STATE_IDLE;
AttackMode currentMode = MODE_NONE;

unsigned long modeStartTimeMs = 0;
unsigned long modeDurationMs = 0;
unsigned long lastHeartbeatMs = 0;
const unsigned long HEARTBEAT_INTERVAL_MS = 1000;

int paramPacketRateMs = 10;
int paramTargetNodeId = 1;

String inputBuffer = "";

// Stubs for hardware team to implement attack logic
void runDosMode(int packetRateMs) {
    // TODO(owner: hardware team) — attack payload implementation
    // out of scope for this task. Do not implement here.
}

void runReplayMode() {
    // TODO(owner: hardware team) — attack payload implementation
    // out of scope for this task. Do not implement here.
}

void runSpoofingMode(int targetNodeId) {
    // TODO(owner: hardware team) — attack payload implementation
    // out of scope for this task. Do not implement here.
}

void runRogueNodeMode() {
    // TODO(owner: hardware team) — attack payload implementation
    // out of scope for this task. Do not implement here.
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

AttackMode stringToMode(const String& str) {
    String upper = str;
    upper.toUpperCase();
    if (upper == "DOS") return MODE_DOS;
    if (upper == "REPLAY") return MODE_REPLAY;
    if (upper == "SPOOFING") return MODE_SPOOFING;
    if (upper == "ROGUE_NODE") return MODE_ROGUE_NODE;
    return MODE_NONE;
}

String stateToString(AttackerState state) {
    switch (state) {
        case STATE_IDLE: return "IDLE";
        case STATE_MODE_ENTERED: return "MODE_ENTERED";
        case STATE_MODE_ACTIVE: return "MODE_ACTIVE";
        case STATE_MODE_TIMEOUT: return "MODE_TIMEOUT";
        default: return "UNKNOWN";
    }
}

void sendStateReport(const String& eventMessage = "") {
    unsigned long now = millis();
    long remainingMs = 0;
    if (currentState == STATE_MODE_ACTIVE) {
        long elapsed = now - modeStartTimeMs;
        remainingMs = (long)modeDurationMs - elapsed;
        if (remainingMs < 0) remainingMs = 0;
    }

    Serial.print("{\"type\":\"STATE_REPORT\",\"state\":\"");
    Serial.print(stateToString(currentState));
    Serial.print("\",\"mode\":\"");
    Serial.print(modeToString(currentMode));
    Serial.print("\",\"time_remaining_s\":");
    Serial.print(remainingMs / 1000.0, 1);
    if (eventMessage.length() > 0) {
        Serial.print(",\"event\":\"");
        Serial.print(eventMessage);
        Serial.print("\"");
    }
    Serial.println("}");
}

void parseJsonCommand(const String& line) {
    int cmdIdx = line.indexOf("\"cmd\"");
    if (cmdIdx < 0) cmdIdx = line.indexOf("'cmd'");

    if (cmdIdx >= 0) {
        int colon = line.indexOf(":", cmdIdx);
        int q1 = line.indexOf("\"", colon);
        if (q1 < 0) q1 = line.indexOf("'", colon);
        int q2 = (q1 >= 0) ? line.indexOf("\"", q1 + 1) : -1;
        if (q2 < 0 && q1 >= 0) q2 = line.indexOf("'", q1 + 1);

        if (q1 >= 0 && q2 > q1) {
            String cmd = line.substring(q1 + 1, q2);
            cmd.toUpperCase();
            if (cmd == "STOP" || cmd == "IDLE") {
                currentState = STATE_IDLE;
                currentMode = MODE_NONE;
                sendStateReport("Stopped");
                return;
            } else if (cmd == "STATUS") {
                sendStateReport("Status");
                return;
            }
        }
    }

    int modeIdx = line.indexOf("\"mode\"");
    if (modeIdx < 0) modeIdx = line.indexOf("'mode'");

    if (modeIdx >= 0) {
        int colon = line.indexOf(":", modeIdx);
        int q1 = line.indexOf("\"", colon);
        if (q1 < 0) q1 = line.indexOf("'", colon);
        int q2 = (q1 >= 0) ? line.indexOf("\"", q1 + 1) : -1;
        if (q2 < 0 && q1 >= 0) q2 = line.indexOf("'", q1 + 1);

        String modeStr = "NONE";
        if (q1 >= 0 && q2 > q1) {
            modeStr = line.substring(q1 + 1, q2);
        }

        int durationSec = 60;
        int durIdx = line.indexOf("\"duration_s\"");
        if (durIdx >= 0) {
            int durColon = line.indexOf(":", durIdx);
            int endComma = line.indexOf(",", durColon);
            int endBrace = line.indexOf("}", durColon);
            int endNum = (endComma > 0 && endComma < endBrace) ? endComma : endBrace;
            if (endNum > durColon) {
                String s = line.substring(durColon + 1, endNum);
                s.trim();
                durationSec = s.toInt();
                if (durationSec <= 0) durationSec = 60;
            }
        }

        int prIdx = line.indexOf("\"packet_rate_ms\"");
        if (prIdx >= 0) {
            int prColon = line.indexOf(":", prIdx);
            int endComma = line.indexOf(",", prColon);
            int endBrace = line.indexOf("}", prColon);
            int endNum = (endComma > 0 && endComma < endBrace) ? endComma : endBrace;
            if (endNum > prColon) {
                paramPacketRateMs = line.substring(prColon + 1, endNum).toInt();
            }
        }

        AttackMode newMode = stringToMode(modeStr);
        if (newMode == MODE_NONE) {
            currentState = STATE_IDLE;
            currentMode = MODE_NONE;
            sendStateReport("IDLE");
        } else {
            currentMode = newMode;
            modeDurationMs = (unsigned long)durationSec * 1000UL;
            modeStartTimeMs = millis();
            currentState = STATE_MODE_ENTERED;
            sendStateReport("Mode entered: " + modeStr);
            currentState = STATE_MODE_ACTIVE;
        }
    }
}

void setup() {
    Serial.begin(115200);
    while (!Serial && millis() < 1500);

    currentState = STATE_IDLE;
    currentMode = MODE_NONE;

    Serial.println("{\"type\":\"INIT\",\"status\":\"Attacker Node Ready\",\"baud\":115200}");
    sendStateReport("Boot");
}

void loop() {
    while (Serial.available() > 0) {
        char c = (char)Serial.read();
        if (c == '\n' || c == '\r') {
            if (inputBuffer.length() > 0) {
                inputBuffer.trim();
                parseJsonCommand(inputBuffer);
                inputBuffer = "";
            }
        } else {
            inputBuffer += c;
            if (inputBuffer.length() > 256) {
                inputBuffer = "";
            }
        }
    }

    unsigned long now = millis();

    switch (currentState) {
        case STATE_IDLE:
            break;

        case STATE_MODE_ENTERED:
            currentState = STATE_MODE_ACTIVE;
            break;

        case STATE_MODE_ACTIVE:
            if (now - modeStartTimeMs >= modeDurationMs) {
                currentState = STATE_MODE_TIMEOUT;
            } else {
                switch (currentMode) {
                    case MODE_DOS:
                        runDosMode(paramPacketRateMs);
                        break;
                    case MODE_REPLAY:
                        runReplayMode();
                        break;
                    case MODE_SPOOFING:
                        runSpoofingMode(paramTargetNodeId);
                        break;
                    case MODE_ROGUE_NODE:
                        runRogueNodeMode();
                        break;
                    default:
                        break;
                }
            }
            break;

        case STATE_MODE_TIMEOUT:
            sendStateReport("Timeout");
            currentState = STATE_IDLE;
            currentMode = MODE_NONE;
            break;
    }

    if (now - lastHeartbeatMs >= HEARTBEAT_INTERVAL_MS) {
        lastHeartbeatMs = now;
        sendStateReport();
    }

    delay(20);
}
