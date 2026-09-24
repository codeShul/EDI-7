#!/usr/bin/env python3
"""Mock serial echo program for testing attack_controller.py without ESP32 hardware."""

import json
import sys
import time


def main():
    print(json.dumps({"type": "INIT", "status": "Mock Attacker Ready", "baud": 115200}), flush=True)

    state = "IDLE"
    mode = "NONE"
    start_time = 0.0
    duration_s = 0.0
    last_tick = time.time()

    while True:
        line = sys.stdin.readline()
        if line:
            line = line.strip()
            if line:
                try:
                    cmd = json.loads(line)
                    req_mode = cmd.get("mode", "").upper()
                    req_dur = float(cmd.get("duration_s", 30))
                    if req_mode in ["STOP", "IDLE", "NONE"]:
                        state = "IDLE"
                        mode = "NONE"
                        print(json.dumps({"type": "STATE_REPORT", "state": "IDLE", "mode": "NONE", "time_remaining_s": 0.0}), flush=True)
                    else:
                        state = "MODE_ACTIVE"
                        mode = req_mode
                        start_time = time.time()
                        duration_s = req_dur
                        print(json.dumps({"type": "STATE_REPORT", "state": "MODE_ENTERED", "mode": mode, "time_remaining_s": duration_s}), flush=True)
                except Exception as err:
                    print(json.dumps({"type": "ERROR", "message": str(err)}), flush=True)

        now = time.time()
        if state == "MODE_ACTIVE":
            remaining = max(0.0, duration_s - (now - start_time))
            if remaining <= 0:
                state = "IDLE"
                mode = "NONE"
                print(json.dumps({"type": "STATE_REPORT", "state": "IDLE", "mode": "NONE", "time_remaining_s": 0.0}), flush=True)

        if now - last_tick >= 1.0:
            last_tick = now
            rem = max(0.0, duration_s - (now - start_time)) if state == "MODE_ACTIVE" else 0.0
            print(json.dumps({"type": "STATE_REPORT", "state": state, "mode": mode, "time_remaining_s": round(rem, 1)}), flush=True)

        time.sleep(0.05)


if __name__ == "__main__":
    main()
