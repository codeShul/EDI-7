#!/usr/bin/env python3
"""Attack simulation controller for SecureMesh AI testbed.

Sends control commands to the attacker ESP32 over serial and broadcasts
active attack state for dataset auto-labeling.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import socket
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

VALID_MODES = ["NORMAL", "DOS", "REPLAY", "SPOOFING", "ROGUE_NODE", "IDLE"]

logger = logging.getLogger("AttackController")


class MockAttackerSerial:
    """Mock serial interface that simulates the attacker ESP32 firmware."""

    def __init__(self):
        self.is_open = True
        self.current_mode = "NONE"
        self.current_state = "IDLE"
        self.mode_start_time = 0.0
        self.mode_duration_s = 0.0
        self._rx_buffer = []

    def write(self, data: bytes) -> int:
        line = data.decode("utf-8", errors="ignore").strip()
        try:
            cmd = json.loads(line)
            mode = cmd.get("mode", "").upper()
            duration = float(cmd.get("duration_s", 60))
            if mode in ["STOP", "IDLE", "NONE", "NORMAL"]:
                self.current_mode = "NONE"
                self.current_state = "IDLE"
                self._respond({"type": "STATE_REPORT", "state": "IDLE", "mode": "NONE", "time_remaining_s": 0.0})
            elif mode in ["DOS", "REPLAY", "SPOOFING", "ROGUE_NODE"]:
                self.current_mode = mode
                self.current_state = "MODE_ACTIVE"
                self.mode_start_time = time.time()
                self.mode_duration_s = duration
                self._respond({"type": "STATE_REPORT", "state": "MODE_ENTERED", "mode": mode, "time_remaining_s": duration})
        except Exception as exc:
            self._respond({"type": "ERROR", "message": str(exc)})
        return len(data)

    def _respond(self, payload: dict):
        line = json.dumps(payload) + "\n"
        self._rx_buffer.append(line.encode("utf-8"))

    def readline(self) -> bytes:
        if self._rx_buffer:
            return self._rx_buffer.pop(0)

        if self.current_state == "MODE_ACTIVE":
            elapsed = time.time() - self.mode_start_time
            remaining = max(0.0, self.mode_duration_s - elapsed)
            if remaining <= 0:
                self.current_state = "IDLE"
                self.current_mode = "NONE"
                return (json.dumps({"type": "STATE_REPORT", "state": "IDLE", "mode": "NONE", "time_remaining_s": 0.0}) + "\n").encode()

        time.sleep(0.05)
        return b""

    def close(self):
        self.is_open = False


class AttackController:
    def __init__(
        self,
        serial_port: Optional[str] = None,
        baudrate: int = 115200,
        mock_mode: bool = False,
        ipc_file: str = ".ground_truth_state.json",
        udp_port: int = 9998,
        log_file: str = "attack_controller.log",
        attacker_id: int = 4,
    ):
        self.serial_port = serial_port
        self.baudrate = baudrate
        self.mock_mode = mock_mode
        self.ipc_file = Path(ipc_file).resolve()
        self.udp_port = udp_port
        self.log_file = Path(log_file).resolve()
        self.attacker_id = attacker_id

        self.running = True
        self.current_mode = "NORMAL"

        self._setup_logging()
        self.ser = None
        self._connect_serial()

        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.listener_thread = threading.Thread(target=self._read_serial_loop, daemon=True)
        self.listener_thread.start()

        self.broadcast_state("NORMAL", duration_s=0, parameters={})

    def _setup_logging(self):
        handler = logging.FileHandler(self.log_file, encoding="utf-8")
        handler.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

    def _connect_serial(self):
        if self.mock_mode or not self.serial_port:
            logger.info("Using mock serial interface (no physical ESP32 required).")
            self.ser = MockAttackerSerial()
            return

        try:
            import serial
            logger.info("Connecting to attacker ESP32 on %s @ %d baud...", self.serial_port, self.baudrate)
            self.ser = serial.Serial(self.serial_port, self.baudrate, timeout=1.0)
            time.sleep(1.5)
            logger.info("Connected successfully.")
        except Exception as exc:
            logger.warning("Could not open %s (%s). Falling back to mock mode.", self.serial_port, exc)
            self.mock_mode = True
            self.ser = MockAttackerSerial()

    def _read_serial_loop(self):
        while self.running:
            try:
                if self.ser and hasattr(self.ser, "readline"):
                    line = self.ser.readline().decode("utf-8", errors="ignore").strip()
                    if line:
                        try:
                            msg = json.loads(line)
                            if msg.get("type") == "STATE_REPORT":
                                logger.info("[FIRMWARE REPORT] State: %s | Mode: %s | Remaining: %ss",
                                            msg.get("state"), msg.get("mode"), msg.get("time_remaining_s"))
                        except json.JSONDecodeError:
                            logger.debug("[RAW] %s", line)
                else:
                    time.sleep(0.1)
            except Exception:
                time.sleep(0.1)

    def send_command(self, mode: str, duration_s: int, parameters: Optional[Dict[str, Any]] = None) -> bool:
        mode_upper = mode.upper()
        if mode_upper not in VALID_MODES:
            logger.error("Unknown mode: %s. Valid modes: %s", mode, VALID_MODES)
            return False

        if parameters is None:
            parameters = {}

        cmd = {
            "mode": mode_upper if mode_upper != "NORMAL" else "IDLE",
            "duration_s": duration_s,
            "parameters": parameters,
            "timestamp": time.time(),
        }

        payload = (json.dumps(cmd) + "\n").encode("utf-8")
        logger.info("[AUDIT] Sending command to Attacker ESP32: %s", json.dumps(cmd))

        try:
            if self.ser and hasattr(self.ser, "write"):
                self.ser.write(payload)
        except Exception as exc:
            logger.error("Failed to write to serial: %s", exc)
            return False

        self.broadcast_state(mode_upper, duration_s, parameters)
        return True

    def broadcast_state(self, mode: str, duration_s: int, parameters: Dict[str, Any]):
        now = time.time()
        end_time = now + duration_s if duration_s > 0 else now + 86400.0

        state = {
            "active_state": mode,
            "attacker_id": self.attacker_id,
            "start_time": now,
            "end_time": end_time,
            "duration_s": duration_s,
            "parameters": parameters,
            "updated_at": now,
            "timestamp_str": datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S"),
        }

        self.current_mode = mode

        # Write atomic JSON file for dataset_generator
        try:
            tmp = self.ipc_file.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(state, f, indent=2)
            tmp.replace(self.ipc_file)
        except Exception as exc:
            logger.error("State file write failed: %s", exc)

        # Local UDP broadcast
        try:
            self.udp_sock.sendto(json.dumps(state).encode("utf-8"), ("127.0.0.1", self.udp_port))
        except Exception:
            pass

        logger.info("[STATE BROADCAST] Mode: %s (%ds)", mode, duration_s)

    def run_scripted_scenario(self, scenario_file: Path):
        if not scenario_file.exists():
            logger.error("Scenario file not found: %s", scenario_file)
            return

        with open(scenario_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        name = data.get("name", "Scenario")
        phases = data.get("phases", [])
        if "attacker_id" in data:
            self.attacker_id = int(data["attacker_id"])

        print(f"\n--- Running Scenario: {name} ({len(phases)} phases) ---")

        for i, phase in enumerate(phases, 1):
            if not self.running:
                break
            mode = phase.get("mode", "NORMAL")
            duration_s = int(phase.get("duration_s", 30))
            params = phase.get("parameters", {})
            desc = phase.get("description", "")

            print(f"\n[Phase {i}/{len(phases)}] {mode} for {duration_s}s - {desc}")
            self.send_command(mode, duration_s, params)

            start = time.time()
            while self.running and (time.time() - start < duration_s):
                remaining = int(duration_s - (time.time() - start))
                sys.stdout.write(f"\r  Running [{mode}] | Time left: {remaining:3d}s ")
                sys.stdout.flush()
                time.sleep(1.0)
            sys.stdout.write("\n")

        print("\nScenario completed.")
        self.stop_all()

    def run_interactive_menu(self):
        print("\n=== SecureMesh Attack Controller CLI ===")
        print(f"Attacker Node: Node {self.attacker_id} | Serial: {self.serial_port or 'Mock'}")
        print("1. Set NORMAL (Baseline)")
        print("2. Trigger DOS (Packet Flood)")
        print("3. Trigger REPLAY (Sequence Injection)")
        print("4. Trigger SPOOFING (MAC / Identity)")
        print("5. Trigger ROGUE_NODE (Unregistered Node)")
        print("6. Stop / Return to Idle")
        print("0. Exit")

        while self.running:
            try:
                choice = input("\nSelect option (0-6) > ").strip()
                if choice == "0":
                    break
                elif choice == "1":
                    dur = int(input("Duration in seconds [30]: ").strip() or "30")
                    self.send_command("NORMAL", dur)
                elif choice == "2":
                    dur = int(input("Duration in seconds [60]: ").strip() or "60")
                    rate = int(input("Packet rate ms [10]: ").strip() or "10")
                    self.send_command("DOS", dur, {"packet_rate_ms": rate})
                elif choice == "3":
                    dur = int(input("Duration in seconds [45]: ").strip() or "45")
                    self.send_command("REPLAY", dur, {"repeat_window_s": 5})
                elif choice == "4":
                    dur = int(input("Duration in seconds [45]: ").strip() or "45")
                    target = int(input("Target Node ID [2]: ").strip() or "2")
                    self.send_command("SPOOFING", dur, {"target_node_id": target})
                elif choice == "5":
                    dur = int(input("Duration in seconds [45]: ").strip() or "45")
                    rogue_id = int(input("Rogue Node ID [99]: ").strip() or "99")
                    self.send_command("ROGUE_NODE", dur, {"unauthorized_id": rogue_id})
                elif choice == "6":
                    self.stop_all()
                else:
                    print("Invalid choice.")
            except (ValueError, KeyboardInterrupt):
                break

        self.stop_all()

    def stop_all(self):
        logger.info("[AUDIT] Stopping simulation. Resetting to NORMAL.")
        try:
            if self.ser and hasattr(self.ser, "write"):
                self.ser.write(b'{"cmd":"STOP"}\n')
        except Exception:
            pass
        self.broadcast_state("NORMAL", duration_s=0, parameters={})

    def shutdown(self):
        self.running = False
        self.stop_all()
        if self.ser and hasattr(self.ser, "close"):
            try:
                self.ser.close()
            except Exception:
                pass
        try:
            self.udp_sock.close()
        except Exception:
            pass


def main():
    parser = argparse.ArgumentParser(description="Attack Controller CLI")
    parser.add_argument("--port", "-p", type=str, default=None, help="Serial port (e.g. COM10, /dev/ttyUSB1)")
    parser.add_argument("--baud", "-b", type=int, default=115200, help="Baudrate (default: 115200)")
    parser.add_argument("--mock", "-m", action="store_true", help="Run with mock firmware")
    parser.add_argument("--scenario", "-s", type=str, default=None, help="Path to scenario JSON file")
    parser.add_argument("--interactive", "-i", action="store_true", help="Launch interactive menu")
    parser.add_argument("--ipc-file", type=str, default=".ground_truth_state.json", help="Ground truth state file")
    parser.add_argument("--udp-port", type=int, default=9998, help="Local UDP broadcast port")
    parser.add_argument("--log-file", type=str, default="attack_controller.log", help="Audit log path")
    parser.add_argument("--attacker-id", type=int, default=4, help="Attacker Node ID (default: 4)")

    args = parser.parse_args()

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S"))
    logger.addHandler(console)
    logger.setLevel(logging.INFO)

    controller = AttackController(
        serial_port=args.port,
        baudrate=args.baud,
        mock_mode=args.mock,
        ipc_file=args.ipc_file,
        udp_port=args.udp_port,
        log_file=args.log_file,
        attacker_id=args.attacker_id,
    )

    def handle_exit(signum, frame):
        print("\nStopping...")
        controller.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)

    if args.scenario:
        controller.run_scripted_scenario(Path(args.scenario))
    elif args.interactive or not args.scenario:
        controller.run_interactive_menu()


if __name__ == "__main__":
    main()
