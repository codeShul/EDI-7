"""Central runtime configuration for the SecureMesh AI gateway backend.

Every value can be overridden via environment variable so the same code runs
against a real ESP32 gateway (SECUREMESH_SIMULATE=0) or the built-in traffic
simulator (the default, useful before hardware/firmware is ready).
"""
import os
from pathlib import Path

NODE_COUNT = int(os.getenv("SECUREMESH_NODE_COUNT", "5"))
NODE_IDS = list(range(1, NODE_COUNT + 1))

SIMULATE = os.getenv("SECUREMESH_SIMULATE", "1") != "0"
SERIAL_PORT = os.getenv("SECUREMESH_SERIAL_PORT", "COM9")
SERIAL_BAUDRATE = int(os.getenv("SECUREMESH_BAUDRATE", "115200"))

DB_PATH = os.getenv("SECUREMESH_DB_PATH", str(Path(__file__).parent / "securemesh.db"))

TELEMETRY_WINDOW_SECONDS = float(os.getenv("SECUREMESH_WINDOW_SECONDS", "2.0"))
DOS_PACKET_RATE_THRESHOLD = float(os.getenv("SECUREMESH_DOS_THRESHOLD", "20.0"))
RSSI_SPOOF_JUMP_DBM = float(os.getenv("SECUREMESH_RSSI_JUMP_DBM", "15.0"))
REPLAY_DUPLICATE_THRESHOLD = int(os.getenv("SECUREMESH_REPLAY_DUPLICATES", "3"))
