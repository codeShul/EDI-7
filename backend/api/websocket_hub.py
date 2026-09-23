"""Broadcast hub pushing live telemetry, security events, and topology
changes to every connected dashboard client over a single shared WebSocket."""
from __future__ import annotations

import json
import logging

from fastapi import WebSocket

logger = logging.getLogger("securemesh.ws")


class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active:
            self.active.remove(websocket)

    async def broadcast(self, message: dict) -> None:
        payload = json.dumps(message, default=str)
        stale = []
        for websocket in self.active:
            try:
                await websocket.send_text(payload)
            except Exception:
                stale.append(websocket)
        for websocket in stale:
            self.disconnect(websocket)


manager = ConnectionManager()
