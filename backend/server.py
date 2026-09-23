"""SecureMesh AI Gateway — FastAPI application entrypoint.

Wires together telemetry ingestion (serial gateway or built-in simulator),
SQLite persistence, the rule-based decision engine, graph-based route
recovery, and the WebSocket hub that pushes live updates to the dashboard.

Run with:
    uvicorn backend.server:app --reload
from the repository root (with the `backend/` requirements installed).
"""
from __future__ import annotations

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles

from . import config
from .api import routes_api
from .api.websocket_hub import manager
from .database.db_manager import DatabaseEngine
from .decision_engine.decision_rules import DecisionEngine
from .decision_engine.recovery_controller import RecoveryController
from .telemetry.serial_reader import get_source
from .telemetry.telemetry_parser import PacketAggregator

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("securemesh.server")

REPO_ROOT = Path(__file__).resolve().parent.parent
DASHBOARD_DIR = REPO_ROOT / "dashboard"


async def handle_packet(app: FastAPI, packet: dict) -> Optional[dict]:
    """Single entry point for every raw mesh packet, whether it arrives via
    the background serial/simulated feed or the HTTP `/api/telemetry` route:
    aggregate -> persist -> broadcast -> evaluate -> isolate + log on attack."""
    telemetry = app.state.aggregator.ingest(packet)
    if telemetry is None:
        return None

    await app.state.db.insert_telemetry(telemetry)
    await app.state.db.upsert_node(telemetry["source"])
    await manager.broadcast({"type": "telemetry", "data": telemetry})

    verdict = app.state.decision_engine.evaluate(telemetry)
    if verdict is not None:
        node_id = int(verdict.node_id)
        app.state.recovery.isolate(node_id)
        await app.state.db.set_node_status(verdict.node_id, "ISOLATED")

        affected_routes = [r for r in app.state.recovery.all_routes()
                            if node_id in (r["source"], r["destination"])]

        event_id = await app.state.db.insert_security_event({
            "timestamp": time.time(),
            "event_type": "ATTACK_DETECTED",
            "node_id": verdict.node_id,
            "attack_type": verdict.attack_type,
            "confidence": verdict.confidence,
            "action": "ISOLATE",
            "recovery_route": str(affected_routes),
            "status": "OPEN",
        })
        logger.warning("Security event #%s: %s on node %s (%s)",
                        event_id, verdict.attack_type, verdict.node_id, verdict.detail)

        await manager.broadcast({
            "type": "security_event",
            "data": {
                "id": event_id,
                "timestamp": time.time(),
                "node_id": verdict.node_id,
                "attack_type": verdict.attack_type,
                "confidence": verdict.confidence,
                "detail": verdict.detail,
                "action": "ISOLATE",
            },
        })
        await manager.broadcast({"type": "topology", "data": app.state.recovery.status()})

    return telemetry


async def _ingest_loop(app: FastAPI) -> None:
    source = get_source()
    try:
        async for packet in source.packets():
            try:
                await handle_packet(app, packet)
            except Exception:
                logger.exception("Failed to process packet: %s", packet)
    except asyncio.CancelledError:
        pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.db = DatabaseEngine(config.DB_PATH)
    await app.state.db.init_db()
    for node_id in config.NODE_IDS:
        await app.state.db.upsert_node(str(node_id), status="HEALTHY")

    app.state.recovery = RecoveryController(config.NODE_IDS)
    app.state.decision_engine = DecisionEngine(
        dos_threshold=config.DOS_PACKET_RATE_THRESHOLD,
        rssi_jump_dbm=config.RSSI_SPOOF_JUMP_DBM,
        known_nodes=set(config.NODE_IDS),
    )
    app.state.aggregator = PacketAggregator(config.TELEMETRY_WINDOW_SECONDS)
    app.state.ingest_task = asyncio.create_task(_ingest_loop(app))

    logger.info("SecureMesh AI gateway ready — nodes=%s simulate=%s", config.NODE_IDS, config.SIMULATE)
    yield

    app.state.ingest_task.cancel()
    await app.state.db.close()


app = FastAPI(title="SecureMesh AI Gateway", lifespan=lifespan)
app.include_router(routes_api.router, prefix="/api")


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


if DASHBOARD_DIR.exists():
    app.mount("/", StaticFiles(directory=str(DASHBOARD_DIR), html=True), name="dashboard")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.server:app", host="0.0.0.0", port=8000, reload=True)
