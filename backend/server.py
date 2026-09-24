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
import json
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
from .decision_engine.decision_rules import DecisionEngine, Verdict
from .decision_engine.recovery_controller import RecoveryController
from .telemetry import gateway_schema
from .telemetry.serial_reader import get_source
from .telemetry.telemetry_parser import PacketAggregator

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("securemesh.server")

REPO_ROOT = Path(__file__).resolve().parent.parent
DASHBOARD_DIR = REPO_ROOT / "dashboard"

BLOCKED_BROADCAST_INTERVAL = 0.25  # seconds; a flood is counted in full but only sampled to the UI


async def record_event(app: FastAPI, event_type: str, node_id, *, attack_type: Optional[str] = None,
                        confidence: Optional[float] = None, action: Optional[str] = None,
                        recovery_route: Optional[str] = None, status: str = "RESOLVED",
                        detail: Optional[str] = None) -> int:
    """Persist a security/incident event and tell every dashboard client."""
    timestamp = time.time()
    event_id = await app.state.db.insert_security_event({
        "timestamp": timestamp,
        "event_type": event_type,
        "node_id": str(node_id),
        "attack_type": attack_type,
        "confidence": confidence,
        "action": action,
        "recovery_route": recovery_route,
        "status": status,
        "detail": detail,
    })
    await manager.broadcast({
        "type": "security_event",
        "data": {
            "id": event_id, "timestamp": timestamp, "event_type": event_type,
            "node_id": str(node_id), "attack_type": attack_type, "confidence": confidence,
            "action": action, "detail": detail,
        },
    })
    return event_id


def sync_source(app: FastAPI) -> None:
    app.state.source.set_isolated(app.state.recovery.isolated)


async def _touch_node(app: FastAPI, node_id: str) -> None:
    # last_seen only needs ~1s resolution; writing it on every packet would
    # double the commit rate during a flood for no benefit.
    now = time.time()
    if now - app.state.node_touch.get(node_id, 0.0) >= 1.0:
        app.state.node_touch[node_id] = now
        await app.state.db.upsert_node(node_id)


def _packet_view(packet: dict, status: str, **extra) -> dict:
    """The dict the dashboard's packet inspector consumes, for packets that
    bypass the aggregator (outgoing TX lines and blocked traffic)."""
    rssi = packet.get("rssi") or None  # 0 means "no reception"
    view = {
        "timestamp": time.time(),
        "direction": packet.get("direction", "RX"),
        "source": str(packet["src"]),
        "destination": str(packet["dst"]),
        "receiver": packet.get("receiver"),
        "hop": packet.get("hop"),
        "action": packet.get("action"),
        "delivery": packet.get("delivery"),
        "packet_rate": 0.0,
        "packet_loss": None,
        "rssi": rssi,
        "rssi_instant": rssi,
        "sequence_number": packet.get("seq"),
        "type": packet.get("type", "DATA"),
        "ttl": packet.get("ttl"),
        "checksum": packet.get("checksum"),
        "payload": packet.get("payload"),
        "packet_status": status,
    }
    view.update(extra)
    return view


async def _apply_verdict(app: FastAPI, verdict: Verdict, prefix: str = "") -> None:
    """Isolate the offending node, record the incident, tell the dashboard."""
    node_id = int(verdict.node_id)
    recovery = app.state.recovery
    if node_id in recovery.isolated:
        return

    recovery.isolate(node_id)
    sync_source(app)
    await app.state.db.set_node_status(verdict.node_id, "ISOLATED")

    event_id = await record_event(
        app, "ATTACK_DETECTED", verdict.node_id,
        attack_type=verdict.attack_type, confidence=verdict.confidence,
        action="ISOLATE", recovery_route=json.dumps(recovery.status()),
        status="OPEN", detail=prefix + verdict.detail,
    )
    logger.warning("Security event #%s: %s on node %s (%s)",
                    event_id, verdict.attack_type, verdict.node_id, prefix + verdict.detail)
    await manager.broadcast({"type": "topology", "data": recovery.status()})


async def _handle_blocked(app: FastAPI, packet: dict) -> dict:
    """Traffic from/to an isolated node is dropped at the gateway. It is still
    counted and (sampled) shown so the dashboard can display the block."""
    src = packet["src"]
    counts = app.state.blocked_counts
    counts[src] = counts.get(src, 0) + 1
    dropped = _packet_view(packet, "BLOCKED", blocked_total=counts[src])
    now = time.time()
    if now - app.state.blocked_last_emit.get(src, 0.0) >= BLOCKED_BROADCAST_INTERVAL:
        app.state.blocked_last_emit[src] = now
        await manager.broadcast({"type": "telemetry", "data": dropped})
    return dropped


async def handle_packet(app: FastAPI, packet: dict) -> Optional[dict]:
    """An RX line (a packet as received): aggregate -> persist -> broadcast ->
    evaluate -> isolate + log on attack. Blocked if either end is isolated."""
    src, dst = packet["src"], packet["dst"]
    recovery = app.state.recovery
    if src in recovery.isolated or dst in recovery.isolated:
        return await _handle_blocked(app, packet)

    telemetry = app.state.aggregator.ingest(packet)
    if telemetry is None:
        return None

    await app.state.db.insert_telemetry(telemetry)
    await _touch_node(app, str(telemetry["source"]))
    if packet.get("receiver"):
        await _touch_node(app, str(packet["receiver"]))
    await manager.broadcast({"type": "telemetry", "data": telemetry})

    verdict = app.state.decision_engine.evaluate(telemetry)
    if verdict is not None:
        await _apply_verdict(app, verdict)
    return telemetry


async def handle_tx(app: FastAPI, packet: dict) -> dict:
    """A TX line (a packet a node sent). Display only: its `src` is the
    printing node even when relaying, so it must not feed sequence tracking."""
    status = "FAIL" if packet.get("delivery") == "FAIL" else "OK"
    view = _packet_view(packet, status)
    if packet.get("src"):
        await _touch_node(app, str(packet["src"]))
    await manager.broadcast({"type": "telemetry", "data": view})
    return view


async def handle_peer_stats(app: FastAPI, stats: dict) -> dict:
    """A TELEMETRY line: one peer's statistics over the reporter's last second."""
    stats = {**stats, "timestamp": time.time()}
    await manager.broadcast({"type": "peer_telemetry", "data": stats})

    if stats.get("reporter"):
        await _touch_node(app, str(stats["reporter"]))

    if stats["peer"] not in app.state.recovery.isolated:
        verdict = app.state.decision_engine.evaluate_peer(stats["peer"], stats["reporter"], stats["rate"])
        if verdict is not None:
            await _apply_verdict(app, verdict)
    return stats


async def handle_alert(app: FastAPI, alert: dict) -> dict:
    """An ALERT line: a node's own detection result. Mirror it in the gateway's
    model (isolate the attacker) so the topology and logs reflect it."""
    detected_by = alert["detected_by"]
    who = f"N{detected_by}" if detected_by is not None else "a mesh node"
    if alert["action"] == "ISOLATED":
        await _apply_verdict(
            app,
            Verdict(str(alert["attacker"]), alert["threat"], None, f"threat classified on-device by {who}"),
            prefix="On-device detection: ",
        )
    return alert


async def handle_message(app: FastAPI, msg: dict) -> Optional[dict]:
    """Single entry point for every JSON line from the gateway, whether it
    arrives through the background feed or POST /api/telemetry. Returns None
    for lines that are not part of the schema."""
    if not isinstance(msg, dict):
        return None

    kind = gateway_schema.classify(msg)
    logger.debug("Serial line: kind=%s msg=%s", kind, msg)
    if kind in ("RX", "TX"):
        packet = gateway_schema.to_packet(msg, kind)
        if packet is None:
            return None
        return await (handle_packet(app, packet) if kind == "RX" else handle_tx(app, packet))
    if kind == "TELEMETRY":
        stats = gateway_schema.to_peer_stats(msg)
        return await handle_peer_stats(app, stats) if stats else None
    if kind == "ALERT":
        alert = gateway_schema.to_alert(msg)
        return await handle_alert(app, alert) if alert else None
    return None


async def _ingest_loop(app: FastAPI) -> None:
    try:
        while True:
            try:
                async for message in app.state.source.packets():
                    try:
                        await handle_message(app, message)
                    except Exception:
                        logger.exception("Failed to process message: %s", message)
                return  # the source ended on its own
            except Exception:
                # A source failure (e.g. the gateway's USB cable was unplugged)
                # must not silently end ingestion for the rest of the process.
                logger.exception("Telemetry source failed; restarting it in 2s")
                await asyncio.sleep(2)
    except asyncio.CancelledError:
        pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.db = DatabaseEngine(config.DB_PATH)
    await app.state.db.init_db()
    # Clear the old data so graph and logs start fresh on every boot
    await app.state.db._conn.execute("DELETE FROM security_events")
    await app.state.db._conn.execute("DELETE FROM telemetry")
    await app.state.db._conn.execute("DELETE FROM nodes")
    await app.state.db._conn.commit()

    for node_id in config.NODE_IDS:
        await app.state.db.upsert_node(str(node_id), status="HEALTHY")

    app.state.recovery = RecoveryController(config.NODE_IDS)
    app.state.decision_engine = DecisionEngine(
        dos_threshold=config.DOS_PACKET_RATE_THRESHOLD,
        rssi_jump_dbm=config.RSSI_SPOOF_JUMP_DBM,
        known_nodes=set(config.NODE_IDS),
        replay_dup_threshold=config.REPLAY_DUPLICATE_THRESHOLD,
        initial_ttl=config.INITIAL_TTL,
    )
    app.state.aggregator = PacketAggregator(config.TELEMETRY_WINDOW_SECONDS)
    app.state.source = get_source()
    app.state.node_touch = {}
    app.state.blocked_counts = {}
    app.state.blocked_last_emit = {}
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


class RevalidatingStaticFiles(StaticFiles):
    """Dashboard files change with every update; make browsers revalidate
    (cheap 304 via ETag) instead of serving stale scripts and styles."""

    async def get_response(self, path, scope):
        response = await super().get_response(path, scope)
        response.headers["Cache-Control"] = "no-cache"
        return response


if DASHBOARD_DIR.exists():
    app.mount("/", RevalidatingStaticFiles(directory=str(DASHBOARD_DIR), html=True), name="dashboard")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.server:app", host="0.0.0.0", port=8000, reload=True)
