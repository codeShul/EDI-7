"""REST API for the SecureMesh AI gateway.

Endpoints follow docs/project.md.txt section 20 (`GET /api/nodes`,
`/api/topology`, `/api/telemetry`, `/api/events`, `/api/routes`, `/api/status`,
`POST /api/telemetry`, `/api/control/isolate`, `/api/control/restore`), plus
`/api/simulate/*` for the demo controls (attack injection is only available
while the built-in traffic simulator is the active data source).
"""
from __future__ import annotations

import json
from typing import Literal, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from ..telemetry.serial_reader import SimulatedSource

router = APIRouter()


class TelemetryIn(BaseModel):
    src: int
    dst: int
    seq: Optional[int] = None
    type: Optional[str] = "DATA"
    ttl: Optional[int] = None
    rssi: Optional[int] = None
    checksum: Optional[int] = None
    payload: Optional[str] = None


class ControlRequest(BaseModel):
    node_id: int


class AttackRequest(BaseModel):
    attack: Literal["DOS", "REPLAY", "SPOOFING"]
    node_id: int


class SimulatorToggle(BaseModel):
    enabled: bool


def _source_mode(app) -> str:
    source = app.state.source
    if isinstance(source, SimulatedSource):
        return "SIMULATED" if source.enabled else "EXTERNAL"
    return "SERIAL"


def _require_simulator(app) -> SimulatedSource:
    source = app.state.source
    if not isinstance(source, SimulatedSource):
        raise HTTPException(status_code=409, detail="Only available while the traffic simulator is the data source")
    return source


def _require_known_node(app, node_id: int) -> None:
    if node_id not in app.state.recovery.all_nodes():
        raise HTTPException(status_code=404, detail=f"Unknown node {node_id}")


@router.get("/status")
async def get_status(request: Request):
    db = request.app.state.db
    recovery = request.app.state.recovery
    nodes = await db.get_nodes()
    suspicious = sum(1 for n in nodes if n["status"] == "SUSPICIOUS")
    isolated = sum(1 for n in nodes if n["status"] == "ISOLATED")
    mode = _source_mode(request.app)
    return {
        "network_status": "UNDER_ATTACK" if (isolated or suspicious) else "HEALTHY",
        "total_nodes": len(nodes),
        "active_nodes": len(nodes) - isolated,
        "suspicious_nodes": suspicious,
        "isolated_nodes": isolated,
        "active_links": recovery.graph.number_of_edges(),
        "total_links": recovery.total_links(),
        "mode": mode,
        "attack_simulation": mode == "SIMULATED",
    }


@router.get("/nodes")
async def get_nodes(request: Request):
    return await request.app.state.db.get_nodes()


@router.get("/topology")
async def get_topology(request: Request):
    recovery = request.app.state.recovery
    nodes = recovery.all_nodes()
    links = []
    for i, a in enumerate(nodes):
        for b in nodes[i + 1:]:
            if recovery.graph.has_edge(a, b):
                status = "ACTIVE"
            elif a in recovery.isolated or b in recovery.isolated:
                status = "SEVERED"
            else:
                status = "DOWN"
            links.append({"source": a, "destination": b, "status": status})
    return {"nodes": nodes, "isolated": sorted(recovery.isolated), "links": links}


@router.get("/telemetry")
async def get_telemetry(request: Request, limit: int = 100):
    return await request.app.state.db.get_recent_telemetry(limit)


@router.get("/events")
async def get_events(request: Request, limit: int = 100):
    return await request.app.state.db.get_security_events(limit)


@router.get("/routes")
async def get_routes(request: Request):
    return request.app.state.recovery.all_routes()


@router.post("/telemetry")
async def post_telemetry(payload: TelemetryIn, request: Request):
    """Lets a gateway push a single raw packet over HTTP instead of USB
    serial (e.g. the dashboard's WebSerial bridge). Runs through the exact
    same ingestion path (aggregation, decision engine, DB, WebSocket
    broadcast) as the background feed."""
    from ..server import handle_packet  # deferred import avoids a circular import at load time

    telemetry = await handle_packet(request.app, payload.model_dump())
    if telemetry is None:
        raise HTTPException(status_code=400, detail="Packet missing src/dst")
    return telemetry


async def _apply_control_action(request: Request, node_id: int, new_status: str,
                                 action: str, event_type: str, detail: str) -> dict:
    from ..server import record_event, sync_source  # deferred import (see post_telemetry)
    from .websocket_hub import manager

    app = request.app
    _require_known_node(app, node_id)

    if action == "ISOLATE":
        app.state.recovery.isolate(node_id)
    else:
        app.state.recovery.restore(node_id)
    sync_source(app)

    await app.state.db.set_node_status(str(node_id), new_status)
    event_id = await record_event(
        app, event_type, node_id, action=action, status="RESOLVED", detail=detail,
        recovery_route=json.dumps(app.state.recovery.status()),
    )
    await manager.broadcast({"type": "topology", "data": app.state.recovery.status()})
    return {"ok": True, "event_id": event_id, "isolated": sorted(app.state.recovery.isolated)}


@router.post("/control/isolate")
async def isolate_node(payload: ControlRequest, request: Request):
    return await _apply_control_action(request, payload.node_id, "ISOLATED", "ISOLATE",
                                        "MANUAL_ISOLATE", "Isolated manually from the dashboard")


@router.post("/control/restore")
async def restore_node(payload: ControlRequest, request: Request):
    return await _apply_control_action(request, payload.node_id, "HEALTHY", "RESTORE",
                                        "MANUAL_RESTORE", "Restored manually from the dashboard")


# ---- demo / simulation controls -------------------------------------------------
@router.post("/simulate/attack")
async def simulate_attack(payload: AttackRequest, request: Request):
    from ..server import record_event  # deferred import (see post_telemetry)

    app = request.app
    source = _require_simulator(app)
    if not source.enabled:
        raise HTTPException(status_code=409, detail="Simulator is paused while an external gateway feeds data")
    _require_known_node(app, payload.node_id)
    if payload.node_id in app.state.recovery.isolated:
        raise HTTPException(status_code=409, detail=f"Node {payload.node_id} is isolated; restore it first")

    try:
        description = source.start_attack(payload.attack, payload.node_id)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))

    await record_event(app, "SIM_ATTACK", payload.node_id, attack_type=payload.attack,
                        action="INJECT", status="INFO", detail=description)
    return {"ok": True, "detail": description}


@router.post("/simulate/reset")
async def simulate_reset(request: Request):
    from ..server import record_event, sync_source  # deferred import (see post_telemetry)
    from .websocket_hub import manager

    app = request.app
    source = _require_simulator(app)
    source.reset()
    for node_id in list(app.state.recovery.isolated):
        app.state.recovery.restore(node_id)
    sync_source(app)
    app.state.blocked_counts.clear()
    await app.state.db.set_all_nodes_status("HEALTHY")

    await record_event(app, "SIM_RESET", 0, action="RESET", status="INFO",
                        detail="All attacks stopped and every node restored to the mesh")
    await manager.broadcast({"type": "topology", "data": app.state.recovery.status()})
    return {"ok": True}


@router.post("/simulate/enabled")
async def simulate_enabled(payload: SimulatorToggle, request: Request):
    """Pause the built-in simulator while an external gateway (e.g. the
    dashboard's WebSerial bridge) is feeding real packets, and resume it after."""
    from ..server import record_event  # deferred import (see post_telemetry)

    app = request.app
    source = _require_simulator(app)
    source.enabled = payload.enabled
    if not payload.enabled:
        source.reset()
    await record_event(app, "SOURCE_CHANGED", 0, action="SOURCE", status="INFO",
                        detail="Simulator resumed" if payload.enabled
                        else "Simulator paused; external gateway is feeding packets")
    return {"ok": True, "mode": _source_mode(app)}
