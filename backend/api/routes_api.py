"""REST API for the SecureMesh AI gateway.

Endpoints follow docs/project.md.txt section 20 (`GET /api/nodes`,
`/api/topology`, `/api/telemetry`, `/api/events`, `/api/routes`, `/api/status`,
`POST /api/telemetry`, `/api/control/isolate`, `/api/control/restore`).
"""
from __future__ import annotations

import time
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from .websocket_hub import manager

router = APIRouter()


class TelemetryIn(BaseModel):
    src: int
    dst: int
    seq: Optional[int] = None
    type: Optional[str] = "DATA"
    ttl: Optional[int] = None
    rssi: Optional[int] = None


class ControlRequest(BaseModel):
    node_id: int


@router.get("/status")
async def get_status(request: Request):
    db = request.app.state.db
    recovery = request.app.state.recovery
    nodes = await db.get_nodes()
    suspicious = sum(1 for n in nodes if n["status"] == "SUSPICIOUS")
    isolated = sum(1 for n in nodes if n["status"] == "ISOLATED")
    return {
        "network_status": "UNDER_ATTACK" if (isolated or suspicious) else "HEALTHY",
        "total_nodes": len(nodes),
        "active_nodes": len(nodes) - isolated,
        "suspicious_nodes": suspicious,
        "isolated_nodes": isolated,
        "active_links": recovery.graph.number_of_edges(),
        "total_links": recovery.total_links(),
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
    serial. Runs through the exact same ingestion path (aggregation,
    decision engine, DB, WebSocket broadcast) as the background feed."""
    from ..server import handle_packet  # deferred import avoids a circular import at load time

    telemetry = await handle_packet(request.app, payload.model_dump())
    if telemetry is None:
        raise HTTPException(status_code=400, detail="Packet missing src/dst")
    return telemetry


async def _apply_control_action(request: Request, node_id: int, new_status: str,
                                 action: str, event_type: str) -> dict:
    app = request.app
    if node_id not in app.state.recovery.all_nodes():
        raise HTTPException(status_code=404, detail=f"Unknown node {node_id}")

    if action == "ISOLATE":
        app.state.recovery.isolate(node_id)
    else:
        app.state.recovery.restore(node_id)

    await app.state.db.set_node_status(str(node_id), new_status)
    event_id = await app.state.db.insert_security_event({
        "timestamp": time.time(),
        "event_type": event_type,
        "node_id": str(node_id),
        "attack_type": None,
        "confidence": None,
        "action": action,
        "recovery_route": None,
        "status": "RESOLVED",
    })
    await manager.broadcast({"type": "topology", "data": app.state.recovery.status()})
    return {"ok": True, "event_id": event_id, "isolated": sorted(app.state.recovery.isolated)}


@router.post("/control/isolate")
async def isolate_node(payload: ControlRequest, request: Request):
    return await _apply_control_action(request, payload.node_id, "ISOLATED", "ISOLATE", "MANUAL_ISOLATE")


@router.post("/control/restore")
async def restore_node(payload: ControlRequest, request: Request):
    return await _apply_control_action(request, payload.node_id, "HEALTHY", "RESTORE", "MANUAL_RESTORE")
