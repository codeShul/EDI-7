"""Adapter for the gateway ESP32's serial JSON (docs/serial_json_schema.md).

The firmware prints ONE flat object per event, always with the same keys
(firmware/mesh_node/mesh_node.ino `print_json`):

    {"type":"RX","src":1,"dst":3,"seq":105,"pkt_type":"DATA","ttl":4,"rssi":-52,
     "receiver":3,"hop":0,"action":"CONSUMED","delivery":"","rate":0,
     "avg_rssi":0,"drops":0,"threat":""}

`type` is the event category; the packet type is `pkt_type`:

    RX         a packet as received. src = original sender, dst = final target,
               receiver = the node that printed the line.
    TX         a packet this node sent. NOTE src is the *printing* node even
               when it is relaying (seq is still the original sender's), and
               `hop` is the physical next hop. Display only: it must never
               feed per-sender sequence tracking.
    TELEMETRY  per-peer 1 s statistics: src = peer, receiver = reporter.
    ALERT      on-device detection result (threat + action ISOLATED).

Lines from the earlier schema draft are still understood: a bare packet line
with `type` = DATA/HEARTBEAT/ROUTE_SYNC counts as RX, `telemetry: true` as
TELEMETRY, and `attacker` / `detected_by` as ALERT fields.
"""
from __future__ import annotations

from typing import Optional

PACKET_TYPES = ("DATA", "HEARTBEAT", "ROUTE_SYNC")
KINDS = ("RX", "TX", "TELEMETRY", "ALERT")


def _int(value) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _text(value) -> Optional[str]:
    return value if isinstance(value, str) and value else None


def classify(msg: dict) -> Optional[str]:
    """RX, TX, TELEMETRY, ALERT, or None for anything we do not understand."""
    kind = msg.get("type")
    if kind in KINDS:
        return kind
    if msg.get("telemetry") is True:
        return "TELEMETRY"
    if "src" in msg and "dst" in msg and (kind is None or kind in PACKET_TYPES):
        return "RX"
    return None


def to_packet(msg: dict, kind: str) -> Optional[dict]:
    """Normalise an RX/TX line into the packet dict used by the pipeline."""
    src, dst = _int(msg.get("src")), _int(msg.get("dst"))
    if src is None or dst is None:
        return None

    pkt_type = _text(msg.get("pkt_type"))
    if pkt_type is None and msg.get("type") in PACKET_TYPES:
        pkt_type = msg["type"]

    return {
        "direction": kind,
        "src": src,
        "dst": dst,
        "seq": _int(msg.get("seq")),
        "type": pkt_type or "DATA",
        "ttl": _int(msg.get("ttl")),
        "rssi": _int(msg.get("rssi")),
        "receiver": _int(msg.get("receiver")),
        "hop": _int(msg.get("hop")) or None,      # firmware prints 0 for "none"
        "action": _text(msg.get("action")),
        "delivery": _text(msg.get("delivery")),
        "checksum": _int(msg.get("checksum")),
        "payload": _text(msg.get("payload")),
    }


def to_peer_stats(msg: dict) -> Optional[dict]:
    """TELEMETRY line -> {peer, reporter, rate, avg_rssi, drops}."""
    peer = _int(msg.get("src", msg.get("target")))
    reporter = _int(msg.get("receiver", msg.get("reporter", msg.get("dst"))))
    if peer is None or reporter is None:
        return None
    return {
        "peer": peer,
        "reporter": reporter,
        "rate": _int(msg.get("rate")) or 0,
        "avg_rssi": _int(msg.get("avg_rssi")) or None,   # 0 means "nothing received"
        "drops": _int(msg.get("drops")) or 0,
    }


def to_alert(msg: dict) -> Optional[dict]:
    """ALERT line -> {attacker, detected_by, threat, action}."""
    attacker = _int(msg.get("attacker", msg.get("src")))
    if attacker is None:
        return None
    return {
        "attacker": attacker,
        "detected_by": _int(msg.get("detected_by", msg.get("receiver"))),
        "threat": (_text(msg.get("threat")) or "UNKNOWN").upper(),
        "action": _text(msg.get("action")) or "ISOLATED",
    }
