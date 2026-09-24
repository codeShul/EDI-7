"""Async SQLite persistence layer for nodes, telemetry, security events, and routes."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

import aiosqlite

SCHEMA_PATH = Path(__file__).parent / "schema.sql"


class DatabaseEngine:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._conn: Optional[aiosqlite.Connection] = None

    async def init_db(self) -> None:
        self._conn = await aiosqlite.connect(self.db_path)
        self._conn.row_factory = aiosqlite.Row
        # WAL + NORMAL keeps per-packet commits cheap so a packet flood is not
        # throttled by fsyncs before the decision engine can see it.
        await self._conn.execute("PRAGMA journal_mode=WAL")
        await self._conn.execute("PRAGMA synchronous=NORMAL")
        await self._conn.executescript(SCHEMA_PATH.read_text())
        cur = await self._conn.execute("PRAGMA table_info(security_events)")
        columns = {row["name"] for row in await cur.fetchall()}
        if "detail" not in columns:  # database created before the column existed
            await self._conn.execute("ALTER TABLE security_events ADD COLUMN detail TEXT")
        await self._conn.commit()

    async def close(self) -> None:
        if self._conn is not None:
            await self._conn.close()

    # ---- nodes ---------------------------------------------------------
    async def upsert_node(self, node_id: str, mac_address: Optional[str] = None,
                           status: Optional[str] = None) -> None:
        cur = await self._conn.execute("SELECT status FROM nodes WHERE node_id = ?", (node_id,))
        row = await cur.fetchone()
        now = time.time()
        if row is None:
            await self._conn.execute(
                "INSERT INTO nodes (node_id, mac_address, status, last_seen) VALUES (?, ?, ?, ?)",
                (node_id, mac_address, status or "HEALTHY", now),
            )
        else:
            new_status = status if status is not None else row["status"]
            await self._conn.execute(
                "UPDATE nodes SET last_seen = ?, status = ?, "
                "mac_address = COALESCE(?, mac_address) WHERE node_id = ?",
                (now, new_status, mac_address, node_id),
            )
        await self._conn.commit()

    async def set_node_status(self, node_id: str, status: str) -> None:
        await self._conn.execute("UPDATE nodes SET status = ? WHERE node_id = ?", (status, node_id))
        await self._conn.commit()

    async def set_all_nodes_status(self, status: str) -> None:
        await self._conn.execute("UPDATE nodes SET status = ?", (status,))
        await self._conn.commit()

    async def get_nodes(self) -> list[dict]:
        cur = await self._conn.execute(
            "SELECT node_id, mac_address, status, last_seen FROM nodes ORDER BY CAST(node_id AS INTEGER)"
        )
        return [dict(r) for r in await cur.fetchall()]

    # ---- telemetry -------------------------------------------------------
    async def insert_telemetry(self, record: dict) -> None:
        await self._conn.execute(
            """INSERT INTO telemetry
               (timestamp, source, destination, packet_rate, packet_loss, latency,
                rssi, retransmissions, sequence_number, duplicate_count)
               VALUES (:timestamp, :source, :destination, :packet_rate, :packet_loss, :latency,
                       :rssi, :retransmissions, :sequence_number, :duplicate_count)""",
            record,
        )
        await self._conn.commit()

    async def get_recent_telemetry(self, limit: int = 100) -> list[dict]:
        cur = await self._conn.execute("SELECT * FROM telemetry ORDER BY id DESC LIMIT ?", (limit,))
        return [dict(r) for r in await cur.fetchall()]

    # ---- security events -------------------------------------------------
    async def insert_security_event(self, event: dict) -> int:
        event = {"detail": None, **event}
        cur = await self._conn.execute(
            """INSERT INTO security_events
               (timestamp, event_type, node_id, attack_type, confidence, action,
                recovery_route, status, detail)
               VALUES (:timestamp, :event_type, :node_id, :attack_type, :confidence,
                       :action, :recovery_route, :status, :detail)""",
            event,
        )
        await self._conn.commit()
        return cur.lastrowid

    async def get_security_events(self, limit: int = 100) -> list[dict]:
        cur = await self._conn.execute(
            "SELECT * FROM security_events ORDER BY id DESC LIMIT ?", (limit,)
        )
        return [dict(r) for r in await cur.fetchall()]

    # ---- routes ------------------------------------------------------------
    async def record_route(self, source: str, destination: str,
                            path: Optional[list], status: str) -> None:
        await self._conn.execute(
            "INSERT INTO routes (source, destination, path, status, updated_at) VALUES (?, ?, ?, ?, ?)",
            (source, destination, json.dumps(path) if path else None, status, time.time()),
        )
        await self._conn.commit()

    async def get_routes(self, limit: int = 50) -> list[dict]:
        cur = await self._conn.execute("SELECT * FROM routes ORDER BY id DESC LIMIT ?", (limit,))
        return [dict(r) for r in await cur.fetchall()]
