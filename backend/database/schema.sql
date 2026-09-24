-- SecureMesh AI gateway database schema (SQLite).
-- Matches the conceptual schema in docs/project.md.txt and docs/myrole.txt.

CREATE TABLE IF NOT EXISTS nodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id TEXT UNIQUE NOT NULL,
    mac_address TEXT,
    status TEXT NOT NULL DEFAULT 'HEALTHY',
    last_seen REAL
);

CREATE TABLE IF NOT EXISTS telemetry (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    source TEXT NOT NULL,
    destination TEXT NOT NULL,
    packet_rate REAL,
    packet_loss REAL,
    latency REAL,
    rssi REAL,
    retransmissions INTEGER,
    sequence_number INTEGER,
    duplicate_count INTEGER
);

CREATE INDEX IF NOT EXISTS idx_telemetry_timestamp ON telemetry(timestamp);
CREATE INDEX IF NOT EXISTS idx_telemetry_link ON telemetry(source, destination);

CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    event_type TEXT NOT NULL,
    node_id TEXT NOT NULL,
    attack_type TEXT,
    confidence REAL,
    action TEXT,
    recovery_route TEXT,
    status TEXT NOT NULL DEFAULT 'OPEN',
    detail TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp);

CREATE TABLE IF NOT EXISTS routes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    destination TEXT NOT NULL,
    path TEXT,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    updated_at REAL NOT NULL
);
