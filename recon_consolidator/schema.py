import sqlite3


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS subdomains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fqdn TEXT UNIQUE NOT NULL,
    source TEXT,
    first_seen TEXT DEFAULT CURRENT_TIMESTAMP,
    last_seen TEXT DEFAULT CURRENT_TIMESTAMP,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS dns_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subdomain_id INTEGER NOT NULL REFERENCES subdomains(id),
    record_type TEXT NOT NULL,
    value TEXT NOT NULL,
    ttl INTEGER,
    resolved_at TEXT DEFAULT CURRENT_TIMESTAMP,
    source TEXT,
    notes TEXT,
    UNIQUE(subdomain_id, record_type, value)
);

CREATE TABLE IF NOT EXISTS whois_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    query TEXT NOT NULL,
    netrange TEXT,
    cidr TEXT,
    registrant_org TEXT,
    registrar TEXT,
    asn TEXT,
    country TEXT,
    raw_text TEXT,
    queried_at TEXT DEFAULT CURRENT_TIMESTAMP,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS hosting (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT UNIQUE NOT NULL,
    provider TEXT,
    cdn TEXT,
    region TEXT,
    asn TEXT,
    classification TEXT,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT DEFAULT 'tcp',
    state TEXT,
    service TEXT,
    banner TEXT,
    version TEXT,
    scan_profile TEXT,
    scanned_at TEXT DEFAULT CURRENT_TIMESTAMP,
    notes TEXT,
    UNIQUE(ip, port, protocol, scan_profile)
);

CREATE TABLE IF NOT EXISTS raw_imports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    file_hash TEXT NOT NULL,
    tool TEXT,
    stage TEXT,
    row_count INTEGER,
    ingested_at TEXT DEFAULT CURRENT_TIMESTAMP,
    notes TEXT,
    UNIQUE(file_hash)
);
"""


def init_db(db_path):
    """Create the database with the full schema. Idempotent."""
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA_SQL)
    conn.close()
