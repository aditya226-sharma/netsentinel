"""Database models for NetSentinel.

Contains SQL table definitions and dataclass models for all database entities.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# SQL Table Definitions
# ---------------------------------------------------------------------------

CREATE_DEVICES_TABLE = """
CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    mac TEXT NOT NULL UNIQUE,
    ip TEXT,
    hostname TEXT,
    vendor TEXT,
    os_fingerprint TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac);
CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip);
CREATE INDEX IF NOT EXISTS idx_devices_active ON devices(is_active);
"""

CREATE_SESSIONS_TABLE = """
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER NOT NULL,
    dst_port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    packets INTEGER NOT NULL DEFAULT 0,
    bytes INTEGER NOT NULL DEFAULT 0,
    start_time TEXT NOT NULL,
    end_time TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_src_ip ON sessions(src_ip);
CREATE INDEX IF NOT EXISTS idx_sessions_dst_ip ON sessions(dst_ip);
CREATE INDEX IF NOT EXISTS idx_sessions_protocol ON sessions(protocol);
CREATE INDEX IF NOT EXISTS idx_sessions_start ON sessions(start_time);
"""

CREATE_DNS_LOGS_TABLE = """
CREATE TABLE IF NOT EXISTS dns_logs (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    query_name TEXT NOT NULL,
    query_type TEXT,
    response_code TEXT,
    response_ips TEXT,
    ttl INTEGER
);
CREATE INDEX IF NOT EXISTS idx_dns_logs_timestamp ON dns_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_dns_logs_src_ip ON dns_logs(src_ip);
CREATE INDEX IF NOT EXISTS idx_dns_logs_query_name ON dns_logs(query_name);
"""

CREATE_HTTP_METADATA_TABLE = """
CREATE TABLE IF NOT EXISTS http_metadata (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    method TEXT,
    host TEXT,
    uri TEXT,
    status_code INTEGER,
    content_type TEXT,
    user_agent TEXT
);
CREATE INDEX IF NOT EXISTS idx_http_timestamp ON http_metadata(timestamp);
CREATE INDEX IF NOT EXISTS idx_http_src_ip ON http_metadata(src_ip);
CREATE INDEX IF NOT EXISTS idx_http_host ON http_metadata(host);
CREATE INDEX IF NOT EXISTS idx_http_status ON http_metadata(status_code);
"""

CREATE_TLS_METADATA_TABLE = """
CREATE TABLE IF NOT EXISTS tls_metadata (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    sni TEXT,
    issuer TEXT,
    subject TEXT,
    serial TEXT,
    not_before TEXT,
    not_after TEXT,
    version TEXT,
    cipher TEXT
);
CREATE INDEX IF NOT EXISTS idx_tls_timestamp ON tls_metadata(timestamp);
CREATE INDEX IF NOT EXISTS idx_tls_src_ip ON tls_metadata(src_ip);
CREATE INDEX IF NOT EXISTS idx_tls_sni ON tls_metadata(sni);
"""

CREATE_ALERTS_TABLE = """
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    severity TEXT NOT NULL,
    name TEXT NOT NULL,
    message TEXT NOT NULL,
    source_ip TEXT,
    details TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_name ON alerts(name);
"""

CREATE_TRAFFIC_STATS_TABLE = """
CREATE TABLE IF NOT EXISTS traffic_stats (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    interface TEXT NOT NULL,
    packets_per_sec REAL NOT NULL DEFAULT 0,
    bytes_per_sec REAL NOT NULL DEFAULT 0,
    protocol_counts TEXT
);
CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON traffic_stats(timestamp);
CREATE INDEX IF NOT EXISTS idx_traffic_interface ON traffic_stats(interface);
"""

ALL_TABLES_SQL = (
    CREATE_DEVICES_TABLE
    + CREATE_SESSIONS_TABLE
    + CREATE_DNS_LOGS_TABLE
    + CREATE_HTTP_METADATA_TABLE
    + CREATE_TLS_METADATA_TABLE
    + CREATE_ALERTS_TABLE
    + CREATE_TRAFFIC_STATS_TABLE
)


# ---------------------------------------------------------------------------
# Dataclass Models
# ---------------------------------------------------------------------------

@dataclass
class Device:
    """Represents a network device."""
    id: str
    mac: str
    ip: str = ""
    hostname: str = ""
    vendor: str = ""
    os_fingerprint: str = ""
    first_seen: str = ""
    last_seen: str = ""
    is_active: bool = True


@dataclass
class Session:
    """Represents a network session (connection between two endpoints)."""
    id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packets: int = 0
    bytes: int = 0
    start_time: str = ""
    end_time: str = ""


@dataclass
class DnsLog:
    """Represents a DNS query/response log entry."""
    id: str
    timestamp: str
    src_ip: str
    query_name: str
    query_type: str = ""
    response_code: str = ""
    response_ips: str = ""
    ttl: int = 0


@dataclass
class HttpMetadata:
    """Represents extracted HTTP metadata from a captured request."""
    id: str
    timestamp: str
    src_ip: str
    dst_ip: str
    method: str = ""
    host: str = ""
    uri: str = ""
    status_code: int = 0
    content_type: str = ""
    user_agent: str = ""


@dataclass
class TlsMetadata:
    """Represents TLS handshake metadata."""
    id: str
    timestamp: str
    src_ip: str
    dst_ip: str
    sni: str = ""
    issuer: str = ""
    subject: str = ""
    serial: str = ""
    not_before: str = ""
    not_after: str = ""
    version: str = ""
    cipher: str = ""


@dataclass
class Alert:
    """Represents a security or monitoring alert."""
    id: str
    timestamp: str
    severity: str
    name: str
    message: str
    source_ip: str = ""
    details: str = ""


@dataclass
class TrafficStat:
    """Represents a periodic traffic statistics snapshot."""
    id: str
    timestamp: str
    interface: str
    packets_per_sec: float = 0.0
    bytes_per_sec: float = 0.0
    protocol_counts: dict[str, int] = field(default_factory=dict)
