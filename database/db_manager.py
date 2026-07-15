"""SQLite database manager for NetSentinel."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Generator

from database.models import ALL_TABLES_SQL
from utils.logger import setup_logger
from utils.helpers import generate_id, get_timestamp

logger = setup_logger("netsentinel.database")


class DatabaseManager:
    """Manages SQLite database operations for NetSentinel.

    Uses WAL mode for concurrent read access and provides typed methods
    for all CRUD operations on the application's data models.

    Usage:
        async with DatabaseManager("data/netsentinel.db") as db:
            devices = db.get_devices()
    """

    def __init__(self, db_path: str | Path) -> None:
        """Initialize the database manager.

        Args:
            db_path: Path to the SQLite database file.
        """
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: sqlite3.Connection | None = None

    def __enter__(self) -> DatabaseManager:
        self.initialize()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        self.close()

    @contextmanager
    def _cursor(self) -> Generator[sqlite3.Cursor, None, None]:
        """Context manager yielding a cursor with automatic commit/rollback."""
        if self._conn is None:
            raise RuntimeError(
                "Database not initialized. Call initialize() first."
            )
        cursor = self._conn.cursor()
        try:
            yield cursor
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def initialize(self) -> None:
        """Open the database connection and create tables if they don't exist."""
        if self._conn is not None:
            return

        logger.info("Initializing database at %s", self._db_path)
        self._conn = sqlite3.connect(
            str(self._db_path),
            check_same_thread=False,
            timeout=30.0,
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.execute("PRAGMA busy_timeout = 5000")

        with self._cursor() as cur:
            cur.executescript(ALL_TABLES_SQL)

        logger.info("Database initialized successfully")

    def close(self) -> None:
        """Close the database connection."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None
            logger.debug("Database connection closed")

    # -------------------------------------------------------------------
    # Devices
    # -------------------------------------------------------------------

    def insert_device(self, device: dict[str, Any]) -> str:
        """Insert a new device record.

        Args:
            device: Dictionary with device fields. Must include 'mac'.

        Returns:
            The generated device ID.
        """
        device_id = device.get("id", generate_id())
        now = get_timestamp()

        with self._cursor() as cur:
            cur.execute(
                """
                INSERT OR REPLACE INTO devices
                    (id, mac, ip, hostname, vendor, os_fingerprint,
                     first_seen, last_seen, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    device_id,
                    device["mac"],
                    device.get("ip", ""),
                    device.get("hostname", ""),
                    device.get("vendor", ""),
                    device.get("os_fingerprint", ""),
                    device.get("first_seen", now),
                    device.get("last_seen", now),
                    int(device.get("is_active", True)),
                ),
            )

        logger.debug("Inserted device %s (mac=%s)", device_id, device.get("mac"))
        return device_id

    def update_device(self, mac: str, updates: dict[str, Any]) -> bool:
        """Update an existing device by MAC address.

        Args:
            mac: MAC address of the device to update.
            updates: Dictionary of field=value pairs to update.

        Returns:
            True if a row was updated, False otherwise.
        """
        if not updates:
            return False

        updates["last_seen"] = get_timestamp()

        set_clauses = []
        values: list[Any] = []
        for key, val in updates.items():
            if key == "is_active":
                set_clauses.append(f"{key} = ?")
                values.append(int(val))
            else:
                set_clauses.append(f"{key} = ?")
                values.append(val)

        values.append(mac)
        sql = f"UPDATE devices SET {', '.join(set_clauses)} WHERE mac = ?"

        with self._cursor() as cur:
            cur.execute(sql, values)
            updated = cur.rowcount > 0

        if updated:
            logger.debug("Updated device with mac=%s", mac)
        return updated

    def get_devices(self, *, active_only: bool = False) -> list[dict[str, Any]]:
        """Retrieve all device records.

        Args:
            active_only: If True, only return devices where is_active=1.

        Returns:
            List of device dictionaries.
        """
        sql = "SELECT * FROM devices"
        if active_only:
            sql += " WHERE is_active = 1"
        sql += " ORDER BY last_seen DESC"

        with self._cursor() as cur:
            cur.execute(sql)
            rows = cur.fetchall()

        return [dict(row) for row in rows]

    def get_device_by_mac(self, mac: str) -> dict[str, Any] | None:
        """Look up a device by its MAC address.

        Args:
            mac: MAC address to search for.

        Returns:
            Device dictionary or None if not found.
        """
        with self._cursor() as cur:
            cur.execute("SELECT * FROM devices WHERE mac = ?", (mac,))
            row = cur.fetchone()

        return dict(row) if row else None

    # -------------------------------------------------------------------
    # Sessions
    # -------------------------------------------------------------------

    def insert_session(self, session: dict[str, Any]) -> str:
        """Insert a new session record.

        Args:
            session: Dictionary with session fields.

        Returns:
            The generated session ID.
        """
        session_id = session.get("id", generate_id())
        now = get_timestamp()

        with self._cursor() as cur:
            cur.execute(
                """
                INSERT INTO sessions
                    (id, src_ip, dst_ip, src_port, dst_port, protocol,
                     packets, bytes, start_time, end_time)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    session["src_ip"],
                    session["dst_ip"],
                    int(session["src_port"]),
                    int(session["dst_port"]),
                    session["protocol"],
                    int(session.get("packets", 0)),
                    int(session.get("bytes", 0)),
                    session.get("start_time", now),
                    session.get("end_time", ""),
                ),
            )

        logger.debug("Inserted session %s", session_id)
        return session_id

    def update_session(
        self, session_id: str, updates: dict[str, Any]
    ) -> bool:
        """Update an existing session by ID.

        Args:
            session_id: ID of the session to update.
            updates: Dictionary of field=value pairs.

        Returns:
            True if a row was updated.
        """
        if not updates:
            return False

        set_clauses = []
        values: list[Any] = []
        for key, val in updates.items():
            set_clauses.append(f"{key} = ?")
            values.append(val)

        values.append(session_id)
        sql = f"UPDATE sessions SET {', '.join(set_clauses)} WHERE id = ?"

        with self._cursor() as cur:
            cur.execute(sql, values)
            return cur.rowcount > 0

    def get_sessions(
        self, *, limit: int = 100
    ) -> list[dict[str, Any]]:
        """Retrieve sessions ordered by start time descending.

        Args:
            limit: Maximum number of sessions to return.

        Returns:
            List of session dictionaries.
        """
        with self._cursor() as cur:
            cur.execute(
                "SELECT * FROM sessions ORDER BY start_time DESC LIMIT ?",
                (limit,),
            )
            rows = cur.fetchall()

        return [dict(row) for row in rows]

    # -------------------------------------------------------------------
    # DNS Logs
    # -------------------------------------------------------------------

    def insert_dns_log(self, dns: dict[str, Any]) -> str:
        """Insert a DNS query/response log entry.

        Args:
            dns: Dictionary with DNS log fields.

        Returns:
            The generated record ID.
        """
        dns_id = dns.get("id", generate_id())
        now = get_timestamp()

        with self._cursor() as cur:
            cur.execute(
                """
                INSERT INTO dns_logs
                    (id, timestamp, src_ip, query_name, query_type,
                     response_code, response_ips, ttl)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    dns_id,
                    dns.get("timestamp", now),
                    dns["src_ip"],
                    dns["query_name"],
                    dns.get("query_type", ""),
                    dns.get("response_code", ""),
                    dns.get("response_ips", ""),
                    int(dns.get("ttl", 0)),
                ),
            )

        logger.debug("Inserted DNS log %s", dns_id)
        return dns_id

    def get_dns_logs(
        self,
        *,
        limit: int = 100,
        query_filter: str | None = None,
    ) -> list[dict[str, Any]]:
        """Retrieve DNS logs with optional filtering.

        Args:
            limit: Maximum records to return.
            query_filter: Optional substring to match against query_name.

        Returns:
            List of DNS log dictionaries.
        """
        if query_filter:
            sql = (
                "SELECT * FROM dns_logs "
                "WHERE query_name LIKE ? "
                "ORDER BY timestamp DESC LIMIT ?"
            )
            params: tuple[Any, ...] = (f"%{query_filter}%", limit)
        else:
            sql = (
                "SELECT * FROM dns_logs "
                "ORDER BY timestamp DESC LIMIT ?"
            )
            params = (limit,)

        with self._cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()

        return [dict(row) for row in rows]

    # -------------------------------------------------------------------
    # HTTP Metadata
    # -------------------------------------------------------------------

    def insert_http_metadata(self, http: dict[str, Any]) -> str:
        """Insert HTTP metadata extracted from a captured request.

        Args:
            http: Dictionary with HTTP metadata fields.

        Returns:
            The generated record ID.
        """
        http_id = http.get("id", generate_id())
        now = get_timestamp()

        with self._cursor() as cur:
            cur.execute(
                """
                INSERT INTO http_metadata
                    (id, timestamp, src_ip, dst_ip, method, host, uri,
                     status_code, content_type, user_agent)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    http_id,
                    http.get("timestamp", now),
                    http["src_ip"],
                    http["dst_ip"],
                    http.get("method", ""),
                    http.get("host", ""),
                    http.get("uri", ""),
                    int(http.get("status_code", 0)),
                    http.get("content_type", ""),
                    http.get("user_agent", ""),
                ),
            )

        logger.debug("Inserted HTTP metadata %s", http_id)
        return http_id

    def get_http_metadata(
        self, *, limit: int = 100
    ) -> list[dict[str, Any]]:
        """Retrieve HTTP metadata records.

        Args:
            limit: Maximum records to return.

        Returns:
            List of HTTP metadata dictionaries.
        """
        with self._cursor() as cur:
            cur.execute(
                "SELECT * FROM http_metadata ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            )
            rows = cur.fetchall()

        return [dict(row) for row in rows]

    # -------------------------------------------------------------------
    # TLS Metadata
    # -------------------------------------------------------------------

    def insert_tls_metadata(self, tls: dict[str, Any]) -> str:
        """Insert TLS handshake metadata.

        Args:
            tls: Dictionary with TLS metadata fields.

        Returns:
            The generated record ID.
        """
        tls_id = tls.get("id", generate_id())
        now = get_timestamp()

        with self._cursor() as cur:
            cur.execute(
                """
                INSERT INTO tls_metadata
                    (id, timestamp, src_ip, dst_ip, sni, issuer, subject,
                     serial, not_before, not_after, version, cipher)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    tls_id,
                    tls.get("timestamp", now),
                    tls["src_ip"],
                    tls["dst_ip"],
                    tls.get("sni", ""),
                    tls.get("issuer", ""),
                    tls.get("subject", ""),
                    tls.get("serial", ""),
                    tls.get("not_before", ""),
                    tls.get("not_after", ""),
                    tls.get("version", ""),
                    tls.get("cipher", ""),
                ),
            )

        logger.debug("Inserted TLS metadata %s", tls_id)
        return tls_id

    def get_tls_metadata(
        self, *, limit: int = 100
    ) -> list[dict[str, Any]]:
        """Retrieve TLS metadata records.

        Args:
            limit: Maximum records to return.

        Returns:
            List of TLS metadata dictionaries.
        """
        with self._cursor() as cur:
            cur.execute(
                "SELECT * FROM tls_metadata ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            )
            rows = cur.fetchall()

        return [dict(row) for row in rows]

    # -------------------------------------------------------------------
    # Alerts
    # -------------------------------------------------------------------

    def insert_alert(self, alert: dict[str, Any]) -> str:
        """Insert a new alert record.

        Args:
            alert: Dictionary with alert fields.

        Returns:
            The generated alert ID.
        """
        alert_id = alert.get("id", generate_id())
        now = get_timestamp()

        with self._cursor() as cur:
            cur.execute(
                """
                INSERT INTO alerts
                    (id, timestamp, severity, name, message,
                     source_ip, details)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert_id,
                    alert.get("timestamp", now),
                    alert["severity"],
                    alert["name"],
                    alert["message"],
                    alert.get("source_ip", ""),
                    alert.get("details", ""),
                ),
            )

        logger.info(
            "Alert created: [%s] %s - %s",
            alert["severity"],
            alert["name"],
            alert["message"],
        )
        return alert_id

    def get_alerts(
        self,
        *,
        limit: int = 100,
        severity_filter: str | None = None,
    ) -> list[dict[str, Any]]:
        """Retrieve alerts with optional severity filtering.

        Args:
            limit: Maximum records to return.
            severity_filter: Optional severity level to filter by.

        Returns:
            List of alert dictionaries.
        """
        if severity_filter:
            sql = (
                "SELECT * FROM alerts WHERE severity = ? "
                "ORDER BY timestamp DESC LIMIT ?"
            )
            params: tuple[Any, ...] = (severity_filter, limit)
        else:
            sql = (
                "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?"
            )
            params = (limit,)

        with self._cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()

        return [dict(row) for row in rows]

    # -------------------------------------------------------------------
    # Traffic Stats
    # -------------------------------------------------------------------

    def insert_traffic_stat(self, stat: dict[str, Any]) -> str:
        """Insert a traffic statistics snapshot.

        Args:
            stat: Dictionary with traffic stat fields.

        Returns:
            The generated record ID.
        """
        stat_id = stat.get("id", generate_id())
        now = get_timestamp()
        protocol_counts = stat.get("protocol_counts", {})
        if isinstance(protocol_counts, dict):
            protocol_counts_json = json.dumps(protocol_counts)
        else:
            protocol_counts_json = str(protocol_counts)

        with self._cursor() as cur:
            cur.execute(
                """
                INSERT INTO traffic_stats
                    (id, timestamp, interface, packets_per_sec,
                     bytes_per_sec, protocol_counts)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    stat_id,
                    stat.get("timestamp", now),
                    stat["interface"],
                    float(stat.get("packets_per_sec", 0)),
                    float(stat.get("bytes_per_sec", 0)),
                    protocol_counts_json,
                ),
            )

        logger.debug("Inserted traffic stat %s", stat_id)
        return stat_id

    def get_traffic_stats(
        self,
        *,
        interface: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Retrieve traffic statistics, optionally filtered by interface.

        Args:
            interface: Optional interface name to filter by.
            limit: Maximum records to return.

        Returns:
            List of traffic stat dictionaries.
        """
        if interface:
            sql = (
                "SELECT * FROM traffic_stats "
                "WHERE interface = ? "
                "ORDER BY timestamp DESC LIMIT ?"
            )
            params: tuple[Any, ...] = (interface, limit)
        else:
            sql = (
                "SELECT * FROM traffic_stats "
                "ORDER BY timestamp DESC LIMIT ?"
            )
            params = (limit,)

        with self._cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()

        results: list[dict[str, Any]] = []
        for row in rows:
            d = dict(row)
            raw = d.get("protocol_counts", "{}")
            if isinstance(raw, str):
                try:
                    d["protocol_counts"] = json.loads(raw)
                except (json.JSONDecodeError, TypeError):
                    d["protocol_counts"] = {}
            results.append(d)

        return results

    # -------------------------------------------------------------------
    # Analytics / Aggregation Queries
    # -------------------------------------------------------------------

    def get_protocol_distribution(self) -> dict[str, int]:
        """Get the distribution of protocols across all sessions.

        Returns:
            Dictionary mapping protocol name to count, e.g.
            {"TCP": 1234, "UDP": 567, "ICMP": 42}.
        """
        with self._cursor() as cur:
            cur.execute(
                "SELECT protocol, COUNT(*) as cnt "
                "FROM sessions "
                "GROUP BY protocol "
                "ORDER BY cnt DESC"
            )
            rows = cur.fetchall()

        return {row["protocol"]: row["cnt"] for row in rows}

    def get_top_talkers(self, *, limit: int = 10) -> list[dict[str, Any]]:
        """Get the top talking hosts by total bytes transferred.

        Args:
            limit: Number of top talkers to return.

        Returns:
            List of dicts with 'ip' and 'total_bytes' keys.
        """
        with self._cursor() as cur:
            cur.execute(
                """
                WITH talkers AS (
                    SELECT src_ip AS ip, bytes FROM sessions
                    UNION ALL
                    SELECT dst_ip AS ip, bytes FROM sessions
                )
                SELECT ip, SUM(bytes) as total_bytes
                FROM talkers
                WHERE ip != ''
                GROUP BY ip
                ORDER BY total_bytes DESC
                LIMIT ?
                """,
                (limit,),
            )
            rows = cur.fetchall()

        return [dict(row) for row in rows]

    def get_bandwidth_timeline(
        self, *, minutes: int = 60
    ) -> list[dict[str, Any]]:
        """Get bandwidth usage timeline for the last N minutes.

        Args:
            minutes: Number of minutes of history to return.

        Returns:
            List of traffic stat dictionaries ordered by timestamp.
        """
        with self._cursor() as cur:
            cur.execute(
                """
                SELECT * FROM traffic_stats
                WHERE timestamp >= datetime('now', ?)
                ORDER BY timestamp ASC
                """,
                (f"-{minutes} minutes",),
            )
            rows = cur.fetchall()

        results: list[dict[str, Any]] = []
        for row in rows:
            d = dict(row)
            raw = d.get("protocol_counts", "{}")
            if isinstance(raw, str):
                try:
                    d["protocol_counts"] = json.loads(raw)
                except (json.JSONDecodeError, TypeError):
                    d["protocol_counts"] = {}
            results.append(d)

        return results

    def cleanup_old_records(self, *, days: int = 30) -> dict[str, int]:
        """Delete records older than the specified number of days.

        Args:
            days: Retention period in days.

        Returns:
            Dictionary mapping table name to number of rows deleted.
        """
        cutoff_expr = f"-{days} days"
        tables = [
            ("dns_logs", "timestamp"),
            ("http_metadata", "timestamp"),
            ("tls_metadata", "timestamp"),
            ("sessions", "start_time"),
            ("traffic_stats", "timestamp"),
            ("alerts", "timestamp"),
        ]

        deleted: dict[str, int] = {}
        for table, ts_column in tables:
            with self._cursor() as cur:
                cur.execute(
                    f"DELETE FROM {table} "
                    f"WHERE {ts_column} < datetime('now', ?)",
                    (cutoff_expr,),
                )
                count = cur.rowcount
            if count > 0:
                deleted[table] = count
                logger.info(
                    "Cleaned up %d old records from %s", count, table
                )

        return deleted
