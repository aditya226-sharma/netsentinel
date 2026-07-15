"""Tests for database.db_manager module."""

from __future__ import annotations

import json

import pytest

from database.db_manager import DatabaseManager
from database.models import (
    Alert,
    Device,
    DnsLog,
    HttpMetadata,
    Session,
    TlsMetadata,
    TrafficStat,
)


# ---------------------------------------------------------------------------
# Table creation
# ---------------------------------------------------------------------------

class TestDatabaseInit:
    """Verify that DatabaseManager creates all tables on initialize()."""

    def test_initialize_creates_tables(self, db_manager: DatabaseManager) -> None:
        """All expected tables must exist after initialization."""
        cursor = db_manager._conn.cursor()
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        tables = {row["name"] for row in cursor.fetchall()}
        expected = {
            "devices", "sessions", "dns_logs", "http_metadata",
            "tls_metadata", "alerts", "traffic_stats",
        }
        assert expected.issubset(tables), f"Missing tables: {expected - tables}"


# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------

class TestDeviceOperations:
    """Tests for device CRUD operations."""

    def test_insert_and_get_device(self, db_manager: DatabaseManager) -> None:
        device = {
            "mac": "aa:bb:cc:dd:ee:ff",
            "ip": "192.168.1.10",
            "hostname": "test-host",
            "vendor": "TestVendor",
        }
        device_id = db_manager.insert_device(device)
        assert device_id is not None
        assert len(device_id) > 0

        result = db_manager.get_device_by_mac("aa:bb:cc:dd:ee:ff")
        assert result is not None
        assert result["ip"] == "192.168.1.10"
        assert result["hostname"] == "test-host"
        assert result["vendor"] == "TestVendor"

    def test_update_device(self, db_manager: DatabaseManager) -> None:
        db_manager.insert_device({"mac": "aa:bb:cc:dd:ee:ff", "ip": "10.0.0.1"})
        updated = db_manager.update_device(
            "aa:bb:cc:dd:ee:ff", {"hostname": "new-host", "is_active": False}
        )
        assert updated is True

        result = db_manager.get_device_by_mac("aa:bb:cc:dd:ee:ff")
        assert result["hostname"] == "new-host"
        assert result["is_active"] == 0

    def test_update_device_nonexistent(self, db_manager: DatabaseManager) -> None:
        updated = db_manager.update_device("ff:ff:ff:ff:ff:ff", {"ip": "1.1.1.1"})
        assert updated is False

    def test_get_devices_active_only(self, db_manager: DatabaseManager) -> None:
        db_manager.insert_device({"mac": "aa:bb:cc:dd:ee:01", "is_active": True})
        db_manager.insert_device({"mac": "aa:bb:cc:dd:ee:02", "is_active": False})

        active = db_manager.get_devices(active_only=True)
        assert len(active) == 1
        assert active[0]["mac"] == "aa:bb:cc:dd:ee:01"

        all_devs = db_manager.get_devices(active_only=False)
        assert len(all_devs) == 2


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------

class TestSessionOperations:
    """Tests for session CRUD operations."""

    def test_insert_and_get_session(self, db_manager: DatabaseManager) -> None:
        session = {
            "src_ip": "192.168.1.1",
            "dst_ip": "10.0.0.1",
            "src_port": 54321,
            "dst_port": 80,
            "protocol": "TCP",
            "packets": 10,
            "bytes": 5000,
        }
        sid = db_manager.insert_session(session)
        assert sid

        sessions = db_manager.get_sessions(limit=10)
        assert len(sessions) == 1
        assert sessions[0]["src_ip"] == "192.168.1.1"
        assert sessions[0]["dst_port"] == 80

    def test_update_session(self, db_manager: DatabaseManager) -> None:
        sid = db_manager.insert_session({
            "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
            "src_port": 1000, "dst_port": 2000, "protocol": "UDP",
        })
        updated = db_manager.update_session(sid, {"packets": 50, "bytes": 25000})
        assert updated is True


# ---------------------------------------------------------------------------
# DNS Logs
# ---------------------------------------------------------------------------

class TestDnsLogOperations:
    """Tests for DNS log CRUD operations."""

    def test_insert_and_get_dns_log(self, db_manager: DatabaseManager) -> None:
        dns = {
            "src_ip": "192.168.1.10",
            "query_name": "example.com",
            "query_type": "A",
            "response_code": "NOERROR",
            "response_ips": "93.184.216.34",
            "ttl": 300,
        }
        dns_id = db_manager.insert_dns_log(dns)
        assert dns_id

        logs = db_manager.get_dns_logs(limit=10)
        assert len(logs) == 1
        assert logs[0]["query_name"] == "example.com"

    def test_get_dns_logs_with_filter(self, db_manager: DatabaseManager) -> None:
        db_manager.insert_dns_log({"src_ip": "10.0.0.1", "query_name": "foo.com"})
        db_manager.insert_dns_log({"src_ip": "10.0.0.1", "query_name": "bar.org"})

        filtered = db_manager.get_dns_logs(query_filter="foo")
        assert len(filtered) == 1
        assert filtered[0]["query_name"] == "foo.com"


# ---------------------------------------------------------------------------
# HTTP Metadata
# ---------------------------------------------------------------------------

class TestHttpMetadataOperations:
    """Tests for HTTP metadata CRUD operations."""

    def test_insert_and_get_http_metadata(self, db_manager: DatabaseManager) -> None:
        http = {
            "src_ip": "192.168.1.5",
            "dst_ip": "93.184.216.34",
            "method": "GET",
            "host": "example.com",
            "uri": "/index.html",
            "status_code": 200,
            "content_type": "text/html",
            "user_agent": "Mozilla/5.0",
        }
        http_id = db_manager.insert_http_metadata(http)
        assert http_id

        records = db_manager.get_http_metadata(limit=10)
        assert len(records) == 1
        assert records[0]["method"] == "GET"
        assert records[0]["status_code"] == 200


# ---------------------------------------------------------------------------
# TLS Metadata
# ---------------------------------------------------------------------------

class TestTlsMetadataOperations:
    """Tests for TLS metadata CRUD operations."""

    def test_insert_and_get_tls_metadata(self, db_manager: DatabaseManager) -> None:
        tls = {
            "src_ip": "192.168.1.5",
            "dst_ip": "93.184.216.34",
            "sni": "example.com",
            "issuer": "Let's Encrypt",
            "subject": "CN=example.com",
            "serial": "AA:BB:CC",
            "version": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
        }
        tls_id = db_manager.insert_tls_metadata(tls)
        assert tls_id

        records = db_manager.get_tls_metadata(limit=10)
        assert len(records) == 1
        assert records[0]["sni"] == "example.com"
        assert records[0]["version"] == "TLSv1.3"


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

class TestAlertOperations:
    """Tests for alert CRUD operations."""

    def test_insert_and_get_alert(self, db_manager: DatabaseManager) -> None:
        alert = {
            "severity": "high",
            "name": "Port Scan",
            "message": "Port scan detected from 10.0.0.1",
            "source_ip": "10.0.0.1",
        }
        alert_id = db_manager.insert_alert(alert)
        assert alert_id

        alerts = db_manager.get_alerts(limit=10)
        assert len(alerts) == 1
        assert alerts[0]["severity"] == "high"
        assert alerts[0]["name"] == "Port Scan"

    def test_get_alerts_severity_filter(self, db_manager: DatabaseManager) -> None:
        db_manager.insert_alert({"severity": "low", "name": "a", "message": "x"})
        db_manager.insert_alert({"severity": "critical", "name": "b", "message": "y"})

        critical = db_manager.get_alerts(severity_filter="critical")
        assert len(critical) == 1
        assert critical[0]["severity"] == "critical"


# ---------------------------------------------------------------------------
# Traffic Stats
# ---------------------------------------------------------------------------

class TestTrafficStatOperations:
    """Tests for traffic stats CRUD operations."""

    def test_insert_and_get_traffic_stat(self, db_manager: DatabaseManager) -> None:
        stat = {
            "interface": "eth0",
            "packets_per_sec": 1500.5,
            "bytes_per_sec": 2048000.0,
            "protocol_counts": {"TCP": 1000, "UDP": 500},
        }
        stat_id = db_manager.insert_traffic_stat(stat)
        assert stat_id

        stats = db_manager.get_traffic_stats(interface="eth0")
        assert len(stats) == 1
        assert stats[0]["packets_per_sec"] == 1500.5
        assert stats[0]["protocol_counts"] == {"TCP": 1000, "UDP": 500}

    def test_get_traffic_stats_by_interface(self, db_manager: DatabaseManager) -> None:
        db_manager.insert_traffic_stat({"interface": "eth0", "packets_per_sec": 100})
        db_manager.insert_traffic_stat({"interface": "wlan0", "packets_per_sec": 200})

        eth0_stats = db_manager.get_traffic_stats(interface="eth0")
        assert len(eth0_stats) == 1
        assert eth0_stats[0]["interface"] == "eth0"


# ---------------------------------------------------------------------------
# Analytics
# ---------------------------------------------------------------------------

class TestAnalyticsQueries:
    """Tests for aggregation / analytics methods."""

    def test_get_protocol_distribution(self, db_manager: DatabaseManager) -> None:
        for _ in range(5):
            db_manager.insert_session({
                "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
                "src_port": 1, "dst_port": 2, "protocol": "TCP",
            })
        for _ in range(3):
            db_manager.insert_session({
                "src_ip": "10.0.0.1", "dst_ip": "10.0.0.3",
                "src_port": 3, "dst_port": 4, "protocol": "UDP",
            })

        dist = db_manager.get_protocol_distribution()
        assert dist["TCP"] == 5
        assert dist["UDP"] == 3

    def test_get_top_talkers(self, db_manager: DatabaseManager) -> None:
        db_manager.insert_session({
            "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
            "src_port": 1, "dst_port": 2, "protocol": "TCP",
            "packets": 100, "bytes": 10000,
        })
        db_manager.insert_session({
            "src_ip": "10.0.0.3", "dst_ip": "10.0.0.4",
            "src_port": 3, "dst_port": 4, "protocol": "UDP",
            "packets": 200, "bytes": 50000,
        })

        talkers = db_manager.get_top_talkers(limit=10)
        assert len(talkers) >= 2
        # Top talker should have the most bytes
        assert talkers[0]["total_bytes"] >= talkers[-1]["total_bytes"]
        # 10.0.0.3 and 10.0.0.4 should appear (each has 50000 bytes in the union)
        ips = {t["ip"] for t in talkers}
        assert "10.0.0.3" in ips
        assert "10.0.0.4" in ips


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

class TestCleanup:
    """Tests for cleanup_old_records."""

    def test_cleanup_old_records(self, db_manager: DatabaseManager) -> None:
        """Insert an old record and verify cleanup removes it."""
        from datetime import datetime, timedelta, timezone

        old_time = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat()
        db_manager.insert_dns_log({
            "src_ip": "10.0.0.1",
            "query_name": "old.example.com",
            "timestamp": old_time,
        })
        db_manager.insert_dns_log({
            "src_ip": "10.0.0.2",
            "query_name": "new.example.com",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        deleted = db_manager.cleanup_old_records(days=30)
        assert deleted.get("dns_logs", 0) >= 1

        remaining = db_manager.get_dns_logs(limit=100)
        assert len(remaining) == 1
        assert remaining[0]["query_name"] == "new.example.com"
