"""Tests for modules.alert_engine module."""

from __future__ import annotations

import time

import pytest

from database.db_manager import DatabaseManager
from modules.alert_engine import AlertEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def alert_engine(db_manager: DatabaseManager) -> AlertEngine:
    """Create an AlertEngine wired to the test database."""
    return AlertEngine(db_manager=db_manager, config=None)


# ---------------------------------------------------------------------------
# Basic operations
# ---------------------------------------------------------------------------

class TestAlertEngineInit:
    """Verify AlertEngine initialisation and empty state."""

    def test_alert_engine_init(self, alert_engine: AlertEngine) -> None:
        """Engine starts with no rules."""
        assert alert_engine.get_rules() == []


class TestAddRemoveRule:
    """Tests for rule management."""

    def test_add_rule(self, alert_engine: AlertEngine) -> None:
        rule = {
            "name": "test_rule",
            "condition": "dst_port > 1024",
            "severity": "info",
            "message": "Port open: {{dst_port}}",
        }
        alert_engine.add_rule(rule)
        rules = alert_engine.get_rules()
        assert len(rules) == 1
        assert rules[0]["name"] == "test_rule"

    def test_add_rule_invalid_severity(self, alert_engine: AlertEngine) -> None:
        rule = {
            "name": "bad_rule",
            "condition": "true",
            "severity": "ultra_critical_extreme",
            "message": "fail",
        }
        with pytest.raises(ValueError, match="Invalid severity"):
            alert_engine.add_rule(rule)

    def test_remove_rule(self, alert_engine: AlertEngine) -> None:
        alert_engine.add_rule({"name": "to_remove", "condition": "true", "severity": "info", "message": ""})
        assert alert_engine.remove_rule("to_remove") is True
        assert alert_engine.get_rules() == []

    def test_remove_rule_not_found(self, alert_engine: AlertEngine) -> None:
        assert alert_engine.remove_rule("nonexistent") is False


# ---------------------------------------------------------------------------
# Condition evaluation
# ---------------------------------------------------------------------------

class TestEvaluateCondition:
    """Tests for the condition evaluation logic."""

    def test_evaluate_no_match(self, alert_engine: AlertEngine) -> None:
        """Rule condition does not match event – no alert produced."""
        alert_engine.add_rule({
            "name": "high_port",
            "condition": "dst_port > 10000",
            "severity": "info",
            "message": "High port",
        })
        triggered = alert_engine.evaluate({"src_ip": "10.0.0.1", "dst_port": 80})
        assert triggered == []

    def test_evaluate_match(self, alert_engine: AlertEngine) -> None:
        """Rule condition matches – alert produced."""
        alert_engine.add_rule({
            "name": "high_port",
            "condition": "dst_port > 100",
            "severity": "low",
            "message": "Port {{dst_port}} open",
        })
        triggered = alert_engine.evaluate({"src_ip": "10.0.0.1", "dst_port": 8080})
        assert len(triggered) == 1
        assert triggered[0]["name"] == "high_port"
        assert "8080" in triggered[0]["message"]

    def test_evaluate_dotted_key(self, alert_engine: AlertEngine) -> None:
        """Dotted key paths are resolved correctly."""
        alert_engine.add_rule({
            "name": "nested",
            "condition": "data.bytes > 5000",
            "severity": "info",
            "message": "large",
        })
        triggered = alert_engine.evaluate({
            "src_ip": "10.0.0.1",
            "data": {"bytes": 10000},
        })
        assert len(triggered) == 1


# ---------------------------------------------------------------------------
# Built-in detectors
# ---------------------------------------------------------------------------

class TestPortScanDetection:
    """Tests for the built-in high_port_scan detector."""

    def test_port_scan_detection(self, alert_engine: AlertEngine) -> None:
        """Sending SYN packets to many ports from the same IP triggers port scan alert."""
        alert_engine.add_rule({
            "name": "port_scan",
            "condition": "high_port_scan",
            "severity": "high",
            "message": "Port scan from {{src_ip}}",
        })

        # Send 25 SYN packets to different ports (threshold is 20)
        triggered = []
        for port in range(1, 30):
            result = alert_engine.evaluate({
                "src_ip": "10.0.0.50",
                "dst_port": port,
                "tcp_flags": "SYN",
            })
            triggered.extend(result)

        # The alert should fire once the threshold is reached
        port_scan_alerts = [a for a in triggered if a["name"] == "port_scan"]
        assert len(port_scan_alerts) >= 1

    def test_non_syn_does_not_trigger(self, alert_engine: AlertEngine) -> None:
        """Non-SYN packets do not count toward port scan threshold."""
        alert_engine.add_rule({
            "name": "port_scan",
            "condition": "high_port_scan",
            "severity": "high",
            "message": "scan",
        })

        for port in range(1, 25):
            result = alert_engine.evaluate({
                "src_ip": "10.0.0.50",
                "dst_port": port,
                "tcp_flags": "ACK",
            })
            assert result == []


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

class TestRateLimiting:
    """Tests for alert rate limiting (same rule+src_ip within window)."""

    def test_rate_limiting(self, alert_engine: AlertEngine) -> None:
        """Second identical trigger within 60s is suppressed."""
        alert_engine.add_rule({
            "name": "bw_spike",
            "condition": "bandwidth_spike",
            "severity": "critical",
            "message": "Spike",
        })

        # Force a match
        first = alert_engine.evaluate({
            "src_ip": "10.0.0.1",
            "bytes_per_sec": 20 * 1024 * 1024,  # 20 MB/s > 10 MB/s threshold
        })
        assert len(first) == 1

        # Immediate re-trigger should be rate-limited
        second = alert_engine.evaluate({
            "src_ip": "10.0.0.1",
            "bytes_per_sec": 50 * 1024 * 1024,
        })
        assert second == []


# ---------------------------------------------------------------------------
# Built-in: DNS tunnel suspect
# ---------------------------------------------------------------------------

class TestDnsTunnelDetector:
    """Tests for the built-in dns_tunnel_suspect detector."""

    def test_dns_tunnel_long_query(self, alert_engine: AlertEngine) -> None:
        """Very long DNS query triggers tunnel suspicion."""
        alert_engine.add_rule({
            "name": "dns_tunnel",
            "condition": "dns_tunnel_suspect",
            "severity": "high",
            "message": "DNS tunnel suspect",
        })

        long_query = "a" * 60 + ".example.com"
        triggered = alert_engine.evaluate({
            "src_ip": "10.0.0.1",
            "dns_query": long_query,
        })
        assert len(triggered) == 1

    def test_dns_tunnel_short_query_no_trigger(self, alert_engine: AlertEngine) -> None:
        """Short DNS query does not trigger."""
        alert_engine.add_rule({
            "name": "dns_tunnel",
            "condition": "dns_tunnel_suspect",
            "severity": "high",
            "message": "tunnel",
        })
        triggered = alert_engine.evaluate({
            "src_ip": "10.0.0.1",
            "dns_query": "example.com",
        })
        assert triggered == []


# ---------------------------------------------------------------------------
# Built-in: new device
# ---------------------------------------------------------------------------

class TestNewDeviceDetector:
    """Tests for the built-in new_device detector."""

    def test_new_device_triggers(self, alert_engine: AlertEngine) -> None:
        alert_engine.add_rule({
            "name": "new_dev",
            "condition": "new_device",
            "severity": "info",
            "message": "New device",
        })
        triggered = alert_engine.evaluate({"src_ip": "10.0.0.99", "is_new_device": True})
        assert len(triggered) == 1

    def test_old_device_no_trigger(self, alert_engine: AlertEngine) -> None:
        alert_engine.add_rule({
            "name": "new_dev",
            "condition": "new_device",
            "severity": "info",
            "message": "New device",
        })
        triggered = alert_engine.evaluate({"src_ip": "10.0.0.99", "is_new_device": False})
        assert triggered == []


# ---------------------------------------------------------------------------
# Alert persistence
# ---------------------------------------------------------------------------

class TestAlertPersistence:
    """Verify alerts are persisted to the database."""

    def test_alert_persisted(self, alert_engine: AlertEngine, db_manager: DatabaseManager) -> None:
        alert_engine.add_rule({
            "name": "test_persist",
            "condition": "dst_port > 0",
            "severity": "medium",
            "message": "Port {{dst_port}}",
        })
        alert_engine.evaluate({"src_ip": "10.0.0.1", "dst_port": 999})

        alerts = db_manager.get_alerts(limit=10)
        assert len(alerts) == 1
        assert alerts[0]["name"] == "test_persist"
