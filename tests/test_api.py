"""Tests for FastAPI application and API endpoints."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# Ensure project root is importable
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from api.app import AppState, create_app
from database.db_manager import DatabaseManager
from config.settings import Config, CaptureConfig, DatabaseConfig, ApiConfig, AuthConfig, DashboardConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_test_state(tmp_db_path: Path) -> AppState:
    """Build an AppState with mocked modules for API testing."""
    db = DatabaseManager(tmp_db_path)
    db.initialize()

    state = AppState(db_manager=db)
    state.device_discovery = MagicMock()
    state.device_discovery.get_devices.return_value = [
        {"mac": "aa:bb:cc:dd:ee:ff", "ip": "10.0.0.1", "is_active": True, "vendor": "Test"},
    ]
    state.device_discovery.get_device.return_value = {
        "mac": "aa:bb:cc:dd:ee:ff", "ip": "10.0.0.1", "is_active": True,
    }

    state.alert_engine = MagicMock()
    state.alert_engine.get_recent_alerts.return_value = [
        {"id": "a1", "severity": "high", "name": "test", "message": "msg"},
    ]
    state.alert_engine.get_alert_stats.return_value = {
        "total": 1, "by_severity": {"high": 1}, "last_24h": 1,
    }

    state.traffic_stats = MagicMock()
    state.traffic_stats.get_packets_per_second.return_value = 1000.0
    state.traffic_stats.get_bytes_per_second.return_value = 500000.0
    state.traffic_stats.get_total_packets.return_value = 100000
    state.traffic_stats.get_total_bytes.return_value = 50000000

    state.flow_monitor = MagicMock()
    state.flow_monitor.get_flow_stats.return_value = {"active": 10}

    state.dns_analytics = MagicMock()
    state.dns_analytics.get_query_stats.return_value = {"queries": 500}

    state.certificate_inspector = MagicMock()
    state.certificate_inspector.get_certificate_stats.return_value = {"certs": 50}

    state.bandwidth_monitor = MagicMock()
    state.bandwidth_monitor.get_current_bandwidth.return_value = {"mbps": 100}
    state.bandwidth_monitor.get_history.return_value = []

    state.interface_detector = MagicMock()
    state.interface_detector.get_interfaces.return_value = [
        {"name": "en0", "ip": "192.168.1.10"},
    ]

    state.capture_engine = MagicMock()
    state.capture_engine.is_running.return_value = False
    state.capture_engine.get_stats.return_value = {"packets": 0}

    return state


@pytest.fixture()
def test_app(tmp_path: Path):
    """Create a FastAPI test application with mocked state."""
    db_path = tmp_path / "api_test.db"
    state = _make_test_state(db_path)

    with patch("api.app.get_config") as mock_cfg:
        mock_cfg.return_value = Config(
            capture=CaptureConfig(interface="lo0"),
            database=DatabaseConfig(path=str(db_path)),
            api=ApiConfig(host="127.0.0.1", port=0),
            auth=AuthConfig(enabled=False),
            dashboard=DashboardConfig(theme="dark"),
        )
        app = create_app(state)

    yield app, state
    state.db_manager.close()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestAppCreation:
    """Tests for the FastAPI application factory."""

    def test_app_creation(self, test_app) -> None:
        """create_app returns a configured FastAPI instance."""
        app, state = test_app
        assert app.title == "NetSentinel"
        assert hasattr(app.state, "netsentinel")

    def test_health_endpoint(self, test_app) -> None:
        """GET /api/health returns status ok."""
        from fastapi.testclient import TestClient
        app, state = test_app
        client = TestClient(app)
        resp = client.get("/api/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_info_endpoint(self, test_app) -> None:
        """GET /api/info returns server metadata."""
        from fastapi.testclient import TestClient
        app, state = test_app
        client = TestClient(app)
        resp = client.get("/api/info")
        assert resp.status_code == 200
        data = resp.json()
        assert "version" in data
        assert data["auth_enabled"] is False


class TestDevicesEndpoint:
    """Tests for the /api/devices routes."""

    def test_get_devices_endpoint(self, test_app) -> None:
        """GET /api/devices returns a list of devices."""
        from fastapi.testclient import TestClient
        app, state = test_app
        client = TestClient(app)
        resp = client.get("/api/devices")
        assert resp.status_code == 200
        devices = resp.json()
        assert isinstance(devices, list)
        assert len(devices) >= 1

    def test_get_device_by_mac(self, test_app) -> None:
        """GET /api/devices/{mac} returns a single device."""
        from fastapi.testclient import TestClient
        app, state = test_app
        client = TestClient(app)
        resp = client.get("/api/devices/aa:bb:cc:dd:ee:ff")
        assert resp.status_code == 200
        assert resp.json()["mac"] == "aa:bb:cc:dd:ee:ff"

    def test_get_device_not_found(self, test_app) -> None:
        """GET /api/devices/{mac} returns 404 for unknown MAC."""
        from fastapi.testclient import TestClient
        app, state = test_app
        state.device_discovery.get_device.return_value = None
        client = TestClient(app)
        resp = client.get("/api/devices/ff:ff:ff:ff:ff:ff")
        assert resp.status_code == 404


class TestAlertsEndpoint:
    """Tests for the /api/alerts routes."""

    def test_get_alerts_endpoint(self, test_app) -> None:
        """GET /api/alerts returns a list of alerts."""
        from fastapi.testclient import TestClient
        app, state = test_app
        client = TestClient(app)
        resp = client.get("/api/alerts")
        assert resp.status_code == 200
        alerts = resp.json()
        assert isinstance(alerts, list)
        assert len(alerts) >= 1

    def test_alerts_stats_endpoint(self, test_app) -> None:
        """GET /api/alerts/stats returns aggregate statistics."""
        from fastapi.testclient import TestClient
        app, state = test_app
        client = TestClient(app)
        resp = client.get("/api/alerts/stats")
        assert resp.status_code == 200
        stats = resp.json()
        assert "total" in stats


class TestStatsEndpoint:
    """Tests for the /api/stats routes."""

    def test_get_stats_endpoint(self, test_app) -> None:
        """GET /api/stats/overview returns a combined overview."""
        from fastapi.testclient import TestClient
        app, state = test_app
        client = TestClient(app)
        resp = client.get("/api/stats/overview")
        assert resp.status_code == 200
        overview = resp.json()
        assert "devices" in overview


class TestCaptureEndpoint:
    """Tests for the /api/capture routes."""

    def test_capture_status_endpoint(self, test_app) -> None:
        """GET /api/capture/status returns capture state."""
        from fastapi.testclient import TestClient
        app, state = test_app
        client = TestClient(app)
        resp = client.get("/api/capture/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "running" in data

    def test_capture_status_when_engine_none(self, test_app) -> None:
        """Status endpoint works even when capture_engine is None."""
        from fastapi.testclient import TestClient
        app, state = test_app
        state.capture_engine = None
        client = TestClient(app)
        resp = client.get("/api/capture/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["running"] is False

    def test_list_interfaces_endpoint(self, test_app) -> None:
        """GET /api/capture/interfaces returns available interfaces."""
        from fastapi.testclient import TestClient
        app, state = test_app
        client = TestClient(app)
        resp = client.get("/api/capture/interfaces")
        assert resp.status_code == 200
        interfaces = resp.json()
        assert isinstance(interfaces, list)
        assert len(interfaces) >= 1
