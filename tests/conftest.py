"""Shared pytest fixtures for the NetSentinel test suite."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from typing import Generator
from unittest.mock import MagicMock, patch

import pytest

# Ensure the project root is on sys.path so that absolute imports work
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database.db_manager import DatabaseManager
from config.settings import Config, CaptureConfig, DatabaseConfig, ApiConfig, AlertsConfig, AlertRule


# ---------------------------------------------------------------------------
# Database fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def tmp_db_path(tmp_path: Path) -> Generator[Path, None, None]:
    """Provide a temporary SQLite database path and clean up after the test."""
    db_path = tmp_path / "test_netsentinel.db"
    yield db_path
    # Clean up WAL/SHM files if present
    for suffix in ("", "-wal", "-shm"):
        p = Path(str(db_path) + suffix)
        if p.exists():
            p.unlink(missing_ok=True)


@pytest.fixture()
def db_manager(tmp_db_path: Path) -> Generator[DatabaseManager, None, None]:
    """Create an initialized DatabaseManager for tests."""
    manager = DatabaseManager(tmp_db_path)
    manager.initialize()
    yield manager
    manager.close()


# ---------------------------------------------------------------------------
# Scapy packet fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def sample_packet_eth():
    """Minimal Ethernet frame (IPv4/TCP payload)."""
    from scapy.layers.l2 import Ether
    return Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66") / b"\x00" * 10


@pytest.fixture()
def sample_packet_ip_tcp():
    """Complete IP/TCP packet resembling an HTTP request."""
    from scapy.layers.inet import IP, TCP
    from scapy.packet import Raw

    pkt = (
        IP(src="192.168.1.100", dst="10.0.0.1", ttl=64)
        / TCP(sport=54321, dport=80, flags="S")
        / Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    )
    # Rebuild from bytes so auto-computed fields (len, chksum) are set
    return IP(bytes(pkt))


@pytest.fixture()
def sample_packet_ip_udp():
    """IP/UDP packet (no DNS layer)."""
    from scapy.layers.inet import IP, UDP
    from scapy.packet import Raw

    pkt = (
        IP(src="192.168.1.50", dst="8.8.8.8")
        / UDP(sport=12345, dport=5353)
        / Raw(load=b"\x00" * 8)
    )
    return IP(bytes(pkt))


@pytest.fixture()
def sample_packet_dns():
    """IP/UDP/DNS query packet."""
    from scapy.layers.inet import IP, UDP
    from scapy.layers.dns import DNS, DNSQR

    pkt = (
        IP(src="192.168.1.10", dst="8.8.8.8")
        / UDP(sport=51234, dport=53)
        / DNS(
            id=0x1234,
            qr=0,
            qd=DNSQR(qname="example.com", qtype="A"),
        )
    )
    return pkt


@pytest.fixture()
def sample_packet_arp():
    """ARP request packet."""
    from scapy.layers.l2 import ARP, Ether

    pkt = (
        Ether(src="aa:bb:cc:dd:ee:ff", dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=1, hwsrc="aa:bb:cc:dd:ee:ff", psrc="192.168.1.1",
              hwdst="00:00:00:00:00:00", pdst="192.168.1.2")
    )
    return pkt


@pytest.fixture()
def sample_packet_icmp():
    """ICMP echo request (ping) packet."""
    from scapy.layers.inet import ICMP, IP

    pkt = IP(src="192.168.1.100", dst="8.8.8.8") / ICMP(type=8, code=0, id=0x1234, seq=1)
    return pkt


# ---------------------------------------------------------------------------
# Config fixture
# ---------------------------------------------------------------------------

@pytest.fixture()
def config_override():
    """Patch get_config to return a minimal test-friendly Config."""
    test_config = Config(
        capture=CaptureConfig(interface="lo0", bpf_filter=""),
        database=DatabaseConfig(path=":memory:"),
        api=ApiConfig(host="127.0.0.1", port=0),
        alerts=AlertsConfig(
            enabled=True,
            rules=[
                AlertRule(name="test_rule", condition="dst_port > 1000", severity="info", message="Port > 1000"),
            ],
        ),
    )
    with patch("config.settings.get_config", return_value=test_config):
        yield test_config
