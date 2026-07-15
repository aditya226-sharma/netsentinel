"""Tests for utils.validators module."""

from __future__ import annotations

import pytest

from utils.validators import (
    validate_bpf_filter,
    validate_ip,
    validate_mac,
    validate_port,
)


# ---------------------------------------------------------------------------
# validate_ip
# ---------------------------------------------------------------------------

class TestValidateIp:
    """Tests for validate_ip function."""

    def test_validate_ip_valid(self) -> None:
        assert validate_ip("192.168.1.1") is True

    def test_validate_ip_loopback(self) -> None:
        assert validate_ip("127.0.0.1") is True

    def test_validate_ip_invalid_format(self) -> None:
        assert validate_ip("999.999.999.999") is False

    def test_validate_ip_empty_string(self) -> None:
        assert validate_ip("") is False

    def test_validate_ip_ipv6_rejected(self) -> None:
        """IPv6 addresses should not be accepted (function is IPv4-only)."""
        assert validate_ip("::1") is False

    def test_validate_ip_hostname_rejected(self) -> None:
        assert validate_ip("example.com") is False


# ---------------------------------------------------------------------------
# validate_mac
# ---------------------------------------------------------------------------

class TestValidateMac:
    """Tests for validate_mac function."""

    def test_validate_mac_valid_colon(self) -> None:
        assert validate_mac("aa:bb:cc:dd:ee:ff") is True

    def test_validate_mac_valid_dash(self) -> None:
        assert validate_mac("AA-BB-CC-DD-EE-FF") is True

    def test_validate_mac_valid_uppercase(self) -> None:
        assert validate_mac("AA:BB:CC:DD:EE:FF") is True

    def test_validate_mac_invalid_too_short(self) -> None:
        assert validate_mac("aa:bb:cc") is False

    def test_validate_mac_invalid_hex(self) -> None:
        assert validate_mac("zz:bb:cc:dd:ee:ff") is False

    def test_validate_mac_empty(self) -> None:
        assert validate_mac("") is False

    def test_validate_mac_no_separator(self) -> None:
        assert validate_mac("aabbccddeeff") is False


# ---------------------------------------------------------------------------
# validate_port
# ---------------------------------------------------------------------------

class TestValidatePort:
    """Tests for validate_port function."""

    def test_validate_port_valid(self) -> None:
        assert validate_port(80) is True

    def test_validate_port_string_number(self) -> None:
        assert validate_port("443") is True

    def test_validate_port_invalid_zero(self) -> None:
        assert validate_port(0) is False

    def test_validate_port_invalid_negative(self) -> None:
        assert validate_port(-1) is False

    def test_validate_port_invalid_too_high(self) -> None:
        assert validate_port(65536) is False

    def test_validate_port_boundary_min(self) -> None:
        assert validate_port(1) is True

    def test_validate_port_boundary_max(self) -> None:
        assert validate_port(65535) is True

    def test_validate_port_invalid_type(self) -> None:
        assert validate_port("not_a_port") is False

    def test_validate_port_none(self) -> None:
        assert validate_port(None) is False


# ---------------------------------------------------------------------------
# validate_bpf_filter
# ---------------------------------------------------------------------------

class TestValidateBpfFilter:
    """Tests for validate_bpf_filter function."""

    def test_validate_bpf_filter_valid_host(self) -> None:
        assert validate_bpf_filter("host 192.168.1.1") is True

    def test_validate_bpf_filter_valid_port(self) -> None:
        assert validate_bpf_filter("port 443") is True

    def test_validate_bpf_filter_valid_combined(self) -> None:
        assert validate_bpf_filter("tcp and port 80") is True

    def test_validate_bpf_filter_empty(self) -> None:
        assert validate_bpf_filter("") is False

    def test_validate_bpf_filter_whitespace_only(self) -> None:
        assert validate_bpf_filter("   ") is False

    def test_validate_bpf_filter_unbalanced_parens(self) -> None:
        assert validate_bpf_filter("(host 1.1.1.1") is False

    def test_validate_bpf_filter_no_known_token(self) -> None:
        assert validate_bpf_filter("foobarbaz") is False
