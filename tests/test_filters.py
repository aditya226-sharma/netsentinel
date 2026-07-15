"""Tests for capture.filters module."""

from __future__ import annotations

import pytest

from capture.filters import (
    build_capture_filter,
    build_combined_filter,
    build_host_filter,
    build_port_filter,
    build_protocol_filter,
    validate_filter,
)


# ---------------------------------------------------------------------------
# build_host_filter
# ---------------------------------------------------------------------------

class TestBuildHostFilter:
    """Tests for build_host_filter."""

    def test_build_host_filter(self) -> None:
        assert build_host_filter("192.168.1.1") == "host 192.168.1.1"

    def test_build_host_filter_hostname(self) -> None:
        assert build_host_filter("example.com") == "host example.com"

    def test_build_host_filter_ipv6(self) -> None:
        result = build_host_filter("2001:db8::1")
        assert result == "host 2001:db8::1"

    def test_build_host_filter_empty_raises(self) -> None:
        with pytest.raises(ValueError, match="must not be empty"):
            build_host_filter("")

    def test_build_host_filter_invalid_chars_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid host"):
            build_host_filter("192.168.1.1; rm -rf /")


# ---------------------------------------------------------------------------
# build_port_filter
# ---------------------------------------------------------------------------

class TestBuildPortFilter:
    """Tests for build_port_filter."""

    def test_build_port_filter(self) -> None:
        assert build_port_filter(443) == "port 443"

    def test_build_port_filter_string(self) -> None:
        assert build_port_filter("http") == "port http"

    def test_build_port_filter_invalid_negative(self) -> None:
        with pytest.raises(ValueError, match="between 0 and 65535"):
            build_port_filter(-1)

    def test_build_port_filter_invalid_high(self) -> None:
        with pytest.raises(ValueError, match="between 0 and 65535"):
            build_port_filter(70000)


# ---------------------------------------------------------------------------
# build_protocol_filter
# ---------------------------------------------------------------------------

class TestBuildProtocolFilter:
    """Tests for build_protocol_filter."""

    def test_build_protocol_filter_tcp(self) -> None:
        assert build_protocol_filter("tcp") == "tcp"

    def test_build_protocol_filter_udp(self) -> None:
        assert build_protocol_filter("udp") == "udp"

    def test_build_protocol_filter_icmp(self) -> None:
        assert build_protocol_filter("icmp") == "icmp"

    def test_build_protocol_filter_case_insensitive(self) -> None:
        assert build_protocol_filter("TCP") == "tcp"

    def test_build_protocol_filter_unknown_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown protocol"):
            build_protocol_filter("sparql")


# ---------------------------------------------------------------------------
# build_combined_filter
# ---------------------------------------------------------------------------

class TestBuildCombinedFilter:
    """Tests for build_combined_filter."""

    def test_build_combined_filter(self) -> None:
        result = build_combined_filter(["host 10.0.0.1", "port 80"])
        assert result == "(host 10.0.0.1 and port 80)"

    def test_build_combined_filter_single(self) -> None:
        result = build_combined_filter(["tcp"])
        assert result == "tcp"

    def test_build_combined_filter_empty_raises(self) -> None:
        with pytest.raises(ValueError, match="At least one filter"):
            build_combined_filter([])

    def test_build_combined_filter_whitespace_ignored(self) -> None:
        result = build_combined_filter(["  ", "port 443", "  "])
        assert result == "port 443"


# ---------------------------------------------------------------------------
# build_capture_filter
# ---------------------------------------------------------------------------

class TestBuildCaptureFilter:
    """Tests for build_capture_filter."""

    def test_build_capture_filter_with_value(self) -> None:
        config = type("Cfg", (), {"bpf_filter": "tcp port 443"})()
        assert build_capture_filter(config) == "tcp port 443"

    def test_build_capture_filter_empty(self) -> None:
        config = type("Cfg", (), {"bpf_filter": ""})()
        assert build_capture_filter(config) == ""

    def test_build_capture_filter_no_attr(self) -> None:
        assert build_capture_filter(object()) == ""


# ---------------------------------------------------------------------------
# validate_filter
# ---------------------------------------------------------------------------

class TestValidateFilter:
    """Tests for validate_filter."""

    def test_validate_filter_valid(self) -> None:
        assert validate_filter("host 192.168.1.1") is True

    def test_validate_filter_combined(self) -> None:
        assert validate_filter("(tcp and port 80)") is True

    def test_validate_filter_empty(self) -> None:
        assert validate_filter("") is False

    def test_validate_filter_invalid_double_space(self) -> None:
        assert validate_filter("host  1.1.1.1") is False

    def test_validate_filter_invalid_trailing_and(self) -> None:
        assert validate_filter("tcp and") is False

    def test_validate_filter_invalid_leading_or(self) -> None:
        assert validate_filter("or tcp") is False

    def test_validate_filter_unbalanced_open(self) -> None:
        assert validate_filter("(tcp and port 80") is False

    def test_validate_filter_unbalanced_close(self) -> None:
        assert validate_filter("tcp and port 80)") is False

    def test_validate_filter_negative_depth(self) -> None:
        assert validate_filter(")tcp(") is False
