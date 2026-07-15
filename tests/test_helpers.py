"""Tests for utils.helpers module."""

from __future__ import annotations

import re

import pytest

from utils.helpers import (
    chunk_list,
    format_ip,
    format_mac,
    generate_id,
    get_timestamp,
    human_readable_bytes,
    human_readable_speed,
    safe_int,
)


# ---------------------------------------------------------------------------
# format_mac
# ---------------------------------------------------------------------------

class TestFormatMac:
    """Tests for format_mac utility function."""

    def test_format_mac_valid(self) -> None:
        """Colon-separated lowercase hex output for valid 6-byte tuple."""
        result = format_mac((0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF))
        assert result == "aa:bb:cc:dd:ee:ff"

    def test_format_mac_bytes(self) -> None:
        """Handles raw bytes input as well as tuples."""
        result = format_mac(b"\x01\x02\x03\x04\x05\x06")
        assert result == "01:02:03:04:05:06"

    def test_format_mac_short_raises(self) -> None:
        """ValueError raised for fewer than 6 bytes."""
        with pytest.raises(ValueError, match="exactly 6 bytes"):
            format_mac(b"\x01\x02\x03")

    def test_format_mac_long_raises(self) -> None:
        """ValueError raised for more than 6 bytes."""
        with pytest.raises(ValueError, match="exactly 6 bytes"):
            format_mac(b"\x01\x02\x03\x04\x05\x06\x07")


# ---------------------------------------------------------------------------
# format_ip
# ---------------------------------------------------------------------------

class TestFormatIp:
    """Tests for format_ip utility function."""

    def test_format_ip_valid(self) -> None:
        """Dotted-quad string for valid 4-byte input."""
        result = format_ip((192, 168, 1, 1))
        assert result == "192.168.1.1"

    def test_format_ip_bytes(self) -> None:
        """Accepts raw bytes."""
        result = format_ip(b"\x0a\x00\x00\x01")
        assert result == "10.0.0.1"

    def test_format_ip_wrong_length_raises(self) -> None:
        """ValueError for non-4-byte input."""
        with pytest.raises(ValueError, match="exactly 4 bytes"):
            format_ip(b"\x01\x02")


# ---------------------------------------------------------------------------
# human_readable_bytes
# ---------------------------------------------------------------------------

class TestHumanReadableBytes:
    """Tests for human_readable_bytes utility function."""

    def test_zero_bytes(self) -> None:
        assert human_readable_bytes(0) == "0 B"

    def test_kilobytes(self) -> None:
        assert human_readable_bytes(1024) == "1.00 KB"

    def test_megabytes(self) -> None:
        result = human_readable_bytes(1024 * 1024 * 5)
        assert result == "5.00 MB"

    def test_gigabytes(self) -> None:
        result = human_readable_bytes(1024 ** 3 * 2)
        assert result == "2.00 GB"

    def test_fractional(self) -> None:
        result = human_readable_bytes(1536)  # 1.5 KB
        assert result == "1.50 KB"

    def test_negative_raises(self) -> None:
        with pytest.raises(ValueError, match="cannot be negative"):
            human_readable_bytes(-1)


# ---------------------------------------------------------------------------
# human_readable_speed
# ---------------------------------------------------------------------------

class TestHumanReadableSpeed:
    """Tests for human_readable_speed utility function."""

    def test_zero_speed(self) -> None:
        assert human_readable_speed(0) == "0 B/s"

    def test_kilobytes_per_sec(self) -> None:
        assert human_readable_speed(2048) == "2.00 KB/s"

    def test_megabytes_per_sec(self) -> None:
        assert human_readable_speed(1024 ** 2 * 10) == "10.00 MB/s"

    def test_negative_raises(self) -> None:
        with pytest.raises(ValueError, match="cannot be negative"):
            human_readable_speed(-5)


# ---------------------------------------------------------------------------
# get_timestamp
# ---------------------------------------------------------------------------

class TestGetTimestamp:
    """Tests for get_timestamp utility function."""

    def test_get_timestamp_format(self) -> None:
        """Returns an ISO 8601 string with UTC offset."""
        ts = get_timestamp()
        assert isinstance(ts, str)
        # ISO 8601 pattern: YYYY-MM-DDTHH:MM:SS.ffffff+00:00
        assert re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", ts)


# ---------------------------------------------------------------------------
# safe_int
# ---------------------------------------------------------------------------

class TestSafeInt:
    """Tests for safe_int utility function."""

    def test_safe_int_valid(self) -> None:
        assert safe_int("42") == 42

    def test_safe_int_int_input(self) -> None:
        assert safe_int(7) == 7

    def test_safe_int_invalid(self) -> None:
        assert safe_int("not_a_number") == 0

    def test_safe_int_custom_default(self) -> None:
        assert safe_int(None, default=-1) == -1

    def test_safe_int_bool_passthrough(self) -> None:
        """Booleans pass through int conversion (bool is int subclass)."""
        assert safe_int(True) == 1
        assert safe_int(False) == 0


# ---------------------------------------------------------------------------
# chunk_list
# ---------------------------------------------------------------------------

class TestChunkList:
    """Tests for chunk_list utility function."""

    def test_chunk_list(self) -> None:
        result = chunk_list([1, 2, 3, 4, 5], 2)
        assert result == [[1, 2], [3, 4], [5]]

    def test_chunk_list_exact(self) -> None:
        result = chunk_list([1, 2, 3, 4], 2)
        assert result == [[1, 2], [3, 4]]

    def test_chunk_list_empty(self) -> None:
        assert chunk_list([], 3) == []

    def test_chunk_list_size_zero_raises(self) -> None:
        with pytest.raises(ValueError, match="positive"):
            chunk_list([1, 2], 0)


# ---------------------------------------------------------------------------
# generate_id
# ---------------------------------------------------------------------------

class TestGenerateId:
    """Tests for generate_id utility function."""

    def test_generate_id_unique(self) -> None:
        """Two generated IDs must differ."""
        id1 = generate_id()
        id2 = generate_id()
        assert id1 != id2

    def test_generate_id_format(self) -> None:
        """IDs are UUID4 strings."""
        uid = generate_id()
        parts = uid.split("-")
        assert len(parts) == 5
        assert len(uid) == 36
