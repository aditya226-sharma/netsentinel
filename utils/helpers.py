"""Utility helper functions for NetSentinel."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone


def format_mac(mac_bytes: bytes | bytearray | tuple[int, ...]) -> str:
    """Format raw MAC address bytes into a colon-separated string.

    Args:
        mac_bytes: 6 bytes representing a MAC address.

    Returns:
        Formatted MAC string, e.g. "aa:bb:cc:dd:ee:ff".

    Raises:
        ValueError: If mac_bytes is not exactly 6 bytes.
    """
    if len(mac_bytes) != 6:
        raise ValueError(
            f"MAC address must be exactly 6 bytes, got {len(mac_bytes)}"
        )
    return ":".join(f"{b:02x}" for b in mac_bytes)


def format_ip(ip_bytes: bytes | bytearray | tuple[int, ...]) -> str:
    """Format raw IP address bytes into a dotted-quad string.

    Args:
        ip_bytes: 4 bytes representing an IPv4 address.

    Returns:
        Formatted IP string, e.g. "192.168.1.1".

    Raises:
        ValueError: If ip_bytes is not exactly 4 bytes.
    """
    if len(ip_bytes) != 4:
        raise ValueError(
            f"IP address must be exactly 4 bytes, got {len(ip_bytes)}"
        )
    return ".".join(str(b) for b in ip_bytes)


def human_readable_bytes(byte_count: int | float) -> str:
    """Convert a byte count into a human-readable string.

    Args:
        byte_count: Number of bytes.

    Returns:
        Human-readable string, e.g. "1.50 GB".
    """
    if byte_count < 0:
        raise ValueError("Byte count cannot be negative")

    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    value = float(byte_count)

    for unit in units:
        if abs(value) < 1024.0:
            if unit == "B":
                return f"{value:.0f} {unit}"
            return f"{value:.2f} {unit}"
        value /= 1024.0

    return f"{value:.2f} EB"


def human_readable_speed(bytes_per_sec: int | float) -> str:
    """Convert bytes per second into a human-readable speed string.

    Args:
        bytes_per_sec: Transfer rate in bytes per second.

    Returns:
        Human-readable speed string, e.g. "12.50 MB/s".
    """
    if bytes_per_sec < 0:
        raise ValueError("Bytes per second cannot be negative")

    units = ["B/s", "KB/s", "MB/s", "GB/s", "TB/s"]
    value = float(bytes_per_sec)

    for unit in units:
        if abs(value) < 1024.0:
            if unit == "B/s":
                return f"{value:.0f} {unit}"
            return f"{value:.2f} {unit}"
        value /= 1024.0

    return f"{value:.2f} PB/s"


def get_timestamp() -> str:
    """Get the current UTC timestamp in ISO 8601 format.

    Returns:
        ISO 8601 timestamp string, e.g. "2024-01-15T12:30:45.123456+00:00".
    """
    return datetime.now(timezone.utc).isoformat()


def safe_int(value: object, default: int = 0) -> int:
    """Safely convert a value to int, returning default on failure.

    Args:
        value: Value to convert.
        default: Value to return if conversion fails.

    Returns:
        The converted integer or the default.
    """
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def chunk_list(lst: list[object], size: int) -> list[list[object]]:
    """Split a list into chunks of a given size.

    Args:
        lst: List to chunk.
        size: Maximum size of each chunk. Must be > 0.

    Returns:
        List of sub-lists, each with at most `size` elements.

    Raises:
        ValueError: If size is not positive.
    """
    if size <= 0:
        raise ValueError(f"Chunk size must be positive, got {size}")
    return [lst[i:i + size] for i in range(0, len(lst), size)]


def generate_id() -> str:
    """Generate a unique identifier based on UUID4.

    Returns:
        A UUID4 string, e.g. "550e8400-e29b-41d4-a716-446655440000".
    """
    return str(uuid.uuid4())
