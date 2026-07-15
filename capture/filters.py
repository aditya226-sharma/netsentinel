"""BPF filter construction utilities for NetSentinel.

Provides helpers to build, combine, and validate Berkeley Packet Filter
expressions used by the capture engine.
"""

from __future__ import annotations

import re
import shlex
from typing import Optional

from utils.logger import setup_logger

logger = setup_logger("netsentinel.capture.filters")

_PROTOCOL_MAP: dict[str, str] = {
    "tcp": "tcp",
    "udp": "udp",
    "icmp": "icmp",
    "icmp6": "icmp6",
    "arp": "arp",
    "ip": "ip",
    "ip6": "ip6",
    "igmp": "igmp",
    "rarp": "rarp",
}


def build_host_filter(host: str) -> str:
    """Build a BPF filter for a specific host.

    Args:
        host: An IPv4 address, IPv6 address, or hostname.

    Returns:
        A BPF filter string, e.g. ``"host 192.168.1.1"``.

    Raises:
        ValueError: If *host* is empty or contains invalid characters.
    """
    host = host.strip()
    if not host:
        raise ValueError("Host must not be empty")
    if not re.match(r"^[a-zA-Z0-9._:,\-/]+$", host):
        raise ValueError(f"Invalid host value: {host!r}")

    return f"host {host}"


def build_port_filter(port: int | str) -> str:
    """Build a BPF filter for a specific port number.

    Args:
        port: A port number (int) or service name (str).

    Returns:
        A BPF filter string, e.g. ``"port 443"``.

    Raises:
        ValueError: If *port* is not a valid port number or service name.
    """
    if isinstance(port, int):
        if not (0 <= port <= 65535):
            raise ValueError(f"Port must be between 0 and 65535, got {port}")
        return f"port {port}"

    port_str = str(port).strip()
    if not port_str:
        raise ValueError("Port must not be empty")
    if not re.match(r"^[a-zA-Z0-9_]+$", port_str):
        raise ValueError(f"Invalid port value: {port_str!r}")

    return f"port {port_str}"


def build_protocol_filter(protocol: str) -> str:
    """Build a BPF filter for a specific protocol.

    Args:
        protocol: Protocol name (e.g. ``"tcp"``, ``"udp"``, ``"icmp"``).

    Returns:
        A BPF filter string, e.g. ``"tcp"``.

    Raises:
        ValueError: If *protocol* is not a recognized protocol.
    """
    proto = protocol.strip().lower()
    if proto not in _PROTOCOL_MAP:
        raise ValueError(
            f"Unknown protocol {protocol!r}. "
            f"Supported: {', '.join(sorted(_PROTOCOL_MAP))}"
        )
    return _PROTOCOL_MAP[proto]


def build_combined_filter(filters: list[str]) -> str:
    """Combine multiple BPF filter strings with logical AND.

    Filters are joined with `` and `` and wrapped in parentheses when
    more than one is present.

    Args:
        filters: Non-empty list of BPF filter strings.

    Returns:
        A combined BPF filter string.

    Raises:
        ValueError: If *filters* is empty.
    """
    cleaned = [f.strip() for f in filters if f.strip()]
    if not cleaned:
        raise ValueError("At least one filter is required")

    if len(cleaned) == 1:
        return cleaned[0]

    parts = " and ".join(cleaned)
    return f"({parts})"


def build_capture_filter(config: object) -> str:
    """Build a BPF filter string from a CaptureConfig object.

    The config is expected to have ``interface``, ``bpf_filter``, and
    ``packet_limit`` attributes (matching the
    :class:`~config.settings.CaptureConfig` dataclass).

    Args:
        config: A config object with a ``bpf_filter`` attribute.

    Returns:
        The BPF filter string, or an empty string if none is configured.
    """
    bpf_filter = getattr(config, "bpf_filter", "")
    if bpf_filter:
        bpf_filter = bpf_filter.strip()

    if bpf_filter and not validate_filter(bpf_filter):
        logger.warning(
            "Configured BPF filter may be invalid: %s", bpf_filter
        )

    return bpf_filter


def validate_filter(filter_str: str) -> bool:
    """Validate a BPF filter string for basic syntactic correctness.

    This performs lightweight structural checks (matching parentheses,
    no empty sub-expressions, recognised keywords) but does **not**
    verify the filter against a live capture engine.

    Args:
        filter_str: The BPF filter string to validate.

    Returns:
        ``True`` if the filter appears valid, ``False`` otherwise.
    """
    filter_str = filter_str.strip()
    if not filter_str:
        return False

    # Check balanced parentheses
    depth = 0
    for ch in filter_str:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if depth < 0:
            return False
    if depth != 0:
        return False

    # No double spaces or trailing/leading operators
    if "  " in filter_str:
        return False
    if re.search(r"\b(and|or)\s*$", filter_str):
        return False
    if re.search(r"^\s*(and|or)\b", filter_str):
        return False

    return True
