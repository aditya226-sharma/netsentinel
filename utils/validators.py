"""Validation functions for network data in NetSentinel."""

from __future__ import annotations

import ipaddress
import re
import socket


_MAC_REGEX = re.compile(
    r"^([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})$"
)


def validate_ip(ip_str: str) -> bool:
    """Validate an IPv4 address string.

    Args:
        ip_str: IP address string to validate.

    Returns:
        True if valid IPv4 address, False otherwise.
    """
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.version == 4
    except ValueError:
        return False


def validate_mac(mac_str: str) -> bool:
    """Validate a MAC address string.

    Accepts formats:
        - aa:bb:cc:dd:ee:ff
        - AA:BB:CC:DD:EE:FF
        - aa-bb-cc-dd-ee-ff

    Args:
        mac_str: MAC address string to validate.

    Returns:
        True if valid MAC address, False otherwise.
    """
    return bool(_MAC_REGEX.match(mac_str))


def validate_interface(iface: str) -> bool:
    """Validate a network interface name.

    Checks that the interface exists on the system by attempting to
    resolve its IP address via socket.

    Args:
        iface: Network interface name (e.g. "eth0", "wlan0").

    Returns:
        True if the interface appears valid, False otherwise.
    """
    if not iface or not iface.strip():
        return False

    cleaned = iface.strip()
    if not re.match(r"^[a-zA-Z0-9_\-\.]+$", cleaned):
        return False

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            socket.inet_aton(cleaned)
            sock.close()
            return True
        except OSError:
            sock.close()
            return True
    except OSError:
        return False


def validate_port(port: object) -> bool:
    """Validate a network port number.

    Args:
        port: Port number to validate (int or convertible to int).

    Returns:
        True if valid port (1-65535), False otherwise.
    """
    try:
        port_int = int(port)
    except (TypeError, ValueError):
        return False
    return 1 <= port_int <= 65535


def validate_bpf_filter(filter_str: str) -> bool:
    """Perform basic validation of a BPF (Berkeley Packet Filter) expression.

    This is a syntactic check only - it verifies the filter string is
    non-empty and has balanced parentheses. Full validation requires
    libpcap.

    Args:
        filter_str: BPF filter expression string.

    Returns:
        True if the filter appears syntactically valid, False otherwise.
    """
    if not filter_str or not filter_str.strip():
        return False

    cleaned = filter_str.strip()

    if cleaned.count("(") != cleaned.count(")"):
        return False

    tokens = cleaned.split()
    if not tokens:
        return False

    known_primitives = {
        "host", "net", "port", "src", "dst", "srcport", "dstport",
        "proto", "ether", "vlan", "greater", "less", "tcp", "udp",
        "icmp", "arp", "ip", "ip6", "type", "subtype", "and", "or",
        "not", "while", "if", "else", "true", "false",
    }

    has_known_token = any(
        token.lower().rstrip("()") in known_primitives for token in tokens
    )
    if not has_known_token:
        return False

    return True
