"""Network interface detection and enumeration module.

Provides a cached view of available network interfaces on the host,
including IP addresses, MAC addresses, link speed, and status.
"""

from __future__ import annotations

import time
from typing import Any

import psutil
from scapy.arch import get_if_list, get_if_hwaddr
from scapy.config import conf

from utils.logger import setup_logger
from utils.helpers import format_mac, get_timestamp

logger = setup_logger("netsentinel.modules.interface_detector")

_CACHE_TTL: float = 30.0


class InterfaceDetector:
    """Detects and enumerates local network interfaces.

    Caches results for 30 seconds to avoid repeated syscalls during
    high-frequency packet processing.

    Usage:
        detector = InterfaceDetector()
        interfaces = detector.get_interfaces()
        default_iface = detector.get_default_interface()
    """

    def __init__(self) -> None:
        self._cache: list[dict[str, Any]] = []
        self._cache_timestamp: float = 0.0
        self._default_gateway_interface: str = ""

    def _is_cache_valid(self) -> bool:
        """Check whether the cached interface list is still fresh."""
        return (
            bool(self._cache)
            and (time.monotonic() - self._cache_timestamp) < _CACHE_TTL
        )

    def _build_interface_entry(self, if_name: str) -> dict[str, Any] | None:
        """Build a single interface info dictionary.

        Args:
            if_name: Operating system interface name.

        Returns:
            Dictionary with interface metadata, or None on failure.
        """
        try:
            stats = psutil.net_if_stats().get(if_name)
            addrs = psutil.net_if_addrs().get(if_name, [])

            ip_addr = ""
            mac_addr = ""
            for addr in addrs:
                if addr.family == 2 and not ip_addr:  # AF_INET
                    ip_addr = addr.address
                if addr.family == 17 and not mac_addr:  # AF_LINK (macOS)
                    mac_addr = addr.address.lower()

            if not mac_addr:
                try:
                    raw_mac = get_if_hwaddr(if_name)
                    mac_addr = raw_mac.lower()
                except Exception:
                    mac_addr = ""

            status = "up" if (stats and stats.isup) else "down"
            speed = stats.speed if stats else 0

            iface_type = "loopback" if if_name == "lo" or if_name.startswith("lo") else "ethernet"
            if "en" in if_name or "eth" in if_name or "en0" in if_name:
                iface_type = "ethernet"
            elif "bridge" in if_name.lower():
                iface_type = "bridge"
            elif "utun" in if_name.lower() or "tun" in if_name.lower():
                iface_type = "tunnel"
            elif "awdl" in if_name.lower():
                iface_type = "wireless_direct"
            elif "vlan" in if_name.lower():
                iface_type = "vlan"

            return {
                "name": if_name,
                "ip": ip_addr,
                "mac": mac_addr,
                "speed": speed,
                "status": status,
                "type": iface_type,
            }
        except Exception as exc:
            logger.debug("Failed to build entry for interface %s: %s", if_name, exc)
            return None

    def _refresh_cache(self) -> None:
        """Rebuild the interface cache from system data."""
        entries: list[dict[str, Any]] = []
        try:
            for if_name in get_if_list():
                entry = self._build_interface_entry(if_name)
                if entry is not None:
                    entries.append(entry)
        except Exception as exc:
            logger.error("Failed to enumerate interfaces: %s", exc)

        self._cache = entries
        self._cache_timestamp = time.monotonic()
        logger.debug("Interface cache refreshed with %d entries", len(entries))

    def get_interfaces(self) -> list[dict[str, Any]]:
        """Return a list of all detected network interfaces.

        Returns:
            List of dictionaries, each with keys:
            ``name``, ``ip``, ``mac``, ``speed``, ``status``, ``type``.
        """
        if not self._is_cache_valid():
            self._refresh_cache()
        return list(self._cache)

    def get_active_interfaces(self) -> list[dict[str, Any]]:
        """Return only interfaces that are currently up.

        Returns:
            List of interface dictionaries where ``status == "up"``.
        """
        return [iface for iface in self.get_interfaces() if iface["status"] == "up"]

    def get_interface_by_name(self, name: str) -> dict[str, Any] | None:
        """Look up a single interface by its OS name.

        Args:
            name: Interface name (e.g. ``"en0"``, ``"eth0"``).

        Returns:
            Interface dictionary, or ``None`` if not found.
        """
        for iface in self.get_interfaces():
            if iface["name"] == name:
                return iface
        return None

    def get_default_interface(self) -> str:
        """Determine the default gateway interface.

        Checks the routing table for the interface attached to the
        default route, falling back to the first active non-loopback
        interface.

        Returns:
            Interface name string.
        """
        if self._default_gateway_interface:
            cached = self.get_interface_by_name(self._default_gateway_interface)
            if cached and cached["status"] == "up":
                return self._default_gateway_interface

        try:
            import subprocess
            result = subprocess.run(
                ["route", "-n", "get", "default"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            for line in result.stdout.splitlines():
                stripped = line.strip()
                if stripped.startswith("interface:"):
                    iface_name = stripped.split(":", 1)[1].strip()
                    if iface_name:
                        self._default_gateway_interface = iface_name
                        logger.debug("Default interface detected: %s", iface_name)
                        return iface_name
        except Exception as exc:
            logger.debug("Route lookup failed, using fallback: %s", exc)

        for iface in self.get_active_interfaces():
            if iface["type"] in ("ethernet", "wireless_direct") and iface["ip"]:
                self._default_gateway_interface = iface["name"]
                logger.debug("Default interface fallback: %s", iface["name"])
                return iface["name"]

        logger.warning("No suitable default interface found")
        return ""
