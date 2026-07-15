"""Device tracking plugin for NetSentinel.

Maintains a registry of seen network devices, tracks first/last-seen
timestamps, and reports newly discovered or currently active devices.
"""

from __future__ import annotations

import threading
import time
from typing import Any

from plugins.base import BasePlugin
from utils.helpers import get_timestamp
from utils.logger import setup_logger

logger = setup_logger("netsentinel.plugins.device_tracker")

_ACTIVITY_TIMEOUT: float = 300.0  # 5 minutes


class DeviceTrackerPlugin(BasePlugin):
    """Tracks network devices and their activity.

    Each device is keyed by MAC address and enriched with IP, hostname,
    vendor and activity timestamps.
    """

    def __init__(self) -> None:
        super().__init__()
        self._lock = threading.Lock()
        # mac -> device info dict
        self._devices: dict[str, dict[str, Any]] = {}
        self._new_device_count: int = 0
        self._start_time: float = 0.0

    # ------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "device_tracker"

    @property
    def description(self) -> str:
        return "Tracks network devices and their activity"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def author(self) -> str:
        return "NetSentinel"

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def initialize(self) -> None:
        self._start_time = time.time()
        logger.info("DeviceTrackerPlugin initialised")

    def process_packet(self, packet: dict[str, Any]) -> None:
        """Update the device registry from a packet dict.

        Expected keys:
            ``src_mac`` – source MAC address
            ``dst_mac`` – destination MAC address (optional)
            ``src_ip`` – source IP (optional)
            ``dst_ip`` – destination IP (optional)
        """
        src_mac = packet.get("src_mac", "")
        if src_mac:
            self._update_device(
                src_mac,
                ip=packet.get("src_ip", ""),
            )

        dst_mac = packet.get("dst_mac", "")
        if dst_mac and dst_mac != src_mac:
            self._update_device(
                dst_mac,
                ip=packet.get("dst_ip", ""),
            )

    def cleanup(self) -> None:
        logger.info("DeviceTrackerPlugin cleaned up")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _update_device(self, mac: str, ip: str = "") -> None:
        mac_lower = mac.lower()
        now = time.time()
        now_ts = get_timestamp()

        with self._lock:
            if mac_lower in self._devices:
                dev = self._devices[mac_lower]
                dev["last_seen"] = now_ts
                dev["last_seen_ts"] = now
                dev["is_active"] = True
                if ip and not dev.get("ip"):
                    dev["ip"] = ip
            else:
                self._devices[mac_lower] = {
                    "mac": mac_lower,
                    "ip": ip,
                    "hostname": "",
                    "vendor": "",
                    "first_seen": now_ts,
                    "last_seen": now_ts,
                    "first_seen_ts": now,
                    "last_seen_ts": now,
                    "is_active": True,
                }
                self._new_device_count += 1
                logger.info("New device discovered: %s (ip=%s)", mac_lower, ip)

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> dict[str, Any]:
        now = time.time()
        active = 0
        with self._lock:
            for dev in self._devices.values():
                last = dev.get("last_seen_ts", 0.0)
                if now - last <= _ACTIVITY_TIMEOUT:
                    active += 1
                else:
                    dev["is_active"] = False

            total = len(self._devices)
            recent = [
                dev for dev in self._devices.values()
                if now - dev.get("first_seen_ts", 0.0) <= 3600
            ]

        return {
            "total_devices": total,
            "active_devices": active,
            "new_devices": self._new_device_count,
            "recently_seen_1h": len(recent),
            "uptime_seconds": round(now - self._start_time, 1)
            if self._start_time
            else 0,
        }

    def get_device_list(self) -> list[dict[str, Any]]:
        """Return a copy of all tracked devices."""
        with self._lock:
            return [
                {k: v for k, v in dev.items() if not k.endswith("_ts")}
                for dev in self._devices.values()
            ]

    def get_config_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "activity_timeout": {
                    "type": "number",
                    "default": _ACTIVITY_TIMEOUT,
                    "description": "Seconds of inactivity before a device is marked inactive",
                },
            },
        }
