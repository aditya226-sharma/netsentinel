"""Bandwidth monitoring plugin for NetSentinel.

Tracks bytes in/out per interface per second, detects spikes and reports
peak and total byte counts.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from typing import Any

from plugins.base import BasePlugin
from utils.logger import setup_logger

logger = setup_logger("netsentinel.plugins.bandwidth_monitor")

_SPIKE_THRESHOLD_BPS: float = 10 * 1024 * 1024  # 10 MB/s


class BandwidthMonitorPlugin(BasePlugin):
    """Monitors bandwidth usage per interface and detects spikes.

    Maintains a sliding window of bytes-per-second readings and exposes
    current, peak and total byte counts via :meth:`get_stats`.
    """

    def __init__(self) -> None:
        super().__init__()
        self._lock = threading.Lock()
        self._start_time: float = 0.0

        # Per-interface counters
        self._bytes_in: dict[str, int] = defaultdict(int)
        self._bytes_out: dict[str, int] = defaultdict(int)
        self._total_bytes_in: int = 0
        self._total_bytes_out: int = 0

        # Per-second rate tracking
        self._current_bps_in: dict[str, float] = defaultdict(float)
        self._current_bps_out: dict[str, float] = defaultdict(float)
        self._peak_bps_in: dict[str, float] = defaultdict(float)
        self._peak_bps_out: dict[str, float] = defaultdict(float)

        # Accumulator for the current second window
        self._window_bytes_in: dict[str, int] = defaultdict(int)
        self._window_bytes_out: dict[str, int] = defaultdict(int)
        self._window_start: float = time.time()

        self._spike_count: int = 0

    # ------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "bandwidth_monitor"

    @property
    def description(self) -> str:
        return "Monitors bandwidth usage per interface"

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
        self._window_start = self._start_time
        logger.info("BandwidthMonitorPlugin initialised")

    def process_packet(self, packet: dict[str, Any]) -> None:
        """Accumulate byte counts from a packet dict.

        Expected keys:
            ``packet_length`` – total captured bytes
            ``direction`` – ``"inbound"`` or ``"outbound"``
            ``interface`` – interface name (default ``"default"``)
        """
        length = int(packet.get("packet_length", 0))
        if length <= 0:
            return

        direction = str(packet.get("direction", "")).lower()
        iface = packet.get("interface", "default")

        with self._lock:
            if direction == "outbound":
                self._bytes_out[iface] += length
                self._total_bytes_out += length
                self._window_bytes_out[iface] += length
            else:
                self._bytes_in[iface] += length
                self._total_bytes_in += length
                self._window_bytes_in[iface] += length

            self._maybe_advance_window()

    def cleanup(self) -> None:
        logger.info("BandwidthMonitorPlugin cleaned up")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _maybe_advance_window(self) -> None:
        """Recalculate per-second rates if at least one second has elapsed."""
        now = time.time()
        elapsed = now - self._window_start
        if elapsed < 1.0:
            return

        all_ifaces = set(self._window_bytes_in) | set(self._window_bytes_out)
        for iface in all_ifaces:
            bps_in = self._window_bytes_in[iface] / elapsed
            bps_out = self._window_bytes_out[iface] / elapsed
            self._current_bps_in[iface] = bps_in
            self._current_bps_out[iface] = bps_out

            if bps_in > self._peak_bps_in[iface]:
                self._peak_bps_in[iface] = bps_in
            if bps_out > self._peak_bps_out[iface]:
                self._peak_bps_out[iface] = bps_out

            if bps_in > _SPIKE_THRESHOLD_BPS or bps_out > _SPIKE_THRESHOLD_BPS:
                self._spike_count += 1

        self._window_bytes_in.clear()
        self._window_bytes_out.clear()
        self._window_start = now

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> dict[str, Any]:
        interfaces: dict[str, dict[str, Any]] = {}
        all_ifaces = (
            set(self._bytes_in)
            | set(self._bytes_out)
            | set(self._current_bps_in)
        )
        for iface in sorted(all_ifaces):
            interfaces[iface] = {
                "total_bytes_in": self._bytes_in[iface],
                "total_bytes_out": self._bytes_out[iface],
                "current_bps_in": round(self._current_bps_in.get(iface, 0.0), 2),
                "current_bps_out": round(self._current_bps_out.get(iface, 0.0), 2),
                "peak_bps_in": round(self._peak_bps_in.get(iface, 0.0), 2),
                "peak_bps_out": round(self._peak_bps_out.get(iface, 0.0), 2),
            }

        return {
            "total_bytes_in": self._total_bytes_in,
            "total_bytes_out": self._total_bytes_out,
            "spike_count": self._spike_count,
            "interfaces": interfaces,
            "uptime_seconds": round(time.time() - self._start_time, 1)
            if self._start_time
            else 0,
        }

    def get_config_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "spike_threshold_bps": {
                    "type": "number",
                    "default": _SPIKE_THRESHOLD_BPS,
                    "description": "Bytes/sec threshold for spike detection",
                },
            },
        }
