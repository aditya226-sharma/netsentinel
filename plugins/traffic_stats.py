"""Traffic statistics plugin for NetSentinel.

Collects per-protocol packet counts, tracks top talking IP addresses,
and calculates packet and byte rates.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from typing import Any

from plugins.base import BasePlugin
from utils.logger import setup_logger

logger = setup_logger("netsentinel.plugins.traffic_stats")


class TrafficStatsPlugin(BasePlugin):
    """Collects and reports network traffic statistics.

    Maintains running counters for protocol distribution, top talkers
    and packet / byte rates updated each second.
    """

    def __init__(self) -> None:
        super().__init__()
        self._lock = threading.Lock()
        self._start_time: float = 0.0

        # Global counters
        self._total_packets: int = 0
        self._total_bytes: int = 0
        self._protocol_counts: dict[str, int] = defaultdict(int)

        # Per-second rate accumulator
        self._window_packets: int = 0
        self._window_bytes: int = 0
        self._window_start: float = 0.0
        self._current_pps: float = 0.0
        self._current_bps: float = 0.0
        self._peak_pps: float = 0.0
        self._peak_bps: float = 0.0

        # Top talkers (cumulative)
        self._ip_bytes: dict[str, int] = defaultdict(int)
        self._ip_packets: dict[str, int] = defaultdict(int)

    # ------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "traffic_stats"

    @property
    def description(self) -> str:
        return "Collects and reports traffic statistics"

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
        logger.info("TrafficStatsPlugin initialised")

    def process_packet(self, packet: dict[str, Any]) -> None:
        """Record statistics from a packet dict.

        Expected keys:
            ``protocol`` – e.g. ``"TCP"``, ``"UDP"``, ``"ICMP"``
            ``packet_length`` – total bytes captured
            ``src_ip`` / ``dst_ip`` – endpoint addresses
        """
        length = int(packet.get("packet_length", 0))
        protocol = str(packet.get("protocol", "UNKNOWN")).upper()
        src_ip = packet.get("src_ip", "")
        dst_ip = packet.get("dst_ip", "")

        with self._lock:
            self._total_packets += 1
            self._total_bytes += length
            self._protocol_counts[protocol] += 1

            self._window_packets += 1
            self._window_bytes += length

            if src_ip:
                self._ip_bytes[src_ip] += length
                self._ip_packets[src_ip] += 1
            if dst_ip:
                self._ip_bytes[dst_ip] += length
                self._ip_packets[dst_ip] += 1

            self._maybe_advance_window()

    def cleanup(self) -> None:
        logger.info("TrafficStatsPlugin cleaned up")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _maybe_advance_window(self) -> None:
        now = time.time()
        elapsed = now - self._window_start
        if elapsed < 1.0:
            return

        pps = self._window_packets / elapsed
        bps = self._window_bytes / elapsed
        self._current_pps = pps
        self._current_bps = bps

        if pps > self._peak_pps:
            self._peak_pps = pps
        if bps > self._peak_bps:
            self._peak_bps = bps

        self._window_packets = 0
        self._window_bytes = 0
        self._window_start = now

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            top_by_bytes = sorted(
                self._ip_bytes.items(), key=lambda kv: kv[1], reverse=True
            )[:20]
            top_by_packets = sorted(
                self._ip_packets.items(), key=lambda kv: kv[1], reverse=True
            )[:20]

        return {
            "total_packets": self._total_packets,
            "total_bytes": self._total_bytes,
            "protocol_distribution": dict(
                sorted(self._protocol_counts.items(), key=lambda kv: kv[1], reverse=True)
            ),
            "current_pps": round(self._current_pps, 2),
            "current_bps": round(self._current_bps, 2),
            "peak_pps": round(self._peak_pps, 2),
            "peak_bps": round(self._peak_bps, 2),
            "top_talkers_by_bytes": dict(top_by_bytes),
            "top_talkers_by_packets": dict(top_by_packets),
            "unique_ips": len(self._ip_bytes),
            "uptime_seconds": round(time.time() - self._start_time, 1)
            if self._start_time
            else 0,
        }

    def get_config_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "top_n": {
                    "type": "integer",
                    "default": 20,
                    "description": "Number of top talkers to include in stats",
                },
            },
        }
