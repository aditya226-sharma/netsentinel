"""Real-time bandwidth monitoring with sliding-window rate calculation.

Tracks inbound and outbound bytes using 1-second buckets for accurate
throughput measurement.  Maintains a history buffer for trend analysis.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet

from utils.logger import setup_logger

logger = setup_logger("netsentinel.modules.bandwidth_monitor")

_DEFAULT_HISTORY_SECONDS: int = 300
_BUCKET_INTERVAL: float = 1.0


class BandwidthMonitor:
    """Monitors real-time bandwidth usage with per-second resolution.

    Uses a sliding window of 1-second buckets to compute accurate
    instantaneous rates.  Supports both push (``process_packet``) and
    pull (``get_current_bandwidth``) access patterns.

    Usage:
        monitor = BandwidthMonitor()
        monitor.start()
        # ... in packet callback ...
        monitor.process_packet(pkt)
        stats = monitor.get_current_bandwidth()
        history = monitor.get_history(seconds=60)
        monitor.stop()
    """

    def __init__(self, interface: str | None = None) -> None:
        """Initialize the bandwidth monitor.

        Args:
            interface: Optional interface name for logging context.
        """
        self._interface = interface or ""
        self._lock = threading.Lock()

        self._bytes_in: int = 0
        self._bytes_out: int = 0
        self._total_bytes_in: int = 0
        self._total_bytes_out: int = 0
        self._total_packets: int = 0

        self._current_bucket_in: int = 0
        self._current_bucket_out: int = 0
        self._current_bucket_start: float = time.monotonic()

        self._history: deque[dict[str, Any]] = deque(
            maxlen=_DEFAULT_HISTORY_SECONDS
        )

        self._running: bool = False
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """Start the background sampling thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._sampling_loop,
            name="bandwidth-monitor",
            daemon=True,
        )
        self._thread.start()
        logger.info("Bandwidth monitor started (interface=%s)", self._interface or "(all)")

    def stop(self) -> None:
        """Stop the background sampling thread and flush the final bucket."""
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None
        self._flush_bucket()
        logger.info("Bandwidth monitor stopped")

    def _sampling_loop(self) -> None:
        """Background loop that snapshots each 1-second bucket."""
        while self._running:
            time.sleep(_BUCKET_INTERVAL)
            self._flush_bucket()

    def _flush_bucket(self) -> None:
        """Snapshot the current bucket into history and start a new one."""
        now = time.monotonic()
        with self._lock:
            self._history.append({
                "timestamp": time.time(),
                "bytes_per_sec_in": self._current_bucket_in,
                "bytes_per_sec_out": self._current_bucket_out,
            })
            self._bytes_in = self._current_bucket_in
            self._bytes_out = self._current_bucket_out
            self._current_bucket_in = 0
            self._current_bucket_out = 0
            self._current_bucket_start = now

    def process_packet(self, packet: Packet) -> None:
        """Count a packet's bytes into the current bucket.

        Determines direction by checking if the source IP is a local
        address (simplified heuristic).

        Args:
            packet: Scapy packet to measure.
        """
        try:
            pkt_len = len(packet)
            with self._lock:
                self._total_packets += 1

                is_outbound = True
                if packet.haslayer(IP):
                    src = packet[IP].src
                    if src.startswith("127.") or src.startswith("10.") or src.startswith("192.168.") or src.startswith("172."):
                        is_outbound = False

                self._current_bucket_in += pkt_len if not is_outbound else 0
                self._current_bucket_out += pkt_len if is_outbound else 0
                self._total_bytes_in += pkt_len if not is_outbound else 0
                self._total_bytes_out += pkt_len if is_outbound else 0

        except Exception as exc:
            logger.debug("Error processing packet for bandwidth: %s", exc)

    def get_current_bandwidth(self) -> dict[str, int]:
        """Return the most recent 1-second bandwidth snapshot.

        Returns:
            Dictionary with keys:
            ``bytes_per_sec_in``, ``bytes_per_sec_out``, ``total_bytes_in``,
            ``total_bytes_out``, ``total_packets``.
        """
        with self._lock:
            return {
                "bytes_per_sec_in": self._bytes_in,
                "bytes_per_sec_out": self._bytes_out,
                "total_bytes_in": self._total_bytes_in,
                "total_bytes_out": self._total_bytes_out,
                "total_packets": self._total_packets,
            }

    def get_history(self, seconds: int = 300) -> list[dict[str, Any]]:
        """Return historical bandwidth samples.

        Args:
            seconds: Number of seconds of history to return.

        Returns:
            List of timestamped bandwidth dictionaries, oldest first.
        """
        with self._lock:
            history = list(self._history)

        if seconds > 0 and len(history) > seconds:
            history = history[-seconds:]

        return history
