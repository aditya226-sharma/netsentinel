"""Per-packet traffic statistics aggregation.

Maintains protocol distribution, top talker / destination rankings,
and throughput counters using thread-safe sliding windows.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet

from database.db_manager import DatabaseManager
from utils.logger import setup_logger
from utils.helpers import get_timestamp, generate_id

logger = setup_logger("netsentinel.modules.traffic_stats")

_PROTOCOL_NAMES: dict[int, str] = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    58: "ICMPv6",
    89: "OSPF",
    132: "SCTP",
}

_RATE_WINDOW_SECONDS: int = 10
_STATS_FLUSH_INTERVAL: float = 60.0


class TrafficStats:
    """Computes real-time traffic statistics from observed packets.

    Tracks per-protocol counts, per-IP byte totals, and instantaneous
    packet / byte rates using 1-second sliding windows.

    Usage:
        stats = TrafficStats(db_manager)
        stats.process_packet(pkt)
        dist = stats.get_protocol_distribution()
        top = stats.get_top_talkers()
    """

    def __init__(self, db_manager: DatabaseManager, interface: str | None = None) -> None:
        self._db = db_manager
        self._interface = interface or ""
        self._lock = threading.Lock()

        self._total_packets: int = 0
        self._total_bytes: int = 0

        self._protocol_counts: dict[str, int] = {}
        self._ip_bytes: dict[str, int] = {}
        self._src_bytes: dict[str, int] = {}
        self._dst_bytes: dict[str, int] = {}

        self._pps_window: deque[tuple[float, int]] = deque(maxlen=600)
        self._bps_window: deque[tuple[float, int]] = deque(maxlen=600)

        self._last_flush: float = time.monotonic()

    def process_packet(self, packet: Packet) -> None:
        """Update statistics for a single packet.

        Increments protocol counters, per-IP byte counts, and appends
        a sample to the rate windows.

        Args:
            packet: Scapy packet to process.
        """
        try:
            pkt_len = len(packet)
            now = time.monotonic()

            with self._lock:
                self._total_packets += 1
                self._total_bytes += pkt_len

                proto_name = self._identify_protocol(packet)
                self._protocol_counts[proto_name] = self._protocol_counts.get(proto_name, 0) + 1

                if packet.haslayer(IP):
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    self._src_bytes[src_ip] = self._src_bytes.get(src_ip, 0) + pkt_len
                    self._dst_bytes[dst_ip] = self._dst_bytes.get(dst_ip, 0) + pkt_len
                    self._ip_bytes[src_ip] = self._ip_bytes.get(src_ip, 0) + pkt_len
                    self._ip_bytes[dst_ip] = self._ip_bytes.get(dst_ip, 0) + pkt_len

                self._pps_window.append((now, 1))
                self._bps_window.append((now, pkt_len))

            if now - self._last_flush > _STATS_FLUSH_INTERVAL:
                self._flush_to_database()

        except Exception as exc:
            logger.debug("Error updating traffic stats: %s", exc)

    def _identify_protocol(self, packet: Packet) -> str:
        """Determine the protocol name for a packet.

        Args:
            packet: Scapy packet.

        Returns:
            Human-readable protocol name.
        """
        if packet.haslayer(ICMP):
            return "ICMP"
        if packet.haslayer(TCP):
            return "TCP"
        if packet.haslayer(UDP):
            if packet.haslayer(Ether):
                eth_type = packet[Ether].type
                if eth_type == 0x0806:
                    return "ARP"
            return "UDP"
        if packet.haslayer(ARP):
            return "ARP"
        if packet.haslayer(IP):
            proto_num = packet[IP].proto
            return _PROTOCOL_NAMES.get(proto_num, f"IP-{proto_num}")
        if packet.haslayer(Ether):
            return f"Ether-0x{packet[Ether].type:04x}"
        return "Other"

    def _compute_rate(self, window: deque[tuple[float, int]], seconds: int) -> float:
        """Compute the average rate from a sliding window.

        Args:
            window: Deque of (timestamp, count) tuples.
            seconds: Look-back window in seconds.

        Returns:
            Average rate (packets or bytes per second).
        """
        now = time.monotonic()
        cutoff = now - seconds
        total = 0
        for ts, count in reversed(window):
            if ts < cutoff:
                break
            total += count
        return total / max(seconds, 1)

    def _flush_to_database(self) -> None:
        """Snapshot current stats into the database."""
        now = time.monotonic()
        with self._lock:
            self._last_flush = now
            pps = self._compute_rate(self._pps_window, _RATE_WINDOW_SECONDS)
            bps = self._compute_rate(self._bps_window, _RATE_WINDOW_SECONDS)
            proto_copy = dict(self._protocol_counts)

        try:
            self._db.insert_traffic_stat({
                "id": generate_id(),
                "timestamp": get_timestamp(),
                "interface": self._interface,
                "packets_per_sec": pps,
                "bytes_per_sec": bps,
                "protocol_counts": proto_copy,
            })
            logger.debug("Flushed traffic stats: pps=%.1f, bps=%.1f", pps, bps)
        except Exception as exc:
            logger.error("Failed to flush traffic stats: %s", exc)

    def get_protocol_distribution(self) -> dict[str, int]:
        """Return protocol packet counts.

        Returns:
            Dictionary mapping protocol name to packet count.
        """
        with self._lock:
            return dict(self._protocol_counts)

    def get_top_talkers(self, limit: int = 10) -> list[tuple[str, int]]:
        """Return the highest-volume source IP addresses.

        Args:
            limit: Number of top talkers to return.

        Returns:
            List of (ip, total_bytes) tuples sorted descending.
        """
        with self._lock:
            sorted_ips = sorted(
                self._src_bytes.items(), key=lambda x: x[1], reverse=True
            )
        return sorted_ips[:limit]

    def get_top_destinations(self, limit: int = 10) -> list[tuple[str, int]]:
        """Return the highest-volume destination IP addresses.

        Args:
            limit: Number of top destinations to return.

        Returns:
            List of (ip, total_bytes) tuples sorted descending.
        """
        with self._lock:
            sorted_ips = sorted(
                self._dst_bytes.items(), key=lambda x: x[1], reverse=True
            )
        return sorted_ips[:limit]

    def get_packets_per_second(self) -> float:
        """Return the current packets-per-second rate.

        Returns:
            Average pps over the last 10-second window.
        """
        with self._lock:
            return self._compute_rate(self._pps_window, _RATE_WINDOW_SECONDS)

    def get_bytes_per_second(self) -> float:
        """Return the current bytes-per-second rate.

        Returns:
            Average bps over the last 10-second window.
        """
        with self._lock:
            return self._compute_rate(self._bps_window, _RATE_WINDOW_SECONDS)

    def get_total_packets(self) -> int:
        """Return the total number of packets processed since creation.

        Returns:
            Total packet count.
        """
        with self._lock:
            return self._total_packets

    def get_total_bytes(self) -> int:
        """Return the total number of bytes processed since creation.

        Returns:
            Total byte count.
        """
        with self._lock:
            return self._total_bytes
