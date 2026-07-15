"""Bidirectional network flow tracking and lifecycle management.

Defines flows by the 5-tuple (src_ip, dst_ip, src_port, dst_port,
protocol) and automatically expires inactive entries after a
configurable timeout.
"""

from __future__ import annotations

import threading
import time
from typing import Any

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet

from database.db_manager import DatabaseManager
from utils.logger import setup_logger
from utils.helpers import generate_id, get_timestamp

logger = setup_logger("netsentinel.modules.flow_monitor")

_DEFAULT_FLOW_TIMEOUT: float = 300.0
_EXPIRY_CHECK_INTERVAL: float = 30.0
_PROTOCOL_MAP: dict[int, str] = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    58: "ICMPv6",
}


class FlowMonitor:
    """Tracks active network flows and expires stale entries.

    A flow is identified by the canonical 5-tuple and records
    byte/packet counters in each direction.

    Usage:
        monitor = FlowMonitor(db_manager)
        monitor.process_packet(pkt)
        active = monitor.get_active_flows()
        stats = monitor.get_flow_stats()
    """

    def __init__(
        self,
        db_manager: DatabaseManager,
        flow_timeout: float = _DEFAULT_FLOW_TIMEOUT,
    ) -> None:
        """Initialize the flow monitor.

        Args:
            db_manager: Database handle for persisting completed flows.
            flow_timeout: Seconds of inactivity before a flow is expired.
        """
        self._db = db_manager
        self._flow_timeout = flow_timeout
        self._lock = threading.Lock()

        self._active_flows: dict[str, dict[str, Any]] = {}
        self._expired_flows: list[dict[str, Any]] = []
        self._total_flows: int = 0

    def _make_flow_key(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
    ) -> str:
        """Build a canonical flow key string.

        The key is constructed so that the lower IP/port pair is always
        first, making the flow direction-agnostic.

        Args:
            src_ip: Source IP address.
            dst_ip: Destination IP address.
            src_port: Source port.
            dst_port: Destination port.
            protocol: Protocol name (e.g. ``"TCP"``).

        Returns:
            Canonical flow key.
        """
        a = (src_ip, src_port)
        b = (dst_ip, dst_port)
        if a <= b:
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"

    def process_packet(self, packet: Packet) -> None:
        """Update flow state for an observed packet.

        Creates a new flow entry if one does not exist, or updates
        byte/packet counters and timestamps on an existing flow.

        Args:
            packet: Scapy packet to process.
        """
        try:
            if not packet.haslayer(IP):
                return

            ip = packet[IP]
            src_ip = ip.src
            dst_ip = ip.dst
            src_port = 0
            dst_port = 0
            protocol_num = ip.proto
            protocol_name = _PROTOCOL_MAP.get(protocol_num, f"IP-{protocol_num}")

            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                protocol_name = "TCP"
            elif packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                protocol_name = "UDP"

            pkt_len = len(packet)
            now = time.time()
            flow_key = self._make_flow_key(
                src_ip, dst_ip, src_port, dst_port, protocol_name
            )

            with self._lock:
                if flow_key in self._active_flows:
                    flow = self._active_flows[flow_key]
                    flow["last_seen"] = now
                    flow["packets"] = flow.get("packets", 0) + 1
                    flow["bytes"] = flow.get("bytes", 0) + pkt_len

                    if src_ip == flow.get("original_src"):
                        flow["src_bytes"] = flow.get("src_bytes", 0) + pkt_len
                        flow["src_packets"] = flow.get("src_packets", 0) + 1
                    else:
                        flow["dst_bytes"] = flow.get("dst_bytes", 0) + pkt_len
                        flow["dst_packets"] = flow.get("dst_packets", 0) + 1
                else:
                    self._active_flows[flow_key] = {
                        "id": generate_id(),
                        "flow_key": flow_key,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "protocol": protocol_name,
                        "packets": 1,
                        "bytes": pkt_len,
                        "src_bytes": pkt_len,
                        "dst_bytes": 0,
                        "src_packets": 1,
                        "dst_packets": 0,
                        "original_src": src_ip,
                        "first_seen": now,
                        "last_seen": now,
                        "start_time": get_timestamp(),
                    }
                    self._total_flows += 1

            if len(self._active_flows) % 1000 == 0:
                self._expire_flows()

        except Exception as exc:
            logger.debug("Error processing packet for flow monitor: %s", exc)

    def _expire_flows(self) -> None:
        """Expire flows that have been inactive longer than the timeout.

        Completed flows are flushed to the database and moved to the
        expired list.
        """
        now = time.time()
        expired_keys: list[str] = []

        with self._lock:
            for key, flow in self._active_flows.items():
                if now - flow["last_seen"] > self._flow_timeout:
                    expired_keys.append(key)

            for key in expired_keys:
                flow = self._active_flows.pop(key)
                flow["end_time"] = get_timestamp()
                flow["duration"] = flow["last_seen"] - flow["first_seen"]
                self._expired_flows.append(flow)

                if len(self._expired_flows) > 10000:
                    self._expired_flows = self._expired_flows[-5000:]

        if expired_keys:
            self._flush_expired_to_database()
            logger.debug("Expired %d flows", len(expired_keys))

    def _flush_expired_to_database(self) -> None:
        """Persist expired flows to the database."""
        with self._lock:
            flows_to_flush = [
                f for f in self._expired_flows if not f.get("_flushed")
            ]
            for f in flows_to_flush:
                f["_flushed"] = True

        for flow in flows_to_flush:
            try:
                self._db.insert_session({
                    "id": flow["id"],
                    "src_ip": flow["src_ip"],
                    "dst_ip": flow["dst_ip"],
                    "src_port": flow["src_port"],
                    "dst_port": flow["dst_port"],
                    "protocol": flow["protocol"],
                    "packets": flow["packets"],
                    "bytes": flow["bytes"],
                    "start_time": flow["start_time"],
                    "end_time": flow["end_time"],
                })
            except Exception as exc:
                logger.debug("Failed to persist flow %s: %s", flow["id"], exc)

    def get_active_flows(self) -> list[dict[str, Any]]:
        """Return all currently active flows.

        Returns:
            List of flow dictionaries.
        """
        self._expire_flows()
        with self._lock:
            return [
                {k: v for k, v in f.items() if not k.startswith("_")}
                for f in self._active_flows.values()
            ]

    def get_flow_by_id(self, flow_id: str) -> dict[str, Any] | None:
        """Look up a flow by its unique ID.

        Args:
            flow_id: UUID of the flow to find.

        Returns:
            Flow dictionary or ``None`` if not found.
        """
        with self._lock:
            for flow in self._active_flows.values():
                if flow["id"] == flow_id:
                    return {k: v for k, v in flow.items() if not k.startswith("_")}

        for flow in self._expired_flows:
            if flow["id"] == flow_id:
                return {k: v for k, v in flow.items() if not k.startswith("_")}

        return None

    def get_flow_stats(self) -> dict[str, Any]:
        """Return aggregate flow statistics.

        Returns:
            Dictionary with keys:
            ``active_flows``, ``total_flows``, ``avg_duration``,
            ``total_bytes``, ``total_packets``.
        """
        self._expire_flows()
        with self._lock:
            active = len(self._active_flows)
            total = self._total_flows

            total_bytes = 0
            total_packets = 0
            for flow in self._active_flows.values():
                total_bytes += flow.get("bytes", 0)
                total_packets += flow.get("packets", 0)

            durations = [
                f.get("duration", 0) for f in self._expired_flows
                if f.get("duration")
            ]
            avg_duration = sum(durations) / len(durations) if durations else 0.0

        return {
            "active_flows": active,
            "total_flows": total,
            "avg_duration": round(avg_duration, 2),
            "total_bytes": total_bytes,
            "total_packets": total_packets,
        }
