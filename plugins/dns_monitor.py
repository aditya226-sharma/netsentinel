"""DNS monitoring plugin for NetSentinel.

Tracks DNS query counts, unique domains, error rates and suspicious
patterns such as high NXDOMAIN responses or unusually long query names.
"""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Any

from plugins.base import BasePlugin
from utils.logger import setup_logger

logger = setup_logger("netsentinel.plugins.dns_monitor")


class DnsMonitorPlugin(BasePlugin):
    """Monitors DNS queries and responses seen on the network.

    Tracks per-source query counts, unique queried domains, NXDOMAIN
    rates and long-label anomalies that may indicate DNS tunneling.
    """

    def __init__(self) -> None:
        super().__init__()
        self._query_count: int = 0
        self._response_count: int = 0
        self._error_count: int = 0
        self._nxdomain_count: int = 0
        self._unique_domains: set[str] = set()
        self._top_domains: dict[str, int] = defaultdict(int)
        self._src_queries: dict[str, int] = defaultdict(int)
        self._long_queries: int = 0
        self._start_time: float = 0.0

    # ------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "dns_monitor"

    @property
    def description(self) -> str:
        return "Monitors DNS queries and responses"

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
        logger.info("DnsMonitorPlugin initialised")

    def process_packet(self, packet: dict[str, Any]) -> None:
        """Extract DNS information from a packet dict.

        Expected keys (when DNS layer is present):
            ``dns_type`` – ``"query"`` or ``"response"``
            ``dns_query`` – the queried domain name
            ``dns_response_code`` – e.g. ``"NOERROR"``, ``"NXDOMAIN"``
            ``src_ip`` – source IP address
        """
        dns_type = str(packet.get("dns_type", "")).lower()
        if not dns_type:
            return

        src_ip = packet.get("src_ip", "")
        query_name = str(packet.get("dns_query", "")).rstrip(".")
        response_code = str(packet.get("dns_response_code", "")).upper()

        if dns_type == "query" and query_name:
            self._query_count += 1
            self._unique_domains.add(query_name.lower())
            self._top_domains[query_name.lower()] += 1
            if src_ip:
                self._src_queries[src_ip] += 1
            if len(query_name) > 50:
                self._long_queries += 1

        elif dns_type == "response":
            self._response_count += 1
            if response_code in ("NXDOMAIN", "3"):
                self._nxdomain_count += 1
                self._error_count += 1
            elif response_code not in ("NOERROR", "0", ""):
                self._error_count += 1

    def cleanup(self) -> None:
        logger.info("DnsMonitorPlugin cleaned up")

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> dict[str, Any]:
        total = self._query_count + self._response_count
        error_rate = (
            round(self._error_count / total, 4) if total > 0 else 0.0
        )
        top = sorted(self._top_domains.items(), key=lambda kv: kv[1], reverse=True)[:20]

        return {
            "query_count": self._query_count,
            "response_count": self._response_count,
            "unique_domains": len(self._unique_domains),
            "error_count": self._error_count,
            "nxdomain_count": self._nxdomain_count,
            "error_rate": error_rate,
            "long_query_count": self._long_queries,
            "top_domains": dict(top),
            "top_query_sources": dict(
                sorted(self._src_queries.items(), key=lambda kv: kv[1], reverse=True)[:10]
            ),
            "uptime_seconds": round(time.time() - self._start_time, 1)
            if self._start_time
            else 0,
        }

    def get_config_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "long_query_threshold": {
                    "type": "integer",
                    "default": 50,
                    "description": "Minimum query name length to flag as long",
                },
            },
        }
