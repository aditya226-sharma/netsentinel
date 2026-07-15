"""DNS query and response analytics.

Parses DNS traffic to build a real-time view of name resolution
activity, including query statistics, error tracking, and per-domain
frequency analysis.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.packet import Packet

from database.db_manager import DatabaseManager
from utils.logger import setup_logger
from utils.helpers import generate_id, get_timestamp

logger = setup_logger("netsentinel.modules.dns_analytics")

_QUERY_TYPE_MAP: dict[int, str] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    41: "OPT",
    43: "DS",
    46: "RRSIG",
    47: "NSEC",
    48: "DNSKEY",
    52: "TLSA",
    65: "HTTPS",
}

_RCODE_MAP: dict[int, str] = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
    6: "YXDOMAIN",
    7: "YXRRSET",
    8: "NXRRSET",
    9: "NOTAUTH",
    10: "NOTZONE",
}

_HISTORY_SIZE: int = 5000


class DNSAnalytics:
    """Captures and analyzes DNS queries and responses.

    Matches queries to responses via transaction ID and stores
    correlated results in the database.  Maintains in-memory statistics
    for fast dashboard queries.

    Usage:
        dns_mod = DNSAnalytics(db_manager)
        dns_mod.process_packet(pkt)
        recent = dns_mod.get_recent_queries()
        stats = dns_mod.get_query_stats()
    """

    def __init__(self, db_manager: DatabaseManager) -> None:
        self._db = db_manager
        self._lock = threading.Lock()

        self._pending_queries: dict[int, dict[str, Any]] = {}
        self._recent_queries: deque[dict[str, Any]] = deque(maxlen=_HISTORY_SIZE)
        self._domain_counts: dict[str, int] = {}
        self._type_counts: dict[str, int] = {}
        self._total_queries: int = 0
        self._unique_domains: set[str] = set()
        self._dns_errors: deque[dict[str, Any]] = deque(maxlen=1000)

    def process_packet(self, packet: Packet) -> None:
        """Parse a DNS query or response from the packet.

        For queries (qr=0) the transaction ID is stored to allow
        correlation with the subsequent response.  For responses (qr=1)
        the matched query is looked up and the full record is stored.

        Args:
            packet: Scapy packet containing a DNS layer.
        """
        try:
            if not packet.haslayer(DNS):
                return

            dns = packet[DNS]
            if not packet.haslayer(IP) or not packet.haslayer(UDP):
                return

            src_ip = packet[IP].src

            if dns.qr == 0:
                self._handle_query(dns, src_ip)
            elif dns.qr == 1:
                self._handle_response(dns, src_ip)

        except Exception as exc:
            logger.debug("Error processing DNS packet: %s", exc)

    def _handle_query(self, dns: Any, src_ip: str) -> None:
        """Store an outbound DNS query for later correlation.

        Args:
            dns: Scapy DNS layer.
            src_ip: IP address of the querier.
        """
        try:
            qname = dns.qd.qname.decode("utf-8", errors="replace").rstrip(".")
            qd_first = dns.qd[0] if dns.qd else None
            qtype_num = qd_first.qtype if qd_first else 0
            qtype = _QUERY_TYPE_MAP.get(qtype_num, f"TYPE{qtype_num}")
            tx_id = dns.id

            query_record = {
                "id": generate_id(),
                "timestamp": get_timestamp(),
                "src_ip": src_ip,
                "query_name": qname,
                "query_type": qtype,
                "response_code": "",
                "response_ips": "",
                "ttl": 0,
                "_tx_id": tx_id,
            }

            with self._lock:
                self._pending_queries[tx_id] = query_record
                self._total_queries += 1
                self._unique_domains.add(qname)
                self._type_counts[qtype] = self._type_counts.get(qtype, 0) + 1
                self._domain_counts[qname] = self._domain_counts.get(qname, 0) + 1

        except Exception as exc:
            logger.debug("Error handling DNS query: %s", exc)

    def _handle_response(self, dns: Any, src_ip: str) -> None:
        """Correlate a DNS response with its query and store the result.

        Args:
            dns: Scapy DNS layer.
            src_ip: IP address of the resolver.
        """
        try:
            tx_id = dns.id
            rcode = _RCODE_MAP.get(dns.rcode, f"RCODE{dns.rcode}")

            response_ips: list[str] = []
            ttl = 0

            an_list = list(dns.an) if dns.an else []
            if an_list:
                for rr in an_list:
                    try:
                        if rr.type == 1 and rr.rdata:  # A record
                            response_ips.append(str(rr.rdata))
                        elif rr.type == 28 and rr.rdata:  # AAAA record
                            response_ips.append(str(rr.rdata))
                        ttl = rr.ttl
                    except Exception:
                        continue

            with self._lock:
                query_info = self._pending_queries.pop(tx_id, None)

            qname = ""
            qtype = ""
            src_ip_query = src_ip
            record_id = generate_id()
            timestamp = get_timestamp()

            if query_info:
                qname = query_info["query_name"]
                qtype = query_info["query_type"]
                src_ip_query = query_info["src_ip"]
                record_id = query_info["id"]
                timestamp = query_info["timestamp"]

            db_entry = {
                "id": record_id,
                "timestamp": timestamp,
                "src_ip": src_ip_query,
                "query_name": qname,
                "query_type": qtype,
                "response_code": rcode,
                "response_ips": ",".join(response_ips),
                "ttl": ttl,
            }

            self._recent_queries.appendleft(db_entry)

            if rcode in ("NXDOMAIN", "SERVFAIL", "REFUSED", "FORMERR"):
                self._dns_errors.appendleft({
                    "timestamp": timestamp,
                    "query_name": qname,
                    "response_code": rcode,
                    "src_ip": src_ip_query,
                })

            try:
                self._db.insert_dns_log(db_entry)
            except Exception as exc:
                logger.debug("Failed to insert DNS log: %s", exc)

        except Exception as exc:
            logger.debug("Error handling DNS response: %s", exc)

    def get_recent_queries(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return the most recent DNS queries.

        Args:
            limit: Maximum number of queries to return.

        Returns:
            List of DNS record dictionaries, most recent first.
        """
        with self._lock:
            queries = list(self._recent_queries)
        return queries[:limit]

    def get_query_stats(self) -> dict[str, Any]:
        """Return aggregate DNS statistics.

        Returns:
            Dictionary with keys:
            ``total_queries``, ``unique_domains``, ``query_type_distribution``.
        """
        with self._lock:
            return {
                "total_queries": self._total_queries,
                "unique_domains": len(self._unique_domains),
                "query_type_distribution": dict(self._type_counts),
            }

    def get_top_domains(self, limit: int = 10) -> list[tuple[str, int]]:
        """Return the most frequently queried domains.

        Args:
            limit: Number of top domains to return.

        Returns:
            List of (domain, count) tuples, sorted by count descending.
        """
        with self._lock:
            sorted_domains = sorted(
                self._domain_counts.items(), key=lambda x: x[1], reverse=True
            )
        return sorted_domains[:limit]

    def get_dns_errors(self) -> list[dict[str, Any]]:
        """Return recent DNS errors (NXDOMAIN, SERVFAIL, etc.).

        Returns:
            List of error dictionaries, most recent first.
        """
        with self._lock:
            return list(self._dns_errors)
