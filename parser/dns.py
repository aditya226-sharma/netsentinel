"""DNS packet parser for NetSentinel.

Parses DNS queries and responses carried inside UDP (port 53).
"""

from __future__ import annotations

from typing import Any

from scapy.layers.dns import DNS, DNSRR
from scapy.layers.inet import UDP
from scapy.packet import Packet

from utils.logger import setup_logger

logger = setup_logger("netsentinel.parser.dns")

_DNS_PORT = 53

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
    255: "ANY",
    256: "URI",
    65281: "OPT",
}

_RESPONSE_CODE_MAP: dict[int, str] = {
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


class DNSParser:
    """Parse a DNS packet carried inside UDP port 53.

    Usage::

        parser = DNSParser()
        info = parser.parse(packet)
        if info:
            print(info["query_name"])
    """

    def parse(self, packet: Packet) -> dict[str, Any] | None:
        """Extract DNS metadata.

        Parameters
        ----------
        packet : scapy.packet.Packet
            A raw scapy packet expected to contain DNS layers.

        Returns
        -------
        dict | None
            Dictionary with DNS fields or ``None`` when the packet lacks
            DNS layers or is malformed.
        """
        try:
            if not packet.haslayer(UDP) or not packet.haslayer(DNS):
                return None

            udp_layer = packet[UDP]
            src_port = int(udp_layer.sport)
            dst_port = int(udp_layer.dport)

            if src_port != _DNS_PORT and dst_port != _DNS_PORT:
                return None

            dns_layer = packet[DNS]
        except Exception:
            return None

        try:
            qr = int(dns_layer.qr)
            is_response = qr == 1

            query_name = str(dns_layer.qd.qname).rstrip(".") if dns_layer.qd else ""
            query_type_raw = int(dns_layer.qd.qtype) if dns_layer.qd else 0
            query_type = _QUERY_TYPE_MAP.get(query_type_raw, f"TYPE{query_type_raw}")

            rcode_raw = int(dns_layer.rcode)
            response_code = _RESPONSE_CODE_MAP.get(rcode_raw, f"RCODE{rcode_raw}")

            answer_count = int(dns_layer.ancount)
            answers: list[dict[str, Any]] = []

            if dns_layer.an is not None:
                for i in range(answer_count):
                    try:
                        rr = dns_layer.an[i]
                        if rr is None:
                            continue

                        rr_type_raw = int(rr.type)
                        rr_type = _QUERY_TYPE_MAP.get(rr_type_raw, f"TYPE{rr_type_raw}")
                        rr_data = str(rr.rdata).rstrip(".") if rr.rdata else ""
                        rr_ttl = int(rr.ttl) if rr.ttl else 0

                        answers.append({
                            "type": rr_type,
                            "data": rr_data,
                            "ttl": rr_ttl,
                        })
                    except Exception:
                        continue

            result: dict[str, Any] = {
                "query_name": query_name,
                "query_type": query_type,
                "response_code": response_code,
                "is_response": is_response,
                "answers": answers,
                "authoritative": bool(dns_layer.aa),
                "truncated": bool(dns_layer.tc),
                "recursion_desired": bool(dns_layer.rd),
                "recursion_available": bool(dns_layer.ra),
            }

        except Exception:
            logger.debug("Malformed DNS packet, skipping")
            return None

        return result
