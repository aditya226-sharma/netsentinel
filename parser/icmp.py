"""ICMP packet parser for NetSentinel.

Extracts ICMP header fields and maps type/code pairs to human-readable
descriptions.
"""

from __future__ import annotations

from typing import Any

from scapy.layers.inet import ICMP
from scapy.packet import Packet

from utils.logger import setup_logger

logger = setup_logger("netsentinel.parser.icmp")

# Mapping of (type, code) to human-readable descriptions
_TYPE_NAMES: dict[int, str] = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    4: "Source Quench",
    5: "Redirect",
    8: "Echo Request",
    9: "Router Advertisement",
    10: "Router Solicitation",
    11: "Time Exceeded",
    12: "Parameter Problem",
    13: "Timestamp",
    14: "Timestamp Reply",
    30: "Traceroute",
    40: "Photuris",
}

_CODE_NAMES_UNREACHABLE: dict[int, str] = {
    0: "Net Unreachable",
    1: "Host Unreachable",
    2: "Protocol Unreachable",
    3: "Port Unreachable",
    4: "Fragmentation Needed",
    5: "Source Route Failed",
    6: "Destination Network Unknown",
    7: "Destination Host Unknown",
    13: "Communication Administratively Prohibited",
}

_CODE_NAMES_REDIRECT: dict[int, str] = {
    0: "Redirect for Network",
    1: "Redirect for Host",
    2: "Redirect for ToS & Network",
    3: "Redirect for ToS & Host",
}

_CODE_NAMES_TIME_EXCEEDED: dict[int, str] = {
    0: "TTL Expired in Transit",
    1: "Fragment Reassembly Time Exceeded",
}


class ICMPParser:
    """Parse the ICMP layer of a scapy packet.

    Usage::

        parser = ICMPParser()
        info = parser.parse(packet)
        if info:
            print(info["type_name"])
    """

    def parse(self, packet: Packet) -> dict[str, Any] | None:
        """Extract ICMP metadata.

        Parameters
        ----------
        packet : scapy.packet.Packet
            A raw scapy packet expected to contain an ICMP layer.

        Returns
        -------
        dict | None
            Dictionary with ICMP fields or ``None`` when the packet lacks
            an ICMP layer or is malformed.
        """
        try:
            icmp_layer = packet[ICMP]
            if icmp_layer is None:
                return None
        except IndexError:
            return None

        try:
            icmp_type = int(icmp_layer.type)
            icmp_code = int(icmp_layer.code)

            type_name = _TYPE_NAMES.get(icmp_type, f"Unknown ({icmp_type})")

            if icmp_type == 3:
                code_name = _CODE_NAMES_UNREACHABLE.get(
                    icmp_code, f"Code {icmp_code}"
                )
            elif icmp_type == 5:
                code_name = _CODE_NAMES_REDIRECT.get(
                    icmp_code, f"Code {icmp_code}"
                )
            elif icmp_type == 11:
                code_name = _CODE_NAMES_TIME_EXCEEDED.get(
                    icmp_code, f"Code {icmp_code}"
                )
            else:
                code_name = str(icmp_code)

            icmp_id = int(icmp_layer.id) if icmp_layer.id else 0
            icmp_seq = int(icmp_layer.seq) if icmp_layer.seq else 0

            result: dict[str, Any] = {
                "type": icmp_type,
                "code": icmp_code,
                "type_name": type_name,
                "code_name": code_name,
                "id": icmp_id,
                "seq": icmp_seq,
                "data_length": len(icmp_layer.payload),
            }
        except Exception:
            logger.debug("Malformed ICMP packet, skipping")
            return None

        return result
