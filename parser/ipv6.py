"""IPv6 packet parser for NetSentinel.

Extracts key IPv6 header fields from a scapy packet.
"""

from __future__ import annotations

from typing import Any

from scapy.layers.inet6 import IPv6
from scapy.packet import Packet

from utils.logger import setup_logger

logger = setup_logger("netsentinel.parser.ipv6")


class IPv6Parser:
    """Parse the IPv6 layer of a scapy packet.

    Usage::

        parser = IPv6Parser()
        info = parser.parse(packet)
        if info:
            print(info["src_ip"])
    """

    def parse(self, packet: Packet) -> dict[str, Any] | None:
        """Extract IPv6 header metadata.

        Parameters
        ----------
        packet : scapy.packet.Packet
            A raw scapy packet expected to contain an IPv6 layer.

        Returns
        -------
        dict | None
            Dictionary with IPv6 fields or ``None`` if the packet lacks
            an IPv6 layer or is malformed.
        """
        try:
            ip6_layer = packet[IPv6]
            if ip6_layer is None:
                return None
        except IndexError:
            return None

        try:
            result: dict[str, Any] = {
                "src_ip": str(ip6_layer.src),
                "dst_ip": str(ip6_layer.dst),
                "version": int(ip6_layer.version),
                "hop_limit": int(ip6_layer.hlim),
                "payload_length": int(ip6_layer.plen),
                "next_header": int(ip6_layer.nh),
                "flow_label": int(ip6_layer.fl),
            }
        except Exception:
            logger.debug("Malformed IPv6 packet, skipping")
            return None

        return result
