"""ARP packet parser for NetSentinel.

Extracts ARP header fields and maps opcodes to human-readable names.
"""

from __future__ import annotations

from typing import Any

from scapy.layers.l2 import ARP
from scapy.packet import Packet

from utils.logger import setup_logger

logger = setup_logger("netsentinel.parser.arp")

_OPCODE_MAP: dict[int, str] = {
    1: "request",
    2: "reply",
    3: "reverse request",
    4: "reverse reply",
}


class ARPParser:
    """Parse the ARP layer of a scapy packet.

    Usage::

        parser = ARPParser()
        info = parser.parse(packet)
        if info:
            print(info["opcode_name"])
    """

    def parse(self, packet: Packet) -> dict[str, Any] | None:
        """Extract ARP metadata.

        Parameters
        ----------
        packet : scapy.packet.Packet
            A raw scapy packet expected to contain an ARP layer.

        Returns
        -------
        dict | None
            Dictionary with ARP fields or ``None`` when the packet lacks
            an ARP layer or is malformed.
        """
        try:
            arp_layer = packet[ARP]
            if arp_layer is None:
                return None
        except IndexError:
            return None

        try:
            opcode = int(arp_layer.op)

            result: dict[str, Any] = {
                "opcode": opcode,
                "opcode_name": _OPCODE_MAP.get(opcode, f"unknown ({opcode})"),
                "src_mac": str(arp_layer.hwsrc),
                "src_ip": str(arp_layer.psrc),
                "dst_mac": str(arp_layer.hwdst),
                "dst_ip": str(arp_layer.pdst),
            }
        except Exception:
            logger.debug("Malformed ARP packet, skipping")
            return None

        return result
