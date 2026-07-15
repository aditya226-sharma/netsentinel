"""DHCP packet parser for NetSentinel.

Parses BOOTP/DHCP packets carried inside UDP (server port 67 / client
port 68) and extracts commonly useful DHCP fields.
"""

from __future__ import annotations

from typing import Any

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import UDP
from scapy.packet import Packet

from utils.logger import setup_logger

logger = setup_logger("netsentinel.parser.dhcp")

_MESSAGE_TYPES: dict[int, str] = {
    1: "DHCPDISCOVER",
    2: "DHCPOFFER",
    3: "DHCPREQUEST",
    4: "DHCPDECLINE",
    5: "DHCPACK",
    6: "DHCPNAK",
    7: "DHCPRELEASE",
    8: "DHCPINFORM",
}

_OPTION_NAMES: dict[int, str] = {
    1: "subnet_mask",
    3: "router",
    6: "dns_server",
    12: "hostname",
    15: "domain_name",
    44: "wins_server",
    51: "lease_time",
    53: "message_type",
    58: "renewal_time",
    59: "rebinding_time",
    61: "client_identifier",
    255: "end",
}

# Ports that typically carry DHCP traffic
_DHCP_CLIENT_PORT = 68
_DHCP_SERVER_PORT = 67


class DHCPParser:
    """Parse a BOOTP/DHCP packet carried inside UDP.

    Usage::

        parser = DHCPParser()
        info = parser.parse(packet)
        if info:
            print(info["message_type_name"])
    """

    def parse(self, packet: Packet) -> dict[str, Any] | None:
        """Extract DHCP metadata.

        Parameters
        ----------
        packet : scapy.packet.Packet
            A raw scapy packet expected to contain BOOTP/DHCP layers.

        Returns
        -------
        dict | None
            Dictionary with DHCP fields or ``None`` when the packet lacks
            the expected layers or is malformed.
        """
        try:
            # Validate it looks like a DHCP packet (UDP 67/68)
            if packet.haslayer(UDP):
                udp_layer = packet[UDP]
                src_port = int(udp_layer.sport)
                dst_port = int(udp_layer.dport)
                if src_port not in (_DHCP_CLIENT_PORT, _DHCP_SERVER_PORT) or \
                   dst_port not in (_DHCP_CLIENT_PORT, _DHCP_SERVER_PORT):
                    return None

            if not packet.haslayer(BOOTP):
                return None

            bootp = packet[BOOTP]
        except Exception:
            return None

        try:
            client_mac_bytes = bytes(bootp.chaddr[:6])
            client_mac = ":".join(f"{b:02x}" for b in client_mac_bytes)

            result: dict[str, Any] = {
                "message_type": 0,
                "message_type_name": "UNKNOWN",
                "client_mac": client_mac,
                "offered_ip": str(bootp.yiaddr) if bootp.yiaddr != "0.0.0.0" else "",
                "server_ip": str(bootp.siaddr) if bootp.siaddr != "0.0.0.0" else "",
                "relay_ip": str(bootp.giaddr) if bootp.giaddr != "0.0.0.0" else "",
                "transaction_id": int(bootp.xid),
                "hostname": "",
                "options": {},
            }

            # Parse DHCP options layer if present
            if packet.haslayer(DHCP):
                dhcp_options = packet[DHCP].options
                parsed_options: dict[str, Any] = {}

                for opt in dhcp_options:
                    if isinstance(opt, tuple) and len(opt) == 2:
                        opt_name_raw, opt_value = opt
                        if opt_name_raw == 255:
                            break

                        opt_name = _OPTION_NAMES.get(opt_name_raw, f"option_{opt_name_raw}")

                        if opt_name_raw == 53 and isinstance(opt_value, int):
                            result["message_type"] = opt_value
                            result["message_type_name"] = _MESSAGE_TYPES.get(
                                opt_value, f"UNKNOWN ({opt_value})"
                            )
                        elif opt_name_raw == 12 and isinstance(opt_value, bytes):
                            try:
                                result["hostname"] = opt_value.decode("utf-8", errors="replace")
                            except Exception:
                                result["hostname"] = str(opt_value)
                        else:
                            parsed_options[opt_name] = opt_value

                result["options"] = parsed_options

        except Exception:
            logger.debug("Malformed DHCP packet, skipping")
            return None

        return result
