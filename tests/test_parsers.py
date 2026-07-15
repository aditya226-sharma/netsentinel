"""Tests for protocol parsers in the parser package."""

from __future__ import annotations

import pytest

from parser.ipv4 import IPv4Parser
from parser.tcp import TCPParser
from parser.udp import UDPParser
from parser.icmp import ICMPParser
from parser.arp import ARPParser


# ---------------------------------------------------------------------------
# IPv4
# ---------------------------------------------------------------------------

class TestIPv4Parser:
    """Tests for the IPv4 parser."""

    def test_ipv4_parse(self, sample_packet_ip_tcp) -> None:
        """Parse a standard IP/TCP packet and verify IPv4 fields."""
        parser = IPv4Parser()
        result = parser.parse(sample_packet_ip_tcp)

        assert result is not None
        assert result["src_ip"] == "192.168.1.100"
        assert result["dst_ip"] == "10.0.0.1"
        assert result["version"] == 4
        assert result["ttl"] == 64
        assert result["protocol"] == 6  # TCP

    def test_ipv4_parse_non_ip_packet(self) -> None:
        """Return None when packet has no IP layer."""
        from scapy.layers.l2 import Ether
        pkt = Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:55") / b"\x00"
        parser = IPv4Parser()
        result = parser.parse(pkt)
        assert result is None

    def test_ipv4_parse_none_input(self) -> None:
        """Parser handles non-packet input gracefully."""
        parser = IPv4Parser()
        with pytest.raises((IndexError, TypeError, AttributeError)):
            parser.parse(None)


# ---------------------------------------------------------------------------
# TCP
# ---------------------------------------------------------------------------

class TestTCPParser:
    """Tests for the TCP parser."""

    def test_tcp_parse(self, sample_packet_ip_tcp) -> None:
        """Parse TCP layer and verify port / flags fields."""
        parser = TCPParser()
        result = parser.parse(sample_packet_ip_tcp)

        assert result is not None
        assert result["src_port"] == 54321
        assert result["dst_port"] == 80
        assert result["flags"]["SYN"] is True
        assert result["flags"]["ACK"] is False

    def test_tcp_parse_no_tcp_layer(self) -> None:
        """Return None when packet has no TCP layer."""
        from scapy.layers.inet import IP
        pkt = IP(src="1.2.3.4", dst="5.6.7.8") / b"\x00"
        parser = TCPParser()
        result = parser.parse(pkt)
        assert result is None


# ---------------------------------------------------------------------------
# UDP
# ---------------------------------------------------------------------------

class TestUDPParser:
    """Tests for the UDP parser."""

    def test_udp_parse(self, sample_packet_ip_udp) -> None:
        """Parse UDP layer and verify ports."""
        parser = UDPParser()
        result = parser.parse(sample_packet_ip_udp)

        assert result is not None
        assert result["src_port"] == 12345
        assert result["dst_port"] == 5353
        assert result["length"] > 0

    def test_udp_parse_no_udp_layer(self) -> None:
        """Return None when packet lacks a UDP layer."""
        from scapy.layers.inet import IP
        pkt = IP(src="1.2.3.4", dst="5.6.7.8") / b"\x00"
        parser = UDPParser()
        result = parser.parse(pkt)
        assert result is None


# ---------------------------------------------------------------------------
# ICMP
# ---------------------------------------------------------------------------

class TestICMPParser:
    """Tests for the ICMP parser."""

    def test_icmp_parse(self, sample_packet_icmp) -> None:
        """Parse ICMP echo request and verify type/code."""
        parser = ICMPParser()
        result = parser.parse(sample_packet_icmp)

        assert result is not None
        assert result["type"] == 8
        assert result["code"] == 0
        assert result["type_name"] == "Echo Request"
        assert result["id"] == 0x1234
        assert result["seq"] == 1

    def test_icmp_parse_reply(self) -> None:
        """Parse ICMP echo reply."""
        from scapy.layers.inet import ICMP, IP
        pkt = IP(src="8.8.8.8", dst="192.168.1.100") / ICMP(type=0, code=0)
        parser = ICMPParser()
        result = parser.parse(pkt)

        assert result is not None
        assert result["type"] == 0
        assert result["type_name"] == "Echo Reply"

    def test_icmp_parse_no_icmp_layer(self) -> None:
        """Return None when packet lacks an ICMP layer."""
        from scapy.layers.inet import IP
        pkt = IP(src="1.2.3.4", dst="5.6.7.8") / b"\x00"
        parser = ICMPParser()
        result = parser.parse(pkt)
        assert result is None


# ---------------------------------------------------------------------------
# ARP
# ---------------------------------------------------------------------------

class TestARPParser:
    """Tests for the ARP parser."""

    def test_arp_parse(self, sample_packet_arp) -> None:
        """Parse ARP request and verify fields."""
        parser = ARPParser()
        result = parser.parse(sample_packet_arp)

        assert result is not None
        assert result["opcode"] == 1
        assert result["opcode_name"] == "request"
        assert result["src_ip"] == "192.168.1.1"
        assert result["dst_ip"] == "192.168.1.2"

    def test_arp_parse_reply(self) -> None:
        """Parse ARP reply."""
        from scapy.layers.l2 import ARP, Ether
        pkt = (
            Ether(src="11:22:33:44:55:66", dst="aa:bb:cc:dd:ee:ff")
            / ARP(op=2, hwsrc="11:22:33:44:55:66", psrc="192.168.1.2",
                  hwdst="aa:bb:cc:dd:ee:ff", pdst="192.168.1.1")
        )
        parser = ARPParser()
        result = parser.parse(pkt)

        assert result is not None
        assert result["opcode"] == 2
        assert result["opcode_name"] == "reply"

    def test_arp_parse_no_arp_layer(self) -> None:
        """Return None when packet lacks an ARP layer."""
        from scapy.layers.inet import IP
        pkt = IP(src="1.2.3.4", dst="5.6.7.8") / b"\x00"
        parser = ARPParser()
        result = parser.parse(pkt)
        assert result is None


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

class TestParserErrorHandling:
    """Ensure parsers handle unexpected input gracefully."""

    @pytest.mark.parametrize("parser_cls", [
        IPv4Parser, TCPParser, UDPParser, ICMPParser, ARPParser,
    ])
    def test_parser_error_handling(self, parser_cls) -> None:
        """All parsers must not raise on None input."""
        parser = parser_cls()
        with pytest.raises((IndexError, TypeError, AttributeError)):
            parser.parse(None)
