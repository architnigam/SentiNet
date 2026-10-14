from dataclasses import replace
import math
import struct
import unittest

from scapy.layers.inet import ICMP, IP, IPOption, TCP, UDP
from scapy.layers.inet6 import (
    IPv6, IPv6ExtHdrDestOpt, IPv6ExtHdrFragment,
    IPv6ExtHdrHopByHop, IPv6ExtHdrRouting,
)
from scapy.layers.l2 import ARP, CookedLinux, Dot1Q, Ether, Loopback
from scapy.packet import Raw

from netsentinel.analyzer import analyze_packet
from netsentinel.models import CapturedPacket

from tests.helpers import tcp_bytes, udp_bytes

ETHERNET = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
IPV4 = IP(src="192.0.2.1", dst="192.0.2.2")
IPV6 = IPv6(src="2001:db8::1", dst="2001:db8::2")


def frame(packet, *, timestamp=10.25, wire=None, link=1):
    data = packet if isinstance(packet, bytes) else bytes(packet)
    return CapturedPacket(data, timestamp, len(data) if wire is None else wire, link)


class AnalyzerTests(unittest.TestCase):
    def assert_skipped(self, packet, reason, **kwargs):
        result = analyze_packet(frame(packet, **kwargs))
        self.assertIsNone(result.record)
        self.assertEqual(result.skip_reason, reason)

    def test_ipv4_tcp_normalization_and_syn_flags(self):
        for flags, expected in [("S", True), ("SA", False), ("A", False), ("", False), ("F", False), ("R", False)]:
            with self.subTest(flags=flags):
                record = analyze_packet(frame(tcp_bytes(sport=0, dport=65535, flags=flags))).record
                self.assertIsNotNone(record)
                self.assertEqual((record.source_ip, record.destination_ip), ("192.0.2.1", "192.0.2.2"))
                self.assertEqual((record.source_port, record.destination_port), (0, 65535))
                self.assertEqual((record.ip_version, record.protocol, record.timestamp), (4, "TCP", 10.25))
                self.assertEqual(record.syn_without_ack, expected)
                self.assertEqual(record.to_dict()["syn_without_ack"], expected)
                self.assertFalse(record.truncated)

    def test_ipv4_udp_has_no_tcp_flags_even_for_payload_resembling_tcp(self):
        packet = ETHERNET / IPV4 / UDP(sport=53, dport=0) / Raw(tcp_bytes(flags="S"))
        record = analyze_packet(frame(packet)).record
        self.assertEqual((record.protocol, record.source_port, record.destination_port), ("UDP", 53, 0))
        self.assertEqual(record.tcp_flags, 0)
        self.assertFalse(record.syn_without_ack)

    def test_ipv6_tcp_and_udp(self):
        for transport in [TCP(sport=1, dport=2, flags="S"), UDP(sport=1, dport=2)]:
            with self.subTest(transport=type(transport).__name__):
                record = analyze_packet(frame(ETHERNET / IPV6 / transport)).record
                self.assertEqual(record.ip_version, 6)
                self.assertEqual(record.source_ip, "2001:db8::1")
                self.assertEqual(record.destination_ip, "2001:db8::2")
                self.assertEqual(record.destination_port, 2)

    def test_ipv6_extension_headers(self):
        for extension in [IPv6ExtHdrHopByHop(), IPv6ExtHdrDestOpt(), IPv6ExtHdrRouting()]:
            with self.subTest(extension=type(extension).__name__):
                record = analyze_packet(frame(ETHERNET / IPV6 / extension / UDP(sport=4, dport=5))).record
                self.assertIsNotNone(record)
                self.assertEqual(record.protocol, "UDP")
        chain = ETHERNET / IPV6 / IPv6ExtHdrHopByHop() / IPv6ExtHdrDestOpt() / TCP(dport=443)
        self.assertEqual(analyze_packet(frame(chain)).record.destination_port, 443)

    def test_vlan_and_double_vlan(self):
        for tags in [Dot1Q(vlan=7), Dot1Q(vlan=7) / Dot1Q(vlan=8)]:
            with self.subTest(tags=tags.summary()):
                record = analyze_packet(frame(ETHERNET / tags / IPV4 / TCP(dport=443))).record
                self.assertEqual(record.destination_port, 443)

    def test_raw_ip_linux_cooked_and_loopback_link_types(self):
        packets = [(IPV4 / UDP(dport=53), 101), (IPV6 / UDP(dport=53), 101),
                   (IPV4 / TCP(dport=53), 228), (IPV6 / TCP(dport=53), 229),
                   (CookedLinux(proto=0x0800) / IPV4 / UDP(dport=53), 113),
                   (Loopback(type=2) / IPV4 / TCP(dport=53), 0)]
        for packet, link in packets:
            with self.subTest(link=link, packet=packet.summary()):
                self.assertEqual(analyze_packet(frame(packet, link=link)).record.destination_port, 53)

    def test_ipv4_and_tcp_options(self):
        packet = ETHERNET / IP(src="192.0.2.1", dst="192.0.2.2", options=[IPOption(b"\x01")])
        packet /= TCP(sport=123, dport=443, options=[("MSS", 1460), ("NOP", None)])
        self.assertEqual(analyze_packet(frame(packet)).record.destination_port, 443)

    def test_fragments_including_atomic_ipv6_are_skipped(self):
        packets = [ETHERNET / IP(src="192.0.2.1", dst="192.0.2.2", flags="MF") / UDP(),
                   ETHERNET / IP(src="192.0.2.1", dst="192.0.2.2", frag=1) / Raw(b"fragment"),
                   ETHERNET / IPV6 / IPv6ExtHdrFragment(offset=0, m=1) / UDP(),
                   ETHERNET / IPV6 / IPv6ExtHdrFragment(offset=1, m=0) / Raw(b"fragment"),
                   ETHERNET / IPV6 / IPv6ExtHdrFragment(offset=0, m=0) / UDP()]
        for packet in packets:
            with self.subTest(packet=packet.summary()):
                self.assert_skipped(packet, "fragmented_packet")

    def test_unsupported_protocols_and_tunnels_are_not_unwrapped(self):
        packets = [ETHERNET / ARP(hwsrc="02:00:00:00:00:01", hwdst="00:00:00:00:00:00"),
                   ETHERNET / IPV4 / ICMP(), ETHERNET / IPV4 / IPV4 / TCP(),
                   ETHERNET / IPV4 / IPV6 / UDP(), ETHERNET / IPV6 / IPV4 / TCP(),
                   ETHERNET / IPv6(src="2001:db8::1", dst="2001:db8::2", nh=59) / Raw(b"x")]
        for packet in packets:
            with self.subTest(packet=packet.summary()):
                self.assert_skipped(packet, "unsupported_protocol")

    def test_invalid_and_missing_timestamps(self):
        self.assert_skipped(tcp_bytes(), "missing_timestamp", timestamp=None)
        for timestamp in [-1, math.nan, math.inf, -math.inf, True, "10", 10**1000]:
            with self.subTest(timestamp=repr(timestamp)[:20]):
                self.assert_skipped(tcp_bytes(), "invalid_timestamp", timestamp=timestamp)
        self.assertEqual(analyze_packet(frame(tcp_bytes(), timestamp=0)).record.timestamp, 0)

    def test_invalid_metadata_and_unknown_link_type(self):
        normal = frame(tcp_bytes())
        for changed in [replace(normal, wire_length=-1), replace(normal, wire_length=1),
                        replace(normal, wire_length=True), replace(normal, link_type=True),
                        replace(normal, link_type=-1), replace(normal, data="not bytes")]:
            with self.subTest(frame=changed):
                self.assertEqual(analyze_packet(changed).skip_reason, "invalid_metadata")
        self.assert_skipped(b"abc", "unsupported_link_type", link=9999)

    def test_truncated_payload_is_accepted_with_complete_headers(self):
        for transport in [TCP(dport=443), UDP(dport=53)]:
            packet = bytes(ETHERNET / IPV4 / transport / Raw(b"x" * 100))
            header_length = 54 if isinstance(transport, TCP) else 42
            record = analyze_packet(frame(packet[:header_length], wire=len(packet))).record
            with self.subTest(transport=type(transport).__name__):
                self.assertTrue(record.truncated)
                self.assertEqual(record.wire_length, len(packet))
                self.assertEqual(record.captured_length, header_length)

    def test_truncated_network_and_transport_headers_are_rejected(self):
        for packet in [tcp_bytes(), udp_bytes()]:
            header_length = len(packet)
            for size in [0, 1, 13, 14, 20, 33, 34, 35, header_length - 1]:
                with self.subTest(size=size, header_length=header_length):
                    self.assert_skipped(packet[:size], "malformed_packet", wire=header_length)
        packet = bytes(ETHERNET / IPV6 / TCP())
        for size in [14, 30, 53, 54, len(packet) - 1]:
            with self.subTest(ipv6_size=size):
                self.assert_skipped(packet[:size], "malformed_packet", wire=len(packet))

    def test_invalid_declared_ipv4_and_tcp_header_lengths(self):
        for ip_changes in [{"ihl": 4}, {"version": 5}, {"len": 10}, {"len": 20}, {"ihl": 15}, {"len": 1000}]:
            packet = ETHERNET / IP(src="192.0.2.1", dst="192.0.2.2", **ip_changes) / TCP()
            with self.subTest(changes=ip_changes):
                self.assert_skipped(packet, "malformed_packet")
        for offset in [0, 4, 15]:
            with self.subTest(offset=offset):
                self.assert_skipped(ETHERNET / IPV4 / TCP(dataofs=offset), "malformed_packet")

    def test_invalid_udp_lengths_and_zero_ipv6_payload_length(self):
        for length in [0, 7, 1000]:
            with self.subTest(length=length):
                self.assert_skipped(ETHERNET / IPV4 / UDP(len=length), "malformed_packet")
        self.assert_skipped(ETHERNET / IPv6(src="2001:db8::1", dst="2001:db8::2", plen=0) / UDP(), "unsupported_jumbogram")
        self.assert_skipped(ETHERNET / IPv6(src="2001:db8::1", dst="2001:db8::2", plen=1000) / UDP(), "malformed_packet")

    def test_ip_declared_length_cannot_be_extended_by_ethernet_padding(self):
        packet = bytes(ETHERNET / IP(src="192.0.2.1", dst="192.0.2.2", len=20, proto=6)) + b"\0" * 40
        self.assert_skipped(packet, "malformed_packet")

    def test_overlong_ipv6_extension_chain_and_truncated_extension(self):
        packet = ETHERNET / IPV6
        for _ in range(17):
            packet /= IPv6ExtHdrDestOpt()
        packet /= UDP()
        self.assert_skipped(packet, "malformed_packet")
        packet = bytes(ETHERNET / IPV6 / IPv6ExtHdrHopByHop() / UDP())
        self.assert_skipped(packet[:58], "malformed_packet", wire=len(packet))

    def test_seeded_random_frames_do_not_crash(self):
        import random
        randomizer = random.Random(42)
        for size in [0, 1, 13, 14, 20, 40, 64, 128, 512]:
            for _ in range(25):
                result = analyze_packet(frame(randomizer.randbytes(size)))
                self.assertTrue(result.record is not None or result.skip_reason is not None)
