"""Decode outer IPv4/IPv6 TCP/UDP headers without interpreting payload content."""

import math
import struct

from scapy.config import conf
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import (
    IPv6, IPv6ExtHdrDestOpt, IPv6ExtHdrFragment,
    IPv6ExtHdrHopByHop, IPv6ExtHdrRouting,
)
from scapy.layers.l2 import Ether  # noqa: F401 - register link-layer decoders
from scapy.packet import NoPayload

from .models import AnalysisResult, CapturedPacket, PacketRecord


def _skip(reason: str) -> AnalysisResult:
    return AnalysisResult(None, reason)


def analyze_packet(frame: CapturedPacket) -> AnalysisResult:
    """Return a normalized record or an explicit reason for skipping the frame.

    Fragments are skipped (no reassembly). Truncated payloads are accepted only
    when all network/transport headers are present. Tunnels are not unwrapped.
    Checksums are not validated because capture offloading can alter them.
    """
    if frame.timestamp is None:
        return _skip("missing_timestamp")
    try:
        valid_time = type(frame.timestamp) in (int, float) and math.isfinite(frame.timestamp) and frame.timestamp >= 0
    except OverflowError:
        valid_time = False
    if not valid_time:
        return _skip("invalid_timestamp")
    if (not isinstance(frame.data, bytes) or type(frame.wire_length) is not int
            or frame.wire_length < len(frame.data) or type(frame.link_type) is not int
            or frame.link_type < 0):
        return _skip("invalid_metadata")
    decoder = conf.l2types.num2layer.get(frame.link_type)
    if decoder is None:
        return _skip("unsupported_link_type")
    if not frame.data:
        return _skip("malformed_packet")
    try:
        packet = decoder(frame.data)
        network = packet
        # Stop at the first network header: inner tunnel traffic is not traffic
        # observed directly from the outer source.
        while not isinstance(network, (IP, IPv6, NoPayload)):
            if isinstance(network.payload, NoPayload) or network.payload.__class__.__name__ == "Raw":
                if getattr(network, "type", None) in (0x0800, 0x86dd, 0x8100, 0x88a8):
                    return _skip("malformed_packet")
            network = network.payload
        if isinstance(network, NoPayload):
            return _skip("unsupported_protocol")
        raw_network = network.original
        wire_network_length = frame.wire_length - (len(frame.data) - len(raw_network))
        if isinstance(network, IP):
            header_size = int(network.ihl) * 4
            if (network.version != 4 or header_size < 20 or header_size > len(raw_network)
                    or network.len < header_size or network.len > wire_network_length):
                return _skip("malformed_packet")
            if network.frag or int(network.flags) & 1:
                return _skip("fragmented_packet")
            protocol_number = network.proto
            declared_size = network.len - header_size
            available_size = min(len(raw_network), network.len) - header_size
            transport = network.payload
            version = 4
        else:
            if network.version != 6 or len(raw_network) < 40:
                return _skip("malformed_packet")
            if network.plen == 0:
                return _skip("unsupported_jumbogram")
            if 40 + network.plen > wire_network_length:
                return _skip("malformed_packet")
            declared_size = int(network.plen)
            available_size = min(len(raw_network) - 40, declared_size)
            protocol_number = network.nh
            transport = network.payload
            extensions = (IPv6ExtHdrHopByHop, IPv6ExtHdrDestOpt, IPv6ExtHdrRouting)
            depth = 0
            while isinstance(transport, extensions):
                depth += 1
                extension_size = len(bytes(transport)) - len(bytes(transport.payload))
                if depth > 16 or extension_size < 8 or extension_size > min(declared_size, available_size):
                    return _skip("malformed_packet")
                protocol_number = transport.nh
                declared_size -= extension_size
                available_size -= extension_size
                transport = transport.payload
            if isinstance(transport, IPv6ExtHdrFragment) or protocol_number == 44:
                return _skip("fragmented_packet")
            if protocol_number in (0, 43, 60):
                return _skip("malformed_packet")
            version = 6
        if protocol_number not in (6, 17):
            return _skip("unsupported_protocol")
        if protocol_number == 6:
            if not isinstance(transport, TCP):
                return _skip("malformed_packet")
            tcp_size = int(transport.dataofs) * 4
            if tcp_size < 20 or tcp_size > min(declared_size, available_size):
                return _skip("malformed_packet")
            protocol, flags = "TCP", int(transport.flags)
        else:
            if not isinstance(transport, UDP) or min(declared_size, available_size) < 8:
                return _skip("malformed_packet")
            if transport.len < 8 or transport.len > declared_size:
                return _skip("malformed_packet")
            protocol, flags = "UDP", 0
        return AnalysisResult(PacketRecord(
            timestamp=float(frame.timestamp), source_ip=network.src,
            destination_ip=network.dst, ip_version=version, protocol=protocol,
            source_port=int(transport.sport), destination_port=int(transport.dport),
            tcp_flags=flags, captured_length=len(frame.data), wire_length=frame.wire_length,
            truncated=len(frame.data) < frame.wire_length,
        ))
    except (ValueError, TypeError, AttributeError, IndexError, OverflowError, struct.error, RecursionError):
        # A malformed packet must not prevent analysis of the following packet.
        return _skip("malformed_packet")
