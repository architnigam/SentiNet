"""Small binary fixtures to exercise real capture format boundaries."""

from pathlib import Path
import struct
import tempfile
import unittest

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

ROOT = Path(__file__).resolve().parents[1]


class TemporaryCase(unittest.TestCase):
    def setUp(self):
        base = ROOT / "tests" / ".tmp"
        base.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=base)
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)

    def save(self, content: bytes, name: str = "input.pcap") -> Path:
        path = self.directory / name
        path.write_bytes(content)
        return path


def tcp_bytes(**kwargs) -> bytes:
    return bytes(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") /
                 IP(src="192.0.2.1", dst="192.0.2.2") / TCP(**kwargs))


def udp_bytes(**kwargs) -> bytes:
    return bytes(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") /
                 IP(src="192.0.2.1", dst="192.0.2.2") / UDP(**kwargs))


def pcap_header(endian="<", nano=False, snaplen=65535, linktype=1, version=(2, 4)) -> bytes:
    magic = (b"\x4d\x3c\xb2\xa1" if nano else b"\xd4\xc3\xb2\xa1") if endian == "<" else (
        b"\xa1\xb2\x3c\x4d" if nano else b"\xa1\xb2\xc3\xd4"
    )
    return magic + struct.pack(endian + "HHIIII", *version, 0, 0, snaplen, linktype)


def pcap_record(data: bytes, *, endian="<", seconds=10, fraction=0,
                captured=None, wire=None) -> bytes:
    captured = len(data) if captured is None else captured
    wire = len(data) if wire is None else wire
    return struct.pack(endian + "IIII", seconds, fraction, captured, wire) + data


def pcap_bytes(*packets: bytes, endian="<", nano=False, **kwargs) -> bytes:
    return pcap_header(endian=endian, nano=nano, **kwargs) + b"".join(
        pcap_record(data, endian=endian, seconds=10 + i) for i, data in enumerate(packets)
    )


def ng_block(kind: int, body: bytes, endian="<") -> bytes:
    size = 12 + len(body)
    return struct.pack(endian + "II", kind, size) + body + struct.pack(endian + "I", size)


def ng_section(endian="<", version=(1, 0), options=b"") -> bytes:
    return ng_block(0x0A0D0D0A, struct.pack(endian + "IHHq", 0x1A2B3C4D, *version, -1) + options, endian)


def ng_option(code: int, value: bytes, endian="<") -> bytes:
    return struct.pack(endian + "HH", code, len(value)) + value + b"\0" * (-len(value) % 4)


def ng_interface(endian="<", linktype=1, snaplen=65535, options=b"") -> bytes:
    return ng_block(1, struct.pack(endian + "HHI", linktype, 0, snaplen) + options, endian)


def ng_packet(data: bytes, endian="<", interface=0, ticks=10_000_000,
              captured=None, wire=None, options=b"", kind=6) -> bytes:
    caplen = len(data) if captured is None else captured
    wirelen = len(data) if wire is None else wire
    if kind == 6:
        header = struct.pack(endian + "5I", interface, ticks >> 32, ticks & 0xffffffff, caplen, wirelen)
    else:
        header = struct.pack(endian + "HH4I", interface, 0, ticks >> 32, ticks & 0xffffffff, caplen, wirelen)
    return ng_block(kind, header + data + b"\0" * (-len(data) % 4) + options, endian)
