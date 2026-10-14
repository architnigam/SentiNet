"""Bounded offline capture reading with structural checks before Scapy decoding.

Preflight prevents Scapy's tolerant EOF handling from hiding corrupt records.
It scans the entire container before yielding anything, including with a limit.
"""

from collections.abc import Iterator
from decimal import Decimal
from pathlib import Path
import struct
from typing import BinaryIO

from scapy.error import Scapy_Exception
from scapy.utils import RawPcapNgReader, RawPcapReader

from .errors import CaptureError
from .models import CapturedPacket

MAX_PACKET_BYTES = 65_535
MAX_BLOCK_BYTES = 16 * 1024 * 1024
PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
NG_MAGIC = b"\x0a\x0d\x0d\x0a"


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CaptureError(message)


def _read_exact(handle: BinaryIO, size: int) -> bytes:
    data = handle.read(size)
    _require(len(data) == size, "Truncated capture header or block.")
    return data


def _validate_pcap(handle: BinaryIO, magic: bytes, file_size: int) -> int:
    endian, scale = PCAP_MAGIC[magic]
    major, minor, _, _, snaplen, _ = struct.unpack(endian + "HHIIII", _read_exact(handle, 20))
    _require((major, minor) == (2, 4), "Only PCAP version 2.4 is supported.")
    _require(snaplen > 0, "PCAP snapshot length must be positive.")
    count = 0
    while handle.tell() < file_size:
        _, fraction, captured, wire = struct.unpack(endian + "IIII", _read_exact(handle, 16))
        _require(fraction < scale, "Invalid PCAP timestamp fraction.")
        _require(captured <= min(snaplen, MAX_PACKET_BYTES), "PCAP packet exceeds snapshot or size limit.")
        _require(captured <= wire, "Captured length exceeds original packet length.")
        _require(handle.tell() + captured <= file_size, "Truncated PCAP packet data.")
        handle.seek(captured, 1)
        count += 1
    return count


def _options(data: bytes, endian: str) -> dict[int, bytes]:
    """Validate padded option lengths instead of accepting partial options."""
    result = {}
    offset = 0
    while offset < len(data):
        _require(len(data) - offset >= 4, "Truncated PCAPNG option header.")
        code, size = struct.unpack_from(endian + "HH", data, offset)
        offset += 4
        if code == 0:
            _require(size == 0 and not any(data[offset:]), "Invalid PCAPNG end-of-options.")
            break
        padded = size + (-size % 4)
        _require(offset + padded <= len(data), "Truncated PCAPNG option value.")
        result[code] = data[offset:offset + size]
        offset += padded
    return result


def _validate_pcapng(handle: BinaryIO, file_size: int) -> int:
    handle.seek(0)
    endian = "<"
    interfaces: list[int] = []
    sections = count = 0
    while handle.tell() < file_size:
        prefix = _read_exact(handle, 8)
        is_section = prefix[:4] == NG_MAGIC
        bom = b""
        if is_section:
            bom = _read_exact(handle, 4)
            _require(bom in (b"\x4d\x3c\x2b\x1a", b"\x1a\x2b\x3c\x4d"), "Invalid PCAPNG byte order.")
            endian = "<" if bom[0] == 0x4d else ">"
        kind, size = struct.unpack(endian + "II", prefix)
        _require(12 <= size <= MAX_BLOCK_BYTES and size % 4 == 0, "Invalid or oversized PCAPNG block length.")
        _require(size >= 28 if is_section else True, "Truncated PCAPNG section header.")
        body = bom + _read_exact(handle, size - 12 - len(bom))
        tail, = struct.unpack(endian + "I", _read_exact(handle, 4))
        _require(tail == size, "PCAPNG block lengths do not match.")
        if is_section:
            sections += 1
            _require(sections == 1, "Multiple PCAPNG sections are not supported; split the capture first.")
            major, minor = struct.unpack_from(endian + "HH", body, 4)
            _require((major, minor) == (1, 0), "Only PCAPNG version 1.0 is supported.")
            _options(body[16:], endian)
        elif kind == 1:
            _require(len(body) >= 8, "Truncated PCAPNG interface description.")
            _, _, snaplen = struct.unpack_from(endian + "HHI", body)
            options = _options(body[8:], endian)
            if 9 in options:
                _require(len(options[9]) == 1, "Invalid PCAPNG timestamp resolution.")
            if 14 in options:
                _require(len(options[14]) == 8 and not any(options[14]), "Nonzero PCAPNG timestamp offsets are unsupported.")
            interfaces.append(snaplen)
        elif kind in (2, 6):
            _require(len(body) >= 20, "Truncated PCAPNG packet header.")
            if kind == 6:
                interface, _, _, captured, wire = struct.unpack_from(endian + "5I", body)
            else:
                interface, _, _, _, captured, wire = struct.unpack_from(endian + "HH4I", body)
            _require(interface < len(interfaces), "PCAPNG packet references an unknown interface.")
            snaplen = interfaces[interface] or MAX_PACKET_BYTES
            _require(captured <= min(wire, snaplen, MAX_PACKET_BYTES), "Invalid or oversized PCAPNG packet length.")
            option_start = 20 + captured + (-captured % 4)
            _require(option_start <= len(body), "Truncated PCAPNG packet data.")
            options = _options(body[option_start:], endian)
            for code in (2, 0x8001, 0x8003):
                if kind == 6 and code in options:
                    _require(len(options[code]) == 4, "Invalid PCAPNG packet option size.")
            count += 1
        elif kind == 3:
            _require(len(body) >= 4 and bool(interfaces), "Invalid PCAPNG simple packet header/interface.")
            wire, = struct.unpack_from(endian + "I", body)
            captured = min(wire, interfaces[0] or wire)
            _require(captured <= MAX_PACKET_BYTES, "PCAPNG simple packet exceeds size limit.")
            _require(len(body) == 4 + captured + (-captured % 4), "Invalid PCAPNG simple packet data length.")
            # Scapy interprets snaplen=0 as a zero-byte simple packet.
            _require(interfaces[0] > 0, "Simple PCAPNG packets require a nonzero snapshot length.")
            count += 1
        # Unknown metadata blocks are intentionally ignored, not decoded.
    return count


def read_capture(path: str | Path, *, limit: int | None = None) -> Iterator[CapturedPacket]:
    """Stream at most ``limit`` frames from a structurally valid PCAP/PCAPNG.

    No gzip support. Per-packet limit: 65,535 bytes; per-PCAPNG-block: 16 MiB.
    A missing timestamp stays missing, never replaced with the current time.
    The generator owns its file; callers stopping early must close it.
    """
    if limit is not None and (type(limit) is not int or limit < 1):
        raise ValueError("limit must be a positive integer or None")
    source = Path(path)
    try:
        with source.open("rb") as handle:
            handle.seek(0, 2)
            file_size = handle.tell()
            handle.seek(0)
            magic = _read_exact(handle, 4)
            if magic in PCAP_MAGIC:
                expected = _validate_pcap(handle, magic, file_size)
            elif magic == NG_MAGIC:
                expected = _validate_pcapng(handle, file_size)
            else:
                raise CaptureError("Unsupported capture format; use an uncompressed PCAP or PCAPNG.")
            handle.seek(0)
            with RawPcapReader(handle) as reader:
                is_ng = isinstance(reader, RawPcapNgReader)
                if is_ng:
                    # Avoid interpreting unrelated metadata (e.g. embedded TLS secrets).
                    reader.blocktypes = {k: v for k, v in reader.blocktypes.items() if k in (1, 2, 3, 6)}
                count = 0
                while limit is None or count < limit:
                    try:
                        data, meta = reader._read_packet(size=MAX_PACKET_BYTES)
                    except EOFError:
                        _require(count == expected, "Capture decoding ended before all packets were read.")
                        break
                    if is_ng:
                        timestamp = None if meta.tshigh is None else float(
                            Decimal((meta.tshigh << 32) + meta.tslow) / meta.tsresol
                        )
                        link_type = meta.linktype
                    else:
                        scale = 1_000_000_000 if reader.nano else 1_000_000
                        timestamp = float(Decimal(meta.sec) + Decimal(meta.usec) / scale)
                        link_type = reader.linktype
                    count += 1
                    yield CapturedPacket(data, timestamp, meta.wirelen, link_type)
    except (OSError, Scapy_Exception, struct.error, OverflowError) as exc:
        raise CaptureError(f"Cannot read capture '{source}': {exc}") from exc
