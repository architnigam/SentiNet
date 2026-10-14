import struct
from unittest.mock import MagicMock, patch

from netsentinel.capture import MAX_BLOCK_BYTES, MAX_PACKET_BYTES, read_capture
from netsentinel.errors import CaptureError

from tests.helpers import (
    TemporaryCase, ng_block, ng_interface, ng_option, ng_packet, ng_section,
    pcap_bytes, pcap_header, pcap_record, tcp_bytes, udp_bytes,
)


class CaptureTests(TemporaryCase):
    def read(self, data, **kwargs):
        return list(read_capture(self.save(data), **kwargs))

    def test_all_pcap_byte_orders_and_timestamp_precisions(self):
        packet = tcp_bytes(flags="S")
        for endian in ("<", ">"):
            for nano in (False, True):
                scale = 1_000_000_000 if nano else 1_000_000
                data = pcap_header(endian, nano) + pcap_record(packet, endian=endian, fraction=scale // 4)
                with self.subTest(endian=endian, nano=nano):
                    frame, = self.read(data)
                    self.assertEqual(frame.data, packet)
                    self.assertEqual(frame.timestamp, 10.25)
                    self.assertEqual(frame.wire_length, len(packet))
                    self.assertEqual(frame.link_type, 1)

    def test_empty_valid_capture_and_zero_byte_packet(self):
        self.assertEqual(self.read(pcap_header()), [])
        frame, = self.read(pcap_header() + pcap_record(b"", seconds=0))
        self.assertEqual(frame.timestamp, 0)
        self.assertEqual(frame.data, b"")

    def test_preserves_snapshot_truncation_and_unknown_link_type(self):
        frame, = self.read(pcap_header(linktype=999) + pcap_record(b"short", wire=100))
        self.assertEqual(frame.wire_length, 100)
        self.assertEqual(frame.link_type, 999)

    def test_limits_count_raw_frames(self):
        self.assertEqual(len(self.read(pcap_bytes(tcp_bytes(), udp_bytes()), limit=1)), 1)
        self.assertEqual(len(self.read(pcap_bytes(tcp_bytes()), limit=10)), 1)
        self.assertEqual(self.read(pcap_header(), limit=1), [])
        for limit in [0, -1, True, 1.5, "1"]:
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                self.read(pcap_header(), limit=limit)

    def test_corruption_after_limit_is_still_rejected(self):
        with self.assertRaises(CaptureError):
            self.read(pcap_bytes(tcp_bytes()) + b"trailing garbage", limit=1)

    def test_rejects_bad_pcap_headers(self):
        cases = [b"", b"abc", b"not a capture", b"\x1f\x8b" + b"gzip" * 10,
                 pcap_header()[:23], pcap_header(version=(2, 3)), pcap_header(snaplen=0)]
        for data in cases:
            with self.subTest(data=data[:24]), self.assertRaises(CaptureError):
                self.read(data)

    def test_rejects_bad_pcap_records(self):
        cases = [b"a", pcap_record(b"abc", captured=4, wire=4),
                 pcap_record(b"abc", wire=2), pcap_record(b"", fraction=1_000_000),
                 pcap_record(b"", captured=MAX_PACKET_BYTES + 1, wire=MAX_PACKET_BYTES + 1)]
        for record in cases:
            with self.subTest(record=record[:16]), self.assertRaises(CaptureError):
                self.read(pcap_header() + record)
        with self.assertRaises(CaptureError):
            self.read(pcap_header(snaplen=2) + pcap_record(b"abc"))

    def test_read_failures_and_early_close_release_file(self):
        with self.assertRaises(CaptureError):
            list(read_capture(self.directory / "absent"))
        with self.assertRaises(CaptureError):
            list(read_capture(self.directory))
        with patch("pathlib.Path.open", side_effect=PermissionError("denied")):
            with self.assertRaisesRegex(CaptureError, "denied"):
                list(read_capture("blocked"))
        path = self.save(pcap_bytes(tcp_bytes(), udp_bytes()))
        reader = read_capture(path)
        next(reader)
        reader.close()
        path.unlink()  # Also verifies Windows file handles are closed.

    def test_decoder_early_eof_is_not_silently_accepted(self):
        reader = MagicMock()
        reader._read_packet.side_effect = EOFError
        reader.__enter__.return_value = reader
        with patch("netsentinel.capture.RawPcapReader", return_value=reader):
            with self.assertRaisesRegex(CaptureError, "before all"):
                self.read(pcap_bytes(tcp_bytes()))

    def test_ng_endian_multi_interface_and_obsolete_packet_block(self):
        for endian in ("<", ">"):
            data = ng_section(endian) + ng_interface(endian) + ng_interface(endian, linktype=101)
            data += ng_packet(tcp_bytes(), endian, ticks=12_500_000)
            data += ng_packet(b"raw", endian, interface=1, kind=2)
            with self.subTest(endian=endian):
                frames = self.read(data)
                self.assertEqual(len(frames), 2)
                self.assertEqual(frames[0].timestamp, 12.5)
                self.assertEqual(frames[1].link_type, 101)

    def test_ng_decimal_binary_timestamp_resolution_and_zero_offset(self):
        for resolution, ticks, expected in [(9, 1_250_000_000, 1.25), (0x8a, 1280, 1.25)]:
            options = ng_option(9, bytes([resolution])) + ng_option(14, b"\0" * 8)
            data = ng_section() + ng_interface(options=options) + ng_packet(tcp_bytes(), ticks=ticks)
            with self.subTest(resolution=resolution):
                self.assertEqual(self.read(data)[0].timestamp, expected)

    def test_ng_empty_capture_unknown_metadata_and_unlimited_snapshot(self):
        self.assertEqual(self.read(ng_section()), [])
        data = ng_section() + ng_interface(snaplen=0) + ng_block(0x12345678, b"data") + ng_packet(tcp_bytes())
        self.assertEqual(len(self.read(data)), 1)

    def test_ng_simple_packet_has_no_invented_timestamp(self):
        packet = udp_bytes()
        body = struct.pack("<I", len(packet)) + packet + b"\0" * (-len(packet) % 4)
        data = ng_section() + ng_interface() + ng_block(3, body)
        frame, = self.read(data)
        self.assertIsNone(frame.timestamp)
        self.assertEqual(frame.data, packet)

    def test_rejects_bad_ng_section_and_block_structure(self):
        base = ng_section() + ng_interface()
        section_bad_bom = bytearray(ng_section())
        section_bad_bom[8:12] = b"xxxx"
        mismatch = bytearray(ng_packet(tcp_bytes()))
        mismatch[-4:] = struct.pack("<I", 12)
        cases = [ng_section()[:10], bytes(section_bad_bom), ng_section(version=(2, 0)),
                 ng_section() + ng_section(), base + b"x", base + bytes(mismatch),
                 base + struct.pack("<II", 6, 13), base + struct.pack("<II", 6, 8),
                 base + struct.pack("<II", 6, MAX_BLOCK_BYTES + 4),
                 base + ng_packet(tcp_bytes())[:-1],
                 struct.pack("<III", 0x0A0D0D0A, 16, 0x1A2B3C4D) + struct.pack("<I", 16)]
        for data in cases:
            with self.subTest(length=len(data)), self.assertRaises(CaptureError):
                self.read(data)

    def test_rejects_bad_ng_interfaces_and_packets(self):
        base = ng_section() + ng_interface()
        cases = [ng_section() + ng_block(1, b""),
                 ng_section() + ng_packet(tcp_bytes()),
                 base + ng_packet(tcp_bytes(), interface=1), base + ng_block(6, b""),
                 base + ng_packet(b"", captured=100, wire=100),
                 base + ng_packet(tcp_bytes(), wire=1),
                 ng_section() + ng_interface(snaplen=1) + ng_packet(tcp_bytes()),
                 base + ng_packet(b"", captured=65536, wire=65536),
                 ng_section() + ng_block(3, b"abcd"), base + ng_block(3, b""),
                 base + ng_block(3, struct.pack("<I", 100)),
                 base + ng_block(3, struct.pack("<I", 65536)),
                 ng_section() + ng_interface(snaplen=0) + ng_block(3, struct.pack("<I", 0))]
        for data in cases:
            with self.subTest(length=len(data)), self.assertRaises(CaptureError):
                self.read(data)

    def test_rejects_bad_ng_options(self):
        options = [ng_option(9, b"12"), ng_option(14, b"x"), ng_option(14, b"\1" * 8),
                   struct.pack("<HH", 2, 100), struct.pack("<HH", 0, 1),
                   struct.pack("<HHI", 0, 0, 1)]
        for option in options:
            with self.subTest(option=option), self.assertRaises(CaptureError):
                self.read(ng_section() + ng_interface(options=option))
        for code in (2, 0x8001, 0x8003):
            with self.subTest(code=code), self.assertRaises(CaptureError):
                self.read(ng_section() + ng_interface() + ng_packet(tcp_bytes(), options=ng_option(code, b"x")))
