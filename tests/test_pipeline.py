import json
from unittest.mock import patch

from scapy.layers.inet import ICMP, IP, TCP
from scapy.layers.l2 import ARP, Ether

from examples.create_demo_capture import create_demo
from netsentinel.analyzer import analyze_packet
from netsentinel.config import load_settings
from netsentinel.errors import CaptureError
from netsentinel.models import AnalysisResult, CapturedPacket
from netsentinel.pipeline import analyze_capture
from netsentinel.statistics import TrafficStatistics

from tests.helpers import TemporaryCase, ng_block, ng_interface, ng_section, pcap_bytes, pcap_header, pcap_record, tcp_bytes, udp_bytes


class PipelineTests(TemporaryCase):
    def test_demo_end_to_end_statistics_and_sample(self):
        path = self.directory / "demo.pcap"
        create_demo(path)
        report = analyze_capture(path)
        stats = report["statistics"]
        self.assertEqual(stats["total_packets"], 8)
        self.assertEqual(stats["analyzed_packets"], 5)
        self.assertEqual(stats["skipped_packets"], 3)
        self.assertEqual(stats["protocol_counts"], {"TCP": 3, "UDP": 2})
        self.assertEqual(stats["skip_reasons"], {"unsupported_protocol": 2, "fragmented_packet": 1})
        self.assertEqual(stats["source_counts"], {"192.0.2.10": 3, "192.0.2.20": 1, "2001:db8::1": 1})
        self.assertEqual(stats["duration_seconds"], 1.75)
        self.assertEqual(len(report["sample_packets"]), 5)
        self.assertEqual(report["source"], str(path.resolve()))
        self.assertNotIn("alerts", report)  # Detection does not exist in Part 1.
        json.dumps(report, allow_nan=False)

    def test_empty_capture_returns_zero_counters_and_null_times(self):
        report = analyze_capture(self.save(pcap_header()))
        stats = report["statistics"]
        self.assertEqual(stats["total_packets"], 0)
        self.assertEqual(stats["protocol_counts"], {"TCP": 0, "UDP": 0})
        self.assertIsNone(stats["first_timestamp"])
        self.assertIsNone(stats["last_timestamp"])
        self.assertEqual(stats["duration_seconds"], 0)
        self.assertEqual(report["sample_packets"], [])

    def test_bad_packet_does_not_prevent_next_good_packet(self):
        report = analyze_capture(self.save(pcap_bytes(b"bad", tcp_bytes())))
        self.assertEqual(report["statistics"]["analyzed_packets"], 1)
        self.assertEqual(report["statistics"]["skip_reasons"], {"malformed_packet": 1})

    def test_limits_and_bounded_samples_do_not_change_statistics(self):
        path = self.save(pcap_bytes(b"bad", tcp_bytes(), udp_bytes()))
        for sample_limit in [0, 1, 1000]:
            with self.subTest(sample_limit=sample_limit):
                report = analyze_capture(path, sample_limit=sample_limit)
                self.assertEqual(report["statistics"]["total_packets"], 3)
                self.assertEqual(len(report["sample_packets"]), min(2, sample_limit))
        limited = analyze_capture(path, packet_limit=1)
        self.assertEqual(limited["statistics"]["total_packets"], 1)
        self.assertEqual(limited["sample_packets"], [])
        for value in [-1, 1001, True, "1", 1.5, None]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                analyze_capture(path, sample_limit=value)

    def test_out_of_order_duplicate_and_zero_timestamps(self):
        packet = tcp_bytes()
        data = pcap_header() + b"".join(pcap_record(packet, seconds=t) for t in [2, 1, 1, 0, 3])
        stats = analyze_capture(self.save(data))["statistics"]
        self.assertEqual(stats["out_of_order_timestamps"], 2)
        self.assertEqual((stats["first_timestamp"], stats["last_timestamp"], stats["duration_seconds"]), (0, 3, 3))

    def test_capture_truncation_is_reported_separately_from_invalid_packet(self):
        packet = tcp_bytes()
        path = self.save(pcap_header() + pcap_record(packet, wire=100))
        report = analyze_capture(path)
        stats = report["statistics"]
        self.assertEqual(stats["truncated_packets"], 1)
        self.assertEqual(stats["captured_bytes"], len(packet))
        self.assertEqual(stats["wire_bytes"], 100)
        self.assertTrue(report["sample_packets"][0]["truncated"])

    def test_missing_timestamp_is_skipped_and_not_replaced_with_wall_clock(self):
        packet = udp_bytes()
        import struct
        body = struct.pack("<I", len(packet)) + packet + b"\0" * (-len(packet) % 4)
        stats = analyze_capture(self.save(ng_section() + ng_interface() + ng_block(3, body)))["statistics"]
        self.assertEqual(stats["skip_reasons"], {"missing_timestamp": 1})
        self.assertIsNone(stats["first_timestamp"])

    def test_custom_settings_are_preserved_in_report(self):
        config = self.save(b'{"window_seconds":5}', "settings.json")
        settings = load_settings(config)
        report = analyze_capture(self.save(pcap_header()), settings=settings)
        self.assertEqual(report["settings"]["window_seconds"], 5)

    def test_stream_is_closed_if_processing_fails(self):
        closed = []
        def frames(*args, **kwargs):
            try:
                yield CapturedPacket(tcp_bytes(), 0, len(tcp_bytes()), 1)
            finally:
                closed.append(True)
        with patch("netsentinel.pipeline.read_capture", side_effect=frames):
            with patch("netsentinel.pipeline.analyze_packet", side_effect=RuntimeError("test failure")):
                with self.assertRaises(RuntimeError):
                    analyze_capture("unused")
        self.assertEqual(closed, [True])

    def test_corrupt_container_produces_no_report(self):
        with self.assertRaises(CaptureError):
            analyze_capture(self.save(pcap_bytes(tcp_bytes())[:-1]))


class StatisticsTests(TemporaryCase):
    def test_source_tracking_is_bounded_and_existing_sources_continue_counting(self):
        stats = TrafficStatistics(source_limit=2)
        ips = ["192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.1", "192.0.2.3"]
        for ip in ips:
            data = bytes(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") /
                         IP(src=ip, dst="192.0.2.10") / TCP())
            frame = CapturedPacket(data, 1, len(data), 1)
            stats.observe(frame, analyze_packet(frame))
        self.assertEqual(dict(stats.source_counts), {"192.0.2.1": 2, "192.0.2.2": 1})
        self.assertEqual(stats.untracked_source_packets, 2)
        self.assertEqual(sum(stats.source_counts.values()) + stats.untracked_source_packets, stats.analyzed_packets)

    def test_invalid_source_tracking_limits(self):
        for value in [0, -1, True, 1.5]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                TrafficStatistics(source_limit=value)

    def test_invalid_timestamps_do_not_poison_statistics(self):
        stats = TrafficStatistics()
        for timestamp in [None, float("nan"), float("inf"), -1, "bad", True, 10**1000]:
            frame = CapturedPacket(b"", timestamp, 0, 1)
            stats.observe(frame, analyze_packet(frame))
        self.assertIsNone(stats.first_timestamp)
        self.assertEqual(stats.to_dict()["skipped_packets"], 7)
        json.dumps(stats.to_dict(), allow_nan=False)
