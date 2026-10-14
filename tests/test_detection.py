"""Rule, handshake, event-time, and bounded-state tests using normalized records."""

from dataclasses import replace
import random
import unittest

from netsentinel.config import Settings, settings_from_dict
from netsentinel.detection.engine import DetectionEngine
from netsentinel.errors import ConfigurationError, DetectionError
from netsentinel.models import PacketRecord


def record(t=0, *, source="192.0.2.1", target="192.0.2.2", sport=40000,
           port=80, protocol="TCP", flags=0x10):
    return PacketRecord(t, source, target, 4, protocol, sport, port, flags, 54, 54, False)


def settings(**overrides):
    return settings_from_dict(overrides)


class DetectionTests(unittest.TestCase):
    def test_equal_large_timestamps_do_not_expire_each_other(self):
        engine = DetectionEngine(settings(port_scan_unique_ports_threshold=2))
        engine.process(record(1e20, port=80, flags=2))
        finding = engine.process(record(1e20, port=81, flags=2))
        self.assertIsNotNone(finding)
        self.assertEqual(engine.snapshot()["active_events"], 2)
        self.assertEqual(engine.snapshot()["pending_connections"], 2)

    def test_normal_packets_below_all_thresholds(self):
        engine = DetectionEngine(Settings())
        self.assertIsNone(engine.process(record()))
        self.assertIsNone(engine.process(record(protocol="UDP", port=53, flags=0)))
        self.assertEqual(engine.snapshot()["processed_packets"], 2)

    def test_scan_threshold_repeated_ports_and_protocol_policy(self):
        engine = DetectionEngine(settings(port_scan_unique_ports_threshold=3))
        self.assertIsNone(engine.process(record()))
        self.assertIsNone(engine.process(record(sport=40001)))
        self.assertIsNone(engine.process(record(protocol="UDP", flags=0)))
        finding = engine.process(record(port=81))
        self.assertEqual(finding.evidence["port_scan"]["unique_destination_ports"], 3)
        above = engine.process(record(port=82))
        self.assertEqual(above.evidence["port_scan"]["unique_destination_ports"], 4)
        self.assertEqual(finding.destination_ip, "192.0.2.2")

    def test_sources_and_targets_are_isolated(self):
        engine = DetectionEngine(settings(port_scan_unique_ports_threshold=2, syn_packets_threshold=2))
        first = record(flags=2)
        for packet in [first, replace(first, destination_ip="192.0.2.3"), replace(first, source_ip="192.0.2.4")]:
            self.assertIsNone(engine.process(packet))
        finding = engine.process(replace(first, destination_port=81))
        self.assertEqual(set(finding.evidence), {"port_scan", "syn_flood"})
        self.assertEqual(finding.source_ip, first.source_ip)
        self.assertEqual(finding.destination_ip, first.destination_ip)

    def test_exact_window_boundary_expires_old_events(self):
        engine = DetectionEngine(settings(port_scan_unique_ports_threshold=2))
        self.assertIsNone(engine.process(record(0, port=80)))
        self.assertIsNotNone(engine.process(record(9.999, port=81)))
        finding = engine.process(record(10, port=82))
        ports = finding.evidence["port_scan"]["sample_ports"]
        self.assertEqual({p["port"] for p in ports}, {81, 82})
        self.assertEqual(engine.snapshot()["active_events"], 2)

    def test_inactive_source_target_and_pending_state_expires(self):
        engine = DetectionEngine(Settings())
        engine.process(record(0, flags=2))
        engine.process(record(10, source="192.0.2.3"))
        snapshot = engine.snapshot()
        self.assertEqual(snapshot["active_events"], 1)
        self.assertEqual(snapshot["active_sources"], 1)
        self.assertEqual(snapshot["active_ip_pairs"], 1)
        self.assertEqual(snapshot["pending_connections"], 0)

    def test_rate_uses_full_window_and_all_source_destinations(self):
        engine = DetectionEngine(settings(window_seconds=2, traffic_packets_per_second_threshold=2))
        for index in range(3):
            self.assertIsNone(engine.process(record(0, target=f"192.0.2.{index + 2}")))
        finding = engine.process(record(0, target="192.0.2.5"))
        self.assertIsNone(finding.destination_ip)
        self.assertEqual(finding.evidence["traffic_anomaly"]["packet_count"], 4)
        self.assertEqual(finding.evidence["traffic_anomaly"]["packets_per_second"], 2)
        self.assertIsNone(engine.process(record(0, source="192.0.2.100")))
        self.assertEqual(engine.process(record(0)).evidence["traffic_anomaly"]["packet_count"], 5)
        self.assertIsNone(engine.process(record(2)))

    def test_all_active_rules_correlate_for_current_pair(self):
        engine = DetectionEngine(settings(window_seconds=1, port_scan_unique_ports_threshold=2,
                                          syn_packets_threshold=2, traffic_packets_per_second_threshold=2))
        self.assertIsNone(engine.process(record(0, flags=2)))
        finding = engine.process(record(0, port=81, flags=2))
        self.assertEqual(set(finding.evidence), {"port_scan", "syn_flood", "traffic_anomaly"})
        self.assertEqual(finding.destination_ip, "192.0.2.2")

    def test_late_packets_do_not_mutate_detection_or_complete_handshakes(self):
        engine = DetectionEngine(settings(port_scan_unique_ports_threshold=2))
        engine.process(record(2, flags=2))
        snapshot = engine.snapshot()
        self.assertIsNone(engine.process(record(1, port=81)))
        current = engine.snapshot()
        self.assertEqual(current["late_packets_skipped"], 1)
        for field in ("active_events", "processed_packets", "pending_connections", "watermark"):
            self.assertEqual(current[field], snapshot[field])
        self.assertIsNotNone(engine.process(record(2, port=82)))

    def test_syn_retransmission_counts_packets_but_not_duplicate_connections(self):
        engine = DetectionEngine(settings(syn_packets_threshold=2))
        self.assertIsNone(engine.process(record(flags=2)))
        finding = engine.process(record(flags=2))
        self.assertEqual(finding.evidence["syn_flood"]["syn_packets"], 2)
        self.assertEqual(finding.evidence["syn_flood"]["incomplete_connections"], 1)
        self.assertEqual(engine.snapshot()["pending_connections"], 1)

    def test_syn_ack_is_not_counted_as_syn_without_ack(self):
        engine = DetectionEngine(settings(syn_packets_threshold=1))
        self.assertIsNone(engine.process(record(flags=0x12)))
        self.assertEqual(engine.snapshot()["pending_connections"], 0)

    def test_complete_handshake_requires_syn_ack_then_originating_ack(self):
        engine = DetectionEngine(Settings())
        engine.process(record(flags=2))
        engine.process(record(flags=0x10))  # ACK without observed SYN-ACK.
        self.assertEqual(engine.snapshot()["pending_connections"], 1)
        engine.process(record(source="192.0.2.2", target="192.0.2.1", sport=80, port=40000, flags=0x12))
        engine.process(record(flags=0x18))
        self.assertEqual(engine.snapshot()["pending_connections"], 0)
        self.assertEqual(engine.snapshot()["completed_handshakes"], 1)
        engine.process(record(flags=0x10))
        self.assertEqual(engine.snapshot()["completed_handshakes"], 1)

    def test_wrong_flow_syn_ack_does_not_complete_connection(self):
        engine = DetectionEngine(Settings())
        engine.process(record(flags=2))
        engine.process(record(source="192.0.2.2", target="192.0.2.1", sport=81, port=40000, flags=0x12))
        engine.process(record(flags=0x10))
        self.assertEqual(engine.snapshot()["pending_connections"], 1)

    def test_retransmission_preserves_observed_syn_ack_progress(self):
        engine = DetectionEngine(Settings())
        engine.process(record(0, flags=2))
        engine.process(record(1, source="192.0.2.2", target="192.0.2.1", sport=80, port=40000, flags=0x12))
        engine.process(record(2, flags=2))
        engine.process(record(3, flags=0x10))
        self.assertEqual(engine.completed_handshakes, 1)

    def test_reset_in_either_direction_clears_pending_flow(self):
        for reverse in (False, True):
            with self.subTest(reverse=reverse):
                engine = DetectionEngine(Settings())
                engine.process(record(flags=2))
                reset = record(flags=4) if not reverse else record(
                    source="192.0.2.2", target="192.0.2.1", sport=80, port=40000, flags=0x14)
                engine.process(reset)
                self.assertEqual(engine.snapshot()["pending_connections"], 0)
                self.assertEqual(engine.snapshot()["reset_connections"], 1)

    def test_syn_fin_and_syn_reset_are_not_pending_connections(self):
        engine = DetectionEngine(settings(syn_packets_threshold=1))
        for flags in (3, 6):
            finding = engine.process(record(flags=flags))
            self.assertIn("syn_flood", finding.evidence)
            self.assertEqual(engine.snapshot()["pending_connections"], 0)

    def test_pending_expiry_order_after_retransmission(self):
        engine = DetectionEngine(Settings())
        engine.process(record(0, flags=2))
        engine.process(record(1, flags=2, sport=40001))
        engine.process(record(2, flags=2))
        engine.process(record(11, protocol="UDP", flags=0))
        self.assertEqual(engine.snapshot()["pending_connections"], 1)
        engine.process(record(12))
        self.assertEqual(engine.snapshot()["pending_connections"], 0)

    def test_event_limit_fails_explicitly_and_expiry_frees_capacity(self):
        engine = DetectionEngine(Settings(), max_events=2)
        engine.process(record())
        engine.process(record())
        with self.assertRaisesRegex(DetectionError, "event limit"):
            engine.process(record())
        self.assertEqual(engine.snapshot()["active_events"], 2)
        engine.process(record(10))
        self.assertEqual(engine.snapshot()["active_events"], 1)

    def test_connection_limit_does_not_silently_discard_flows(self):
        engine = DetectionEngine(Settings(), max_connections=1)
        engine.process(record(flags=2))
        engine.process(record(flags=2))  # Same flow may be retransmitted at capacity.
        with self.assertRaisesRegex(DetectionError, "connection limit"):
            engine.process(record(flags=2, sport=40001))
        self.assertEqual(engine.snapshot()["pending_connections"], 1)
        self.assertEqual(engine.snapshot()["active_events"], 2)

    def test_invalid_limits_and_programmatic_configuration(self):
        for argument in ("max_events", "max_connections"):
            for value in (0, -1, True, 1.5):
                with self.subTest(argument=argument, value=value), self.assertRaises(ValueError):
                    DetectionEngine(Settings(), **{argument: value})
        with self.assertRaises(ConfigurationError):
            DetectionEngine(replace(Settings(), window_seconds=0))

    def test_invalid_record_time_or_protocol_does_not_mutate_state(self):
        engine = DetectionEngine(Settings())
        for timestamp in (None, -1, float("nan"), float("inf"), True, "0", 10**1000):
            with self.subTest(timestamp=str(timestamp)[:20]), self.assertRaises(ValueError):
                engine.process(record(timestamp))
        with self.assertRaises(ValueError):
            engine.process(record(protocol="ICMP"))
        self.assertEqual(engine.snapshot()["active_events"], 0)

    def test_rule_state_matches_independent_brute_force_window_oracle(self):
        config = settings(window_seconds=5, port_scan_unique_ports_threshold=3,
                          syn_packets_threshold=3, traffic_packets_per_second_threshold=2)
        engine = DetectionEngine(config)
        randomizer = random.Random(123)
        history = []
        now = 0
        for _ in range(500):
            now += randomizer.choice([0, 0, 1, 2])
            packet = record(now, source=f"192.0.2.{randomizer.randrange(1, 4)}",
                            target=f"198.51.100.{randomizer.randrange(1, 4)}",
                            port=randomizer.randrange(80, 85), sport=randomizer.randrange(40000, 40010),
                            protocol=randomizer.choice(["TCP", "UDP"]), flags=randomizer.choice([2, 16]))
            history.append(packet)
            window = [p for p in history if now - 5 < p.timestamp <= now]
            pair = [p for p in window if (p.source_ip, p.destination_ip) == (packet.source_ip, packet.destination_ip)]
            expected = set()
            if len({(p.protocol, p.destination_port) for p in pair}) >= 3:
                expected.add("port_scan")
            if sum(p.syn_without_ack for p in pair) >= 3:
                expected.add("syn_flood")
            if sum(p.source_ip == packet.source_ip for p in window) >= 10:
                expected.add("traffic_anomaly")
            finding = engine.process(packet)
            self.assertEqual(set(finding.evidence) if finding else set(), expected)
            self.assertEqual(engine.snapshot()["active_events"], len(window))

    def test_port_evidence_sample_is_bounded(self):
        engine = DetectionEngine(settings(port_scan_unique_ports_threshold=1))
        for port in range(30):
            finding = engine.process(record(port=port))
        self.assertEqual(finding.evidence["port_scan"]["unique_destination_ports"], 30)
        self.assertEqual(len(finding.evidence["port_scan"]["sample_ports"]), 20)
