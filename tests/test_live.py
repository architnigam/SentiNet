"""Live capture without NIC privileges: deterministic socket and clock providers."""

from types import SimpleNamespace
from threading import Event
import unittest
from unittest.mock import Mock, patch

from scapy.error import Scapy_Exception
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from netsentinel.capture import MAX_PACKET_BYTES
from netsentinel.errors import CaptureError, DetectionError
from netsentinel.live import capture_live, interface_catalog, packet_to_frame, resolve_interface

from tests.helpers import tcp_bytes


class LiveCaptureTests(unittest.TestCase):
    def test_socket_cleanup_failure_is_visible_without_masking_processing_error(self):
        self.sniff.side_effect = self.pump
        self.socket.close.side_effect = OSError("close failed")
        with self.assertRaisesRegex(CaptureError, "cleanup failed"):
            capture_live("Lab", Mock(), packet_limit=1)
        with self.assertRaisesRegex(DetectionError, "original detection error"):
            capture_live("Lab", Mock(side_effect=DetectionError("original detection error")))

    def setUp(self):
        self.interface = SimpleNamespace(name="Lab", network_name="lab0", description="Lab adapter",
                                         ips={4: ["192.0.2.1"], 6: ["2001:db8::1"]}, dummy=False)
        self.socket = SimpleNamespace(closed=False, close=Mock())
        self.conf = SimpleNamespace(use_pcap=True, ifaces={"lab0": self.interface},
                                    L2listen=Mock(return_value=self.socket),
                                    l2types=SimpleNamespace(layer2num={Ether: 1}))
        self.addCleanup(patch.stopall)
        patch("netsentinel.live.conf", self.conf).start()
        patch("netsentinel.live.WINDOWS", True).start()
        self.sniff = patch("netsentinel.live.sniff").start()
        self.packet = Ether(tcp_bytes())
        self.packet.time = 10.25

    def pump(self, **kwargs):
        kwargs["prn"](self.packet)

    def test_catalog_reports_addresses_dummy_filter_and_provider(self):
        self.conf.ifaces["dummy"] = SimpleNamespace(dummy=True)
        value = interface_catalog()
        self.assertEqual(len(value["interfaces"]), 1)
        self.assertTrue(value["provider_available"])
        self.assertEqual(value["interfaces"][0]["addresses"], ["192.0.2.1", "2001:db8::1"])
        self.conf.use_pcap = False
        self.assertFalse(interface_catalog()["provider_available"])
        with patch("netsentinel.live.WINDOWS", False):
            self.assertTrue(interface_catalog()["provider_available"])

    def test_interface_selection_exact_name_description_and_ambiguity(self):
        for selector in ("lab0", "Lab", "Lab adapter"):
            self.assertEqual(resolve_interface(selector), "lab0")
        self.conf.ifaces["lab1"] = SimpleNamespace(**{**self.interface.__dict__, "network_name": "lab1"})
        with self.assertRaisesRegex(CaptureError, "ambiguous"):
            resolve_interface("Lab")
        self.assertEqual(resolve_interface("lab0"), "lab0")
        for selector in ("", "  ", None, "absent"):
            with self.subTest(selector=selector), self.assertRaises(CaptureError):
                resolve_interface(selector)

    def test_missing_provider_and_catalog_failure_are_clear(self):
        self.conf.use_pcap = False
        with self.assertRaisesRegex(CaptureError, "Npcap"):
            capture_live("Lab", Mock(), packet_limit=1)
        self.conf.L2listen.assert_not_called()
        self.conf.ifaces = Mock()
        self.conf.ifaces.values.side_effect = OSError("enumeration denied")
        with self.assertRaisesRegex(CaptureError, "enumeration denied"):
            interface_catalog()

    def test_packet_conversion_preserves_metadata(self):
        result = packet_to_frame(self.packet)
        self.assertEqual(result.timestamp, 10.25)
        self.assertEqual(result.link_type, 1)
        self.assertEqual(result.data, tcp_bytes())
        self.packet.wirelen = 100
        self.assertEqual(packet_to_frame(self.packet).wire_length, 100)
        self.packet.time = None
        self.assertIsNone(packet_to_frame(self.packet).timestamp)

    def test_large_packet_is_capped_with_original_wire_length(self):
        packet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02", type=0x1234) / Raw(b"x" * (MAX_PACKET_BYTES + 100))
        result = packet_to_frame(packet)
        self.assertEqual(len(result.data), MAX_PACKET_BYTES)
        self.assertGreater(result.wire_length, MAX_PACKET_BYTES)

    def test_invalid_wire_metadata_is_not_silently_invented(self):
        for wire in ("bad", -1, float("inf")):
            self.packet.wirelen = wire
            with self.subTest(wire=wire), self.assertRaises(CaptureError):
                packet_to_frame(self.packet)
        self.packet.wirelen = None
        self.packet.time = "bad"
        with self.assertRaises(CaptureError):
            packet_to_frame(self.packet)

    def test_packet_limit_and_no_packet_retention(self):
        self.sniff.side_effect = self.pump
        callback, tick = Mock(), Mock()
        result = capture_live("Lab", callback, on_tick=tick, packet_limit=1)
        self.assertEqual((result.packets, result.reason), (1, "packet_limit"))
        self.assertFalse(self.sniff.call_args.kwargs["store"])
        self.assertTrue(self.sniff.call_args.kwargs["chainCC"])
        self.assertIs(self.sniff.call_args.kwargs["opened_socket"], self.socket)
        callback.assert_called_once()
        tick.assert_called_once()
        self.socket.close.assert_called_once()

    def test_polling_uses_one_socket_and_remaining_packet_count(self):
        self.sniff.side_effect = self.pump
        result = capture_live("Lab", Mock(), packet_limit=2)
        self.assertEqual(result.packets, 2)
        self.conf.L2listen.assert_called_once()
        self.assertEqual([call.kwargs["count"] for call in self.sniff.call_args_list], [2, 1])

    def test_idle_duration_is_bounded_and_publishes_heartbeat(self):
        tick = Mock()
        with patch("netsentinel.live.time.monotonic", side_effect=[0, 0, 0.25]):
            result = capture_live("Lab", Mock(), duration=0.25, on_tick=tick)
        self.assertEqual((result.packets, result.reason), (0, "duration"))
        self.assertEqual(self.sniff.call_args.kwargs["timeout"], 0.25)
        tick.assert_called_once()
        self.socket.close.assert_called_once()

    def test_pre_stopped_session_never_opens_a_socket(self):
        stop = Event()
        stop.set()
        result = capture_live("unused", Mock(), stop_event=stop)
        self.assertEqual(result.reason, "stopped")
        self.conf.L2listen.assert_not_called()

    def test_stop_during_packet_processing_ends_the_poll(self):
        stop = Event()
        def pump(**kwargs):
            kwargs["prn"](self.packet)
            self.assertTrue(kwargs["stop_filter"](self.packet))
            kwargs["prn"](self.packet)  # Do not deliver packets after stop.
        self.sniff.side_effect = pump
        callback = Mock(side_effect=lambda frame: stop.set())
        result = capture_live("Lab", callback, stop_event=stop)
        self.assertEqual((result.packets, result.reason), (1, "stopped"))
        callback.assert_called_once()

    def test_processing_failure_is_rethrown_even_if_sniff_would_swallow_it(self):
        callback = Mock(side_effect=DetectionError("state full"))
        def pump(**kwargs):
            kwargs["prn"](self.packet)
            self.assertTrue(kwargs["stop_filter"](self.packet))
            kwargs["prn"](self.packet)
        self.sniff.side_effect = pump
        with self.assertRaisesRegex(DetectionError, "state full"):
            capture_live("Lab", callback)
        callback.assert_called_once()
        self.socket.close.assert_called_once()

    def test_socket_failure_and_unexpected_socket_close_are_visible(self):
        for failure in (PermissionError("denied"), Scapy_Exception("provider failed"), RuntimeError("backend failed")):
            with self.subTest(failure=failure):
                self.conf.L2listen.side_effect = failure
                with self.assertRaises(CaptureError):
                    capture_live("Lab", Mock(), packet_limit=1)
        self.conf.L2listen.side_effect = None
        self.sniff.side_effect = lambda **kwargs: setattr(self.socket, "closed", True)
        with self.assertRaisesRegex(CaptureError, "closed unexpectedly"):
            capture_live("Lab", Mock())
        self.socket.close.assert_called_once()

    def test_sniff_failure_and_keyboard_interrupt_close_socket(self):
        for failure in (OSError("read failed"), KeyboardInterrupt()):
            self.sniff.side_effect = failure
            with self.subTest(failure=type(failure).__name__):
                with self.assertRaises(KeyboardInterrupt if isinstance(failure, KeyboardInterrupt) else CaptureError):
                    capture_live("Lab", Mock())
        self.assertEqual(self.socket.close.call_count, 2)

    def test_invalid_limits_and_durations(self):
        for limit in (0, -1, True, 1.5):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                capture_live("Lab", Mock(), packet_limit=limit)
        for name in ("duration", "poll_interval"):
            for value in (0, -1, True, "1", float("nan"), float("inf"), 10**1000):
                with self.subTest(name=name, value=str(value)[:20]), self.assertRaises(ValueError):
                    capture_live("Lab", Mock(), **{name: value})
        for value in (None, 6):
            with self.assertRaises(ValueError):
                capture_live("Lab", Mock(), poll_interval=value)
