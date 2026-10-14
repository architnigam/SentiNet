from contextlib import redirect_stderr, redirect_stdout
import io
import json
from threading import Event
from unittest.mock import Mock, patch

from netsentinel.cli import main
from netsentinel.config import settings_from_dict
from netsentinel.errors import CaptureError, NetSentinelError
from netsentinel.live import LiveResult
from netsentinel.models import CapturedPacket
from netsentinel.runtime import monitor_live
from netsentinel.storage import capture_lock

from tests.helpers import TemporaryCase, tcp_bytes


class RuntimeTests(TemporaryCase):
    def setUp(self):
        super().setUp()
        self.output = self.directory / "live.json"
        self.log = self.directory / "alerts.jsonl"
        self.config = settings_from_dict({"port_scan_unique_ports_threshold": 1})

    def run_monitor(self, **kwargs):
        return monitor_live("Lab", output=self.output, settings=self.config, alert_log_path=self.log, **kwargs)

    def test_live_pipeline_publishes_incremental_stats_alerts_and_completion(self):
        snapshots = []
        def capture(interface, callback, **kwargs):
            self.assertEqual(interface, "Lab")
            snapshots.append(json.loads(self.output.read_text()))
            data = tcp_bytes()
            callback(CapturedPacket(data, 10, len(data), 1))
            kwargs["on_tick"]()
            snapshots.append(json.loads(self.output.read_text()))
            return LiveResult(1, "packet_limit")
        with patch("netsentinel.runtime.capture_live", side_effect=capture):
            report = self.run_monitor(packet_limit=1)
        self.assertEqual([s["monitor"]["status"] for s in snapshots], ["starting", "running"])
        self.assertEqual(snapshots[1]["statistics"]["total_packets"], 1)
        self.assertEqual(report["monitor"]["status"], "completed")
        self.assertEqual(report["detection"]["alerts_emitted"], 1)
        self.assertEqual(json.loads(self.log.read_text()), report["recent_alerts"][0])
        self.assertEqual(json.loads(self.output.read_text()), report)
        self.assertEqual(list(self.directory.glob("*.capture.lock")), [])

    def test_idle_capture_and_stop_preserve_empty_snapshot(self):
        def idle(interface, callback, **kwargs):
            kwargs["on_tick"]()
            return LiveResult(0, "stopped")
        with patch("netsentinel.runtime.capture_live", side_effect=idle):
            report = self.run_monitor(stop_event=Event())
        self.assertEqual(report["monitor"]["status"], "stopped")
        self.assertEqual(report["statistics"]["total_packets"], 0)

    def test_provider_failure_is_published_and_ownership_is_released(self):
        with patch("netsentinel.runtime.capture_live", side_effect=CaptureError("Npcap unavailable")):
            with self.assertRaises(CaptureError):
                self.run_monitor()
        report = json.loads(self.output.read_text())
        self.assertEqual(report["monitor"]["status"], "failed")
        self.assertIn("Npcap", report["monitor"]["error"])
        self.assertEqual(list(self.directory.glob("*.capture.lock")), [])

    def test_keyboard_interrupt_publishes_stop_before_reraising(self):
        with patch("netsentinel.runtime.capture_live", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.run_monitor()
        self.assertEqual(json.loads(self.output.read_text())["monitor"]["stop_reason"], "keyboard_interrupt")
        self.assertEqual(list(self.directory.glob("*.capture.lock")), [])

    def test_failed_snapshot_write_preserves_cause_and_releases_locks(self):
        with patch("netsentinel.runtime.write_report", side_effect=OSError("disk full")):
            with self.assertRaisesRegex(OSError, "disk full"):
                self.run_monitor()
        self.assertEqual(list(self.directory.glob("*.capture.lock")), [])

    def test_second_capture_cannot_overwrite_owner_snapshot_or_alert_log(self):
        self.output.write_text("owner report")
        with capture_lock(self.output):
            with self.assertRaisesRegex(NetSentinelError, "ownership"):
                self.run_monitor()
            self.assertEqual(self.output.read_text(), "owner report")
        with capture_lock(self.log):
            with self.assertRaisesRegex(NetSentinelError, "ownership"):
                self.run_monitor()
        self.assertEqual(list(self.directory.glob("*.capture.lock")), [])

    def test_same_log_and_output_rejected_before_writing(self):
        with self.assertRaises(NetSentinelError):
            monitor_live("Lab", output=self.output, alert_log_path=self.output)
        self.assertFalse(self.output.exists())

    def test_analysis_only_live_capture_does_not_create_log(self):
        with patch("netsentinel.runtime.capture_live", return_value=LiveResult(0, "duration")):
            report = monitor_live("Lab", output=self.output, detect=False)
        self.assertNotIn("detection", report)
        self.assertFalse(self.log.exists())

    def test_lock_records_pid_and_cleans_up_after_processing_failure(self):
        with self.assertRaises(RuntimeError):
            with capture_lock(self.output):
                lock = self.output.with_name(self.output.name + ".capture.lock")
                self.assertGreater(int(lock.read_text()), 0)
                raise RuntimeError("processing failed")
        self.assertFalse(lock.exists())


class LiveCliTests(TemporaryCase):
    def test_cli_lazily_delegates_to_live_modules(self):
        with patch("netsentinel.live.interface_catalog", return_value={"interfaces": []}) as catalog:
            code, stdout, _ = self.invoke(["--list-interfaces"])
        self.assertEqual(code, 0)
        catalog.assert_called_once()
        with patch("netsentinel.runtime.monitor_live", return_value={}) as monitor:
            code, stdout, _ = self.invoke(["--interface", "Lab", "--output", self.directory / "live.json"])
        self.assertEqual(code, 0)
        monitor.assert_called_once()

    def invoke(self, args):
        output, error = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(error):
            code = main([str(arg) for arg in args])
        return code, output.getvalue(), error.getvalue()

    def test_interface_listing_json(self):
        catalog = {"provider_available": False, "interfaces": []}
        with patch("netsentinel.cli.interface_catalog", return_value=catalog):
            code, output, error = self.invoke(["--list-interfaces"])
        self.assertEqual((code, error), (0, ""))
        self.assertEqual(json.loads(output), catalog)

    def test_live_flags_forward_limits_output_and_detection(self):
        report = {"monitor": {"status": "completed"}}
        output, log = self.directory / "live.json", self.directory / "alerts.jsonl"
        with patch("netsentinel.cli.monitor_live", return_value=report) as monitor:
            code, stdout, error = self.invoke(["--interface", "Lab", "--duration", "0.5", "--limit", 5,
                                               "--output", output, "--detect", "--alert-log", log])
        self.assertEqual((code, error), (0, ""))
        self.assertEqual(json.loads(stdout), report)
        self.assertEqual(monitor.call_args.kwargs["duration"], 0.5)
        self.assertEqual(monitor.call_args.kwargs["packet_limit"], 5)
        self.assertTrue(monitor.call_args.kwargs["detect"])

    def test_default_live_output_path(self):
        with patch("netsentinel.cli.monitor_live", return_value={}) as monitor:
            code, _, _ = self.invoke(["--interface", "Lab"])
        self.assertEqual(code, 0)
        self.assertEqual(str(monitor.call_args.kwargs["output"]).replace("\\", "/"), "logs/live_summary.json")

    def test_live_error_has_no_traceback(self):
        with patch("netsentinel.cli.monitor_live", side_effect=CaptureError("missing provider")):
            code, stdout, error = self.invoke(["--interface", "Lab"])
        self.assertEqual((code, stdout), (1, ""))
        self.assertIn("missing provider", error)
        self.assertNotIn("Traceback", error)

    def test_mutually_exclusive_sources_duration_and_list_flags(self):
        cases = [["--pcap", "x", "--interface", "Lab"], ["--list-interfaces", "--pcap", "x"],
                 ["--pcap", "x", "--duration", "1"], ["--list-interfaces", "--detect"],
                 ["--list-interfaces", "--output", "x"]]
        for duration in ("0", "-1", "nan", "inf", "bad"):
            cases.append(["--interface", "Lab", "--duration", duration])
        for args in cases:
            with self.subTest(args=args), self.assertRaises(SystemExit) as context:
                self.invoke(args)
            self.assertEqual(context.exception.code, 2)
