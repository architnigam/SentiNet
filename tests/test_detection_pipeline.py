"""Part 2 pipeline/CLI behavior, including real synthetic PCAP integration."""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from unittest.mock import patch

from examples.create_demo_capture import create_demo as create_normal_demo
from examples.create_detection_demo import create_demo as create_threat_demo
from netsentinel.alerts import AlertLog, AlertManager
from netsentinel.cli import main
from netsentinel.config import Settings, settings_from_dict
from netsentinel.detection.engine import DetectionEngine
from netsentinel.errors import AlertLogError, CaptureError, DetectionError, NetSentinelError
from netsentinel.pipeline import analyze_capture

from tests.helpers import TemporaryCase, pcap_bytes, pcap_header, pcap_record, tcp_bytes, udp_bytes
from tests.test_alerts import finding


class DetectionPipelineTests(TemporaryCase):
    def analyze(self, data, config=None, **kwargs):
        return analyze_capture(self.save(data), settings=config or Settings(), detect=True,
                               alert_log_path=self.directory / "alerts.jsonl", **kwargs)

    def test_normal_demo_has_no_alerts_and_complete_observed_handshake(self):
        path = self.directory / "normal.pcap"
        create_normal_demo(path)
        log = self.directory / "alerts.jsonl"
        report = analyze_capture(path, detect=True, alert_log_path=log)
        self.assertEqual(report["stage"], "threat_analysis")
        self.assertEqual(report["schema_version"], 2)
        self.assertEqual(report["detection"]["alerts_emitted"], 0)
        self.assertEqual(report["detection"]["processed_packets"], 5)
        self.assertEqual(report["detection"]["completed_handshakes"], 1)
        self.assertEqual(report["recent_alerts"], [])
        self.assertEqual(log.read_bytes(), b"")

    def test_empty_capture_creates_empty_log_and_zero_detection_counts(self):
        report = self.analyze(pcap_header())
        self.assertEqual(report["detection"]["processed_packets"], 0)
        self.assertEqual(report["detection"]["active_events"], 0)
        self.assertIsNone(report["detection"]["watermark"])

    def test_scan_integration_logs_exact_evidence(self):
        data = pcap_bytes(*(tcp_bytes(dport=port, flags="A") for port in (80, 81, 82)))
        report = self.analyze(data, settings_from_dict({"port_scan_unique_ports_threshold": 3}))
        self.assertEqual(report["detection"]["alerts_emitted"], 1)
        alert, = report["recent_alerts"]
        self.assertEqual(alert["rules"], ["port_scan"])
        self.assertEqual(alert["evidence"]["port_scan"]["unique_destination_ports"], 3)
        logged = json.loads((self.directory / "alerts.jsonl").read_text())
        self.assertEqual(logged, alert)

    def test_syn_retransmission_integration(self):
        report = self.analyze(pcap_bytes(tcp_bytes(flags="S"), tcp_bytes(flags="S")),
                              settings_from_dict({"syn_packets_threshold": 2}))
        alert, = report["recent_alerts"]
        self.assertEqual(alert["rules"], ["syn_flood"])
        self.assertEqual(alert["evidence"]["syn_flood"]["incomplete_connections"], 1)
        self.assertEqual(alert["evidence"]["syn_flood"]["syn_packets"], 2)

    def test_traffic_rate_integration_and_window_expiry(self):
        data = pcap_header() + b"".join(pcap_record(udp_bytes(), seconds=0) for _ in range(3))
        data += pcap_record(udp_bytes(), seconds=1)
        report = self.analyze(data, settings_from_dict({"window_seconds": 1, "traffic_packets_per_second_threshold": 3}))
        alert, = report["recent_alerts"]
        self.assertEqual(alert["rules"], ["traffic_anomaly"])
        self.assertIsNone(alert["destination_ip"])
        self.assertEqual(report["detection"]["active_events"], 1)

    def test_combined_rules_have_critical_score_once_each(self):
        data = pcap_header() + pcap_record(tcp_bytes(dport=80, flags="S"))
        data += pcap_record(tcp_bytes(dport=81, flags="S"))
        config = settings_from_dict({"window_seconds": 1, "port_scan_unique_ports_threshold": 2,
                                    "syn_packets_threshold": 2, "traffic_packets_per_second_threshold": 2})
        report = self.analyze(data, config)
        alert, = report["recent_alerts"]
        self.assertEqual((alert["score"], alert["severity"]), (100, "Critical"))
        self.assertEqual(len(alert["rules"]), 3)

    def test_late_packets_remain_in_statistics_but_not_detection(self):
        data = pcap_header() + pcap_record(tcp_bytes(dport=80), seconds=2)
        data += pcap_record(tcp_bytes(dport=81), seconds=1)
        data += pcap_record(tcp_bytes(dport=82), seconds=2)
        report = self.analyze(data, settings_from_dict({"port_scan_unique_ports_threshold": 2}))
        self.assertEqual(report["statistics"]["analyzed_packets"], 3)
        self.assertEqual(report["statistics"]["out_of_order_timestamps"], 1)
        self.assertEqual(report["detection"]["processed_packets"], 2)
        self.assertEqual(report["detection"]["late_packets_skipped"], 1)
        self.assertEqual(report["recent_alerts"][0]["evidence"]["port_scan"]["unique_destination_ports"], 2)

    def test_recent_alerts_bounded_but_all_alerts_are_logged(self):
        data = pcap_header() + b"".join(pcap_record(tcp_bytes(), seconds=0) for _ in range(105))
        config = settings_from_dict({"port_scan_unique_ports_threshold": 1, "alert_cooldown_seconds": 0})
        report = self.analyze(data, config)
        self.assertEqual(report["detection"]["alerts_emitted"], 105)
        self.assertEqual(len(report["recent_alerts"]), 100)
        lines = [json.loads(line) for line in (self.directory / "alerts.jsonl").read_text().splitlines()]
        self.assertEqual(len(lines), 105)
        self.assertEqual(report["recent_alerts"], lines[-100:])
        self.assertEqual(len({line["alert_id"] for line in lines}), 105)

    def test_configured_log_path_and_analysis_only_compatibility(self):
        path = self.save(pcap_header())
        log = self.directory / "configured.jsonl"
        config = settings_from_dict({"alert_log_path": str(log)})
        report = analyze_capture(path, settings=config)
        self.assertFalse(log.exists())
        self.assertEqual(report["schema_version"], 1)
        self.assertNotIn("detection", report)
        analyze_capture(path, settings=config, detect=True)
        self.assertTrue(log.exists())

    def test_invalid_flags_and_log_capture_alias(self):
        path = self.save(pcap_header())
        for flag in (1, "yes", None):
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                analyze_capture(path, detect=flag)
        with self.assertRaises(ValueError):
            analyze_capture(path, alert_log_path=self.directory / "alerts.jsonl")
        with self.assertRaises(NetSentinelError):
            analyze_capture(path, detect=True, alert_log_path=path)
        self.assertEqual(path.read_bytes(), pcap_header())

    def test_corrupt_capture_does_not_append_alerts(self):
        log_path = self.directory / "alerts.jsonl"
        with AlertLog(log_path) as log:
            AlertManager(Settings()).create(finding(), log)
        previous = log_path.read_bytes()
        with self.assertRaises(CaptureError):
            self.analyze(pcap_bytes(tcp_bytes()) + b"bad")
        self.assertEqual(log_path.read_bytes(), previous)

    def test_corrupt_existing_log_is_rejected(self):
        (self.directory / "alerts.jsonl").write_bytes(b"partial")
        with self.assertRaises(AlertLogError):
            self.analyze(pcap_header())

    def test_state_limit_failure_retains_completed_alerts(self):
        config = settings_from_dict({"port_scan_unique_ports_threshold": 1})
        engine = DetectionEngine(config, max_events=1)
        with patch("netsentinel.pipeline.DetectionEngine", return_value=engine):
            with self.assertRaises(DetectionError):
                self.analyze(pcap_header() + pcap_record(tcp_bytes()) * 2, config)
        lines = (self.directory / "alerts.jsonl").read_text().splitlines()
        self.assertEqual(len(lines), 1)

    def test_full_threat_demo_escalates_medium_high_critical(self):
        path = self.directory / "threat.pcap"
        create_threat_demo(path)
        report = analyze_capture(path, detect=True, alert_log_path=self.directory / "alerts.jsonl")
        self.assertEqual(report["statistics"]["analyzed_packets"], 2000)
        self.assertEqual([a["severity"] for a in report["recent_alerts"]], ["Medium", "High", "Critical"])
        self.assertEqual([a["score"] for a in report["recent_alerts"]], [30, 70, 100])
        self.assertEqual(report["detection"]["alerts_emitted"], 3)
        self.assertEqual(report["detection"]["pending_connections"], 2000)


class DetectionCliTests(TemporaryCase):
    def test_alert_log_hardlink_to_capture_is_rejected(self):
        path = self.save(pcap_header())
        alias = self.directory / "alias.jsonl"
        try:
            os.link(path, alias)
        except OSError as exc:
            self.skipTest(f"Hard links unavailable: {exc}")
        code, stdout, error = self.invoke(["--pcap", path, "--detect", "--alert-log", alias])
        self.assertEqual((code, stdout), (1, ""))
        self.assertIn("must not overwrite", error)
        self.assertEqual(path.read_bytes(), pcap_header())

    def invoke(self, args):
        out, error = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(error):
            code = main([str(value) for value in args])
        return code, out.getvalue(), error.getvalue()

    def test_detection_flags_write_log_and_report(self):
        path = self.save(pcap_bytes(tcp_bytes(dport=80), tcp_bytes(dport=81)))
        config = self.save(b'{"port_scan_unique_ports_threshold":2}', "settings.json")
        output, log = self.directory / "summary.json", self.directory / "alerts.jsonl"
        code, stdout, stderr = self.invoke(["--pcap", path, "--config", config, "--detect",
                                           "--alert-log", log, "--output", output])
        self.assertEqual((code, stderr), (0, ""))
        report = json.loads(stdout)
        self.assertEqual(json.loads(output.read_text()), report)
        self.assertEqual(report["detection"]["alerts_emitted"], 1)
        self.assertEqual(json.loads(log.read_text()), report["recent_alerts"][0])

    def test_alert_log_flag_requires_detect(self):
        with self.assertRaises(SystemExit) as context:
            self.invoke(["--pcap", "unused", "--alert-log", "unused.jsonl"])
        self.assertEqual(context.exception.code, 2)

    def test_log_cannot_alias_capture_config_or_summary(self):
        path = self.save(pcap_header())
        config = self.save(b"{}", "settings.json")
        summary = self.save(b"old report", "summary.json")
        for log in (path, config, summary):
            with self.subTest(log=log):
                code, stdout, stderr = self.invoke(["--pcap", path, "--config", config, "--detect",
                                                   "--alert-log", log, "--output", summary])
                self.assertEqual((code, stdout), (1, ""))
                self.assertIn("must not overwrite", stderr)
        self.assertEqual(path.read_bytes(), pcap_header())
        self.assertEqual(config.read_bytes(), b"{}")
        self.assertEqual(summary.read_bytes(), b"old report")

    def test_configured_log_alias_is_also_rejected(self):
        path = self.save(pcap_header())
        config = self.save(json.dumps({"alert_log_path": str(path)}).encode(), "settings.json")
        code, _, error = self.invoke(["--pcap", path, "--config", config, "--detect"])
        self.assertEqual(code, 1)
        self.assertIn("must not overwrite", error)

    def test_log_error_preserves_previous_summary_and_prints_no_traceback(self):
        path = self.save(pcap_header())
        output = self.save(b"previous", "summary.json")
        log = self.save(b"partial", "alerts.jsonl")
        code, stdout, error = self.invoke(["--pcap", path, "--detect", "--alert-log", log, "--output", output])
        self.assertEqual((code, stdout), (1, ""))
        self.assertIn("incomplete final line", error)
        self.assertNotIn("Traceback", error)
        self.assertEqual(output.read_bytes(), b"previous")

    def test_log_permission_error_returns_application_error(self):
        path = self.save(pcap_header())
        with patch("netsentinel.pipeline.AlertLog.__enter__", side_effect=AlertLogError("denied")):
            code, stdout, error = self.invoke(["--pcap", path, "--detect", "--alert-log", self.directory / "alerts.jsonl"])
        self.assertEqual((code, stdout), (1, ""))
        self.assertIn("denied", error)
