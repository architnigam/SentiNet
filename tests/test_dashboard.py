"""Dashboard data and actual Streamlit widget behavior; no browser/NIC needed."""

from copy import deepcopy
import json
import os
import time
from pathlib import Path
from unittest.mock import patch

from streamlit.testing.v1 import AppTest

from netsentinel.config import settings_from_dict
from netsentinel.dashboard.app import default_snapshot
from netsentinel.dashboard.data import (
    DashboardDataError, MAX_LOG_BYTES, MAX_REPORT_BYTES, SEVERITIES,
    alert_rows, read_recent_alerts, read_snapshot, valid_alert,
)
from netsentinel.pipeline import analyze_capture

from tests.helpers import ROOT, TemporaryCase, pcap_header, pcap_record, tcp_bytes

APP = ROOT / "src/netsentinel/dashboard/app.py"


class DashboardFixture(TemporaryCase):
    def setUp(self):
        super().setUp()
        self.log = self.directory / "alerts.jsonl"
        data = pcap_header() + pcap_record(tcp_bytes(dport=80, flags="S")) + pcap_record(tcp_bytes(dport=81, flags="S"))
        config = settings_from_dict({"window_seconds": 1, "port_scan_unique_ports_threshold": 2,
                                    "syn_packets_threshold": 2, "traffic_packets_per_second_threshold": 2})
        self.report = analyze_capture(self.save(data), settings=config, detect=True, alert_log_path=self.log)
        self.path = self.directory / "summary.json"
        self.path.write_text(json.dumps(self.report), encoding="utf-8")
        self.alert = self.report["recent_alerts"][0]


class DashboardDataTests(DashboardFixture):
    def test_real_snapshot_and_alert_are_accepted(self):
        self.assertEqual(read_snapshot(self.path), self.report)
        self.assertTrue(valid_alert(self.alert))

    def test_missing_directory_bad_json_encoding_and_oversized_snapshot(self):
        for data in (b"", b"{", b"\xff", b' {"value":NaN}', b" " * (MAX_REPORT_BYTES + 1)):
            path = self.save(data, "bad.json")
            with self.subTest(length=len(data)), self.assertRaises(DashboardDataError):
                read_snapshot(path)
        for path in (self.directory / "missing", self.directory):
            with self.assertRaises(DashboardDataError):
                read_snapshot(path)

    def test_wrong_schema_stage_or_missing_statistics_is_rejected(self):
        cases = [[], None, {}, {**self.report, "schema_version": 3},
                 {**self.report, "schema_version": True}, {**self.report, "stage": "unknown"},
                 {**self.report, "statistics": []}]
        for value in cases:
            self.path.write_text(json.dumps(value))
            with self.subTest(value=str(value)[:50]), self.assertRaises(DashboardDataError):
                read_snapshot(self.path)

    def test_packet_protocol_and_source_counters_are_validated(self):
        changes = [{"total_packets": -1}, {"total_packets": True}, {"total_packets": 10**100},
                   {"analyzed_packets": 0}, {"skipped_packets": 1}, {"protocol_counts": []},
                   {"protocol_counts": {"TCP": 2}}, {"protocol_counts": {"TCP": 2, "UDP": True}},
                   {"protocol_counts": {"TCP": 1, "UDP": 0}}, {"source_counts": []},
                   {"source_counts": {"x": -1}}, {"source_counts": {"x": 3}},
                   {"source_counts": {str(index): 0 for index in range(4097)}}]
        for change in changes:
            value = deepcopy(self.report)
            value["statistics"].update(change)
            self.path.write_text(json.dumps(value))
            with self.subTest(change=str(change)[:60]), self.assertRaises(DashboardDataError):
                read_snapshot(self.path)

    def test_bad_samples_detection_alerts_and_monitor_are_rejected(self):
        changes = [{"sample_packets": [1]}, {"sample_packets": [] * 0 + [{}] * 1001},
                   {"sample_packets": None}, {"detection": []}, {"detection": {"alerts_emitted": -1}},
                   {"detection": {"run_id": 1}}, {"recent_alerts": [self.alert] * 101},
                   {"recent_alerts": [{}]}, {"recent_alerts": None}, {"monitor": []},
                   {"monitor": {"status": "bad"}},
                   {"monitor": {"status": "running", "updated_at": 0, "interface": 2}},
                   {"monitor": {"status": "running", "updated_at": -1, "interface": "Lab"}},
                   {"monitor": {"status": "failed", "updated_at": 0, "interface": "Lab", "error": []}}]
        for change in changes:
            self.path.write_text(json.dumps({**self.report, **change}))
            with self.subTest(change=str(change)[:50]), self.assertRaises(DashboardDataError):
                read_snapshot(self.path)

    def test_invalid_alert_shapes_are_rejected(self):
        changes = [{"schema_version": True}, {"schema_version": 2}, {"alert_id": ""},
                   {"run_id": None}, {"timestamp": -1}, {"timestamp": 10**1000},
                   {"source_ip": ""}, {"destination_ip": []}, {"destination_ip": ""},
                   {"score": True}, {"score": 101}, {"score": 0}, {"severity": "Unknown"},
                   {"rules": []}, {"rules": ["port_scan", "port_scan"]}, {"rules": [[]]},
                   {"rules": ["unknown"]}, {"rules": None}, {"evidence": None}]
        self.assertFalse(valid_alert([]))
        for change in changes:
            with self.subTest(change=str(change)[:40]):
                self.assertFalse(valid_alert({**self.alert, **change}))

    def test_alert_reader_filters_run_and_keeps_bounded_recent_records(self):
        lines = []
        for index in range(105):
            lines.append(json.dumps({**self.alert, "alert_id": str(index)}))
        lines.append(json.dumps({**self.alert, "run_id": "other-run"}))
        self.log.write_text("\n".join(lines) + "\n")
        alerts, warnings = read_recent_alerts(self.log, run_id=self.alert["run_id"], limit=3)
        self.assertEqual([a["alert_id"] for a in alerts], ["102", "103", "104"])
        self.assertEqual(warnings, [])

    def test_partial_invalid_and_nonstandard_log_lines_are_ignored(self):
        line = json.dumps(self.alert).encode() + b"\n"
        self.log.write_bytes(b"bad\n[]\n\xff\n{\"x\":NaN}\n" + line + b"partial")
        alerts, warnings = read_recent_alerts(self.log)
        self.assertEqual(alerts, [self.alert])
        self.assertTrue(any("incomplete" in message for message in warnings))
        self.assertTrue(any("4 invalid" in message for message in warnings))
        self.log.write_bytes(b"partial")
        self.assertEqual(read_recent_alerts(self.log)[0], [])

    def test_missing_empty_and_unreadable_logs(self):
        alerts, warnings = read_recent_alerts(self.directory / "missing")
        self.assertEqual(alerts, [])
        self.assertTrue(warnings)
        self.log.write_bytes(b"")
        self.assertEqual(read_recent_alerts(self.log), ([], []))
        with patch("pathlib.Path.open", side_effect=PermissionError("denied")):
            self.assertIn("denied", read_recent_alerts(self.log)[1][0])

    def test_tail_reading_bounds_memory_and_drops_partial_first_line(self):
        line = json.dumps(self.alert).encode() + b"\n"
        self.log.write_bytes(b"x" * (MAX_LOG_BYTES + 100) + b"\n" + line)
        alerts, warnings = read_recent_alerts(self.log)
        self.assertEqual(alerts, [self.alert])
        self.assertTrue(any("2 MiB" in message for message in warnings))

    def test_tail_beginning_at_exact_line_boundary_keeps_first_complete_line(self):
        line = json.dumps(self.alert).encode() + b"\n"
        padding = b" " * (MAX_LOG_BYTES - len(line) - 1) + b"\n"
        self.log.write_bytes(b"old\n" + line + padding)
        alerts, _ = read_recent_alerts(self.log)
        self.assertEqual(alerts, [self.alert])

    def test_alert_reader_invalid_limits(self):
        for limit in (0, 101, True, 1.5):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                read_recent_alerts(self.log, limit=limit)

    def test_alert_filters_and_large_timestamp_fallback(self):
        alert = {**self.alert, "destination_ip": None, "timestamp": 1e20}
        self.assertEqual(alert_rows([alert], ["Low"]), [])
        self.assertEqual(alert_rows([alert], SEVERITIES, "absent"), [])
        rows = alert_rows([alert], SEVERITIES, "192.0.2.1")
        self.assertEqual(rows[0]["Destination"], "All destinations")
        self.assertEqual(rows[0]["Time"], "1e+20")

    def test_default_snapshot_environment_and_fallbacks(self):
        with patch.dict(os.environ, {"NETSENTINEL_REPORT": "chosen.json"}):
            self.assertEqual(default_snapshot(), "chosen.json")
        with patch.dict(os.environ, {"NETSENTINEL_REPORT": ""}):
            with patch("pathlib.Path.is_file", return_value=False):
                self.assertEqual(default_snapshot(), "logs/live_summary.json")
            with patch("pathlib.Path.is_file", side_effect=[False, True]):
                self.assertEqual(default_snapshot(), "logs/summary.json")


class DashboardAppTests(DashboardFixture):
    def test_fresh_running_snapshot_has_no_staleness_warning(self):
        self.report["monitor"] = {"status": "running", "interface": "Lab", "updated_at": time.time(), "error": None}
        self.path.write_text(json.dumps(self.report))
        app = self.app()
        self.assertEqual(len(app.exception), 0)
        self.assertEqual(len(app.warning), 0)

    def test_evidence_respects_source_filter_when_other_alerts_exist(self):
        other = {**self.alert, "alert_id": "other", "source_ip": "192.0.2.99", "score": 30,
                 "severity": "Medium", "rules": ["port_scan"],
                 "evidence": {"port_scan": self.alert["evidence"]["port_scan"]}}
        self.report["recent_alerts"].append(other)
        self.report["detection"]["alerts_emitted"] = 2
        self.path.write_text(json.dumps(self.report))
        app = self.app()
        self.assertEqual(len(app.get("json")), 4)
        app.text_input[2].set_value("192.0.2.1").run()
        self.assertEqual(len(app.exception), 0)
        self.assertEqual(len(app.dataframe[0].value), 1)
        self.assertEqual(len(app.get("json")), 3)

    def app(self):
        environment = patch.dict(os.environ, {"NETSENTINEL_REPORT": str(self.path)})
        environment.start()
        self.addCleanup(environment.stop)
        return AppTest.from_file(str(APP), default_timeout=20).run()

    def test_actual_app_metrics_protocol_charts_and_critical_alert(self):
        app = self.app()
        self.assertEqual(len(app.exception), 0)
        self.assertEqual([metric.value for metric in app.metric], ["2", "2", "0", "1"])
        self.assertEqual(app.title[0].value, "NetSentinel")
        self.assertEqual(len(app.dataframe), 1)
        self.assertEqual(app.dataframe[0].value.iloc[0]["Severity"], "Critical")
        self.assertEqual(app.dataframe[0].value.iloc[0]["Score"], 100)

    def test_refresh_never_starts_capture_or_changes_files(self):
        report_before, log_before = self.path.read_bytes(), self.log.read_bytes()
        with patch("netsentinel.runtime.capture_live") as capture:
            app = self.app()
            app.button[0].click().run()
            app.toggle[0].set_value(False).run()
        capture.assert_not_called()
        self.assertEqual(len(app.exception), 0)
        self.assertEqual(self.path.read_bytes(), report_before)
        self.assertEqual(self.log.read_bytes(), log_before)

    def test_severity_and_source_filters_hide_nonmatching_alerts(self):
        app = self.app()
        app.multiselect[0].set_value(["Low"]).run()
        self.assertEqual(len(app.dataframe), 0)
        self.assertEqual(len(app.exception), 0)
        app.multiselect[0].set_value(list(SEVERITIES)).run()
        app.text_input[2].set_value("no matching address").run()
        self.assertEqual(len(app.dataframe), 0)
        app.text_input[2].set_value("192.0.2.1").run()
        self.assertEqual(len(app.dataframe), 1)

    def test_missing_snapshot_warns_and_recovers_after_path_change(self):
        app = self.app()
        app.text_input[0].set_value(str(self.directory / "missing.json")).run()
        self.assertEqual(len(app.exception), 0)
        self.assertGreater(len(app.warning), 0)
        self.assertEqual(len(app.metric), 0)
        app.text_input[0].set_value(str(self.path)).run()
        self.assertEqual(len(app.exception), 0)
        self.assertEqual(len(app.metric), 4)

    def test_log_override_missing_partial_and_valid_files(self):
        app = self.app()
        app.text_input[1].set_value(str(self.directory / "missing.jsonl")).run()
        self.assertEqual(len(app.exception), 0)
        self.assertGreater(len(app.warning), 0)
        self.log.write_bytes(self.log.read_bytes() + b"partial")
        app.text_input[1].set_value(str(self.log)).run()
        self.assertEqual(len(app.exception), 0)
        self.assertEqual(len(app.dataframe), 1)
        self.assertTrue(any("incomplete" in warning.value for warning in app.warning))

    def test_provider_failure_stale_and_stopped_states_are_visible(self):
        self.report["monitor"] = {"status": "failed", "interface": "Lab", "updated_at": 0, "error": "Npcap unavailable"}
        self.path.write_text(json.dumps(self.report))
        app = self.app()
        self.assertEqual(len(app.exception), 0)
        self.assertIn("Npcap unavailable", app.error[0].value)
        self.report["monitor"].update(status="running", error=None)
        self.path.write_text(json.dumps(self.report))
        app.button[0].click().run()
        self.assertTrue(any("stale" in warning.value for warning in app.warning))
        self.report["monitor"]["status"] = "stopped"
        self.path.write_text(json.dumps(self.report))
        app.button[0].click().run()
        self.assertTrue(any("Capture stopped" in info.value for info in app.info))

    def test_empty_analysis_snapshot_has_zero_metrics_and_no_exception(self):
        report = analyze_capture(self.save(pcap_header()))
        self.path.write_text(json.dumps(report))
        app = self.app()
        self.assertEqual(len(app.exception), 0)
        self.assertEqual([metric.value for metric in app.metric], ["0", "0", "0", "0"])
        self.assertEqual(len(app.dataframe), 0)
