"""Risk, cooldown, persistence, and recovery tests."""

from dataclasses import replace
import itertools
import json
from unittest.mock import Mock, patch

from netsentinel.alerts import MAX_ALERT_BYTES, AlertLog, AlertManager
from netsentinel.config import Settings, settings_from_dict
from netsentinel.detection.engine import Findings
from netsentinel.errors import AlertLogError, DetectionError
from netsentinel.risk import RULE_NAMES, score_rules

from tests.helpers import TemporaryCase


def finding(t=0, source="192.0.2.1", target="192.0.2.2", rules=("port_scan",)):
    return Findings(source, target, t, {rule: {"count": 20} for rule in rules})


class RiskTests(TemporaryCase):
    def test_all_rule_combinations_have_expected_scores(self):
        for count in range(4):
            for rules in itertools.combinations(RULE_NAMES, count):
                with self.subTest(rules=rules):
                    assessment = score_rules(rules, Settings())
                    expected = sum(Settings().risk_weights[rule] for rule in rules)
                    self.assertEqual(assessment.score, expected)
                    self.assertEqual(assessment.rules, rules)
                    expected_severity = None if expected == 0 else (
                        "Medium" if expected < 50 else "High" if expected < 75 else "Critical")
                    self.assertEqual(assessment.severity, expected_severity)

    def test_repeated_rules_do_not_inflate_score_and_order_is_stable(self):
        assessment = score_rules(["syn_flood", "port_scan", "port_scan"], Settings())
        self.assertEqual(assessment.score, 70)
        self.assertEqual(assessment.rules, ("port_scan", "syn_flood"))

    def test_exact_severity_boundaries(self):
        for score, severity in [(1, "Low"), (24, "Low"), (25, "Medium"), (49, "Medium"),
                                (50, "High"), (74, "High"), (75, "Critical"), (98, "Critical")]:
            config = settings_from_dict({"risk_weights": {"port_scan": score, "syn_flood": 1, "traffic_anomaly": 1}})
            with self.subTest(score=score):
                self.assertEqual(score_rules(["port_scan"], config).severity, severity)

    def test_custom_severity_boundaries(self):
        config = settings_from_dict({"severity_min_scores": {"medium": 10, "high": 20, "critical": 30}})
        self.assertEqual(score_rules(["port_scan"], config).severity, "Critical")

    def test_unknown_rule_is_rejected(self):
        with self.assertRaises(ValueError):
            score_rules(["typo"], Settings())


class AlertManagerTests(TemporaryCase):
    def test_equal_large_timestamps_do_not_expire_cooldowns(self):
        manager = AlertManager(Settings())
        log = Mock()
        manager.create(finding(1e20), log)
        self.assertIsNone(manager.create(finding(1e20), log))
        self.assertEqual(manager.snapshot()["active_cooldowns"], 1)

    def setUp(self):
        super().setUp()
        self.log = Mock()

    def test_alert_contains_identity_scope_evidence_and_risk(self):
        manager = AlertManager(Settings())
        alert = manager.create(finding(), self.log)
        self.log.append.assert_called_once_with(alert)
        self.assertEqual(alert["score"], 30)
        self.assertEqual(alert["severity"], "Medium")
        self.assertEqual(alert["rules"], ["port_scan"])
        self.assertEqual(alert["window_start"], 0)
        self.assertEqual(alert["window_seconds"], 10)
        self.assertEqual(alert["evidence"], {"port_scan": {"count": 20}})
        self.assertEqual(len(alert["alert_id"]), 32)
        self.assertEqual(alert["run_id"], manager.run_id)
        self.assertEqual(manager.snapshot()["rule_alert_counts"], {"port_scan": 1})
        self.assertEqual(manager.snapshot()["severity_alert_counts"], {"Medium": 1})
        json.dumps(alert, allow_nan=False)

    def test_cooldown_is_from_last_emission_not_last_suppression(self):
        manager = AlertManager(Settings())
        first = manager.create(finding(0), self.log)
        self.assertIsNone(manager.create(finding(10), self.log))
        self.assertIsNone(manager.create(finding(29.999), self.log))
        second = manager.create(finding(30), self.log)
        self.assertIsNotNone(second)
        self.assertNotEqual(first["alert_id"], second["alert_id"])
        self.assertEqual((manager.emitted, manager.suppressed), (2, 2))

    def test_escalation_source_target_and_rule_signature_are_independent(self):
        manager = AlertManager(Settings())
        manager.create(finding(0), self.log)
        escalated = manager.create(finding(1, rules=("port_scan", "syn_flood")), self.log)
        self.assertEqual((escalated["score"], escalated["severity"]), (70, "High"))
        manager.create(finding(1, source="192.0.2.3"), self.log)
        manager.create(finding(1, target="192.0.2.4"), self.log)
        manager.create(finding(1, target=None, rules=("traffic_anomaly",)), self.log)
        self.assertEqual(manager.emitted, 5)
        self.assertIsNone(manager.create(finding(2, rules=("syn_flood", "port_scan")), self.log))

    def test_zero_cooldown_emits_repeated_findings_without_retaining_state(self):
        manager = AlertManager(settings_from_dict({"alert_cooldown_seconds": 0}))
        for _ in range(3):
            self.assertIsNotNone(manager.create(finding(), self.log))
        self.assertEqual(manager.emitted, 3)
        self.assertEqual(manager.snapshot()["active_cooldowns"], 0)

    def test_empty_findings_do_not_emit_or_persist(self):
        manager = AlertManager(Settings())
        self.assertIsNone(manager.create(finding(rules=()), self.log))
        self.log.append.assert_not_called()
        self.assertEqual(manager.emitted, 0)

    def test_cooldowns_expire_during_quiet_periods(self):
        manager = AlertManager(Settings())
        manager.create(finding(), self.log)
        manager.advance(30)
        self.assertEqual(manager.snapshot()["active_cooldowns"], 0)

    def test_bounded_cooldowns_fail_explicitly_and_recover_after_expiry(self):
        manager = AlertManager(Settings(), max_cooldowns=1)
        manager.create(finding(), self.log)
        with self.assertRaisesRegex(DetectionError, "cooldown limit"):
            manager.create(finding(source="192.0.2.3"), self.log)
        self.assertEqual(manager.emitted, 1)
        self.assertIsNotNone(manager.create(finding(30, source="192.0.2.3"), self.log))

    def test_failed_persistence_does_not_mark_alert_emitted_or_start_cooldown(self):
        manager = AlertManager(Settings())
        self.log.append.side_effect = [AlertLogError("disk full"), None]
        with self.assertRaises(AlertLogError):
            manager.create(finding(), self.log)
        self.assertEqual(manager.emitted, 0)
        self.assertEqual(manager.snapshot()["active_cooldowns"], 0)
        self.assertIsNotNone(manager.create(finding(), self.log))

    def test_runs_have_distinct_identities_and_independent_cooldowns(self):
        first, second = AlertManager(Settings()), AlertManager(Settings())
        self.assertNotEqual(first.run_id, second.run_id)
        self.assertIsNotNone(first.create(finding(), self.log))
        self.assertIsNotNone(second.create(finding(), self.log))

    def test_invalid_limits_and_time(self):
        for value in (0, -1, True, 1.5):
            with self.subTest(value=value), self.assertRaises(ValueError):
                AlertManager(Settings(), max_cooldowns=value)
        manager = AlertManager(Settings())
        for now in (None, -1, True, float("nan"), float("inf"), "0", 10**1000):
            with self.subTest(now=now), self.assertRaises(ValueError):
                manager.advance(now)
        manager.advance(2)
        with self.assertRaises(ValueError):
            manager.advance(1)


class AlertLogTests(TemporaryCase):
    def test_existing_record_at_exact_size_limit_is_accepted(self):
        line = b'{"schema_version":1,"alert_id":"x"}\n'
        path = self.directory / "alerts.jsonl"
        path.write_bytes(line + b" " * (MAX_ALERT_BYTES - len(line)) + line)
        with AlertLog(path):
            pass

    def test_oversized_new_and_existing_record_are_rejected(self):
        path = self.directory / "alerts.jsonl"
        with AlertLog(path) as log:
            with self.assertRaisesRegex(AlertLogError, "1 MiB"):
                log.append({"padding": "x" * MAX_ALERT_BYTES})
        self.assertEqual(path.read_bytes(), b"")
        path.write_bytes(b" " * MAX_ALERT_BYTES + b'{"schema_version":1,"alert_id":"x"}\n')
        with self.assertRaisesRegex(AlertLogError, "1 MiB"):
            with AlertLog(path):
                pass

    def test_large_valid_log_checks_final_record_without_reading_whole_file(self):
        path = self.directory / "alerts.jsonl"
        line = b'{"schema_version":1,"alert_id":"x"}\n'
        path.write_bytes(line * (MAX_ALERT_BYTES // len(line) + 10))
        with AlertLog(path) as log:
            AlertManager(Settings()).create(finding(), log)
        self.assertEqual(json.loads(path.read_bytes().splitlines()[-1])["score"], 30)

    def test_nonstandard_json_constants_and_invalid_envelopes_are_rejected(self):
        for data in [b'{"schema_version":1,"alert_id":"x","timestamp":NaN}\n',
                     b'{"schema_version":true,"alert_id":"x"}\n',
                     b'{"schema_version":1,"alert_id":null}\n',
                     b'{"schema_version":1,"alert_id":""}\n']:
            path = self.save(data, "alerts.jsonl")
            with self.subTest(data=data), self.assertRaises(AlertLogError):
                with AlertLog(path):
                    pass

    def test_create_reopen_append_valid_json_lines(self):
        path = self.directory / "nested" / "alerts.jsonl"
        with AlertLog(path) as log:
            first = AlertManager(Settings()).create(finding(), log)
        with AlertLog(path) as log:
            second = AlertManager(Settings()).create(finding(1), log)
        lines = [json.loads(line) for line in path.read_text().splitlines()]
        self.assertEqual(lines, [first, second])
        self.assertTrue(path.read_bytes().endswith(b"\n"))

    def test_empty_log_is_valid(self):
        path = self.save(b"", "alerts.jsonl")
        with AlertLog(path):
            pass
        self.assertEqual(path.read_bytes(), b"")

    def test_corrupt_or_partial_tail_is_rejected_without_modification(self):
        values = [b"{", b"bad\n", b"[]\n", b"{}\n", b"\xff\n", b' {"schema_version":2,"alert_id":"x"}\n',
                  b' {"schema_version":1,"alert_id":"x"}', b"\n"]
        for data in values:
            path = self.save(data, "alerts.jsonl")
            with self.subTest(data=data), self.assertRaises(AlertLogError):
                with AlertLog(path):
                    pass
            self.assertEqual(path.read_bytes(), data)
            path.unlink()  # Handle was closed even on failed __enter__.

    def test_directory_and_permission_failures_are_clear_errors(self):
        with self.assertRaises(AlertLogError):
            with AlertLog(self.directory):
                pass
        with patch("pathlib.Path.open", side_effect=PermissionError("denied")):
            with self.assertRaisesRegex(AlertLogError, "denied"):
                with AlertLog(self.directory / "alerts.jsonl"):
                    pass

    def test_append_requires_open_log_and_valid_json(self):
        path = self.directory / "alerts.jsonl"
        log = AlertLog(path)
        with self.assertRaises(AlertLogError):
            log.append({})
        with log:
            for value in ({"x": float("nan")}, {"x": {1, 2}}):
                with self.subTest(value=value), self.assertRaises(AlertLogError):
                    log.append(value)
        self.assertEqual(path.read_bytes(), b"")
        log.close()  # Closing twice is safe.

    def test_sync_failure_rolls_back_line_and_preserves_previous_alert(self):
        path = self.directory / "alerts.jsonl"
        with AlertLog(path) as log:
            manager = AlertManager(Settings())
            manager.create(finding(), log)
            previous = path.read_bytes()
            with patch("netsentinel.alerts.os.fsync", side_effect=OSError("disk full")):
                with self.assertRaisesRegex(AlertLogError, "disk full"):
                    manager.create(finding(1, source="192.0.2.3"), log)
            self.assertEqual(path.read_bytes(), previous)
            self.assertEqual(manager.emitted, 1)
            self.assertIsNotNone(manager.create(finding(1, source="192.0.2.3"), log))

    def test_short_write_rolls_back_partial_data(self):
        path = self.directory / "alerts.jsonl"
        with AlertLog(path) as log:
            actual = log._handle
            proxy = Mock(wraps=actual)
            proxy.write.side_effect = lambda data: actual.write(data[:5])
            log._handle = proxy
            with self.assertRaisesRegex(AlertLogError, "Incomplete"):
                AlertManager(Settings()).create(finding(), log)
        self.assertEqual(path.read_bytes(), b"")

    def test_seek_failure_is_wrapped_as_log_error(self):
        path = self.directory / "alerts.jsonl"
        with AlertLog(path) as log:
            actual = log._handle
            log._handle = Mock(wraps=actual)
            log._handle.seek.side_effect = OSError("seek failed")
            with self.assertRaisesRegex(AlertLogError, "seek failed"):
                log.append({})

    def test_rollback_failure_retains_original_error(self):
        path = self.directory / "alerts.jsonl"
        with AlertLog(path) as log:
            actual = log._handle
            proxy = Mock(wraps=actual)
            proxy.truncate.side_effect = OSError("rollback failed")
            log._handle = proxy
            with patch("netsentinel.alerts.os.fsync", side_effect=OSError("original disk error")):
                with self.assertRaisesRegex(AlertLogError, "original disk error"):
                    log.append({})
