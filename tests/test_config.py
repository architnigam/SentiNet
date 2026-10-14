import json
from unittest.mock import patch

from netsentinel.config import Settings, load_settings
from netsentinel.errors import ConfigurationError

from tests.helpers import ROOT, TemporaryCase


class ConfigurationTests(TemporaryCase):
    def test_operational_upper_bounds_are_validated(self):
        for name, maximum in [("window_seconds", 86400), ("alert_cooldown_seconds", 604800),
                              ("syn_packets_threshold", 1_000_000_000),
                              ("port_scan_unique_ports_threshold", 1_000_000_000),
                              ("traffic_packets_per_second_threshold", 1_000_000_000)]:
            with self.subTest(name=name):
                self.assertEqual(getattr(self.load({name: maximum}), name), maximum)
                with self.assertRaises(ConfigurationError):
                    self.load({name: maximum + 1})

    def load(self, value):
        return load_settings(self.save(json.dumps(value).encode(), "settings.json"))

    def test_defaults_match_example(self):
        self.assertEqual(load_settings().to_dict(), load_settings(ROOT / "config/settings.example.json").to_dict())

    def test_partial_configuration_merges_nested_defaults(self):
        settings = self.load({"window_seconds": 5, "risk_weights": {"port_scan": 20}})
        self.assertEqual(settings.window_seconds, 5)
        self.assertEqual(dict(settings.risk_weights), {"port_scan": 20, "syn_flood": 40, "traffic_anomaly": 30})
        self.assertEqual(self.load({}).to_dict(), Settings().to_dict())

    def test_configuration_is_immutable_and_serialization_is_detached(self):
        settings = self.load({})
        with self.assertRaises(TypeError):
            settings.risk_weights["port_scan"] = 100
        copy = settings.to_dict()
        copy["risk_weights"]["port_scan"] = 1
        self.assertEqual(settings.risk_weights["port_scan"], 30)

    def test_accepts_utf8_bom_and_zero_cooldown(self):
        path = self.save(b'\xef\xbb\xbf{"alert_cooldown_seconds":0}', "bom.json")
        self.assertEqual(load_settings(path).alert_cooldown_seconds, 0)

    def test_rejects_invalid_integer_fields(self):
        names = ["window_seconds", "port_scan_unique_ports_threshold", "syn_packets_threshold",
                 "traffic_packets_per_second_threshold", "alert_cooldown_seconds"]
        for name in names:
            for value in [-1, 1.5, "10", True, False, None, float("nan"), float("inf")]:
                with self.subTest(name=name, value=value), self.assertRaises(ConfigurationError):
                    self.load({name: value})
            if name != "alert_cooldown_seconds":
                with self.subTest(name=name), self.assertRaises(ConfigurationError):
                    self.load({name: 0})

    def test_rejects_wrong_shape_unknown_keys_and_bad_nested_maps(self):
        cases = [[], None, 1, "settings", {"typo": 1}, {"risk_weights": []},
                 {"severity_min_scores": None}, {"risk_weights": {"unknown": 1}},
                 {"severity_min_scores": {"unknown": 1}}]
        for case in cases:
            with self.subTest(case=case), self.assertRaises(ConfigurationError):
                self.load(case)

    def test_rejects_invalid_weights(self):
        for value in [0, -1, True, 1.5, "30", 101, None]:
            with self.subTest(value=value), self.assertRaises(ConfigurationError):
                self.load({"risk_weights": {"port_scan": value}})
        with self.assertRaisesRegex(ConfigurationError, "sum"):
            self.load({"risk_weights": {"port_scan": 31}})

    def test_rejects_invalid_severity_boundaries(self):
        cases = [{"low": 2}, {"low": 0}, {"medium": 50}, {"high": 75}, {"critical": 101},
                 {"critical": 0}, {"medium": True}, {"high": "50"}]
        for case in cases:
            with self.subTest(case=case), self.assertRaises(ConfigurationError):
                self.load({"severity_min_scores": case})

    def test_rejects_invalid_log_paths(self):
        for value in ["", "  ", "a\0b", 1, None, True]:
            with self.subTest(value=value), self.assertRaises(ConfigurationError):
                self.load({"alert_log_path": value})

    def test_rejects_duplicate_keys_including_nested(self):
        for text in ['{"window_seconds": 1, "window_seconds": 2}',
                     '{"risk_weights":{"port_scan":1,"port_scan":2}}']:
            with self.subTest(text=text), self.assertRaisesRegex(ConfigurationError, "Duplicate"):
                load_settings(self.save(text.encode()))

    def test_read_failures_are_application_errors(self):
        for data in [b"", b"{", b"\xff"]:
            with self.subTest(data=data), self.assertRaises(ConfigurationError):
                load_settings(self.save(data))
        with self.assertRaises(ConfigurationError):
            load_settings(self.directory / "missing.json")
        with self.assertRaises(ConfigurationError):
            load_settings(self.directory)
        with patch("pathlib.Path.open", side_effect=PermissionError("denied")):
            with self.assertRaisesRegex(ConfigurationError, "denied"):
                load_settings("blocked.json")
