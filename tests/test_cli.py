from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

from netsentinel.cli import main, write_report

from tests.helpers import ROOT, TemporaryCase, pcap_bytes, pcap_header, tcp_bytes, udp_bytes


class CommandLineTests(TemporaryCase):
    def invoke(self, args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main([str(value) for value in args])
        return code, stdout.getvalue(), stderr.getvalue()

    def test_default_analysis_stdout_is_valid_json(self):
        path = self.save(pcap_bytes(tcp_bytes(), udp_bytes()))
        code, stdout, stderr = self.invoke(["--pcap", path])
        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        self.assertEqual(json.loads(stdout)["statistics"]["total_packets"], 2)

    def test_config_limit_sample_limit_and_nested_output(self):
        path = self.save(pcap_bytes(tcp_bytes(), udp_bytes()))
        config = self.save(b'{"window_seconds":5}', "settings.json")
        output = self.directory / "reports" / "summary.json"
        code, stdout, stderr = self.invoke(["--pcap", path, "--config", config, "--limit", 1,
                                           "--sample-limit", 0, "--output", output])
        self.assertEqual((code, stderr), (0, ""))
        report = json.loads(stdout)
        self.assertEqual(report["statistics"]["total_packets"], 1)
        self.assertEqual(report["sample_packets"], [])
        self.assertEqual(report["settings"]["window_seconds"], 5)
        self.assertEqual(json.loads(output.read_text()), report)
        self.assertEqual(list(output.parent.glob(".netsentinel-*.tmp")), [])

    def test_empty_input_is_success(self):
        code, stdout, _ = self.invoke(["--pcap", self.save(pcap_header())])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout)["statistics"]["total_packets"], 0)

    def test_missing_corrupt_directory_and_permission_denied_capture(self):
        paths = [self.directory / "missing", self.save(b"garbage"), self.directory]
        for path in paths:
            with self.subTest(path=path):
                code, stdout, stderr = self.invoke(["--pcap", path])
                self.assertEqual(code, 1)
                self.assertEqual(stdout, "")
                self.assertIn("error:", stderr)
                self.assertNotIn("Traceback", stderr)
        with patch("netsentinel.cli.analyze_capture", side_effect=PermissionError("denied")):
            code, stdout, stderr = self.invoke(["--pcap", "blocked"])
        self.assertEqual(code, 1)
        self.assertIn("denied", stderr)

    def test_invalid_configuration_and_missing_explicit_configuration(self):
        path = self.save(pcap_header())
        for config in [self.save(b'{"window_seconds":0}', "bad.json"), self.directory / "missing.json"]:
            with self.subTest(config=config):
                code, stdout, stderr = self.invoke(["--pcap", path, "--config", config])
                self.assertEqual(code, 1)
                self.assertEqual(stdout, "")
                self.assertIn("error:", stderr)

    def test_rejects_overwriting_capture_or_configuration(self):
        path = self.save(pcap_bytes(tcp_bytes()))
        original = path.read_bytes()
        config = self.save(b"{}", "settings.json")
        for output in [path, path.parent / "." / path.name, config]:
            with self.subTest(output=output):
                code, stdout, stderr = self.invoke(["--pcap", path, "--config", config, "--output", output])
                self.assertEqual(code, 1)
                self.assertIn("must not overwrite", stderr)
                self.assertEqual(stdout, "")
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(config.read_bytes(), b"{}")

    def test_hardlinked_capture_cannot_be_overwritten(self):
        path = self.save(pcap_bytes(tcp_bytes()))
        alias = self.directory / "alias.pcap"
        try:
            os.link(path, alias)
        except OSError as exc:
            self.skipTest(f"Hard links unavailable: {exc}")
        code, _, stderr = self.invoke(["--pcap", path, "--output", alias])
        self.assertEqual(code, 1)
        self.assertIn("must not overwrite", stderr)
        self.assertEqual(path.read_bytes(), alias.read_bytes())

    def test_output_directory_failure_has_no_partial_report(self):
        path = self.save(pcap_header())
        code, stdout, stderr = self.invoke(["--pcap", path, "--output", self.directory])
        self.assertEqual(code, 1)
        self.assertEqual(stdout, "")
        self.assertIn("error:", stderr)
        self.assertEqual(list(self.directory.glob(".netsentinel-*.tmp")), [])

    def test_atomic_replace_failure_preserves_previous_report_and_cleans_temp(self):
        output = self.directory / "summary.json"
        output.write_text("previous report")
        with patch("netsentinel.cli.os.replace", side_effect=PermissionError("denied")):
            with self.assertRaises(PermissionError):
                write_report(output, "new report")
        self.assertEqual(output.read_text(), "previous report")
        self.assertEqual(list(self.directory.glob(".netsentinel-*.tmp")), [])

    def test_failure_creating_temporary_report_is_clean(self):
        output = self.directory / "summary.json"
        with patch("netsentinel.cli.tempfile.NamedTemporaryFile", side_effect=PermissionError("denied")):
            with self.assertRaises(PermissionError):
                write_report(output, "new report")
        self.assertFalse(output.exists())
        self.assertEqual(list(self.directory.glob(".netsentinel-*.tmp")), [])

    def test_failed_capture_does_not_replace_old_report(self):
        output = self.directory / "summary.json"
        output.write_text("previous report")
        code, stdout, _ = self.invoke(["--pcap", self.save(b"bad"), "--output", output])
        self.assertEqual(code, 1)
        self.assertEqual(stdout, "")
        self.assertEqual(output.read_text(), "previous report")

    def test_invalid_arguments_are_usage_errors(self):
        cases = [[], ["--pcap", "input", "--unknown"],
                 ["--pcap", "input", "--limit", "0"], ["--pcap", "input", "--limit", "-1"],
                 ["--pcap", "input", "--limit", "1.5"], ["--pcap", "input", "--limit", "bad"],
                 ["--pcap", "input", "--sample-limit", "-1"], ["--pcap", "input", "--sample-limit", "1001"],
                 ["--pcap", "input", "--sample-limit", "bad"]]
        for args in cases:
            with self.subTest(args=args), self.assertRaises(SystemExit) as context:
                self.invoke(args)
            self.assertEqual(context.exception.code, 2)

    def test_help_does_not_require_input(self):
        with self.assertRaises(SystemExit) as context:
            self.invoke(["--help"])
        self.assertEqual(context.exception.code, 0)

    def test_keyboard_interrupt_is_clean_and_has_distinct_exit_code(self):
        with patch("netsentinel.cli.analyze_capture", side_effect=KeyboardInterrupt):
            code, stdout, stderr = self.invoke(["--pcap", "unused"])
        self.assertEqual(code, 130)
        self.assertEqual(stdout, "")
        self.assertIn("Interrupted", stderr)

    def test_actual_python_module_and_installed_console_entry_points(self):
        path = self.save(pcap_bytes(tcp_bytes()))
        console = Path(sys.executable).parent / ("netsentinel.exe" if os.name == "nt" else "netsentinel")
        commands = [[sys.executable, "-m", "netsentinel"], [str(console)]]
        for command in commands:
            with self.subTest(command=command):
                result = subprocess.run(command + ["--pcap", str(path)], cwd=ROOT,
                                        capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout)["statistics"]["analyzed_packets"], 1)
