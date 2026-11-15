"""CLI smoke tests (real subprocess, no root, nothing applied)."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

from tests.fakes import fixture

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENTRY = os.path.join(ROOT, "cpanel-remotedb-fw")


class TestCli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.config = os.path.join(self.tmp.name, "config.json")
        with open(self.config, "w") as handle:
            json.dump({"state_dir": os.path.join(self.tmp.name, "state"),
                       "log_dir": os.path.join(self.tmp.name, "log"),
                       "lock_file": os.path.join(self.tmp.name, "lock"),
                       "cpanel": {"users_dir": os.path.join(self.tmp.name, "nousers")}},
                      handle)

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, *args):
        return subprocess.run([sys.executable, "-I", ENTRY, "--config", self.config, *args],
                              capture_output=True, text=True, timeout=60)

    def test_validate_reports_rejections_with_exit_3(self):
        proc = self.run_cli("validate", "--intake", fixture("intake.json"))
        self.assertEqual(proc.returncode, 3, proc.stderr)
        self.assertIn("REJECTED  '*'  [wildcard]", proc.stdout)
        self.assertIn("INACTIVE  192.0.2.1", proc.stdout)
        self.assertIn("active    198.51.100.10", proc.stdout)

    def test_validate_ranks_unseen_ips_as_newest(self):
        # State from earlier cron runs: carol's .1-.5 were seen long ago.
        state_dir = os.path.join(self.tmp.name, "state")
        os.makedirs(state_dir)
        with open(os.path.join(state_dir, "state.json"), "w") as handle:
            json.dump({"version": 1, "active": {}, "reported": [], "first_seen": {
                "carol": {f"192.0.2.{i}": 1000.0 for i in range(1, 6)}}}, handle)
        proc = self.run_cli("validate", "--intake", fixture("intake.json"))
        self.assertIn("active    192.0.2.7", proc.stdout)  # new -> newest -> active
        self.assertIn("INACTIVE  192.0.2.1", proc.stdout)
        self.assertNotIn("INACTIVE  192.0.2.7", proc.stdout)

    def test_validate_clean_intake_exit_0(self):
        path = os.path.join(self.tmp.name, "ok.json")
        with open(path, "w") as handle:
            json.dump({"users": {"alice": ["198.51.100.1"]}}, handle)
        self.assertEqual(self.run_cli("validate", "--intake", path).returncode, 0)

    def test_dry_run_json_report(self):
        proc = self.run_cli("sync", "--intake", fixture("intake.json"), "--dry-run",
                            "--firewall", "iptables", "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        report = json.loads(proc.stdout)
        self.assertTrue(report["dry_run"])
        self.assertEqual(len(report["rules"]), 10)
        self.assertFalse(os.path.exists(os.path.join(self.tmp.name, "state")))

    @unittest.skipIf(os.geteuid() == 0, "running as root")
    def test_real_sync_requires_root(self):
        proc = self.run_cli("sync", "--intake", fixture("intake.json"), "--firewall", "iptables")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("must run as root", proc.stderr)

    def test_config_error_exit_2(self):
        with open(self.config, "w") as handle:
            json.dump({"ports": [0]}, handle)
        proc = self.run_cli("detect")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("invalid port", proc.stderr)

    def test_source_error_exit_1(self):
        proc = self.run_cli("validate")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("cannot list cPanel users", proc.stderr)


class TestPythonCompatibility(unittest.TestCase):
    """Target servers run Python 3.9 (AlmaLinux/CloudLinux 9) to 3.12 (Ubuntu 24, CL10)."""

    def sources(self):
        for base, _dirs, files in os.walk(os.path.join(ROOT, "remotedb_fw")):
            for name in files:
                if name.endswith(".py"):
                    yield os.path.join(base, name)
        yield ENTRY

    def test_grammar_is_python39_compatible(self):
        import ast
        for path in self.sources():
            with self.subTest(path=path):
                with open(path) as handle:
                    ast.parse(handle.read(), path, feature_version=(3, 9))

    def test_postponed_annotations_everywhere(self):
        # "X | None" / "list[str]" annotations are only safe on 3.9 with this import.
        for path in self.sources():
            with open(path) as handle:
                text = handle.read()
            if "def " in text and "->" in text:
                with self.subTest(path=path):
                    self.assertIn("from __future__ import annotations", text)

    def test_no_310_only_apis(self):
        import re
        pattern = re.compile(r"strict=True\)|kw_only=|slots=True|\bmatch \w+:|ExceptionGroup")
        for path in self.sources():
            with open(path) as handle:
                self.assertIsNone(pattern.search(handle.read()), path)


if __name__ == "__main__":
    unittest.main()
