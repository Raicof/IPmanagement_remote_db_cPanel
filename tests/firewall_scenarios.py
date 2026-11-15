"""Shared end-to-end scenarios run against every firewall backend.

Data comes from tests/fixtures/intake.json (first cron pass) and
intake_update.json (second pass).  Expected outcome of pass 1:

  alice  198.51.100.10, 203.0.113.20, 2001:db8::10          -> all active
  bob    198.51.100.10 (shared with alice), 192.0.2.55,
         ::ffff:192.0.2.56 (-> 192.0.2.56)                   -> active
         *, localhost, %, 0.0.0.0/0, dup 192.0.2.55, hostname,
         10.0.0.0/8, 127.0.0.1, 192.0.2.%                    -> rejected (9)
  carol  192.0.2.1 .. 192.0.2.7                              -> .3-.7 active, .1-.2 inactive
  dave   (nothing)

Pass 2: alice drops 203.0.113.20, bob empties his list, carol adds
192.0.2.8 (so .3 becomes inactive), new account erin adds 203.0.113.99.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from typing import Optional

from remotedb_fw.config import load_config
from remotedb_fw.sync import VALIDATION_LOG, run_purge, run_sync
from tests.fakes import FakeRunner, fixture

PORT = 3306
PASS1_ALLOWED = ["198.51.100.10", "203.0.113.20", "2001:db8::10", "192.0.2.55", "192.0.2.56",
                 "192.0.2.3", "192.0.2.4", "192.0.2.5", "192.0.2.6", "192.0.2.7"]
PASS1_DENIED = ["192.0.2.1", "192.0.2.2", "127.0.0.1", "10.1.2.3", "203.0.113.250",
                "2001:db8::99"]
PASS2_ALLOWED = ["198.51.100.10", "2001:db8::10", "192.0.2.4", "192.0.2.5", "192.0.2.6",
                 "192.0.2.7", "192.0.2.8", "203.0.113.99"]
PASS2_DENIED = ["203.0.113.20", "192.0.2.55", "192.0.2.56", "192.0.2.3", "192.0.2.1"]


class FirewallScenarios:
    """Mixin - subclasses implement setup_firewall() and allows()."""

    backend: str = ""

    # -- hooks -------------------------------------------------------------
    def setup_firewall(self, runner: FakeRunner) -> dict:
        """Install the simulator; return config overrides."""
        raise NotImplementedError

    def allows(self, ip: str, port: int) -> bool:
        raise NotImplementedError

    def reload_count(self) -> int:
        """How many times the firewall service was restarted / reloaded."""
        return 0

    # -- helpers -----------------------------------------------------------
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.runner = FakeRunner()
        overrides = {
            "state_dir": os.path.join(self.tmp.name, "state"),
            "log_dir": os.path.join(self.tmp.name, "log"),
            "lock_file": os.path.join(self.tmp.name, "lock"),
            "cpanel": {"mainip_file": os.path.join(self.tmp.name, "mainip"),
                       "ips_file": os.path.join(self.tmp.name, "ips")},
        }
        fw_overrides = self.setup_firewall(self.runner)
        for key, value in fw_overrides.items():
            if isinstance(value, dict) and isinstance(overrides.get(key), dict):
                overrides[key].update(value)
            else:
                overrides[key] = value
        self.cfg = load_config(None, overrides)
        os.makedirs(self.cfg.state_dir, exist_ok=True)

    def tearDown(self):
        self.tmp.cleanup()

    def sync(self, name: str = "intake.json", now: float = 1000.0, dry_run: bool = False):
        report = run_sync(self.cfg, self.runner, intake=fixture(name), dry_run=dry_run,
                          backend_name=self.backend, now=now)
        self.assertIsNone(report.error, report.error)
        return report

    def assertAccess(self, allowed, denied, port: int = PORT):
        for ip in allowed:
            self.assertTrue(self.allows(ip, port), f"{ip} should reach {port}")
        for ip in denied:
            self.assertFalse(self.allows(ip, port), f"{ip} must NOT reach {port}")

    # -- scenarios ---------------------------------------------------------
    def test_pass1_only_valid_active_ips_get_access(self):
        report = self.sync()
        self.assertTrue(report.apply.changed)
        self.assertEqual(len(report.rules), len(PASS1_ALLOWED))
        self.assertAccess(PASS1_ALLOWED, PASS1_DENIED)

    def test_other_ports_are_not_opened(self):
        self.sync()
        for ip in PASS1_ALLOWED[:3]:
            self.assertFalse(self.allows(ip, 5432), f"{ip} must not reach 5432")

    def test_shared_ip_is_a_single_rule_owned_by_both_users(self):
        report = self.sync()
        shared = [r for r in report.rules if r.ip == "198.51.100.10"]
        self.assertEqual(len(shared), 1)
        self.assertEqual(shared[0].users, ("alice", "bob"))

    def test_second_identical_run_changes_nothing(self):
        self.sync()
        reloads = self.reload_count()
        report = self.sync(now=1120.0)
        self.assertFalse(report.apply.changed, report.apply.actions)
        self.assertEqual(self.reload_count(), reloads, "no restart/reload when nothing changed")
        self.assertAccess(PASS1_ALLOWED, PASS1_DENIED)

    def test_pass2_reconciles_adds_and_removals(self):
        self.sync(now=1000.0)
        report = self.sync("intake_update.json", now=1120.0)
        self.assertTrue(report.apply.changed)
        self.assertEqual(report.users["carol"].inactive, ["192.0.2.1", "192.0.2.2", "192.0.2.3"])
        self.assertAccess(PASS2_ALLOWED, PASS2_DENIED)

    def test_dry_run_touches_nothing(self):
        before = self.snapshot()
        report = self.sync(dry_run=True)
        self.assertTrue(report.apply.actions)
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(os.path.exists(os.path.join(self.cfg.log_dir, VALIDATION_LOG)))
        self.assertFalse(os.path.exists(os.path.join(self.cfg.state_dir, "state.json")))

    def test_purge_removes_all_managed_rules(self):
        self.sync()
        result = run_purge(self.cfg, self.runner, backend_name=self.backend)
        self.assertTrue(result.changed)
        self.assertAccess([], PASS1_ALLOWED)
        self.assertFalse(run_purge(self.cfg, self.runner, backend_name=self.backend).changed)

    def test_validation_errors_logged_to_file(self):
        self.sync()
        path = os.path.join(self.cfg.log_dir, VALIDATION_LOG)
        with open(path) as handle:
            records = [json.loads(line) for line in handle]
        bob = sorted(r["gate"] for r in records if r["user"] == "bob")
        self.assertEqual(bob, sorted(["wildcard", "localhost", "wildcard", "all_access",
                                      "duplicate", "charset", "single_host", "localhost",
                                      "wildcard"]))
        carol = [(r["host"], r["gate"]) for r in records if r["user"] == "carol"]
        self.assertEqual(carol, [("192.0.2.1", "limit"), ("192.0.2.2", "limit")])

    def snapshot(self) -> Optional[object]:
        """Override to return a comparable snapshot of the firewall state."""
        return None
