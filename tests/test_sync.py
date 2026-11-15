"""Orchestration: logging, state, failure handling, locking."""

import json
import os
import tempfile
import unittest

from remotedb_fw.config import load_config
from remotedb_fw.sources import SourceError
from remotedb_fw.state import State
from remotedb_fw.sync import (STATUS_FILE, VALIDATION_LOG, LockBusy, run_lock, run_sync)
from tests.fakes import FakeRunner, IptablesSim, fail, fixture, ok


class SyncBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.users_dir = os.path.join(t, "users")
        os.makedirs(self.users_dir)
        self.cfg = load_config(None, {
            "state_dir": os.path.join(t, "state"), "log_dir": os.path.join(t, "log"),
            "lock_file": os.path.join(t, "lock"),
            "cpanel": {"users_dir": self.users_dir, "suspended_dir": os.path.join(t, "susp"),
                       "mainip_file": os.path.join(t, "mainip"),
                       "ips_file": os.path.join(t, "ips"),
                       "cpapi2_bin": "/usr/local/cpanel/bin/cpapi2"},
        })
        self.runner = FakeRunner()
        self.v4 = IptablesSim(4, "DROP").install(self.runner)
        self.v6 = IptablesSim(6, "DROP").install(self.runner)

    def tearDown(self):
        self.tmp.cleanup()

    def sync(self, intake="intake.json", now=1000.0, **kw):
        return run_sync(self.cfg, self.runner, intake=fixture(intake) if intake else None,
                        backend_name="iptables", now=now, **kw)

    def log_records(self):
        path = os.path.join(self.cfg.log_dir, VALIDATION_LOG)
        if not os.path.exists(path):
            return []
        with open(path) as handle:
            return [json.loads(line) for line in handle]


class TestValidationLog(SyncBase):
    def test_log_file_created_with_all_errors(self):
        self.sync()
        records = self.log_records()
        self.assertEqual(len(records), 11)  # 9 bob rejections + 2 carol inactive
        for rec in records:
            self.assertEqual(set(rec), {"time", "user", "host", "gate", "reason"})
        path = os.path.join(self.cfg.log_dir, VALIDATION_LOG)
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), "0o600")

    def test_same_problem_logged_once_not_every_run(self):
        self.sync(now=1000.0)
        self.sync(now=1120.0)
        self.sync(now=1240.0)
        self.assertEqual(len(self.log_records()), 11)

    def test_problem_logged_again_after_it_was_fixed_and_reintroduced(self):
        self.sync("intake.json", now=1000.0)
        self.sync("intake_update.json", now=1120.0)  # bob fixed his list
        self.sync("intake.json", now=1240.0)  # ...and broke it again
        bob = [r for r in self.log_records() if r["user"] == "bob"]
        self.assertEqual(len(bob), 18)

    def test_no_log_file_when_everything_is_valid(self):
        path = os.path.join(self.tmp.name, "ok.json")
        with open(path, "w") as handle:
            json.dump({"users": {"alice": ["198.51.100.1"]}}, handle)
        run_sync(self.cfg, self.runner, intake=path, backend_name="iptables", now=1.0)
        self.assertEqual(self.log_records(), [])

    def test_all_access_attempts_produce_zero_rules(self):
        report = self.sync("intake_all_access.json")
        self.assertEqual(report.rules, [])
        gates = {r["gate"] for r in self.log_records()}
        self.assertEqual(gates, {"wildcard", "all_access"})
        self.assertFalse(self.v4.allows("203.0.113.250", 3306))

    def test_invalid_usernames_and_non_string_entries_logged(self):
        report = self.sync("intake_invalid_users.json")
        records = self.log_records()
        self.assertEqual({r["user"] for r in records if r["gate"] == "username"},
                         {"../etc", "Bad User"})
        self.assertEqual([r["user"] for r in records if r["gate"] == "intake"], ["notalist"])
        self.assertEqual(sorted(r["gate"] for r in records if r["user"] == "mixed"),
                         ["type", "type", "type"])
        self.assertEqual(sorted(r.ip for r in report.rules), ["198.51.100.77", "198.51.100.82"])

    def test_status_snapshot(self):
        self.sync()
        with open(os.path.join(self.cfg.log_dir, STATUS_FILE)) as handle:
            status = json.load(handle)
        self.assertEqual(status["backend"], "iptables")
        self.assertEqual(status["users"]["carol"]["inactive"], ["192.0.2.1", "192.0.2.2"])
        self.assertEqual(len(status["users"]["bob"]["rejected"]), 9)


class TestStateAndFailures(SyncBase):
    def test_state_persists_first_seen_for_stack_order(self):
        self.sync(now=1000.0)
        state = State.load(self.cfg.state_dir)
        self.assertEqual(state.first_seen["carol"]["192.0.2.7"], 1000.0)
        self.sync("intake_update.json", now=5000.0)
        state = State.load(self.cfg.state_dir)
        self.assertEqual(state.first_seen["carol"]["192.0.2.8"], 5000.0)
        self.assertEqual(state.first_seen["carol"]["192.0.2.1"], 1000.0)
        self.assertNotIn("203.0.113.20", state.first_seen["alice"])  # removed -> forgotten

    def test_corrupt_state_starts_fresh(self):
        os.makedirs(self.cfg.state_dir)
        with open(State.path(self.cfg.state_dir), "w") as handle:
            handle.write("{garbage")
        report = self.sync()
        self.assertIsNone(report.error)

    def test_total_source_failure_leaves_firewall_untouched(self):
        self.sync()
        before = (dict(self.v4.chains), self.v4.restores[:])
        for name in ("alice", "bob"):
            open(os.path.join(self.users_dir, name), "w").close()
        self.runner.add("mysql", lambda argv, _i: fail("ERROR 2002 (HY000): Can't connect"))
        with self.assertRaises(SourceError):
            run_sync(self.cfg, self.runner, backend_name="iptables", now=2000.0)
        self.assertEqual((dict(self.v4.chains), self.v4.restores), before)

    def test_per_account_api_failure_keeps_last_known_ips(self):
        for name in ("alice", "bob"):
            open(os.path.join(self.users_dir, name), "w").close()
        self.cfg.source = "cpanel_api"
        answers = {"alice": ["198.51.100.10"], "bob": ["203.0.113.5"]}

        def cpapi2(argv, _input):
            user = argv[1].split("=", 1)[1]
            if answers.get(user) is None:
                return fail("timeout talking to cpsrvd")
            return ok(json.dumps({"cpanelresult": {"data": [{"host": h} for h in answers[user]]}}))

        self.runner.add(self.cfg.cpanel.cpapi2_bin, cpapi2)
        run_sync(self.cfg, self.runner, backend_name="iptables", now=1000.0)
        answers["bob"] = None  # bob's API call fails on the next run
        report = run_sync(self.cfg, self.runner, backend_name="iptables", now=1120.0)
        self.assertIn("bob", report.source_errors)
        self.assertTrue(self.v4.allows("203.0.113.5", 3306), "bob keeps access on API error")
        self.assertTrue(any(r["gate"] == "source" for r in self.log_records()))

    def test_deleted_account_loses_access(self):
        open(os.path.join(self.users_dir, "alice"), "w").close()
        self.runner.add("mysql", lambda argv, _i: ok("alice\t198.51.100.10\n"))
        run_sync(self.cfg, self.runner, backend_name="iptables", now=1000.0)
        self.assertTrue(self.v4.allows("198.51.100.10", 3306))
        os.unlink(os.path.join(self.users_dir, "alice"))
        run_sync(self.cfg, self.runner, backend_name="iptables", now=1120.0)
        self.assertFalse(self.v4.allows("198.51.100.10", 3306))
        self.assertNotIn("alice", State.load(self.cfg.state_dir).first_seen)

    def test_suspended_account_loses_access(self):
        open(os.path.join(self.users_dir, "alice"), "w").close()
        self.runner.add("mysql", lambda argv, _i: ok("alice\t198.51.100.10\n"))
        run_sync(self.cfg, self.runner, backend_name="iptables", now=1000.0)
        os.makedirs(self.cfg.cpanel.suspended_dir)
        open(os.path.join(self.cfg.cpanel.suspended_dir, "alice"), "w").close()
        run_sync(self.cfg, self.runner, backend_name="iptables", now=1120.0)
        self.assertFalse(self.v4.allows("198.51.100.10", 3306))

    def test_server_own_ip_is_rejected(self):
        with open(self.cfg.cpanel.mainip_file, "w") as handle:
            handle.write("203.0.113.20\n")
        report = self.sync()
        self.assertNotIn("203.0.113.20", [r.ip for r in report.rules])
        self.assertIn("blocked", {r["gate"] for r in self.log_records()})

    def test_firewall_failure_is_reported(self):
        self.runner.handlers["iptables-restore"] = lambda argv, _i: fail("iptables-restore: line 3 failed")
        report = self.sync()
        self.assertIn("line 3 failed", report.error)


class TestLock(unittest.TestCase):
    def test_second_holder_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "lock")
            with run_lock(path):
                with self.assertRaises(LockBusy):
                    with run_lock(path):
                        pass
            with run_lock(path):  # released again
                pass


if __name__ == "__main__":
    unittest.main()
