import json
import os
import tempfile
import unittest

from remotedb_fw.config import load_config
from remotedb_fw.sources import (SourceError, collect, list_cpanel_users, load_intake,
                                 parse_listhosts, server_ips)
from tests.fakes import FakeRunner, fail, fixture, ok


class CpanelTree(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = self.tmp.name
        self.users_dir = os.path.join(root, "users")
        self.susp_dir = os.path.join(root, "suspended")
        os.makedirs(self.users_dir)
        os.makedirs(self.susp_dir)
        for name in ("alice", "bob", "carol", "system", "root", ".hidden", "Bad"):
            open(os.path.join(self.users_dir, name), "w").close()
        os.makedirs(os.path.join(self.users_dir, "adir"))
        open(os.path.join(self.susp_dir, "carol"), "w").close()
        self.cfg = load_config(None, {"cpanel": {
            "users_dir": self.users_dir, "suspended_dir": self.susp_dir,
            "mainip_file": os.path.join(root, "mainip"), "ips_file": os.path.join(root, "ips")}})

    def tearDown(self):
        self.tmp.cleanup()


class TestUserListing(CpanelTree):
    def test_lists_real_accounts_only_and_skips_suspended(self):
        self.assertEqual(list_cpanel_users(self.cfg), ["alice", "bob"])

    def test_suspended_included_when_configured(self):
        self.cfg.skip_suspended = False
        self.assertEqual(list_cpanel_users(self.cfg), ["alice", "bob", "carol"])

    def test_missing_dir_is_a_source_error(self):
        self.cfg.cpanel.users_dir = "/nonexistent"
        with self.assertRaises(SourceError):
            list_cpanel_users(self.cfg)

    def test_server_ips(self):
        with open(self.cfg.cpanel.mainip_file, "w") as handle:
            handle.write("198.51.100.200")
        with open(self.cfg.cpanel.ips_file, "w") as handle:
            handle.write("198.51.100.201:255.255.255.0:198.51.100.255\n")
        self.assertEqual(server_ips(self.cfg), ["198.51.100.200", "198.51.100.201"])


class TestMysqlSource(CpanelTree):
    def test_reads_grants_for_cpanel_users_only(self):
        runner = FakeRunner()
        rows = ("root\tlocalhost\nalice\tlocalhost\nalice\t198.51.100.10\n"
                "alice_wp\t198.51.100.10\nbob\t%\nmallory\t203.0.113.1\n")
        runner.add("mysql", lambda argv, _i: ok(rows))
        out = collect(self.cfg, runner)
        self.assertEqual(out.hosts, {"alice": ["localhost", "198.51.100.10"], "bob": ["%"]})
        argv = runner.calls[-1]
        self.assertEqual(argv[1], "--defaults-file=/root/.my.cnf")  # must be first option
        self.assertIn("SELECT User, Host FROM mysql.user", argv)

    def test_mysql_failure_aborts(self):
        runner = FakeRunner()
        runner.add("mysql", lambda argv, _i: fail("ERROR 2002: Can't connect"))
        with self.assertRaises(SourceError):
            collect(self.cfg, runner)


class TestCpanelApiSource(CpanelTree):
    def test_per_user_api_and_per_user_errors(self):
        self.cfg.source = "cpanel_api"
        runner = FakeRunner()

        def cpapi2(argv, _input):
            user = argv[1].split("=", 1)[1]
            if user == "bob":
                return fail("cpsrvd unavailable")
            return ok(json.dumps({"cpanelresult": {"event": {"result": 1}, "data": [
                {"host": "198.51.100.10"}, {"host": "203.0.113.20"}]}}))

        runner.add(self.cfg.cpanel.cpapi2_bin, cpapi2)
        out = collect(self.cfg, runner)
        self.assertEqual(out.hosts["alice"], ["198.51.100.10", "203.0.113.20"])
        self.assertIn("bob", out.errors)
        self.assertEqual(runner.calls[0][1:], ["--user=alice", "--output=json", "MysqlFE",
                                               "listhosts"])

    def test_parse_listhosts_errors(self):
        for payload in ("not json", "[]", '{"cpanelresult": {"error": "denied"}}',
                        '{"cpanelresult": {"data": "x"}}'):
            with self.subTest(payload=payload):
                with self.assertRaises(SourceError):
                    parse_listhosts(payload)
        self.assertEqual(parse_listhosts('{"cpanelresult": {"data": []}}'), [])


class TestIntake(unittest.TestCase):
    def test_loads_fixture(self):
        out = load_intake(fixture("intake.json"))
        self.assertEqual(out.users, ["alice", "bob", "carol", "dave"])
        self.assertEqual(out.hosts["alice"][0], "198.51.100.10")

    def test_invalid_usernames_and_shapes(self):
        out = load_intake(fixture("intake_invalid_users.json"))
        self.assertEqual(out.users, ["good", "mixed"])
        self.assertEqual(set(out.errors), {"../etc", "Bad User", "notalist"})

    def test_bad_files(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            handle.write('{"alice": ["198.51.100.1"]}')
        try:
            for path in (handle.name, "/nonexistent.json"):
                with self.subTest(path=path):
                    with self.assertRaises(SourceError):
                        load_intake(path)
        finally:
            os.unlink(handle.name)


if __name__ == "__main__":
    unittest.main()
