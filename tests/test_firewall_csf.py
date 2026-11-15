"""CSF backend: shared intake scenarios + CSF specifics."""

import os
import unittest

from remotedb_fw.firewalls.csf import CsfBackend, parse_csf_conf, parse_port_list
from tests.fakes import CsfSim
from tests.firewall_scenarios import FirewallScenarios


class CsfScenarios(FirewallScenarios, unittest.TestCase):
    backend = "csf"
    sim_kwargs: dict = {}

    def setup_firewall(self, runner):
        root = os.path.join(self.tmp.name, "csf")
        os.makedirs(root)
        self.sim = CsfSim(root, **self.sim_kwargs).install(runner)
        return self.sim.config()

    def allows(self, ip, port):
        return self.sim.allows(ip, port)

    def reload_count(self):
        return self.sim.restarts

    def snapshot(self):
        def read(path):
            return open(path).read() if os.path.exists(path) else None
        return (read(self.sim.allow_file), read(self.sim.include_file), self.sim.restarts)

    # -- CSF specifics -------------------------------------------------------
    def test_rules_are_port_restricted_advanced_filters(self):
        self.sync()
        with open(self.sim.include_file) as handle:
            body = handle.read()
        self.assertIn("tcp|in|d=3306|s=198.51.100.10\n", body)
        self.assertIn("tcp|in|d=3306|s=2001:db8::10\n", body)
        self.assertIn("# cpremotedb users=alice,bob\n", body)
        rule_lines = [l for l in body.splitlines() if l and not l.startswith("#")]
        self.assertTrue(all(l.startswith("tcp|in|d=3306|s=") for l in rule_lines))
        self.assertEqual(oct(os.stat(self.sim.include_file).st_mode & 0o777), "0o600")

    def test_include_added_once_and_admin_entries_preserved(self):
        self.sync()
        self.sync("intake_update.json", now=2000.0)
        with open(self.sim.allow_file) as handle:
            allow = handle.read()
        self.assertEqual(allow.count(f"Include {self.sim.include_file}"), 1)
        self.assertIn("1.2.3.4 # admin office", allow)
        self.assertTrue(self.sim.allows("1.2.3.4", 22), "admin allow entry still works")

    def test_restart_only_when_changed(self):
        self.sync()
        self.sync(now=1200.0)
        self.sync(now=1400.0)
        self.assertEqual(self.sim.restarts, 1)
        self.assertEqual(self.runner.commands(self.sim.bin), [[self.sim.bin, "-r"]])

    def test_purge_removes_include_and_file(self):
        self.sync()
        from remotedb_fw.sync import run_purge
        run_purge(self.cfg, self.runner, backend_name="csf")
        self.assertFalse(os.path.exists(self.sim.include_file))
        with open(self.sim.allow_file) as handle:
            self.assertNotIn("Include", handle.read())

    def test_missing_csf_allow_is_an_error(self):
        os.unlink(self.sim.allow_file)
        from remotedb_fw.firewalls import Rule
        with self.assertRaises(RuntimeError):
            CsfBackend(self.cfg, self.runner).apply([Rule("198.51.100.1", 3306, ("a",))])


class CsfPortOpenWarning(unittest.TestCase):
    """If 3306 is in TCP_IN it is open to the world: the tool must say so."""

    def test_warns_when_port_globally_open(self):
        import tempfile
        from remotedb_fw.config import load_config
        from tests.fakes import FakeRunner
        with tempfile.TemporaryDirectory() as tmp:
            sim = CsfSim(tmp, tcp_in="22,80,443,3000:3400", ipv6=False)
            cfg = load_config(None, sim.config())
            warnings = CsfBackend(cfg, FakeRunner()).checks(
                [__import__("remotedb_fw.firewalls", fromlist=["Rule"]).Rule("2001:db8::1", 3306)])
        self.assertTrue(any("TCP_IN" in w for w in warnings), warnings)
        self.assertTrue(any("TCP6_IN" in w for w in warnings), warnings)
        self.assertTrue(any("IPV6 is disabled" in w for w in warnings), warnings)

    def test_parsers(self):
        self.assertEqual(parse_csf_conf('TCP_IN = "22,80"\n# x\nIPV6 = "1"'),
                         {"TCP_IN": "22,80", "IPV6": "1"})
        ranges = parse_port_list("22, 80,3000:3400,bad,")
        self.assertTrue(any(3306 in r for r in ranges))
        self.assertFalse(any(21 in r for r in ranges))


if __name__ == "__main__":
    unittest.main()
