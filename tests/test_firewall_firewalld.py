"""firewalld backend: shared intake scenarios + firewalld specifics."""

import copy
import unittest

from remotedb_fw.firewalls.firewalld import FirewalldBackend, parse_rich
from tests.fakes import FirewalldSim
from tests.firewall_scenarios import FirewallScenarios


class FirewalldScenarios(FirewallScenarios, unittest.TestCase):
    backend = "firewalld"

    def setup_firewall(self, runner):
        self.sim = FirewalldSim(zone="public", open_ports=("22/tcp", "80/tcp")).install(runner)
        return {}

    def allows(self, ip, port):
        return self.sim.allows(ip, port)

    def reload_count(self):
        return self.sim.reloads

    def snapshot(self):
        return copy.deepcopy((self.sim.permanent, self.sim.runtime))

    # -- firewalld specifics ------------------------------------------------
    def test_structure_created_once(self):
        self.sync()
        perm = self.sim.permanent
        self.assertEqual(perm["ipsets"]["cpremotedb4"]["family"], "inet")
        self.assertEqual(perm["ipsets"]["cpremotedb6"]["family"], "inet6")
        self.assertEqual(sorted(perm["rich"]["public"]), sorted([
            'rule family="ipv4" source ipset="cpremotedb4" port port="3306" protocol="tcp" accept',
            'rule family="ipv6" source ipset="cpremotedb6" port port="3306" protocol="tcp" accept',
        ]))
        self.assertEqual(perm["ipsets"]["cpremotedb6"]["entries"], {"2001:db8::10"})
        self.assertEqual(self.sim.reloads, 1)

    def test_entry_changes_need_no_reload(self):
        self.sync()
        self.sync("intake_update.json", now=2000.0)
        self.assertEqual(self.sim.reloads, 1, "only the initial structural change reloads")
        self.assertEqual(self.sim.permanent["ipsets"], self.sim.runtime["ipsets"])

    def test_runtime_lost_is_repaired_with_reload(self):
        self.sync()
        self.sim.runtime = copy.deepcopy(self.sim.runtime)
        self.sim.runtime["rich"]["public"] = []  # e.g. someone ran a runtime-only change
        self.sync(now=1200.0)
        self.assertEqual(self.sim.reloads, 2)
        self.assertTrue(self.sim.allows("198.51.100.10", 3306))

    def test_admin_rich_rules_untouched(self):
        admin = 'rule family="ipv4" source address="203.0.113.250" service name="ssh" accept'
        self.sim.permanent["rich"]["public"].append(admin)
        self.sim.runtime["rich"]["public"].append(admin)
        self.sync()
        self.sync("intake_update.json", now=2000.0)
        from remotedb_fw.sync import run_purge
        run_purge(self.cfg, self.runner, backend_name="firewalld")
        self.assertEqual(self.sim.permanent["rich"]["public"], [admin])

    def test_port_change_replaces_rich_rule(self):
        self.sync()
        self.cfg.ports = [3307]
        self.sync(now=1200.0)
        self.assertTrue(self.sim.allows("198.51.100.10", 3307))
        self.assertFalse(self.sim.allows("198.51.100.10", 3306))

    def test_ipv6_disabled_uses_only_v4_set(self):
        self.cfg.allow_ipv6 = False
        self.sync()
        self.assertNotIn("cpremotedb6", self.sim.permanent["ipsets"])

    def test_explicit_zone(self):
        self.sim.permanent["rich"]["internal"] = []
        self.sim.runtime["rich"]["internal"] = []
        self.cfg.firewalld.zone = "internal"
        self.sync()
        self.assertEqual(len(self.sim.permanent["rich"]["internal"]), 2)
        self.assertEqual(self.sim.permanent["rich"]["public"], [])

    def test_warns_when_mysql_open_in_zone(self):
        self.sim.permanent["ports"]["public"].add("3306/tcp")
        self.sim.permanent["services"]["public"].add("mysql")
        report = self.sync()
        text = " ".join(report.apply.warnings)
        self.assertIn("3306/tcp is open to everyone", text)
        self.assertIn("mysql service is open", text)


class TestRichRuleParsing(unittest.TestCase):
    def test_tolerant_parsing(self):
        canonical = 'rule family="ipv4" source ipset="cpremotedb4" port port="3306" protocol="tcp" accept'
        spaced = 'rule  family="ipv4"  source ipset="cpremotedb4"  port protocol="tcp" port="3306"  accept'
        self.assertEqual(parse_rich(canonical), ("ipv4", "cpremotedb4", 3306))
        self.assertEqual(parse_rich(spaced), ("ipv4", "cpremotedb4", 3306))
        self.assertIsNone(parse_rich(canonical.replace("accept", "drop")))
        self.assertIsNone(parse_rich(canonical.replace('"tcp"', '"udp"')))

    def test_round_trip(self):
        rule = FirewalldBackend.rich_rule("ipv6", "cpremotedb6", 3306)
        self.assertEqual(parse_rich(rule), ("ipv6", "cpremotedb6", 3306))


if __name__ == "__main__":
    unittest.main()
