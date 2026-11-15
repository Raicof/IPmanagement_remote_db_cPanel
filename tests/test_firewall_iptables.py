"""iptables backend: shared intake scenarios + iptables specifics."""

import copy
import ipaddress
import unittest

from remotedb_fw.firewalls.iptables import parse_chain_rules
from tests.fakes import IptablesSim
from tests.firewall_scenarios import FirewallScenarios


class IptablesScenarios(FirewallScenarios, unittest.TestCase):
    backend = "iptables"

    def setup_firewall(self, runner):
        self.v4 = IptablesSim(4, input_policy="DROP").install(runner)
        self.v6 = IptablesSim(6, input_policy="DROP").install(runner)
        for sim in (self.v4, self.v6):
            sim.add_rule("INPUT", "-p tcp -m tcp --dport 22 -j ACCEPT")
        return {}

    def allows(self, ip, port):
        sim = self.v4 if ipaddress.ip_address(ip).version == 4 else self.v6
        return sim.allows(ip, port)

    def snapshot(self):
        return copy.deepcopy((self.v4.chains, self.v6.chains))

    # -- iptables specifics ---------------------------------------------------
    def test_restore_batch_shape(self):
        self.sync()
        batch = self.v4.restores[0]
        lines = batch.splitlines()
        self.assertEqual(lines[:3], ["*filter", ":CPREMOTEDB - [0:0]", "-F CPREMOTEDB"])
        self.assertIn('-A CPREMOTEDB -s 198.51.100.10/32 -p tcp -m tcp --dport 3306 '
                      '-m comment --comment "cpremotedb users=alice,bob" -j ACCEPT', lines)
        self.assertIn('-I INPUT 1 -m comment --comment "cpremotedb jump" -j CPREMOTEDB', lines)
        self.assertEqual(lines[-1], "COMMIT")
        self.assertIn("-s 2001:db8::10/128", self.v6.restores[0])
        self.assertNotIn("2001:db8", batch)

    def test_jump_goes_before_existing_drop(self):
        self.v4.add_rule("INPUT", "-p tcp -m tcp --dport 3306 -j DROP", insert=True)
        self.sync()
        self.assertTrue(self.v4.allows("198.51.100.10", 3306))
        self.assertFalse(self.v4.allows("203.0.113.250", 3306))

    def test_jump_not_duplicated(self):
        self.sync()
        self.sync("intake_update.json", now=2000.0)
        jumps = [r for r in self.v4.chains["INPUT"] if "-j CPREMOTEDB" in r]
        self.assertEqual(len(jumps), 1)

    def test_foreign_rule_in_our_chain_triggers_rebuild(self):
        self.sync()
        self.v4.chains["CPREMOTEDB"].append("-A CPREMOTEDB -j ACCEPT")
        self.assertTrue(self.v4.allows("203.0.113.250", 3306))
        self.sync(now=1200.0)
        self.assertFalse(self.v4.allows("203.0.113.250", 3306))

    def test_reboot_rules_recreated(self):
        self.sync()
        del self.v4.chains["CPREMOTEDB"]
        self.v4.chains["INPUT"] = [r for r in self.v4.chains["INPUT"] if "CPREMOTEDB" not in r]
        self.assertFalse(self.v4.allows("198.51.100.10", 3306))
        self.sync(now=1200.0)
        self.assertTrue(self.v4.allows("198.51.100.10", 3306))

    def test_missing_ip6tables_warns(self):
        self.runner.binaries.discard("ip6tables")
        report = self.sync()
        self.assertTrue(any("ip6tables not found" in w for w in report.apply.warnings))
        self.assertTrue(self.v4.allows("198.51.100.10", 3306))

    def test_tampered_range_in_our_chain_triggers_rebuild(self):
        self.sync()
        chain = self.v4.chains["CPREMOTEDB"]
        chain[:] = [r.replace("198.51.100.10/32", "198.51.100.10/24") for r in chain]
        self.assertTrue(self.v4.allows("198.51.100.77", 3306))
        self.sync(now=1200.0)
        self.assertFalse(self.v4.allows("198.51.100.77", 3306))

    def test_parse_chain_rules(self):
        lines = ["-N CPREMOTEDB",
                 '-A CPREMOTEDB -s 198.51.100.10/32 -p tcp -m tcp --dport 3306 '
                 '-m comment --comment "cpremotedb users=a" -j ACCEPT']
        self.assertEqual(parse_chain_rules(lines, "CPREMOTEDB"),
                         {("198.51.100.10", 3306, "cpremotedb users=a")})
        self.assertIsNone(parse_chain_rules(lines + ["-A CPREMOTEDB -j ACCEPT"], "CPREMOTEDB"))
        self.assertIsNone(parse_chain_rules(
            ['-A CPREMOTEDB -s 198.51.100.0/24 -p udp --dport 3306 --comment x -j ACCEPT'],
            "CPREMOTEDB"))


if __name__ == "__main__":
    unittest.main()
