"""nftables backend: shared intake scenarios + nftables specifics."""

import json
import unittest

from remotedb_fw.firewalls.nftables import NftablesBackend
from tests.fakes import NftSim
from tests.firewall_scenarios import FirewallScenarios

SSH = [{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                  "right": 22}}, {"accept": None}]


def admin_ruleset() -> NftSim:
    """Typical hand-written /etc/nftables.conf: inet filter, input policy drop."""
    sim = NftSim()
    sim.add_table("inet", "filter")
    sim.add_chain("inet", "filter", "input", hook="input", policy="drop")
    sim.add_chain("inet", "filter", "forward", hook="forward", policy="drop")
    sim.add_rule("inet", "filter", "input", SSH, comment="ssh")
    return sim


class NftablesScenarios(FirewallScenarios, unittest.TestCase):
    backend = "nftables"

    def setup_firewall(self, runner):
        self.sim = admin_ruleset().install(runner)
        return {}

    def allows(self, ip, port):
        return self.sim.allows(ip, port)

    def snapshot(self):
        return json.dumps(self.sim.to_json(), sort_keys=True)

    # -- nftables specifics ---------------------------------------------------
    def test_one_atomic_batch_with_jump_at_top(self):
        self.sync()
        self.assertEqual(len(self.sim.batches), 1)
        batch = self.sim.batches[0]
        self.assertIn("add chain inet filter cpremotedb", batch)
        self.assertIn("flush chain inet filter cpremotedb", batch)
        self.assertIn('add rule inet filter cpremotedb ip saddr 198.51.100.10 tcp dport 3306 '
                      'accept comment "cpremotedb users=alice,bob"', batch)
        self.assertIn("ip6 saddr 2001:db8::10", batch)
        first = self.sim.tables[("inet", "filter")]["chains"]["input"]["rules"][0]
        self.assertEqual(first["expr"], [{"jump": {"target": "cpremotedb"}}])

    def test_admin_rules_untouched(self):
        before = self.sim.tables[("inet", "filter")]["chains"]["input"]["rules"][0]
        self.sync()
        self.sync("intake_update.json", now=2000.0)
        from remotedb_fw.sync import run_purge
        run_purge(self.cfg, self.runner, backend_name="nftables")
        rules = self.sim.tables[("inet", "filter")]["chains"]["input"]["rules"]
        self.assertEqual(rules, [before])
        self.assertTrue(self.sim.allows("203.0.113.250", 22))

    def test_reboot_rules_recreated(self):
        self.sync()
        self.sim.tables = admin_ruleset().tables  # nftables.conf reloaded at boot
        self.assertFalse(self.sim.allows("198.51.100.10", 3306))  # fail-closed
        self.sync(now=1200.0)
        self.assertTrue(self.sim.allows("198.51.100.10", 3306))

    def test_foreign_rule_in_our_chain_triggers_rebuild(self):
        self.sync()
        self.sim.add_rule("inet", "filter", "cpremotedb", [{"accept": None}])  # accept all!
        self.assertTrue(self.sim.allows("203.0.113.250", 3306))
        self.sync(now=1200.0)
        self.assertFalse(self.sim.allows("203.0.113.250", 3306))

    def test_every_input_table_gets_a_chain(self):
        # A second table with its own input hook (e.g. a legacy "ip" table)
        # would still drop the packet: both must be handled.
        self.sim.add_table("ip", "legacy")
        self.sim.add_chain("ip", "legacy", "in", hook="input", policy="drop")
        self.sim.add_table("ip6", "legacy6")
        self.sim.add_chain("ip6", "legacy6", "in", hook="input", policy="drop")
        self.sync()
        self.assertTrue(self.sim.allows("198.51.100.10", 3306))
        self.assertTrue(self.sim.allows("2001:db8::10", 3306))
        batch = self.sim.batches[-1]
        self.assertNotIn("add rule ip legacy cpremotedb ip6", batch)
        self.assertNotIn("add rule ip6 legacy6 cpremotedb ip saddr", batch)

    def test_iptables_nft_table_is_skipped_with_warning(self):
        self.sim.add_table("ip", "filter")
        self.sim.add_chain("ip", "filter", "INPUT", hook="input", policy="accept")
        report = self.sync()
        self.assertTrue(any("iptables-nft" in w for w in report.apply.warnings))
        self.assertNotIn("cpremotedb", self.sim.tables[("ip", "filter")]["chains"])

    def test_configured_targets(self):
        self.sim.add_table("ip", "other")
        self.sim.add_chain("ip", "other", "in", hook="input", policy="accept")
        self.cfg.nftables.targets = ["inet filter input", "inet nope input"]
        report = self.sync()
        self.assertNotIn("cpremotedb", self.sim.tables[("ip", "other")]["chains"])
        self.assertTrue(any("inet nope input" in w for w in report.apply.warnings))

    def test_no_input_chain_warns(self):
        self.sim.tables = {}
        report = self.sync()
        self.assertFalse(report.apply.changed)
        self.assertTrue(any("no nftables input filter chain" in w for w in report.apply.warnings))

    def test_batch_failure_reports_error(self):
        self.runner.handlers["nft"] = lambda argv, inp: (
            self.sim.handle(argv, inp) if argv[1] == "-j" else
            __import__("tests.fakes", fromlist=["fail"]).fail("Error: syntax error"))
        from remotedb_fw.sync import run_sync
        from tests.fakes import fixture
        report = run_sync(self.cfg, self.runner, intake=fixture("intake.json"),
                          backend_name="nftables", now=1.0)
        self.assertIn("nftables", report.error)


if __name__ == "__main__":
    unittest.main()
