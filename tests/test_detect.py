"""Firewall detection on the target distro profiles."""

import os
import tempfile
import unittest

from remotedb_fw.config import load_config
from remotedb_fw.firewalls import DetectionError, detect
from tests.fakes import FakeRunner, ok


def profile(binaries, services, csf_disabled=False):
    tmp = tempfile.mkdtemp()
    disable = os.path.join(tmp, "csf.disable")
    if csf_disabled:
        open(disable, "w").close()
    cfg = load_config(None, {"csf": {"disable_file": disable}})
    runner = FakeRunner(binaries=set(binaries) | {"systemctl"}, services=services)
    runner.add("firewall-cmd", lambda argv, _i: ok("not running\n"))
    if "firewall-cmd" not in binaries:
        runner.binaries.discard("firewall-cmd")
    return cfg, runner


class TestDetection(unittest.TestCase):
    def check(self, binaries, services, expected, csf_disabled=False, warn=False):
        cfg, runner = profile(binaries, services, csf_disabled)
        name, warnings = detect(cfg, runner)
        self.assertEqual(name, expected)
        self.assertEqual(bool(warnings), warn, warnings)

    def test_cpanel_with_csf(self):  # any distro, the most common cPanel setup
        self.check({"/usr/sbin/csf", "iptables", "nft"}, {"csf", "lfd"}, "csf")

    def test_almalinux9_cloudlinux9_firewalld(self):
        self.check({"firewall-cmd", "nft", "iptables"}, {"firewalld"}, "firewalld")

    def test_cloudlinux10_plain_nftables(self):
        self.check({"nft", "iptables"}, {"nftables"}, "nftables")

    def test_ubuntu_iptables_or_ufw_fallback(self):
        self.check({"iptables", "ip6tables"}, set(), "iptables", warn=True)

    def test_installed_but_stopped_csf_is_ignored(self):
        self.check({"/usr/sbin/csf", "firewall-cmd", "iptables"}, {"firewalld"}, "firewalld")

    def test_disabled_csf_is_ignored(self):
        self.check({"/usr/sbin/csf", "firewall-cmd"}, {"csf", "firewalld"}, "firewalld",
                   csf_disabled=True)

    def test_conflict_picks_csf_and_warns(self):
        self.check({"/usr/sbin/csf", "firewall-cmd"}, {"csf", "firewalld"}, "csf", warn=True)

    def test_explicit_override(self):
        cfg, runner = profile(set(), set())
        cfg.firewall = "nftables"
        self.assertEqual(detect(cfg, runner), ("nftables", []))

    def test_nothing_found(self):
        cfg, runner = profile(set(), set())
        with self.assertRaises(DetectionError):
            detect(cfg, runner)


if __name__ == "__main__":
    unittest.main()
