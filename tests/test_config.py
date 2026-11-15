import json
import os
import tempfile
import unittest

from remotedb_fw.config import ConfigError, load_config


class TestConfig(unittest.TestCase):
    def load(self, data):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump(data, handle)
        try:
            return load_config(handle.name)
        finally:
            os.unlink(handle.name)

    def test_defaults(self):
        cfg = load_config(None)
        self.assertEqual(cfg.ports, [3306])
        self.assertEqual(cfg.max_ips_per_user, 5)
        self.assertEqual(cfg.firewall, "auto")

    def test_override_nested(self):
        cfg = self.load({"ports": [3306, 3307], "firewalld": {"zone": "public"},
                         "_comment": "ignored"})
        self.assertEqual(cfg.ports, [3306, 3307])
        self.assertEqual(cfg.firewalld.zone, "public")

    def test_rejects_bad_values(self):
        bad = [
            {"unknown": 1},
            {"firewalld": {"nope": 1}},
            {"firewall": "ufw"},
            {"source": "ldap"},
            {"ports": []},
            {"ports": [0]},
            {"ports": ["3306"]},
            {"ports": [True]},
            {"max_ips_per_user": 0},
            {"max_ips_per_user": "5"},
            {"iptables": {"chain": "X; rm -rf /"}},
            {"nftables": {"chain": "a b"}},
            {"nftables": {"targets": ["inet filter"]}},
            {"firewalld": {"zone": "pub lic"}},
            {"blocked_ips": ["not-an-ip"]},
            {"firewalld": "x"},
        ]
        for data in bad:
            with self.subTest(data=data):
                with self.assertRaises(ConfigError):
                    self.load(data)

    def test_missing_explicit_config_is_an_error(self):
        with self.assertRaises(ConfigError):
            load_config("/nonexistent/config.json")

    def test_invalid_json(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            handle.write("{not json")
        try:
            with self.assertRaises(ConfigError):
                load_config(handle.name)
        finally:
            os.unlink(handle.name)


if __name__ == "__main__":
    unittest.main()
