"""Per-user gates: duplicates and the max-5 "stack" limit."""

import unittest

from remotedb_fw.validation import Policy, evaluate_user


class TestDuplicateGate(unittest.TestCase):
    def test_exact_duplicate_rejected_once_kept_once(self):
        res = evaluate_user("u", ["198.51.100.1", "198.51.100.1"], Policy())
        self.assertEqual(res.active, ["198.51.100.1"])
        self.assertEqual([r.gate for r in res.rejected], ["duplicate"])

    def test_duplicates_detected_after_normalisation(self):
        raw = ["198.51.100.1", "::ffff:198.51.100.1", "198.51.100.1/32", " 198.51.100.1 ",
               "2001:db8::1", "2001:0db8:0:0:0:0:0:1", "2001:DB8::1/128"]
        res = evaluate_user("u", raw, Policy())
        self.assertEqual(sorted(res.active), ["198.51.100.1", "2001:db8::1"])
        self.assertEqual(len(res.rejected), 5)
        self.assertTrue(all(r.gate == "duplicate" for r in res.rejected))

    def test_duplicates_do_not_consume_the_limit(self):
        raw = ["198.51.100.1"] * 10 + ["198.51.100.2"]
        res = evaluate_user("u", raw, Policy(max_per_user=5))
        self.assertEqual(sorted(res.active), ["198.51.100.1", "198.51.100.2"])
        self.assertEqual(res.inactive, [])


class TestLimitGate(unittest.TestCase):
    IPS = [f"198.51.100.{i}" for i in range(1, 8)]  # 7 IPs, oldest first

    def test_max_five_newest_active(self):
        res = evaluate_user("u", self.IPS, Policy())
        self.assertEqual(res.active, self.IPS[2:])
        self.assertEqual(res.inactive, self.IPS[:2])

    def test_exactly_five_all_active(self):
        res = evaluate_user("u", self.IPS[:5], Policy())
        self.assertEqual(res.active, self.IPS[:5])
        self.assertEqual(res.inactive, [])

    def test_limit_is_configurable(self):
        res = evaluate_user("u", self.IPS, Policy(max_per_user=2))
        self.assertEqual(res.active, self.IPS[-2:])

    def test_rejected_entries_do_not_count(self):
        raw = ["*", "localhost", "0.0.0.0/0"] + self.IPS[:5]
        res = evaluate_user("u", raw, Policy())
        self.assertEqual(res.active, self.IPS[:5])
        self.assertEqual(len(res.rejected), 3)

    def test_stack_order_uses_first_seen_across_runs(self):
        # Run 1 at t=100 saw .1-.5. Source order is arbitrary (MySQL), so a
        # newly added IP listed *first* must still count as the newest.
        seen = {ip: 100.0 for ip in self.IPS[:5]}
        new_ip = "198.51.100.99"
        res = evaluate_user("u", [new_ip] + self.IPS[:5], Policy(), seen, now=200.0)
        self.assertIn(new_ip, res.active)
        self.assertEqual(res.inactive, [self.IPS[0]])
        self.assertEqual(res.first_seen[new_ip], 200.0)
        self.assertEqual(res.first_seen[self.IPS[1]], 100.0)

    def test_removing_an_active_ip_reactivates_the_next_oldest(self):
        seen = {ip: float(i) for i, ip in enumerate(self.IPS)}
        res = evaluate_user("u", self.IPS[:-1], Policy(), seen, now=999.0)  # newest removed
        self.assertEqual(res.active, self.IPS[1:6])
        self.assertEqual(res.inactive, [self.IPS[0]])

    def test_first_run_uses_source_order(self):
        res = evaluate_user("u", list(reversed(self.IPS)), Policy(), {}, now=1.0)
        self.assertEqual(res.active, list(reversed(self.IPS))[2:])


class TestRejectionRecords(unittest.TestCase):
    def test_display_sanitises_control_characters(self):
        res = evaluate_user("u", ["198.51.100.1\r\nFAKE LOG LINE"], Policy())
        self.assertNotIn("\n", res.rejected[0].raw)
        self.assertNotIn("\r", res.rejected[0].raw)

    def test_record_fields(self):
        res = evaluate_user("bob", ["*"], Policy())
        self.assertEqual(res.rejected[0].as_dict(),
                         {"user": "bob", "host": "*", "gate": "wildcard",
                          "reason": res.rejected[0].reason})


if __name__ == "__main__":
    unittest.main()
