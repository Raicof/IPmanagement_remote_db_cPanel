"""One test class per validation gate (single-entry gates)."""

import ipaddress
import unittest

from remotedb_fw import validation as v
from remotedb_fw.validation import Policy, ValidationError, validate_host


class GateAssertions(unittest.TestCase):
    def assertRejected(self, raw, gate, policy=None):
        with self.assertRaises(ValidationError, msg=f"{raw!r} should be rejected") as ctx:
            validate_host(raw, policy)
        self.assertEqual(ctx.exception.gate, gate, f"{raw!r}: {ctx.exception}")

    def assertAccepted(self, raw, expected=None, policy=None):
        result = validate_host(raw, policy)
        if expected is not None:
            self.assertEqual(str(result), expected)
        return result


class TestGateType(GateAssertions):
    def test_rejects_non_strings(self):
        for raw in (None, 12345, 1.5, ["198.51.100.1"], {"ip": "198.51.100.1"}, b"198.51.100.1"):
            with self.subTest(raw=raw):
                self.assertRejected(raw, "type")

    def test_gate_function_passes_strings(self):
        self.assertEqual(v.gate_type("x"), "x")


class TestGateEmpty(GateAssertions):
    def test_rejects_blank(self):
        for raw in ("", " ", "\t", "\n  "):
            with self.subTest(raw=raw):
                self.assertRejected(raw, "empty")

    def test_strips_surrounding_whitespace(self):
        self.assertAccepted("  198.51.100.1 \n", "198.51.100.1")


class TestGateLength(GateAssertions):
    def test_rejects_overlong(self):
        self.assertRejected("1" * (v.MAX_HOST_LENGTH + 1), "length")

    def test_longest_ipv6_form_fits(self):
        self.assertAccepted("2001:0db8:0000:0000:0000:0000:0000:0001/128", "2001:db8::1")


class TestGateWildcard(GateAssertions):
    def test_rejects_every_wildcard_form(self):
        for raw in ("*", "%", "192.0.2.%", "192.0.2.*", "192.0.2._", "192.0.2.?",
                    "%.example.com", "*.*.*.*", "fe80::1%eth0"):
            with self.subTest(raw=raw):
                self.assertRejected(raw, "wildcard")

    def test_mysql_single_char_wildcard_underscore(self):
        # '_' matches any single character in a MySQL host pattern.
        self.assertRejected("192.0.2.1_", "wildcard")


class TestGateLocalhost(GateAssertions):
    def test_rejects_localhost_names(self):
        for raw in ("localhost", "LOCALHOST", "localhost.", "localhost.localdomain",
                    "localhost6", "ip6-localhost", "foo.localhost"):
            with self.subTest(raw=raw):
                self.assertRejected(raw, "localhost")

    def test_rejects_loopback_addresses(self):
        for raw in ("127.0.0.1", "127.1.2.3", "127.255.255.254", "::1",
                    "0:0:0:0:0:0:0:1", "::ffff:127.0.0.1", "127.0.0.1/32"):
            with self.subTest(raw=raw):
                self.assertRejected(raw, "localhost")


class TestGateAllAccess(GateAssertions):
    def test_rejects_keywords(self):
        for raw in ("any", "ALL", "everyone", "anywhere", "0/0", "0"):
            with self.subTest(raw=raw):
                self.assertRejected(raw, "all_access")

    def test_rejects_unspecified_and_default_routes(self):
        for raw in ("0.0.0.0", "0.0.0.0/0", "::", "::/0", "::0", "1.2.3.4/0",
                    "::ffff:0.0.0.0"):
            with self.subTest(raw=raw):
                self.assertRejected(raw, "all_access")


class TestGateCharset(GateAssertions):
    def test_rejects_hostnames_and_symbols(self):
        for raw in ("db.example.com", "example", "198.51.100.1;rm -rf /",
                    "198.51.100.1 198.51.100.2", "198.51.100.1,198.51.100.2",
                    "$(id)", "`id`", "198.51.100.1\n", "198.51.100.1\x00"):
            with self.subTest(raw=raw):
                # trailing newline is stripped (empty gate) -> valid; others fail charset
                if raw == "198.51.100.1\n":
                    self.assertAccepted(raw, "198.51.100.1")
                else:
                    self.assertRejected(raw, "charset")

    def test_rejects_unicode_digits(self):
        self.assertRejected("١٩٨.٥١.١٠٠.١", "charset")  # Arabic-Indic digits


class TestGateSyntax(GateAssertions):
    def test_rejects_malformed(self):
        for raw in ("256.1.1.1", "198.51.100", "198.51.100.1.5", "1", "::12345", "1:2:3",
                    "198.51.100.1/33", "2001:db8::1/129", "/32", "198.51.100.1/",
                    "2001:db8:::1"):
            with self.subTest(raw=raw):
                self.assertRejected(raw, "syntax")

    def test_rejects_leading_zeros(self):
        for raw in ("010.1.1.1", "198.051.100.1", "198.51.100.01"):
            with self.subTest(raw=raw):
                self.assertRejected(raw, "syntax")

    def test_gate_parse_returns_prefix(self):
        addr, prefix = v.gate_parse("198.51.100.1/24")
        self.assertEqual((str(addr), prefix), ("198.51.100.1", 24))


class TestGateSingleHost(GateAssertions):
    def test_rejects_ranges(self):
        for raw in ("10.0.0.0/8", "198.51.100.0/24", "198.51.100.1/31",
                    "198.51.100.0/255.255.255.0", "2001:db8::/64", "2001:db8::1/127"):
            with self.subTest(raw=raw):
                self.assertRejected(raw, "single_host")

    def test_full_prefix_is_normalised_to_plain_ip(self):
        self.assertAccepted("198.51.100.1/32", "198.51.100.1")
        self.assertAccepted("198.51.100.1/255.255.255.255", "198.51.100.1")
        self.assertAccepted("2001:db8::1/128", "2001:db8::1")


class TestNormalisation(GateAssertions):
    def test_ipv4_mapped_ipv6_collapses_to_ipv4(self):
        self.assertAccepted("::ffff:198.51.100.1", "198.51.100.1")

    def test_ipv6_is_compressed_and_lowercased(self):
        self.assertAccepted("2001:0DB8:0000:0000:0000:0000:0000:00AB", "2001:db8::ab")


class TestGateIpVersion(GateAssertions):
    def test_ipv6_can_be_disabled(self):
        policy = Policy(allow_ipv6=False)
        self.assertRejected("2001:db8::1", "ip_version", policy)
        self.assertAccepted("198.51.100.1", policy=policy)

    def test_mapped_ipv4_allowed_even_if_ipv6_disabled(self):
        self.assertAccepted("::ffff:198.51.100.1", "198.51.100.1", Policy(allow_ipv6=False))


class TestGateSpecial(GateAssertions):
    def test_rejects_non_unicast_addresses(self):
        for raw in ("0.1.2.3", "169.254.1.1", "224.0.0.1", "239.255.255.250",
                    "240.0.0.1", "255.255.255.255", "fe80::1", "fec0::1", "ff02::1",
                    "::1.2.3.4", "100::1"):
            with self.subTest(raw=raw):
                self.assertRejected(raw, "special")

    def test_accepts_public_and_documentation_addresses(self):
        for raw in ("8.8.8.8", "198.51.100.1", "203.0.113.9", "192.0.2.1",
                    "2001:db8::1", "2606:4700::1111"):
            with self.subTest(raw=raw):
                self.assertAccepted(raw, str(ipaddress.ip_address(raw)))


class TestGatePrivate(GateAssertions):
    PRIVATE = ("10.1.2.3", "172.16.0.5", "172.31.255.1", "192.168.1.10",
               "100.64.0.1", "fd00::1", "fc00::1")

    def test_private_allowed_by_default(self):
        for raw in self.PRIVATE:
            with self.subTest(raw=raw):
                self.assertAccepted(raw)

    def test_private_rejected_when_disabled(self):
        policy = Policy(allow_private=False)
        for raw in self.PRIVATE:
            with self.subTest(raw=raw):
                self.assertRejected(raw, "private", policy)

    def test_boundaries(self):
        policy = Policy(allow_private=False)
        self.assertAccepted("172.15.255.255", policy=policy)
        self.assertAccepted("172.32.0.1", policy=policy)


class TestGateBlocked(GateAssertions):
    def test_server_ip_and_blocklist(self):
        policy = Policy(blocked=Policy.build_blocked(["198.51.100.5", "203.0.113.0/24"]))
        self.assertRejected("198.51.100.5", "blocked", policy)
        self.assertRejected("203.0.113.77", "blocked", policy)
        self.assertRejected("::ffff:198.51.100.5", "blocked", policy)
        self.assertAccepted("198.51.100.6", policy=policy)


class TestGateOrder(GateAssertions):
    """The first failing gate wins, so the reported reason is the most useful."""

    def test_wildcard_beats_charset(self):
        self.assertRejected("*.example.com", "wildcard")

    def test_localhost_name_beats_charset(self):
        self.assertRejected("localhost", "localhost")

    def test_all_access_beats_single_host(self):
        self.assertRejected("0.0.0.0/0", "all_access")


if __name__ == "__main__":
    unittest.main()
