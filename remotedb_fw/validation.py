"""Security validation gates for remote-database hosts entered by cPanel users.

Every host string a cPanel user types into *Remote Database Access* passes
through the single-entry gates below, in order.  The first gate that fails
rejects the entry and the rejection (gate name + reason) is logged.

Single-entry gates (``validate_host``)
    1.  type          - must be a string
    2.  empty         - must not be blank
    3.  length        - must be <= MAX_HOST_LENGTH characters
    4.  wildcard      - no ``*``, ``%``, ``_`` or ``?`` (``%``/``_`` are MySQL wildcards)
    5.  localhost     - no ``localhost`` style names
    6.  all_access    - no "allow everyone" keywords (any, all, 0/0 ...)
    7.  charset       - only IP characters (hostnames are not accepted)
    8.  syntax        - must parse as an IPv4 / IPv6 address (strict, no leading zeros)
    9.  all_access    - no /0 prefixes, ``0.0.0.0`` or ``::``
    10. single_host   - no ranges (only /32 or /128 are accepted, and normalised away)
    11. ip_version    - IPv6 can be disabled by policy
    12. localhost     - no loopback addresses (127.0.0.0/8, ::1, mapped variants)
    13. special       - no multicast, link-local, reserved, "this network"
    14. private       - RFC1918 / CGNAT / ULA are rejected unless policy allows them
    15. blocked       - the server's own IPs and admin-configured block-list

Per-user list gates (``evaluate_user``)
    16. duplicate     - the same IP (after normalisation) only counts once
    17. limit         - at most ``max_per_user`` IPs are active; the most recently
                        added ones win and the oldest become *inactive*.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple, Union

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

MAX_HOST_LENGTH = 64
DEFAULT_MAX_PER_USER = 5

WILDCARD_CHARS = frozenset("*%_?")
LOCALHOST_NAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "localhost4",
        "localhost4.localdomain4",
        "localhost6",
        "localhost6.localdomain6",
        "ip6-localhost",
        "ip6-loopback",
        "loopback",
    }
)
ALL_ACCESS_KEYWORDS = frozenset(
    {"any", "all", "everyone", "anywhere", "world", "public", "0/0", "*.*", "0"}
)
_IP_CHARSET = re.compile(r"^[0-9A-Fa-f:./]+$")
_IPV4_LEADING_ZERO = re.compile(r"(^|\.)0[0-9]")

_LOOPBACK_NETS = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
)
# Addresses that can never be a legitimate remote client.
_SPECIAL_NETS = (
    ipaddress.ip_network("0.0.0.0/8"),  # "this network"
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
    ipaddress.ip_network("224.0.0.0/4"),  # multicast
    ipaddress.ip_network("240.0.0.0/4"),  # reserved + 255.255.255.255 broadcast
    ipaddress.ip_network("::/8"),  # unspecified / IPv4-compatible (deprecated)
    ipaddress.ip_network("100::/64"),  # discard-only
    ipaddress.ip_network("fe80::/10"),  # link-local
    ipaddress.ip_network("fec0::/10"),  # site-local (deprecated)
    ipaddress.ip_network("ff00::/8"),  # multicast
)
# Explicit list instead of ip.is_private, whose meaning changed across
# Python releases (3.9 vs 3.12.4+) and also includes documentation ranges.
PRIVATE_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),  # carrier-grade NAT
    ipaddress.ip_network("fc00::/7"),  # unique local
)


class ValidationError(ValueError):
    """Raised by a gate.  ``gate`` identifies which gate rejected the entry."""

    def __init__(self, gate: str, reason: str):
        super().__init__(f"[{gate}] {reason}")
        self.gate = gate
        self.reason = reason


@dataclass(frozen=True)
class Policy:
    max_per_user: int = DEFAULT_MAX_PER_USER
    allow_private: bool = True
    allow_ipv6: bool = True
    blocked: Tuple[IPNetwork, ...] = ()

    @staticmethod
    def build_blocked(values: Iterable[str]) -> Tuple[IPNetwork, ...]:
        nets = []
        for value in values:
            nets.append(ipaddress.ip_network(str(value).strip(), strict=False))
        return tuple(nets)


# --------------------------------------------------------------------------
# Single-entry gates.  Each gate is a small function so it can be unit-tested
# on its own.  Text gates take/return the raw string, address gates take an
# ip_address object.
# --------------------------------------------------------------------------


def gate_type(raw: object) -> str:
    if not isinstance(raw, str):
        raise ValidationError("type", f"host must be a string, got {type(raw).__name__}")
    return raw


def gate_not_empty(text: str) -> str:
    text = text.strip()
    if not text:
        raise ValidationError("empty", "host is empty")
    return text


def gate_length(text: str) -> str:
    if len(text) > MAX_HOST_LENGTH:
        raise ValidationError("length", f"host longer than {MAX_HOST_LENGTH} characters")
    return text


def gate_no_wildcard(text: str) -> str:
    found = sorted(set(text) & WILDCARD_CHARS)
    if found:
        raise ValidationError(
            "wildcard", f"wildcards are not allowed (found {' '.join(found)})"
        )
    return text


def gate_not_localhost_name(text: str) -> str:
    lowered = text.lower().rstrip(".")
    if lowered in LOCALHOST_NAMES or lowered.endswith(".localhost"):
        raise ValidationError("localhost", "localhost is not allowed")
    return text


def gate_not_all_access_keyword(text: str) -> str:
    if text.lower() in ALL_ACCESS_KEYWORDS:
        raise ValidationError("all_access", f"'{text}' would allow access from everywhere")
    return text


def gate_charset(text: str) -> str:
    if not _IP_CHARSET.match(text):
        raise ValidationError(
            "charset", "only literal IP addresses are allowed (no hostnames or symbols)"
        )
    return text


def gate_parse(text: str) -> Tuple[IPAddress, int]:
    """Parse ``ip`` or ``ip/prefix`` strictly.  Returns (address, prefixlen)."""
    address_part = text.split("/", 1)[0]
    if ":" not in address_part and _IPV4_LEADING_ZERO.search(address_part):
        # Older Pythons (< 3.9.5) silently accepted these; they are ambiguous
        # (octal on some tools), so reject them explicitly everywhere.
        raise ValidationError("syntax", "IPv4 octets with leading zeros are ambiguous")
    try:
        iface = ipaddress.ip_interface(text)
    except ValueError:
        raise ValidationError("syntax", "not a valid IPv4 or IPv6 address") from None
    return iface.ip, iface.network.prefixlen


def gate_not_all_access_network(address: IPAddress, prefixlen: int) -> None:
    if prefixlen == 0 or address.is_unspecified:
        raise ValidationError("all_access", "this would allow access from everywhere")


def gate_single_host(address: IPAddress, prefixlen: int) -> None:
    if prefixlen != address.max_prefixlen:
        raise ValidationError(
            "single_host", f"network ranges are not allowed (/{prefixlen}); add single IPs"
        )


def normalize(address: IPAddress) -> IPAddress:
    """Collapse IPv4-mapped IPv6 (``::ffff:1.2.3.4``) to plain IPv4."""
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def gate_ip_version(address: IPAddress, policy: Policy) -> None:
    if address.version == 6 and not policy.allow_ipv6:
        raise ValidationError("ip_version", "IPv6 addresses are disabled on this server")


def gate_not_loopback(address: IPAddress) -> None:
    if any(address in net for net in _LOOPBACK_NETS if net.version == address.version):
        raise ValidationError("localhost", "loopback addresses are not allowed")


def gate_not_special(address: IPAddress) -> None:
    for net in _SPECIAL_NETS:
        if net.version == address.version and address in net:
            raise ValidationError(
                "special", f"address in {net} (multicast/link-local/reserved) is not allowed"
            )


def gate_private(address: IPAddress, policy: Policy) -> None:
    if policy.allow_private:
        return
    for net in PRIVATE_NETS:
        if net.version == address.version and address in net:
            raise ValidationError("private", f"private address range {net} is not allowed")


def gate_not_blocked(address: IPAddress, policy: Policy) -> None:
    for net in policy.blocked:
        if net.version == address.version and address in net:
            raise ValidationError(
                "blocked", "address is blocked (server's own IP or admin block-list)"
            )


def validate_host(raw: object, policy: Optional[Policy] = None) -> IPAddress:
    """Run every single-entry gate.  Returns the normalised IP or raises."""
    policy = policy or Policy()
    text = gate_type(raw)
    text = gate_not_empty(text)
    text = gate_length(text)
    text = gate_no_wildcard(text)
    text = gate_not_localhost_name(text)
    text = gate_not_all_access_keyword(text)
    text = gate_charset(text)
    address, prefixlen = gate_parse(text)
    gate_not_all_access_network(address, prefixlen)
    gate_single_host(address, prefixlen)
    address = normalize(address)
    gate_ip_version(address, policy)
    gate_not_loopback(address)
    gate_not_all_access_network(address, address.max_prefixlen)  # ::ffff:0.0.0.0
    gate_not_special(address)
    gate_private(address, policy)
    gate_not_blocked(address, policy)
    return address


# --------------------------------------------------------------------------
# Per-user evaluation: duplicates + per-user limit.
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Rejection:
    user: str
    raw: str
    gate: str
    reason: str

    def fingerprint(self) -> str:
        return f"{self.user}\x00{self.raw}\x00{self.gate}"

    def as_dict(self) -> dict:
        return {"user": self.user, "host": self.raw, "gate": self.gate, "reason": self.reason}


@dataclass
class UserResult:
    user: str
    active: List[str] = field(default_factory=list)  # normalised IPs, oldest -> newest
    inactive: List[str] = field(default_factory=list)  # over the limit (oldest ones)
    rejected: List[Rejection] = field(default_factory=list)
    first_seen: Dict[str, float] = field(default_factory=dict)  # ip -> timestamp

    def as_dict(self) -> dict:
        return {
            "active": list(self.active),
            "inactive": list(self.inactive),
            "rejected": [r.as_dict() for r in self.rejected],
        }


def _display(raw: object) -> str:
    text = raw if isinstance(raw, str) else repr(raw)
    # Never let user input inject newlines / control characters into logs.
    text = "".join(ch if ch.isprintable() else "?" for ch in text)
    return text[:MAX_HOST_LENGTH + 16]


def evaluate_user(
    user: str,
    raw_hosts: Sequence[object],
    policy: Policy,
    previously_seen: Optional[Dict[str, float]] = None,
    now: float = 0.0,
) -> UserResult:
    """Validate one user's host list.

    Stack order: an IP's position is decided by when this tool first saw it
    (``previously_seen``, persisted between cron runs), falling back to the
    order the source returned for entries first seen in the same run.  The
    newest ``policy.max_per_user`` IPs are active, older ones are inactive.
    """
    previously_seen = previously_seen or {}
    result = UserResult(user=user)
    accepted: List[Tuple[float, int, str]] = []
    seen: Dict[str, str] = {}

    for index, raw in enumerate(raw_hosts):
        shown = _display(raw)
        try:
            address = validate_host(raw, policy)
        except ValidationError as exc:
            result.rejected.append(Rejection(user, shown, exc.gate, exc.reason))
            continue
        ip = str(address)
        if ip in seen:
            result.rejected.append(
                Rejection(user, shown, "duplicate", f"duplicate of '{seen[ip]}' ({ip})")
            )
            continue
        seen[ip] = shown
        first = previously_seen.get(ip, now)
        result.first_seen[ip] = first
        accepted.append((first, index, ip))

    accepted.sort()
    ordered = [ip for _, _, ip in accepted]
    limit = max(0, policy.max_per_user)
    cut = max(0, len(ordered) - limit)
    result.inactive = ordered[:cut]
    result.active = ordered[cut:]
    return result
