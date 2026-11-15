"""Common pieces for every firewall backend.

Each backend owns a clearly-named object (CSF include file, firewalld ipsets,
nftables / iptables chain), reads the *live* firewall state, compares it with
the desired rules and only changes / reloads something when they differ.
Rules it does not own are never touched.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Sequence, Set, Tuple

from ..config import Config
from ..runner import Runner

log = logging.getLogger("remotedb_fw")

COMMENT_PREFIX = "cpremotedb"
MAX_COMMENT = 120  # nft comments are limited to 128 bytes


@dataclass(frozen=True, order=True)
class Rule:
    """Allow TCP ``port`` from ``ip``.  ``users`` is informational (comments)."""

    ip: str
    port: int
    users: Tuple[str, ...] = ()

    @property
    def version(self) -> int:
        return ipaddress.ip_address(self.ip).version

    @property
    def comment(self) -> str:
        text = f"{COMMENT_PREFIX} users={','.join(self.users)}"
        if len(text) > MAX_COMMENT:
            text = text[: MAX_COMMENT - 3] + "..."
        return text

    @property
    def key(self) -> Tuple[str, int]:
        return (self.ip, self.port)


def build_rules(ip_users: Dict[str, Iterable[str]], ports: Sequence[int]) -> List[Rule]:
    """ip -> users mapping (already validated) to a sorted rule list."""
    rules = []
    for ip, users in ip_users.items():
        for port in ports:
            rules.append(Rule(ip=ip, port=int(port), users=tuple(sorted(set(users)))))
    return sorted(rules, key=lambda r: (r.version, ipaddress.ip_address(r.ip), r.port))


@dataclass
class ApplyResult:
    backend: str
    changed: bool = False
    actions: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class Backend:
    name = "base"

    def __init__(self, cfg: Config, runner: Runner):
        self.cfg = cfg
        self.runner = runner

    def apply(self, rules: List[Rule], dry_run: bool = False) -> ApplyResult:
        raise NotImplementedError

    def purge(self, dry_run: bool = False) -> ApplyResult:
        """Remove everything this tool manages."""
        raise NotImplementedError

    def checks(self, rules: Sequence[Rule] = ()) -> List[str]:
        """Sanity warnings (e.g. port already open to the world)."""
        return []


def keys(rules: Iterable[Rule]) -> Set[Tuple[str, int]]:
    return {r.key for r in rules}
