"""nftables backend.

In nftables an ``accept`` in one base chain does NOT override a ``drop`` in
another base chain hooked at the same point - every input base chain must
accept the packet.  Creating a separate table of our own would therefore be
useless.  Instead, for every ``filter``/``input`` base chain (auto-discovered,
or the ``nftables.targets`` from config) this backend:

* owns a regular chain ``cpremotedb`` inside that same table,
* fills it with one rule per IP/port::

      ip saddr 198.51.100.7 tcp dport 3306 accept comment "cpremotedb users=alice"

* inserts ``jump cpremotedb`` at the top of the base chain.

Everything is applied as a single atomic ``nft -f`` transaction (flush +
re-add), and only when the live ruleset differs from the desired one.  The
nftables *service* is never restarted: that would reload nftables.conf and
wipe these runtime rules.  After a reboot the next cron run (<= 2 minutes)
re-creates them; until then the port stays closed (fail-closed).
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .base import COMMENT_PREFIX, ApplyResult, Backend, Rule

JUMP_COMMENT = f"{COMMENT_PREFIX} jump"
FAMILY_VERSIONS = {"ip": (4,), "ip6": (6,), "inet": (4, 6)}
LiveRule = Tuple[str, int, str]  # (ip, port, comment)


@dataclass
class Target:
    family: str
    table: str
    base_chain: str
    has_our_chain: bool = False
    has_jump: bool = False
    live: Optional[Set[LiveRule]] = field(default_factory=set)  # None = unparseable

    @property
    def label(self) -> str:
        return f"{self.family} {self.table} {self.base_chain}"


def _parse_rule_expr(exprs: list) -> Optional[Tuple[str, int]]:
    ip = None
    port = None
    accept = False
    for expr in exprs or []:
        if not isinstance(expr, dict):
            return None
        if "match" in expr:
            match = expr["match"]
            left = match.get("left", {})
            payload = left.get("payload", {}) if isinstance(left, dict) else {}
            if payload.get("field") == "saddr" and payload.get("protocol") in ("ip", "ip6"):
                ip = match.get("right")
            elif payload.get("field") == "dport" and payload.get("protocol") == "tcp":
                port = match.get("right")
            else:
                return None
        elif "accept" in expr:
            accept = True
        elif "counter" in expr:
            continue
        else:
            return None
    if not (accept and isinstance(ip, str) and isinstance(port, int)):
        return None
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        return None
    return ip, port


class NftablesBackend(Backend):
    name = "nftables"

    @property
    def chain(self) -> str:
        return self.cfg.nftables.chain

    def ruleset(self) -> list:
        out = self.runner.run([self.cfg.nftables.bin, "-j", "list", "ruleset"]).stdout
        data = json.loads(out or '{"nftables": []}')
        return [obj for obj in data.get("nftables", []) if isinstance(obj, dict)]

    # -- discovery ---------------------------------------------------------
    def discover(self, objs: list, warnings: List[str]) -> List[Target]:
        base_chains = []
        for obj in objs:
            chain = obj.get("chain")
            if not chain or chain.get("hook") != "input" or chain.get("type") != "filter":
                continue
            if chain.get("family") not in FAMILY_VERSIONS:
                continue
            base_chains.append((chain["family"], chain["table"], chain["name"]))

        if self.cfg.nftables.targets:
            wanted = [tuple(t.split()) for t in self.cfg.nftables.targets]
            for target in wanted:
                if target not in base_chains:
                    warnings.append(f"configured nftables target '{' '.join(target)}' "
                                    "is not an existing input filter chain - skipped")
            chosen = [t for t in wanted if t in base_chains]
        else:
            chosen = []
            for family, table, name in base_chains:
                if table == "firewalld":
                    warnings.append("table inet firewalld exists but firewalld is not the "
                                    "selected backend - skipped")
                    continue
                if family in ("ip", "ip6") and table == "filter" and name == "INPUT":
                    warnings.append(
                        f"{family} filter INPUT is managed by iptables-nft - skipped; "
                        "set firewall=iptables if it filters the database port"
                    )
                    continue
                chosen.append((family, table, name))

        targets = [Target(f, t, c) for f, t, c in chosen]
        by_table = {(t.family, t.table): t for t in targets}
        for obj in objs:
            if "chain" in obj:
                c = obj["chain"]
                target = by_table.get((c.get("family"), c.get("table")))
                if target and c.get("name") == self.chain:
                    target.has_our_chain = True
            elif "rule" in obj:
                r = obj["rule"]
                target = by_table.get((r.get("family"), r.get("table")))
                if not target:
                    continue
                if r.get("chain") == target.base_chain and any(
                    isinstance(e, dict) and e.get("jump", {}).get("target") == self.chain
                    for e in r.get("expr", [])
                ):
                    target.has_jump = True
                elif r.get("chain") == self.chain and target.live is not None:
                    parsed = _parse_rule_expr(r.get("expr", []))
                    if parsed is None:
                        target.live = None  # something foreign in our chain -> rebuild
                    else:
                        target.live.add((parsed[0], parsed[1], r.get("comment", "")))
        return targets

    def _stale_tables(self, objs: list, targets: List[Target]) -> List[Tuple[str, str]]:
        chosen = {(t.family, t.table) for t in targets}
        stale = []
        for obj in objs:
            c = obj.get("chain")
            if c and c.get("name") == self.chain and (c["family"], c["table"]) not in chosen:
                stale.append((c["family"], c["table"]))
        return stale

    def _removal_lines(self, objs: list, family: str, table: str) -> List[str]:
        lines = []
        for obj in objs:
            r = obj.get("rule")
            if not r or r.get("family") != family or r.get("table") != table:
                continue
            if any(isinstance(e, dict) and e.get("jump", {}).get("target") == self.chain
                   for e in r.get("expr", [])):
                lines.append(f"delete rule {family} {table} {r['chain']} handle {r['handle']}")
        lines.append(f"flush chain {family} {table} {self.chain}")
        lines.append(f"delete chain {family} {table} {self.chain}")
        return lines

    # -- apply -------------------------------------------------------------
    def render(self, target: Target, rules: List[Rule]) -> List[str]:
        fam, table = target.family, target.table
        lines = [f"add chain {fam} {table} {self.chain}", f"flush chain {fam} {table} {self.chain}"]
        for rule in rules:
            if rule.version not in FAMILY_VERSIONS[fam]:
                continue
            proto = "ip" if rule.version == 4 else "ip6"
            lines.append(
                f"add rule {fam} {table} {self.chain} {proto} saddr {rule.ip} "
                f'tcp dport {rule.port} accept comment "{rule.comment}"'
            )
        if not target.has_jump:
            lines.append(
                f'insert rule {fam} {table} {target.base_chain} jump {self.chain} '
                f'comment "{JUMP_COMMENT}"'
            )
        return lines

    def desired_live(self, target: Target, rules: List[Rule]) -> Set[LiveRule]:
        return {
            (r.ip, r.port, r.comment) for r in rules if r.version in FAMILY_VERSIONS[target.family]
        }

    def _submit(self, batch: List[str], result: ApplyResult, dry_run: bool) -> None:
        result.actions.extend(batch)
        result.changed = True
        if not dry_run:
            self.runner.run([self.cfg.nftables.bin, "-f", "-"], input_text="\n".join(batch) + "\n")

    def apply(self, rules: List[Rule], dry_run: bool = False) -> ApplyResult:
        result = ApplyResult(self.name)
        objs = self.ruleset()
        targets = self.discover(objs, result.warnings)
        if not targets:
            result.warnings.append(
                "no nftables input filter chain found: nothing filters inbound traffic, so "
                "the database port is either open to everyone or filtered by another tool"
            )
        batch: List[str] = []
        for family, table in self._stale_tables(objs, targets):
            batch.extend(self._removal_lines(objs, family, table))
        for target in targets:
            in_sync = (
                target.has_our_chain
                and target.has_jump
                and target.live == self.desired_live(target, rules)
            )
            if not in_sync:
                batch.extend(self.render(target, rules))
        if batch:
            self._submit(batch, result, dry_run)
        return result

    def purge(self, dry_run: bool = False) -> ApplyResult:
        result = ApplyResult(self.name)
        objs = self.ruleset()
        batch: List[str] = []
        for family, table in self._stale_tables(objs, []):
            batch.extend(self._removal_lines(objs, family, table))
        if batch:
            self._submit(batch, result, dry_run)
        return result
