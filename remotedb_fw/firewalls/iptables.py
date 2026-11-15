"""iptables / ip6tables backend (works with iptables-legacy and iptables-nft).

Owns the chain ``CPREMOTEDB`` in the ``filter`` table, one rule per IP/port::

    -A CPREMOTEDB -s 198.51.100.7/32 -p tcp -m tcp --dport 3306
       -m comment --comment "cpremotedb users=alice" -j ACCEPT

and a jump at the top of ``INPUT``.  Changes are applied atomically with
``iptables-restore --noflush`` (only our chain is flushed/rebuilt) and only
when the live chain differs from the desired rules.  Like nftables, the rules
are runtime-only: after a reboot the next cron run restores them, and the
port stays closed in between (fail-closed).  This backend also works on
Ubuntu hosts using ufw, whose chains are left untouched.
"""

from __future__ import annotations

import ipaddress
import shlex
from typing import Dict, List, Optional, Set, Tuple

from .base import COMMENT_PREFIX, ApplyResult, Backend, Rule

JUMP_COMMENT = f"{COMMENT_PREFIX} jump"
LiveRule = Tuple[str, int, str]


def parse_chain_rules(lines: List[str], chain: str) -> Optional[Set[LiveRule]]:
    """Parse ``iptables -S <chain>`` output.  None if something foreign is inside."""
    found: Set[LiveRule] = set()
    for line in lines:
        try:
            tokens = shlex.split(line)
        except ValueError:
            return None
        if not tokens or tokens[:2] == ["-N", chain] or tokens[:2] == ["-P", chain]:
            continue
        if tokens[:2] != ["-A", chain]:
            continue
        opts: Dict[str, str] = {}
        i = 2
        while i < len(tokens):
            key = tokens[i]
            value = tokens[i + 1] if i + 1 < len(tokens) else ""
            if key == "-m":
                i += 2
                continue
            opts[key] = value
            i += 2
        expected = {"-s", "-p", "--dport", "--comment", "-j"}
        if set(opts) != expected or opts["-p"] != "tcp" or opts["-j"] != "ACCEPT":
            return None
        try:
            iface = ipaddress.ip_interface(opts["-s"])
            port = int(opts["--dport"])
        except ValueError:
            return None
        if iface.network.prefixlen != iface.max_prefixlen:
            return None  # a range in our chain is never ours -> rebuild
        ip = str(iface.ip)
        found.add((ip, port, opts["--comment"]))
    return found


class IptablesBackend(Backend):
    name = "iptables"

    def families(self) -> Dict[int, Tuple[str, str]]:
        fam = {4: (self.cfg.iptables.bin_v4, self.cfg.iptables.restore_v4)}
        if self.cfg.allow_ipv6:
            fam[6] = (self.cfg.iptables.bin_v6, self.cfg.iptables.restore_v6)
        return fam

    @property
    def chain(self) -> str:
        return self.cfg.iptables.chain

    @property
    def parent(self) -> str:
        return self.cfg.iptables.parent_chain

    def _list(self, binary: str, chain: str) -> Optional[List[str]]:
        result = self.runner.run([binary, "-w", "-S", chain], check=False)
        if not result.ok:
            return None
        return result.stdout.splitlines()

    def _jump_lines(self, binary: str) -> List[str]:
        lines = self._list(binary, self.parent) or []
        out = []
        for line in lines:
            try:
                tokens = shlex.split(line)
            except ValueError:
                continue
            if tokens[:2] == ["-A", self.parent] and "-j" in tokens:
                if tokens[tokens.index("-j") + 1 : tokens.index("-j") + 2] == [self.chain]:
                    out.append(line)
        return out

    def render(self, version: int, rules: List[Rule], add_jump: bool) -> str:
        host_bits = 32 if version == 4 else 128
        lines = ["*filter", f":{self.chain} - [0:0]", f"-F {self.chain}"]
        for rule in rules:
            if rule.version != version:
                continue
            lines.append(
                f"-A {self.chain} -s {rule.ip}/{host_bits} -p tcp -m tcp --dport {rule.port} "
                f'-m comment --comment "{rule.comment}" -j ACCEPT'
            )
        if add_jump:
            lines.append(
                f'-I {self.parent} 1 -m comment --comment "{JUMP_COMMENT}" -j {self.chain}'
            )
        lines.append("COMMIT")
        return "\n".join(lines) + "\n"

    def _restore(self, restore_bin: str, batch: str, result: ApplyResult, dry_run: bool) -> None:
        result.actions.append(f"{restore_bin} -w --noflush <<EOF\n{batch}EOF")
        result.changed = True
        if not dry_run:
            self.runner.run([restore_bin, "-w", "--noflush"], input_text=batch)

    def apply(self, rules: List[Rule], dry_run: bool = False) -> ApplyResult:
        result = ApplyResult(self.name)
        families = self.families()
        if 6 not in families and any(r.version == 6 for r in rules):
            result.warnings.append("IPv6 rules requested but IPv6 is disabled")
        for version, (binary, restore_bin) in families.items():
            if not self.runner.which(binary):
                if any(r.version == version for r in rules):
                    result.warnings.append(f"{binary} not found - IPv{version} rules skipped")
                continue
            chain_lines = self._list(binary, self.chain)
            live = None if chain_lines is None else parse_chain_rules(chain_lines, self.chain)
            desired = {(r.ip, r.port, r.comment) for r in rules if r.version == version}
            has_jump = bool(self._jump_lines(binary))
            if live == desired and has_jump:
                continue
            self._restore(restore_bin, self.render(version, rules, not has_jump), result, dry_run)
        return result

    def purge(self, dry_run: bool = False) -> ApplyResult:
        result = ApplyResult(self.name)
        for version, (binary, restore_bin) in self.families().items():
            if not self.runner.which(binary) or self._list(binary, self.chain) is None:
                continue
            lines = ["*filter"]
            for jump in self._jump_lines(binary):
                lines.append("-D" + jump[2:])  # "-A INPUT ..." -> "-D INPUT ..."
            lines += [f"-F {self.chain}", f"-X {self.chain}", "COMMIT"]
            self._restore(restore_bin, "\n".join(lines) + "\n", result, dry_run)
        return result
