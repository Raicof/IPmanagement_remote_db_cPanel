"""firewalld backend.

firewalld rich rules cannot carry a comment, so per-IP rich rules could not
be told apart from rules an admin added by hand.  Instead this backend owns
two ipsets (``cpremotedb4`` / ``cpremotedb6``); every allowed IP is one entry,
and one rich rule per port and family references the set::

    rule family="ipv4" source ipset="cpremotedb4" port port="3306" protocol="tcp" accept

Entry changes are applied to the permanent *and* runtime configuration, so
no reload is needed for routine changes (a reload would discard runtime-only
rules other tools such as fail2ban may have added).  ``firewall-cmd --reload``
is only used when the ipsets / rich rules themselves had to be created or
changed.
"""

from __future__ import annotations

import os
import re
import tempfile
from typing import Dict, List, Optional, Set, Tuple

from ..runner import CommandError
from .base import ApplyResult, Backend, Rule

_ATTR = re.compile(r'(\w+)="([^"]*)"')

RichKey = Tuple[str, str, int]  # (family, ipset, port)


def parse_rich(line: str) -> Optional[RichKey]:
    """Semantic key of a rich rule we may own, tolerant to formatting."""
    attrs = _ATTR.findall(line)
    values: Dict[str, str] = {}
    for key, value in attrs:
        values.setdefault(key, value)
    words = line.replace('"', " ").split()
    if not words or words[0] != "rule" or words[-1] != "accept":
        return None
    if values.get("protocol") != "tcp" or "ipset" not in values:
        return None
    try:
        port = int(values.get("port", ""))
    except ValueError:
        return None
    return (values.get("family", ""), values["ipset"], port)


class FirewalldBackend(Backend):
    name = "firewalld"

    # -- helpers ---------------------------------------------------------
    def _cmd(self, *args: str, permanent: bool = False) -> List[str]:
        argv = [self.cfg.firewalld.bin]
        if permanent:
            argv.append("--permanent")
        argv.extend(args)
        return argv

    def _run(self, *args: str, permanent: bool = False, check: bool = True):
        return self.runner.run(self._cmd(*args, permanent=permanent), check=check)

    def zone(self) -> str:
        if self.cfg.firewalld.zone:
            return self.cfg.firewalld.zone
        return self._run("--get-default-zone").stdout.strip()

    def ipsets(self) -> Dict[int, str]:
        sets = {4: self.cfg.firewalld.ipset_v4}
        if self.cfg.allow_ipv6:
            sets[6] = self.cfg.firewalld.ipset_v6
        return sets

    def rich_key(self, version: int, port: int) -> RichKey:
        family = "ipv4" if version == 4 else "ipv6"
        return (family, self.ipsets()[version], port)

    @staticmethod
    def rich_rule(family: str, ipset: str, port: int) -> str:
        return (
            f'rule family="{family}" source ipset="{ipset}" '
            f'port port="{port}" protocol="tcp" accept'
        )

    def _list(self, *args: str, permanent: bool) -> Optional[List[str]]:
        result = self._run(*args, permanent=permanent, check=False)
        if not result.ok:
            return None
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]

    def _existing_ipsets(self, permanent: bool) -> Set[str]:
        out = self._list("--get-ipsets", permanent=permanent) or []
        return set(" ".join(out).split())

    def _our_rich_rules(self, zone: str, permanent: bool) -> Dict[str, Optional[RichKey]]:
        """raw rich rule -> semantic key (None if it references our ipset oddly)."""
        ours = {self.cfg.firewalld.ipset_v4, self.cfg.firewalld.ipset_v6}
        found: Dict[str, Optional[RichKey]] = {}
        for line in self._list(f"--zone={zone}", "--list-rich-rules", permanent=permanent) or []:
            if not any(f'ipset="{name}"' in line for name in ours):
                continue
            found[line] = parse_rich(line)
        return found

    def _entries(self, ipset: str, permanent: bool) -> Optional[Set[str]]:
        out = self._list(f"--ipset={ipset}", "--get-entries", permanent=permanent)
        return None if out is None else set(out)

    def _bulk(self, ipset: str, op: str, ips: Set[str], permanent: bool,
              result: ApplyResult, dry_run: bool) -> None:
        if not ips:
            return
        where = "permanent" if permanent else "runtime"
        result.actions.append(f"{where}: {op} {len(ips)} entries {ipset}: {' '.join(sorted(ips))}")
        if dry_run:
            return
        fd, path = tempfile.mkstemp(prefix="cpremotedb-", suffix=".txt", dir=self.cfg.state_dir)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write("\n".join(sorted(ips)) + "\n")
            self._run(f"--ipset={ipset}", f"--{op}-entries-from-file={path}", permanent=permanent)
        finally:
            os.unlink(path)

    # -- main entry points -------------------------------------------------
    def apply(self, rules: List[Rule], dry_run: bool = False) -> ApplyResult:
        result = ApplyResult(self.name)
        zone = self.zone()
        result.warnings.extend(self.checks(rules, zone))
        sets = self.ipsets()
        wanted: Dict[int, Set[str]] = {v: set() for v in sets}
        for rule in rules:
            if rule.version in wanted:
                wanted[rule.version].add(rule.ip)
        wanted_rich = {self.rich_key(v, p) for v in sets for p in self.cfg.ports}

        # 1. structure (permanent): ipsets + rich rules
        structural = False
        existing = self._existing_ipsets(permanent=True)
        for version, ipset in sets.items():
            if ipset not in existing:
                structural = True
                family = "inet" if version == 4 else "inet6"
                result.actions.append(f"permanent: create ipset {ipset} (hash:ip, {family})")
                if not dry_run:
                    self._run(f"--new-ipset={ipset}", "--type=hash:ip",
                              f"--option=family={family}", permanent=True)
        current_rich = self._our_rich_rules(zone, permanent=True)
        for key in sorted(wanted_rich - set(current_rich.values())):
            structural = True
            rich = self.rich_rule(*key)
            result.actions.append(f"permanent: zone {zone} add rich rule: {rich}")
            if not dry_run:
                self._run(f"--zone={zone}", f"--add-rich-rule={rich}", permanent=True)
        for rich, key in sorted(current_rich.items()):
            if key in wanted_rich:
                continue
            structural = True
            result.actions.append(f"permanent: zone {zone} remove rich rule: {rich}")
            if not dry_run:
                self._run(f"--zone={zone}", f"--remove-rich-rule={rich}", permanent=True)

        # 2. entries (permanent)
        for version, ipset in sets.items():
            have = self._entries(ipset, permanent=True) if ipset in existing else set()
            have = have or set()
            self._bulk(ipset, "add", wanted[version] - have, True, result, dry_run)
            self._bulk(ipset, "remove", have - wanted[version], True, result, dry_run)

        # 3. runtime: if the runtime structure is out of sync, reload once;
        #    otherwise patch runtime entries directly (no reload).
        runtime_sets = self._existing_ipsets(permanent=False)
        runtime_rich = self._our_rich_rules(zone, permanent=False)
        runtime_ok = (
            set(sets.values()) <= runtime_sets
            and set(runtime_rich.values()) == wanted_rich
        )
        if structural or not runtime_ok:
            result.actions.append("firewall-cmd --reload")
            if not dry_run:
                self._run("--reload")
        else:
            for version, ipset in sets.items():
                have = self._entries(ipset, permanent=False) or set()
                self._bulk(ipset, "add", wanted[version] - have, False, result, dry_run)
                self._bulk(ipset, "remove", have - wanted[version], False, result, dry_run)

        result.changed = bool(result.actions)
        return result

    def purge(self, dry_run: bool = False) -> ApplyResult:
        result = ApplyResult(self.name)
        zone = self.zone()
        for rich in sorted(self._our_rich_rules(zone, permanent=True)):
            result.actions.append(f"permanent: zone {zone} remove rich rule: {rich}")
            if not dry_run:
                self._run(f"--zone={zone}", f"--remove-rich-rule={rich}", permanent=True)
        existing = self._existing_ipsets(permanent=True)
        for ipset in (self.cfg.firewalld.ipset_v4, self.cfg.firewalld.ipset_v6):
            if ipset in existing:
                result.actions.append(f"permanent: delete ipset {ipset}")
                if not dry_run:
                    self._run(f"--delete-ipset={ipset}", permanent=True)
        if result.actions:
            result.actions.append("firewall-cmd --reload")
            if not dry_run:
                self._run("--reload")
        result.changed = bool(result.actions)
        return result

    def checks(self, rules: List[Rule] = (), zone: Optional[str] = None) -> List[str]:
        warnings = []
        zone = zone or self.zone()
        try:
            ports = self._list(f"--zone={zone}", "--list-ports", permanent=True) or []
            services = self._list(f"--zone={zone}", "--list-services", permanent=True) or []
        except CommandError:
            return warnings
        open_ports = " ".join(ports).split()
        open_services = " ".join(services).split()
        for port in self.cfg.ports:
            if f"{port}/tcp" in open_ports:
                warnings.append(
                    f"port {port}/tcp is open to everyone in firewalld zone {zone}; "
                    "the per-IP rules have no effect - remove it"
                )
        if 3306 in self.cfg.ports and ("mysql" in open_services or "mariadb" in open_services):
            warnings.append(
                f"the mysql service is open to everyone in firewalld zone {zone}; "
                "the per-IP rules have no effect - remove it"
            )
        return warnings
