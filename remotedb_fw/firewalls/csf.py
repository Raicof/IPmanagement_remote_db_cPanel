"""ConfigServer Security & Firewall backend.

Rules go into a dedicated file (``/etc/csf/cpanel-remotedb.allow``) that is
pulled into ``csf.allow`` with a single ``Include`` line.  Each IP gets a
CSF *advanced filter* rule restricted to the database port::

    tcp|in|d=3306|s=198.51.100.7

(A bare IP in csf.allow would open *every* port to that IP, which is why the
port-restricted form is used.)  ``csf -r`` is run only when the file changed.
"""

from __future__ import annotations

import os
import re
from typing import Dict, List, Set

from ..fsutil import atomic_write, existing_mode, read_text
from .base import ApplyResult, Backend, Rule

HEADER = (
    "# Managed by cpanel-remotedb-fw - DO NOT EDIT, regenerated automatically.\n"
    "# Source: cPanel > Remote Database Access (validated, max IPs per user enforced).\n"
)


def parse_port_list(value: str) -> List[range]:
    ranges = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if ":" in part:
                low, high = part.split(":", 1)
                ranges.append(range(int(low), int(high) + 1))
            else:
                ranges.append(range(int(part), int(part) + 1))
        except ValueError:
            continue
    return ranges


def parse_csf_conf(text: str) -> Dict[str, str]:
    values = {}
    for line in text.splitlines():
        match = re.match(r'^\s*([A-Z0-9_]+)\s*=\s*"(.*)"\s*$', line)
        if match:
            values[match.group(1)] = match.group(2)
    return values


class CsfBackend(Backend):
    name = "csf"

    @property
    def include_line(self) -> str:
        return f"Include {self.cfg.csf.include_file}"

    def render(self, rules: List[Rule]) -> str:
        lines = [HEADER]
        for rule in rules:
            lines.append(f"# {rule.comment}\n")
            lines.append(f"tcp|in|d={rule.port}|s={rule.ip}\n")
        return "".join(lines)

    def _allow_text(self) -> str:
        text = read_text(self.cfg.csf.allow_file)
        if text is None:
            raise RuntimeError(f"{self.cfg.csf.allow_file} not found - is CSF installed?")
        return text

    def _has_include(self, allow_text: str) -> bool:
        target = self.cfg.csf.include_file
        for line in allow_text.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[0] == "Include" and parts[1] == target:
                return True
        return False

    def _restart(self, result: ApplyResult, dry_run: bool) -> None:
        result.actions.append(f"{self.cfg.csf.bin} -r")
        if not dry_run:
            self.runner.run([self.cfg.csf.bin, "-r"])

    def apply(self, rules: List[Rule], dry_run: bool = False) -> ApplyResult:
        result = ApplyResult(self.name, warnings=self.checks(rules))
        allow_text = self._allow_text()
        desired = self.render(rules)
        current = read_text(self.cfg.csf.include_file)
        if current != desired:
            result.actions.append(f"write {self.cfg.csf.include_file} ({len(rules)} rules)")
            if not dry_run:
                atomic_write(self.cfg.csf.include_file, desired, 0o600)
        if not self._has_include(allow_text):
            result.actions.append(f"append '{self.include_line}' to {self.cfg.csf.allow_file}")
            if not dry_run:
                suffix = "" if allow_text.endswith("\n") or not allow_text else "\n"
                mode = existing_mode(self.cfg.csf.allow_file, 0o600)
                atomic_write(
                    self.cfg.csf.allow_file,
                    f"{allow_text}{suffix}{self.include_line}\n",
                    mode,
                )
        if result.actions:
            result.changed = True
            self._restart(result, dry_run)
        return result

    def purge(self, dry_run: bool = False) -> ApplyResult:
        result = ApplyResult(self.name)
        allow_text = self._allow_text()
        if self._has_include(allow_text):
            kept = [
                line
                for line in allow_text.splitlines(True)
                if line.split() != ["Include", self.cfg.csf.include_file]
            ]
            result.actions.append(f"remove Include line from {self.cfg.csf.allow_file}")
            if not dry_run:
                mode = existing_mode(self.cfg.csf.allow_file, 0o600)
                atomic_write(self.cfg.csf.allow_file, "".join(kept), mode)
        if os.path.exists(self.cfg.csf.include_file):
            result.actions.append(f"delete {self.cfg.csf.include_file}")
            if not dry_run:
                os.unlink(self.cfg.csf.include_file)
        if result.actions:
            result.changed = True
            self._restart(result, dry_run)
        return result

    def checks(self, rules: List[Rule] = ()) -> List[str]:
        warnings = []
        conf = read_text(self.cfg.csf.conf_file)
        if conf is None:
            return warnings
        values = parse_csf_conf(conf)
        for key in ("TCP_IN", "TCP6_IN"):
            open_ranges = parse_port_list(values.get(key, ""))
            for port in self.cfg.ports:
                if any(port in r for r in open_ranges):
                    warnings.append(
                        f"port {port} is listed in {key} of csf.conf, so it is open to "
                        "everyone and the per-IP rules have no effect - remove it"
                    )
        if values.get("IPV6", "0") != "1" and any(r.version == 6 for r in rules):
            warnings.append("IPV6 is disabled in csf.conf; IPv6 rules will be ignored by CSF")
        return warnings
