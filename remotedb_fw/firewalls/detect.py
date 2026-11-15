"""Detect which firewall manages this server.

Priority: CSF > firewalld > nftables > iptables.  CSF and firewalld are
front-ends that own the kernel ruleset, so when they are active they must be
used instead of talking to nftables/iptables directly.  A front-end that is
installed but *stopped* is never selected: e.g. running ``csf -r`` on a
stopped CSF would switch the whole CSF firewall on.
"""

from __future__ import annotations

import os
from typing import List, Tuple

from ..config import Config
from ..runner import Runner


class DetectionError(RuntimeError):
    pass


def service_active(runner: Runner, name: str) -> bool:
    if not runner.which("systemctl"):
        return False
    return runner.run(["systemctl", "is-active", "--quiet", name], check=False).ok


def csf_active(cfg: Config, runner: Runner) -> bool:
    if not runner.which(cfg.csf.bin) or os.path.exists(cfg.csf.disable_file):
        return False
    return service_active(runner, "csf")


def firewalld_active(cfg: Config, runner: Runner) -> bool:
    if not runner.which(cfg.firewalld.bin):
        return False
    if service_active(runner, "firewalld"):
        return True
    state = runner.run([cfg.firewalld.bin, "--state"], check=False)
    return state.ok and state.stdout.strip() == "running"


def nftables_active(cfg: Config, runner: Runner) -> bool:
    return bool(runner.which(cfg.nftables.bin)) and service_active(runner, "nftables")


def detect(cfg: Config, runner: Runner) -> Tuple[str, List[str]]:
    """Return (backend name, warnings)."""
    if cfg.firewall != "auto":
        return cfg.firewall, []
    warnings: List[str] = []
    active = [
        name
        for name, probe in (
            ("csf", csf_active),
            ("firewalld", firewalld_active),
            ("nftables", nftables_active),
        )
        if probe(cfg, runner)
    ]
    if len(active) > 1:
        warnings.append(
            f"several firewalls look active ({', '.join(active)}); using {active[0]}. "
            "Set \"firewall\" in the config to choose explicitly."
        )
    if active:
        return active[0], warnings
    if runner.which(cfg.iptables.bin_v4):
        warnings.append(
            "no active CSF/firewalld/nftables service found - falling back to iptables. "
            "Make sure the database port is otherwise closed, or the rules have no effect."
        )
        return "iptables", warnings
    raise DetectionError("no supported firewall found (csf, firewalld, nftables, iptables)")
