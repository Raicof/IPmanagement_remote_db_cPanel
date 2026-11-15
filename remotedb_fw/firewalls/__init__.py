"""Firewall backends."""

from __future__ import annotations

from ..config import Config
from ..runner import Runner
from .base import ApplyResult, Backend, Rule, build_rules
from .csf import CsfBackend
from .detect import DetectionError, detect
from .firewalld import FirewalldBackend
from .iptables import IptablesBackend
from .nftables import NftablesBackend

BACKENDS = {
    "csf": CsfBackend,
    "firewalld": FirewalldBackend,
    "nftables": NftablesBackend,
    "iptables": IptablesBackend,
}


def get_backend(name: str, cfg: Config, runner: Runner) -> Backend:
    try:
        return BACKENDS[name](cfg, runner)
    except KeyError:
        raise DetectionError(f"unknown firewall backend: {name}") from None


__all__ = [
    "ApplyResult", "Backend", "Rule", "build_rules", "detect", "get_backend",
    "DetectionError", "BACKENDS",
]
