"""Configuration (JSON, stdlib only) with strict validation.

Unknown keys are rejected so typos never silently fall back to defaults, and
every value that ends up inside a firewall command is checked against a
conservative pattern.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, fields, is_dataclass
from typing import Any, Dict, List, Optional

DEFAULT_CONFIG_PATH = "/etc/cpanel-remotedb-fw/config.json"

FIREWALLS = ("csf", "firewalld", "nftables", "iptables")
SOURCES = ("mysql", "cpanel_api")
_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,27}$")
_NFT_TARGET = re.compile(r"^(ip|ip6|inet) [A-Za-z0-9_.-]{1,64} [A-Za-z0-9_.-]{1,64}$")


class ConfigError(ValueError):
    pass


@dataclass
class CsfConfig:
    bin: str = "/usr/sbin/csf"
    allow_file: str = "/etc/csf/csf.allow"
    include_file: str = "/etc/csf/cpanel-remotedb.allow"
    conf_file: str = "/etc/csf/csf.conf"
    disable_file: str = "/etc/csf/csf.disable"


@dataclass
class FirewalldConfig:
    bin: str = "firewall-cmd"
    zone: Optional[str] = None  # None -> firewalld default zone
    ipset_v4: str = "cpremotedb4"
    ipset_v6: str = "cpremotedb6"


@dataclass
class NftablesConfig:
    bin: str = "nft"
    chain: str = "cpremotedb"
    # e.g. ["inet filter input"]; empty -> auto-discover every input hook chain
    targets: List[str] = field(default_factory=list)


@dataclass
class IptablesConfig:
    bin_v4: str = "iptables"
    bin_v6: str = "ip6tables"
    restore_v4: str = "iptables-restore"
    restore_v6: str = "ip6tables-restore"
    chain: str = "CPREMOTEDB"
    parent_chain: str = "INPUT"


@dataclass
class CpanelConfig:
    users_dir: str = "/var/cpanel/users"
    suspended_dir: str = "/var/cpanel/suspended"
    mainip_file: str = "/var/cpanel/mainip"
    ips_file: str = "/etc/ips"
    mysql_bin: str = "mysql"
    mysql_defaults_file: str = "/root/.my.cnf"
    cpapi2_bin: str = "/usr/local/cpanel/bin/cpapi2"


@dataclass
class Config:
    firewall: str = "auto"
    source: str = "mysql"
    ports: List[int] = field(default_factory=lambda: [3306])
    max_ips_per_user: int = 5
    allow_private_ips: bool = True
    allow_ipv6: bool = True
    skip_suspended: bool = True
    block_server_ips: bool = True
    blocked_ips: List[str] = field(default_factory=list)
    state_dir: str = "/var/lib/cpanel-remotedb-fw"
    log_dir: str = "/var/log/cpanel-remotedb-fw"
    lock_file: str = "/run/cpanel-remotedb-fw.lock"
    command_timeout: int = 120
    csf: CsfConfig = field(default_factory=CsfConfig)
    firewalld: FirewalldConfig = field(default_factory=FirewalldConfig)
    nftables: NftablesConfig = field(default_factory=NftablesConfig)
    iptables: IptablesConfig = field(default_factory=IptablesConfig)
    cpanel: CpanelConfig = field(default_factory=CpanelConfig)

    def validate(self) -> "Config":
        if self.firewall not in ("auto",) + FIREWALLS:
            raise ConfigError(f"firewall must be auto or one of {', '.join(FIREWALLS)}")
        if self.source not in SOURCES:
            raise ConfigError(f"source must be one of {', '.join(SOURCES)}")
        if not self.ports:
            raise ConfigError("ports must not be empty")
        for port in self.ports:
            if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
                raise ConfigError(f"invalid port: {port!r}")
        if isinstance(self.max_ips_per_user, bool) or not isinstance(self.max_ips_per_user, int):
            raise ConfigError("max_ips_per_user must be an integer")
        if not 1 <= self.max_ips_per_user <= 100:
            raise ConfigError("max_ips_per_user must be between 1 and 100")
        if not isinstance(self.command_timeout, int) or self.command_timeout < 5:
            raise ConfigError("command_timeout must be an integer >= 5")
        for name in (
            self.firewalld.ipset_v4,
            self.firewalld.ipset_v6,
            self.nftables.chain,
            self.iptables.chain,
            self.iptables.parent_chain,
        ):
            if not _NAME.match(name):
                raise ConfigError(f"unsafe firewall object name: {name!r}")
        if self.firewalld.zone is not None and not _NAME.match(self.firewalld.zone):
            raise ConfigError(f"unsafe firewalld zone: {self.firewalld.zone!r}")
        for target in self.nftables.targets:
            if not _NFT_TARGET.match(target):
                raise ConfigError(
                    f"nftables target must look like 'inet filter input', got {target!r}"
                )
        # Import lazily to avoid a cycle; just make sure the list parses.
        from .validation import Policy

        try:
            Policy.build_blocked(self.blocked_ips)
        except ValueError as exc:
            raise ConfigError(f"invalid blocked_ips entry: {exc}") from None
        return self


def _merge(obj: Any, data: Dict[str, Any], path: str) -> None:
    if not isinstance(data, dict):
        raise ConfigError(f"{path or 'config'} must be a JSON object")
    known = {f.name: f for f in fields(obj)}
    for key, value in data.items():
        if key.startswith("_"):  # allow "_comment" style keys
            continue
        if key not in known:
            raise ConfigError(f"unknown config key: {path}{key}")
        current = getattr(obj, key)
        if is_dataclass(current):
            _merge(current, value, f"{path}{key}.")
        else:
            setattr(obj, key, value)


def load_config(path: Optional[str] = None, overrides: Optional[Dict[str, Any]] = None) -> Config:
    cfg = Config()
    if path:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except FileNotFoundError:
            if path != DEFAULT_CONFIG_PATH:
                raise ConfigError(f"config file not found: {path}") from None
            data = {}
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigError(f"cannot read config {path}: {exc}") from None
        _merge(cfg, data, "")
    if overrides:
        _merge(cfg, overrides, "")
    return cfg.validate()
