"""Where the per-user remote-database host lists come from.

* ``mysql``      (default) - one query against ``mysql.user``.  When a cPanel
  user adds a host under *Remote Database Access*, cPanel creates a grant for
  ``'<cpuser>'@'<host>'``; this is the exact data MySQL enforces.  One query
  for the whole server keeps the 2-minute cron cheap even with many accounts.
* ``cpanel_api`` - ``cpapi2 --user=<u> MysqlFE listhosts`` per account.  Uses
  the official cPanel API but spawns one process per account (slower).
* ``intake``     - a JSON file (testing, dry runs, migrations)::

      {"users": {"alice": ["198.51.100.7", "203.0.113.9"], "bob": []}}
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .config import Config
from .runner import CommandError, Runner

log = logging.getLogger("remotedb_fw")

USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,31}$")
RESERVED_USERS = frozenset({"root", "system", "nobody", "cpanel", "mysql"})


class SourceError(RuntimeError):
    pass


@dataclass
class Collected:
    users: List[str] = field(default_factory=list)
    hosts: Dict[str, List[object]] = field(default_factory=dict)
    errors: Dict[str, str] = field(default_factory=dict)  # user -> error message


def valid_username(name: str) -> bool:
    return bool(USERNAME_RE.match(name)) and name not in RESERVED_USERS


def list_cpanel_users(cfg: Config) -> List[str]:
    users_dir = cfg.cpanel.users_dir
    try:
        names = os.listdir(users_dir)
    except OSError as exc:
        raise SourceError(f"cannot list cPanel users in {users_dir}: {exc}") from None
    users = []
    for name in sorted(names):
        if not valid_username(name):
            continue
        if not os.path.isfile(os.path.join(users_dir, name)):
            continue
        if cfg.skip_suspended and os.path.exists(os.path.join(cfg.cpanel.suspended_dir, name)):
            log.debug("skipping suspended account %s", name)
            continue
        users.append(name)
    return users


def collect_mysql(cfg: Config, runner: Runner, users: List[str]) -> Collected:
    argv = [cfg.cpanel.mysql_bin]
    if cfg.cpanel.mysql_defaults_file:
        argv.append(f"--defaults-file={cfg.cpanel.mysql_defaults_file}")
    argv += ["--batch", "--skip-column-names", "-e", "SELECT User, Host FROM mysql.user"]
    try:
        result = runner.run(argv)
    except CommandError as exc:
        raise SourceError(f"cannot read MySQL grants: {exc}") from None
    wanted = set(users)
    out = Collected(users=list(users), hosts={u: [] for u in users})
    for line in result.stdout.splitlines():
        if "\t" not in line:
            continue
        user, host = line.split("\t", 1)
        if user in wanted:
            out.hosts[user].append(host)
    return out


def parse_listhosts(payload: str) -> List[object]:
    """Parse ``cpapi2 --output=json MysqlFE listhosts`` output."""
    try:
        data = json.loads(payload)
    except ValueError:
        raise SourceError("cpapi2 returned invalid JSON") from None
    result = data.get("cpanelresult") if isinstance(data, dict) else None
    if not isinstance(result, dict):
        raise SourceError("cpapi2 response has no cpanelresult")
    if result.get("error"):
        raise SourceError(f"cpapi2 error: {result.get('error')}")
    rows = result.get("data") or []
    if not isinstance(rows, list):
        raise SourceError("cpapi2 data is not a list")
    hosts: List[object] = []
    for row in rows:
        if isinstance(row, dict) and "host" in row:
            hosts.append(row["host"])
    return hosts


def collect_cpanel_api(cfg: Config, runner: Runner, users: List[str]) -> Collected:
    out = Collected(users=list(users))
    for user in users:
        argv = [cfg.cpanel.cpapi2_bin, f"--user={user}", "--output=json", "MysqlFE", "listhosts"]
        try:
            out.hosts[user] = parse_listhosts(runner.run(argv).stdout)
        except (CommandError, SourceError) as exc:
            out.errors[user] = str(exc)
    return out


def load_intake(path: str) -> Collected:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as exc:
        raise SourceError(f"cannot read intake {path}: {exc}") from None
    users = data.get("users") if isinstance(data, dict) else None
    if not isinstance(users, dict):
        raise SourceError('intake must be a JSON object like {"users": {"name": ["ip", ...]}}')
    out = Collected()
    for user in sorted(users):
        hosts = users[user]
        if not valid_username(user):
            out.errors[user] = "invalid cPanel username"
            continue
        if not isinstance(hosts, list):
            out.errors[user] = "host list must be a JSON array"
            continue
        out.users.append(user)
        out.hosts[user] = list(hosts)
    return out


def collect(cfg: Config, runner: Runner, intake: Optional[str] = None) -> Collected:
    if intake:
        return load_intake(intake)
    users = list_cpanel_users(cfg)
    if cfg.source == "cpanel_api":
        return collect_cpanel_api(cfg, runner, users)
    return collect_mysql(cfg, runner, users)


def server_ips(cfg: Config) -> List[str]:
    """The server's own addresses (never valid as a *remote* host)."""
    found: List[str] = []
    for path in (cfg.cpanel.mainip_file, cfg.cpanel.ips_file):
        try:
            with open(path, "r", encoding="utf-8") as handle:
                text = handle.read()
        except OSError:
            continue
        # /var/cpanel/mainip: "1.2.3.4"; /etc/ips: "1.2.3.5:255.255.255.0:1.2.3.255"
        for line in text.splitlines():
            candidate = line.strip().split(":", 1)[0] if line.count(":") == 2 else line.strip()
            if candidate:
                found.append(candidate)
    return found
