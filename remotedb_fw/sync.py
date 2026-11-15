"""One synchronisation run: collect -> validate -> build rules -> apply -> log."""

from __future__ import annotations

import errno
import fcntl
import ipaddress
import json
import logging
import os
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional

from .config import Config
from .firewalls import ApplyResult, Rule, build_rules, detect, get_backend
from .fsutil import atomic_write
from .runner import Runner
from .sources import Collected, collect, server_ips, valid_username
from .state import State
from .validation import Policy, Rejection, UserResult, evaluate_user

log = logging.getLogger("remotedb_fw")

VALIDATION_LOG = "validation-errors.log"
STATUS_FILE = "status.json"


class LockBusy(RuntimeError):
    pass


@contextmanager
def run_lock(path: str) -> Iterator[None]:
    """Non-blocking exclusive lock so overlapping cron runs never collide."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in (errno.EAGAIN, errno.EACCES):
                raise LockBusy(f"another run holds {path}") from None
            raise
        yield
    finally:
        os.close(fd)


@dataclass
class SyncReport:
    backend: Optional[str] = None
    dry_run: bool = False
    users: Dict[str, UserResult] = field(default_factory=dict)
    source_errors: Dict[str, str] = field(default_factory=dict)
    rules: List[Rule] = field(default_factory=list)
    apply: Optional[ApplyResult] = None
    warnings: List[str] = field(default_factory=list)
    new_issues: List[dict] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def rejected_count(self) -> int:
        return sum(len(u.rejected) for u in self.users.values())

    @property
    def inactive_count(self) -> int:
        return sum(len(u.inactive) for u in self.users.values())

    def as_dict(self) -> dict:
        return {
            "backend": self.backend,
            "dry_run": self.dry_run,
            "changed": bool(self.apply and self.apply.changed),
            "error": self.error,
            "warnings": list(self.warnings) + (list(self.apply.warnings) if self.apply else []),
            "source_errors": dict(self.source_errors),
            "users": {name: res.as_dict() for name, res in sorted(self.users.items())},
            "rules": [
                {"ip": r.ip, "port": r.port, "users": list(r.users)} for r in self.rules
            ],
            "actions": list(self.apply.actions) if self.apply else [],
        }


def build_policy(cfg: Config) -> Policy:
    blocked = list(cfg.blocked_ips)
    if cfg.block_server_ips:
        for ip in server_ips(cfg):
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            blocked.append(ip)
    return Policy(
        max_per_user=cfg.max_ips_per_user,
        allow_private=cfg.allow_private_ips,
        allow_ipv6=cfg.allow_ipv6,
        blocked=Policy.build_blocked(blocked),
    )


def evaluate(
    collected: Collected, policy: Policy, state: State, now: float
) -> Dict[str, UserResult]:
    results: Dict[str, UserResult] = {}
    for user in collected.users:
        if user in collected.errors:
            continue
        results[user] = evaluate_user(
            user, collected.hosts.get(user, []), policy, state.first_seen.get(user, {}), now
        )
    return results


def merge_rules(
    results: Dict[str, UserResult], collected: Collected, state: State, ports: List[int]
) -> List[Rule]:
    ip_users: Dict[str, set] = {}
    for user, res in results.items():
        for ip in res.active:
            ip_users.setdefault(ip, set()).add(user)
    # Accounts that could not be read this run keep their last known-good IPs.
    for user in collected.errors:
        if user in collected.users:
            for ip in state.active.get(user, []):
                ip_users.setdefault(ip, set()).add(user)
    return build_rules(ip_users, ports)


def _issue_records(results: Dict[str, UserResult], collected: Collected, limit: int) -> List[dict]:
    records = []
    for user, res in sorted(results.items()):
        for rej in res.rejected:
            records.append({**rej.as_dict(), "fp": rej.fingerprint()})
        for ip in res.inactive:
            records.append({
                "user": user, "host": ip, "gate": "limit",
                "reason": f"more than {limit} IPs: oldest entries are inactive, newest {limit} "
                          "are active",
                "fp": f"{user}\x00{ip}\x00limit",
            })
    for user, message in sorted(collected.errors.items()):
        if user in collected.users:
            gate = "source"  # the account could not be read this run
        elif not valid_username(user):
            gate = "username"
        else:
            gate = "intake"  # malformed host list in the intake file
        records.append({"user": user, "host": "", "gate": gate, "reason": message,
                        "fp": f"{user}\x00\x00{gate}\x00{message}"})
    return records


def write_issue_log(log_dir: str, records: List[dict], now: float) -> None:
    if not records:
        return
    os.makedirs(log_dir, mode=0o700, exist_ok=True)
    path = os.path.join(log_dir, VALIDATION_LOG)
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(now))
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as handle:
        for rec in records:
            line = {"time": stamp, **{k: v for k, v in rec.items() if k != "fp"}}
            handle.write(json.dumps(line, sort_keys=True) + "\n")


def run_sync(
    cfg: Config,
    runner: Runner,
    intake: Optional[str] = None,
    dry_run: bool = False,
    backend_name: Optional[str] = None,
    now: Optional[float] = None,
) -> SyncReport:
    now = time.time() if now is None else now
    report = SyncReport(dry_run=dry_run)
    state = State.load(cfg.state_dir)

    # 1. collect.  A total source failure aborts before touching the firewall.
    collected = collect(cfg, runner, intake)
    report.source_errors = dict(collected.errors)

    # 2. validate
    policy = build_policy(cfg)
    report.users = evaluate(collected, policy, state, now)
    report.rules = merge_rules(report.users, collected, state, cfg.ports)

    # 3. log validation issues (each distinct problem once)
    issues = _issue_records(report.users, collected, cfg.max_ips_per_user)
    current_fps = {rec["fp"] for rec in issues}
    report.new_issues = [rec for rec in issues if rec["fp"] not in state.reported]
    for rec in report.new_issues:
        log.warning("validation: user=%s host=%r gate=%s reason=%s",
                    rec["user"], rec["host"], rec["gate"], rec["reason"])

    # 4. firewall
    if not dry_run:
        os.makedirs(cfg.state_dir, mode=0o700, exist_ok=True)
    name = backend_name
    if not name:
        name, detect_warnings = detect(cfg, runner)
        report.warnings.extend(detect_warnings)
    report.backend = name
    backend = get_backend(name, cfg, runner)
    try:
        report.apply = backend.apply(report.rules, dry_run=dry_run)
    except Exception as exc:  # recorded in the report; CLI exits non-zero
        report.error = f"{name}: {exc}"
        log.error("firewall apply failed: %s", report.error)
    if report.apply:
        for action in report.apply.actions:
            log.info("%s%s", "[dry-run] " if dry_run else "", action.splitlines()[0])
    for warning in report.warnings + (report.apply.warnings if report.apply else []):
        log.warning("%s", warning)

    # 5. persist (never in dry-run)
    if not dry_run:
        write_issue_log(cfg.log_dir, report.new_issues, now)
        state.reported = current_fps
        for user, res in report.users.items():
            state.first_seen[user] = dict(res.first_seen)
            state.active[user] = list(res.active)
        for user in list(state.first_seen):
            if user not in collected.users:
                state.first_seen.pop(user, None)
                state.active.pop(user, None)
        state.save(cfg.state_dir)
        status = dict(report.as_dict(), time=now)
        os.makedirs(cfg.log_dir, mode=0o700, exist_ok=True)
        atomic_write(os.path.join(cfg.log_dir, STATUS_FILE),
                     json.dumps(status, indent=2, sort_keys=True) + "\n")

    log.info(
        "run done: backend=%s users=%d rules=%d rejected=%d inactive=%d changed=%s%s",
        report.backend, len(report.users), len(report.rules), report.rejected_count,
        report.inactive_count, bool(report.apply and report.apply.changed),
        " (dry-run)" if dry_run else "",
    )
    return report


def run_purge(cfg: Config, runner: Runner, dry_run: bool = False,
              backend_name: Optional[str] = None) -> ApplyResult:
    name = backend_name
    if not name:
        name, _ = detect(cfg, runner)
    result = get_backend(name, cfg, runner).purge(dry_run=dry_run)
    for action in result.actions:
        log.info("%spurge: %s", "[dry-run] " if dry_run else "", action.splitlines()[0])
    return result
