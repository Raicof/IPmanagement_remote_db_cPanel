"""Command line interface.

    cpanel-remotedb-fw sync                 # what cron runs every 2 minutes
    cpanel-remotedb-fw sync --dry-run -v    # show what would change
    cpanel-remotedb-fw validate --intake ips.json
    cpanel-remotedb-fw detect
    cpanel-remotedb-fw status
    cpanel-remotedb-fw purge [--dry-run]    # remove everything this tool added

Exit codes: 0 ok, 1 runtime/firewall error, 2 usage/config error,
3 (validate only) at least one entry was rejected or made inactive.
"""

from __future__ import annotations

import argparse
from contextlib import nullcontext
import json
import logging
import logging.handlers
import os
import sys
import time
from typing import List, Optional

from . import __version__
from .config import DEFAULT_CONFIG_PATH, FIREWALLS, ConfigError, load_config
from .firewalls import DetectionError, detect
from .runner import Runner
from .sources import SourceError, collect
from .state import State
from .sync import STATUS_FILE, LockBusy, build_policy, evaluate, run_lock, run_purge, run_sync

log = logging.getLogger("remotedb_fw")


def setup_logging(log_dir: Optional[str], verbose: bool) -> None:
    """Console: fatal errors only (cron mails stderr), everything with -v.
    Log file: every action, warning and validation problem."""
    log.setLevel(logging.DEBUG)
    log.handlers[:] = []
    log.propagate = False
    console = logging.StreamHandler(sys.stderr)
    console.setLevel(logging.DEBUG if verbose else logging.ERROR)
    console.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    log.addHandler(console)
    if log_dir:
        os.makedirs(log_dir, mode=0o700, exist_ok=True)
        handler = logging.handlers.WatchedFileHandler(os.path.join(log_dir, "sync.log"))
        handler.setLevel(logging.DEBUG if verbose else logging.INFO)
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        log.addHandler(handler)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cpanel-remotedb-fw",
        description="Sync cPanel Remote Database Access hosts into the server firewall.",
    )
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH, help="JSON config file")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="log everything to the console (default: fatal errors only)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    p_sync = sub.add_parser("sync", help="collect, validate and apply firewall rules")
    p_sync.add_argument("--intake", help="read hosts from a JSON file instead of cPanel")
    p_sync.add_argument("--dry-run", action="store_true", help="show changes, apply nothing")
    p_sync.add_argument("--firewall", choices=FIREWALLS, help="override firewall detection")
    p_sync.add_argument("--json", action="store_true", help="print the run report as JSON")

    p_val = sub.add_parser("validate", help="only run the validation gates and print a report")
    p_val.add_argument("--intake", help="read hosts from a JSON file instead of cPanel")

    sub.add_parser("detect", help="print the detected firewall")
    sub.add_parser("status", help="print the status of the last run")

    p_purge = sub.add_parser("purge", help="remove every rule this tool manages")
    p_purge.add_argument("--dry-run", action="store_true")
    p_purge.add_argument("--firewall", choices=FIREWALLS)
    return parser


def _print_validation(results, errors) -> int:
    problems = 0
    for user in sorted(results):
        res = results[user]
        print(f"{user}:")
        if not (res.active or res.inactive or res.rejected):
            print("  (no remote hosts)")
        for ip in res.active:
            print(f"  active    {ip}")
        for ip in res.inactive:
            problems += 1
            print(f"  INACTIVE  {ip}  (over the per-user limit; older entry)")
        for rej in res.rejected:
            problems += 1
            print(f"  REJECTED  {rej.raw!r}  [{rej.gate}] {rej.reason}")
    for user, message in sorted(errors.items()):
        problems += 1
        print(f"{user}: ERROR {message}")
    return problems


def _require_root(what: str) -> None:
    if os.geteuid() != 0:
        raise PermissionError(f"{what} must run as root (use --dry-run to preview)")


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    command = args.command or "sync"
    for attr, default in (("intake", None), ("dry_run", False), ("firewall", None),
                          ("json", False)):
        if not hasattr(args, attr):
            setattr(args, attr, default)

    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2

    writes = command in ("sync", "purge") and not args.dry_run
    setup_logging(cfg.log_dir if writes else None, args.verbose)
    runner = Runner(timeout=cfg.command_timeout)

    try:
        if command == "detect":
            name, warnings = detect(cfg, runner)
            for warning in warnings:
                print(f"warning: {warning}", file=sys.stderr)
            print(name)
            return 0

        if command == "status":
            path = os.path.join(cfg.log_dir, STATUS_FILE)
            with open(path, "r", encoding="utf-8") as handle:
                print(handle.read(), end="")
            return 0

        if command == "validate":
            collected = collect(cfg, runner, args.intake)
            state = State.load(cfg.state_dir)
            results = evaluate(collected, build_policy(cfg), state, time.time())
            return 3 if _print_validation(results, collected.errors) else 0

        if writes:
            _require_root(command)
            lock = run_lock(cfg.lock_file)
        else:
            lock = nullcontext()

        with lock:
            if command == "purge":
                result = run_purge(cfg, runner, args.dry_run, args.firewall)
                for action in result.actions:
                    print(action)
                if not result.actions:
                    print("nothing to remove")
                return 0

            report = run_sync(cfg, runner, intake=args.intake, dry_run=args.dry_run,
                              backend_name=args.firewall)
            if args.json:
                print(json.dumps(report.as_dict(), indent=2, sort_keys=True))
            elif args.dry_run or args.verbose:
                _print_validation(report.users, report.source_errors)
                warnings = report.warnings + (report.apply.warnings if report.apply else [])
                for warning in warnings:
                    print(f"WARNING: {warning}")
                print(f"\nfirewall: {report.backend}")
                actions = report.apply.actions if report.apply else []
                print("\n".join(actions) if actions else "no firewall changes needed")
            if report.error:
                print(f"error: {report.error}", file=sys.stderr)
                return 1
            return 0
    except LockBusy as exc:
        log.info("skipped: %s", exc)
        return 0
    except (SourceError, DetectionError, PermissionError, OSError) as exc:
        log.error("%s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
