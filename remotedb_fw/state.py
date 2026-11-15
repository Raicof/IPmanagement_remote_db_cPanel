"""Persistent state between cron runs (JSON, root-only, atomic writes).

* ``first_seen[user][ip]`` - when this tool first saw the IP.  Neither the
  MySQL grant table nor the cPanel API records *when* a host was added, so
  this timestamp is what defines the "stack" order for the per-user limit.
* ``active[user]`` - last known-good active IPs, reused if reading one
  account fails (so a transient API error does not cut access).
* ``reported`` - fingerprints of validation problems already written to the
  error log, so the same bad entry is logged once, not every 2 minutes.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Dict, List, Set

from .fsutil import atomic_write

log = logging.getLogger("remotedb_fw")
STATE_VERSION = 1


@dataclass
class State:
    first_seen: Dict[str, Dict[str, float]] = field(default_factory=dict)
    active: Dict[str, List[str]] = field(default_factory=dict)
    reported: Set[str] = field(default_factory=set)

    @staticmethod
    def path(state_dir: str) -> str:
        return os.path.join(state_dir, "state.json")

    @classmethod
    def load(cls, state_dir: str) -> "State":
        path = cls.path(state_dir)
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except FileNotFoundError:
            return cls()
        except (OSError, ValueError) as exc:
            log.warning("state file %s unreadable (%s); starting fresh", path, exc)
            return cls()
        if not isinstance(data, dict) or data.get("version") != STATE_VERSION:
            log.warning("state file %s has an unknown format; starting fresh", path)
            return cls()
        state = cls()
        for user, ips in (data.get("first_seen") or {}).items():
            if isinstance(ips, dict):
                state.first_seen[user] = {
                    str(ip): float(ts) for ip, ts in ips.items() if isinstance(ts, (int, float))
                }
        for user, ips in (data.get("active") or {}).items():
            if isinstance(ips, list):
                state.active[user] = [str(ip) for ip in ips]
        state.reported = {str(x) for x in data.get("reported") or []}
        return state

    def save(self, state_dir: str) -> None:
        os.makedirs(state_dir, mode=0o700, exist_ok=True)
        payload = {
            "version": STATE_VERSION,
            "first_seen": self.first_seen,
            "active": self.active,
            "reported": sorted(self.reported),
        }
        atomic_write(self.path(state_dir), json.dumps(payload, indent=2, sort_keys=True) + "\n")
