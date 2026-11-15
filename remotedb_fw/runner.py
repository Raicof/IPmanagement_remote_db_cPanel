"""Subprocess wrapper.  Never uses a shell; the only place commands are spawned.

Tests replace it with a fake runner, so all firewall logic can be exercised
without touching the real system.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import List, Optional, Sequence

log = logging.getLogger("remotedb_fw")

SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


class CommandError(RuntimeError):
    def __init__(self, argv: Sequence[str], returncode: int, stdout: str, stderr: str):
        detail = (stderr or stdout or "").strip().splitlines()
        tail = detail[-1] if detail else ""
        super().__init__(f"command failed ({returncode}): {' '.join(argv)}: {tail}")
        self.argv = list(argv)
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


@dataclass
class Result:
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class Runner:
    def __init__(self, timeout: int = 120):
        self.timeout = timeout
        self.env = {"PATH": SAFE_PATH, "LANG": "C", "LC_ALL": "C"}

    def which(self, binary: str) -> Optional[str]:
        if os.path.isabs(binary):
            return binary if os.access(binary, os.X_OK) else None
        return shutil.which(binary, path=SAFE_PATH)

    def run(
        self,
        argv: List[str],
        input_text: Optional[str] = None,
        check: bool = True,
        timeout: Optional[int] = None,
    ) -> Result:
        log.debug("exec: %s", " ".join(argv))
        try:
            proc = subprocess.run(
                argv,
                input=input_text,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                env=self.env,
                timeout=timeout or self.timeout,
                check=False,
            )
        except FileNotFoundError:
            result = Result(127, "", f"{argv[0]}: not found")
        except subprocess.TimeoutExpired:
            result = Result(124, "", f"{argv[0]}: timed out")
        else:
            result = Result(proc.returncode, proc.stdout or "", proc.stderr or "")
        if check and not result.ok:
            raise CommandError(argv, result.returncode, result.stdout, result.stderr)
        return result
