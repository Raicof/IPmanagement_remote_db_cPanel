"""Small filesystem helpers: atomic writes with explicit permissions."""

from __future__ import annotations

import os
import tempfile
from typing import Optional


def read_text(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()
    except FileNotFoundError:
        return None


def atomic_write(path: str, content: str, mode: int = 0o600) -> None:
    """Write ``content`` to ``path`` atomically (tmp file + rename).

    Refuses to write through a symlink so a planted link can never redirect
    a root-owned write.
    """
    directory = os.path.dirname(os.path.abspath(path)) or "."
    if os.path.islink(path):
        raise OSError(f"refusing to write through symlink: {path}")
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def existing_mode(path: str, default: int) -> int:
    try:
        return os.stat(path).st_mode & 0o7777
    except OSError:
        return default
