"""Atomic reports and explicit single-writer ownership for live sessions."""

from contextlib import contextmanager
import os
from pathlib import Path
import tempfile

from .errors import NetSentinelError


def write_report(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                         dir=path.parent, prefix=".netsentinel-", suffix=".tmp",
                                         delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(text + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


@contextmanager
def capture_lock(path: Path):
    """Exclusive sidecar lock; never remove another process's preexisting lock."""
    lock = path.with_name(path.name + ".capture.lock")
    lock.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise NetSentinelError(f"Capture ownership exists at '{lock}'. Stop its owner first; remove a stale lock only after verifying the recorded PID is no longer running.") from exc
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(str(os.getpid()))
        yield
    finally:
        lock.unlink(missing_ok=True)
