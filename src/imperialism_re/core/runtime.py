from __future__ import annotations

import contextlib
import fcntl
import os
from pathlib import Path
from typing import Iterator

from .config import RuntimeConfig, get_runtime_config


class WriterLockError(RuntimeError):
    pass


@contextlib.contextmanager
def writer_lock(lock_root: Path | None = None, blocking: bool = False) -> Iterator[None]:
    root = (lock_root or get_runtime_config().project_root).resolve()
    lock_path = root / ".imperialism_re_writer.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fh = lock_path.open("a+", encoding="utf-8")
    try:
        op = fcntl.LOCK_EX
        if not blocking:
            op |= fcntl.LOCK_NB
        try:
            fcntl.flock(fh.fileno(), op)
        except BlockingIOError as exc:
            raise WriterLockError(
                f"writer lock is already held ({lock_path}); wait for current writer to finish"
            ) from exc
        fh.seek(0)
        fh.truncate()
        fh.write(str(os.getpid()))
        fh.flush()
        yield
    finally:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        finally:
            fh.close()



def start_pyghidra(config: RuntimeConfig) -> None:
    import pyghidra

    pyghidra.start(install_dir=config.ghidra_dir)



def open_project_with_lock_cleanup(config: RuntimeConfig):
    import pyghidra

    root = config.project_root
    try:
        return pyghidra.open_project(str(root), config.project_name, create=False)
    except Exception:
        for lock_file in (
            root / f"{config.project_name}.lock",
            root / f"{config.project_name}.lock~",
        ):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), config.project_name, create=False)
