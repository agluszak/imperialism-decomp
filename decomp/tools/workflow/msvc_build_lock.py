"""Run one command while holding this worktree's MSVC build lock."""

from __future__ import annotations

import argparse
import datetime
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    return parser


def main() -> int:
    args = _parser().parse_args()
    command = args.command
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        raise SystemExit("msvc_build_lock: missing command after --")

    lock_path = args.lock.resolve()
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+", encoding="utf-8") as lock_file:
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            lock_file.seek(0)
            holder = lock_file.read().strip()
            detail = holder if holder else "holder metadata is not yet available"
            print(
                f"MSVC build already running in this worktree ({lock_path}).\n"
                f"Lock holder: {detail}",
                file=sys.stderr,
            )
            return 73

        holder = {
            "pid": os.getpid(),
            "started_utc": datetime.datetime.now(datetime.timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "cwd": str(Path.cwd()),
            "command": command,
        }
        lock_file.seek(0)
        lock_file.truncate()
        json.dump(holder, lock_file, separators=(",", ":"))
        lock_file.write("\n")
        lock_file.flush()

        print(
            f"[msvc-build-lock] acquired {lock_path} "
            f"(pid {holder['pid']}, started {holder['started_utc']})",
            flush=True,
        )
        try:
            return subprocess.run(command, check=False).returncode
        except KeyboardInterrupt:
            return 130


if __name__ == "__main__":
    raise SystemExit(main())
