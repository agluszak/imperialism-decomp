#!/usr/bin/env python3
"""Small deterministic GDB/MI peer used by transport tests."""

from __future__ import annotations

import re
import sys
import time


TOKEN_RE = re.compile(r"^(\d+)(.*)$")


def emit(line: str) -> None:
    print(line, flush=True)


def main() -> int:
    for raw in sys.stdin:
        match = TOKEN_RE.match(raw.rstrip("\r\n"))
        if match is None:
            continue
        token, command = match.groups()
        if command == "-emit-interleaved":
            emit('~"command output\\n"')
            emit('*stopped,reason="breakpoint-hit",bkptno="7"')
            emit(f"{token}^done")
        elif command == "-timeout":
            time.sleep(1)
            emit(f"{token}^done")
        elif command == "-exit-before-result":
            return 7
        elif command == "-gdb-exit":
            emit(f"{token}^exit")
            return 0
        else:
            emit(f"{token}^done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
