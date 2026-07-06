#!/usr/bin/env python3
"""One front door for read-only Ghidra queries: daemon when available, one-shot else.

The `just ghidra-listing` / `just xrefs` / `just ghidra-search` / ... targets all
route through here. When the persistent daemon (tools.ghidra.daemon, started with
`just ghidra-daemon`) is listening, the query is answered over its socket in
milliseconds; otherwise this falls back to the classic one-shot path (start
pyghidra, open the project, run, close) with identical output, printing a hint
that the daemon exists.

usage: query <command> [args...]        (commands: see tools.ghidra.query_registry)
"""

from __future__ import annotations

import sys

from tools.common import ghidra_env
from tools.ghidra import daemon
from tools.ghidra.query_registry import COMMANDS, command_help, usage_line


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(f"usage: query <command> [args...]\n{usage_line()}", file=sys.stderr)
        return 2
    cmd = sys.argv[1]
    args = sys.argv[2:]
    if cmd not in COMMANDS:
        print(f"unknown command: {cmd}\n{usage_line()}", file=sys.stderr)
        return 2
    # Answer --help locally: command run() functions parse positional hex args
    # and must never see "--help" (it used to crash int(x, 16) via the daemon).
    if any(a in ("-h", "--help") for a in args):
        print(command_help(cmd))
        return 0

    resp = daemon.request(cmd, args)
    if resp is not None:
        sys.stdout.write(resp.get("output", ""))
        if not resp.get("ok", False) and not resp.get("output"):
            print("daemon error with no output", file=sys.stderr)
        return int(resp.get("rc", 0 if resp.get("ok") else 1))

    print(
        "hint: `just ghidra-daemon` keeps one JVM warm so queries answer instantly",
        file=sys.stderr,
    )
    project = ghidra_env.open_project()
    consumer = None
    program = None
    try:
        consumer, program = ghidra_env.open_program(project)
        return COMMANDS[cmd](program, args)
    finally:
        if program is not None:
            program.release(consumer)
        project.close()


if __name__ == "__main__":
    raise SystemExit(main())
