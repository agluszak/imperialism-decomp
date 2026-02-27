from __future__ import annotations

import argparse
import importlib
import sys
from pathlib import Path

from imperialism_re.core.catalog import catalog_map
from imperialism_re.core.config import get_runtime_config
from imperialism_re.core.runtime import WriterLockError, writer_lock



def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="uv run impk",
        description="Imperialism RE command dispatcher",
    )
    ap.add_argument("command", nargs="?", help="Command name (see list)")
    ap.add_argument("args", nargs=argparse.REMAINDER, help="Arguments for the command")
    ap.add_argument("--list", action="store_true", help="List all maintained commands")
    return ap



def _print_list() -> None:
    for name, spec in sorted(catalog_map().items()):
        print(f"{name:45} {spec.mode:6} {spec.summary}")



def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "list":
        _print_list()
        return 0

    ap = _build_parser()
    ns = ap.parse_args(argv)

    if ns.list or not ns.command:
        _print_list()
        return 0

    commands = catalog_map()
    spec = commands.get(ns.command)
    if spec is None:
        print(f"unknown command: {ns.command}", file=sys.stderr)
        print("use `uv run impk list`", file=sys.stderr)
        return 2

    module = importlib.import_module(spec.module)
    if not hasattr(module, "main"):
        print(f"command module has no main(): {spec.module}", file=sys.stderr)
        return 2

    old_argv = sys.argv
    sys.argv = [f"{spec.name}.py", *ns.args]
    try:
        if spec.mode in {"writer", "hybrid"}:
            cfg = get_runtime_config()
            with writer_lock(Path(cfg.project_root), blocking=False):
                rc = module.main()
        else:
            rc = module.main()
    except WriterLockError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 3
    finally:
        sys.argv = old_argv

    if rc is None:
        return 0
    if isinstance(rc, int):
        return rc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
