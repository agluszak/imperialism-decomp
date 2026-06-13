#!/usr/bin/env python3
"""Compatibility wrapper for the original focused TView datatype experiment."""

from __future__ import annotations

import sys

from tools.ghidra.apply_source_datatypes import main


if __name__ == "__main__":
    if len(sys.argv) == 1:
        sys.argv.extend(["--classes", "CString,TEventHandler,TView"])
    raise SystemExit(main())
