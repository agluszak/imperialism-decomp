#!/usr/bin/env python3
"""
Create arrow split-command enum used by 0x64/0x65 dispatch handlers.
"""

from __future__ import annotations

import argparse

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.datatypes import project_category_path
from imperialism_re.core.ghidra_session import open_program


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--enum-name", default="EArrowSplitCommandId")
    ap.add_argument("--left-name", default="ARROW_SPLIT_CMD_LEFT")
    ap.add_argument("--left-value", type=lambda x: int(x, 0), default=100)
    ap.add_argument("--right-name", default="ARROW_SPLIT_CMD_RIGHT")
    ap.add_argument("--right-value", type=lambda x: int(x, 0), default=101)
    ap.add_argument("--project-root", default=default_project_root())
    args = ap.parse_args()
    root = resolve_project_root(args.project_root)

    with open_program(root) as program:
        from ghidra.program.model.data import CategoryPath, DataTypeConflictHandler, EnumDataType

        dtm = program.getDataTypeManager()
        tx = program.startTransaction("Create arrow command enum")
        try:
            e = EnumDataType(CategoryPath(project_category_path()), args.enum_name, 4)
            e.add(args.left_name, int(args.left_value))
            e.add(args.right_name, int(args.right_value))
            dt = dtm.addDataType(e, DataTypeConflictHandler.REPLACE_HANDLER)
        finally:
            program.endTransaction(tx, True)

        program.save("create arrow command enum", None)
        print(f"[done] enum={dt.getPathName()}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
