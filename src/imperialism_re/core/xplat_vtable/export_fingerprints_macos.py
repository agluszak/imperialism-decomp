from __future__ import annotations

from pathlib import Path

from imperialism_re.core.csvio import write_csv_rows
from imperialism_re.core.ghidra_session import open_program_path
from imperialism_re.core.xplat_vtable.fingerprints_common import (
    collect_fingerprint_rows,
    function_class_name,
)


def run(
    project_root: Path,
    *,
    out_csv: Path,
    macos_program_path: str,
    classes_filter: set[str],
    min_constant: int,
    max_constant: int,
) -> dict[str, int]:
    with open_program_path(project_root, macos_program_path) as program:
        fm = program.getFunctionManager()
        funcs: list[object] = []
        it = fm.getFunctions(True)
        while it.hasNext():
            fn = it.next()
            cls = function_class_name(fn)
            if not cls:
                continue
            if classes_filter and cls not in classes_filter:
                continue
            funcs.append(fn)

        funcs.sort(key=lambda f: int(f.getEntryPoint().getOffset()) & 0xFFFFFFFF)
        rows = collect_fingerprint_rows(
            program,
            funcs,
            min_constant=min_constant,
            max_constant=max_constant,
            progress_label="fp_macos",
        )

    write_csv_rows(
        out_csv,
        rows,
        ["func_addr", "func_name", "class_name", "fingerprint_type", "fingerprint_value"],
    )
    print(f"[export_macos_function_fingerprints] funcs={len(funcs)} rows={len(rows)} -> {out_csv}")
    return {"function_count": len(funcs), "rows": len(rows)}

