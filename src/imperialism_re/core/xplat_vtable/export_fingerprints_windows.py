from __future__ import annotations

from pathlib import Path

from imperialism_re.core.csvio import write_csv_rows
from imperialism_re.core.ghidra_session import open_program
from imperialism_re.core.wave_shared import is_unresolved_name
from imperialism_re.core.xplat_vtable.fingerprints_common import collect_fingerprint_rows


def run(
    project_root: Path,
    *,
    out_csv: Path,
    only_unresolved: bool,
    addr_min: int,
    addr_max: int,
    min_constant: int,
    max_constant: int,
) -> dict[str, int]:
    with open_program(project_root) as program:
        fm = program.getFunctionManager()
        funcs: list[object] = []
        it = fm.getFunctions(True)
        while it.hasNext():
            fn = it.next()
            addr = int(fn.getEntryPoint().getOffset()) & 0xFFFFFFFF
            if addr < addr_min or addr > addr_max:
                continue
            if only_unresolved and not is_unresolved_name(str(fn.getName())):
                continue
            funcs.append(fn)

        funcs.sort(key=lambda f: int(f.getEntryPoint().getOffset()) & 0xFFFFFFFF)
        rows = collect_fingerprint_rows(
            program,
            funcs,
            min_constant=min_constant,
            max_constant=max_constant,
            progress_label="fp_windows",
        )

    if rows:
        # Ensure class_name column exists for globals/unresolved without namespace.
        for row in rows:
            row["class_name"] = row.get("class_name", "")

    write_csv_rows(
        out_csv,
        rows,
        ["func_addr", "func_name", "class_name", "fingerprint_type", "fingerprint_value"],
    )
    print(
        f"[export_windows_function_fingerprints] funcs={len(funcs)} rows={len(rows)} -> {out_csv}"
    )
    return {"function_count": len(funcs), "rows": len(rows)}
