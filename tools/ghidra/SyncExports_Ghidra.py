#@category Imperialism
# Unified export script for Imperialism decomp pipeline.
#
# Script args:
#   0: symbols_txt_path
#   1: symbols_csv_path
#   2: decomp_output_dir
#   3: types_output_dir
#   4: decomp_max_functions_per_file (optional, default 250)
#   5: expected_ghidra_version (optional, default 12.0.2)
#   6: expected_ghidra_release (optional, default PUBLIC)
#
# This script intentionally supports only Ghidra 12.0.2 PUBLIC unless
# expected version/release args are explicitly changed by the caller.

import json
import os
import re

from java.io import StringWriter
from java.util import ArrayList

from ghidra.app.decompiler import DecompInterface
from ghidra.framework import Application
from ghidra.program.model.data import (
    DataTypeWriter,
    Enum,
    FunctionDefinition,
    Structure,
    TypeDef,
    Union,
)
from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import SourceType, SymbolType

DEFAULT_EXPECTED_GHIDRA_VERSION = "12.0.2"
DEFAULT_EXPECTED_GHIDRA_RELEASE = "PUBLIC"
DEFAULT_DECOMPILER_TIMEOUT_SECONDS = 60
DEFAULT_MAX_FUNCTIONS_PER_FILE = 250


def get_arg(idx, default_value):
    args = getScriptArgs()
    if args is None:
        return default_value
    if idx >= len(args):
        return default_value
    value = args[idx]
    if value is None:
        return default_value
    value = str(value).strip()
    if value == "":
        return default_value
    return value


def enforce_ghidra_version(expected_version, expected_release):
    actual_version = Application.getApplicationVersion()
    actual_release = Application.getApplicationReleaseName()
    if actual_version != expected_version or actual_release != expected_release:
        raise RuntimeError(
            "Unsupported Ghidra runtime: {} {}. Expected {} {}.".format(
                actual_version,
                actual_release,
                expected_version,
                expected_release,
            )
        )


def has_ws(s):
    return (" " in s) or ("\t" in s) or ("\r" in s) or ("\n" in s)


def clean_line(s):
    return " ".join(s.split())


def write_bytes(path, data):
    parent = os.path.dirname(path)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent)
    with open(path, "wb") as fd:
        fd.write(data)


def normalize_relpath(relpath):
    return relpath.replace("\\", "/")


def safe_join(base_dir, relpath):
    rel = normalize_relpath(relpath)
    parts = [p for p in rel.split("/") if p]
    if rel.startswith("/") or ".." in parts:
        raise RuntimeError("Unsafe relative path: {}".format(relpath))
    return os.path.join(base_dir, *parts)


def remove_empty_dirs(root_dir):
    for cur, dirs, files in os.walk(root_dir, topdown=False):
        if cur == root_dir:
            continue
        if dirs or files:
            if os.listdir(cur):
                continue
        os.rmdir(cur)


def sanitize_path_component(name):
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", name)
    value = re.sub(r"_+", "_", value).strip("._")
    if not value:
        return "unnamed"
    return value


def load_old_files(manifest_path, key_name):
    if not os.path.isfile(manifest_path):
        return []
    try:
        with open(manifest_path, "rb") as fd:
            payload = json.loads(fd.read().decode("utf-8"))
        return list(payload.get(key_name, []))
    except Exception as exc:
        print("Warning: failed reading manifest {}: {}".format(manifest_path, exc))
        return []


def remove_old_generated_files(base_dir, old_files):
    for rel in old_files:
        try:
            full = safe_join(base_dir, rel)
        except Exception:
            continue
        if os.path.isfile(full):
            os.remove(full)


def export_user_symbols(out_path):
    symtab = currentProgram.getSymbolTable()

    rows = []
    skipped_ws = 0
    skipped_nonmem = 0
    skipped_nonuser = 0
    skipped_nonprimary = 0

    it = symtab.getAllSymbols(True)
    while it.hasNext() and not monitor.isCancelled():
        sym = it.next()
        if sym is None:
            continue
        if not sym.isPrimary():
            skipped_nonprimary += 1
            continue
        if sym.getSource() != SourceType.USER_DEFINED:
            skipped_nonuser += 1
            continue
        addr = sym.getAddress()
        if not addr.isMemoryAddress():
            skipped_nonmem += 1
            continue
        name = sym.getName(True)
        if has_ws(name):
            skipped_ws += 1
            continue
        st = sym.getSymbolType()
        kind = "f" if st == SymbolType.FUNCTION else "l"
        rows.append((addr.getOffset(), name, kind))

    rows.sort(key=lambda t: (t[0], t[2], t[1]))

    write_lines = []
    num_f = 0
    num_l = 0
    for (off, name, kind) in rows:
        if kind == "f":
            num_f += 1
        else:
            num_l += 1
        write_lines.append("{} {:X} {}".format(name, off, kind))
    write_bytes(out_path, ("\n".join(write_lines) + "\n").encode("utf-8"))

    print("User symbol export: {}".format(out_path))
    print("  rows: {} (functions {}, labels {})".format(len(rows), num_f, num_l))
    print("  skipped non-primary: {}".format(skipped_nonprimary))
    print("  skipped non-user-defined: {}".format(skipped_nonuser))
    print("  skipped non-memory: {}".format(skipped_nonmem))
    print("  skipped whitespace names: {}".format(skipped_ws))


def func_insn_bytes(listing, func):
    total = 0
    it = listing.getInstructions(func.getBody(), True)
    while it.hasNext() and not monitor.isCancelled():
        ins = it.next()
        total += ins.getLength()
    return total


def func_body_bytes(func):
    total = 0
    rng_it = func.getBody().getAddressRanges()
    while rng_it.hasNext() and not monitor.isCancelled():
        r = rng_it.next()
        total += r.getLength()
    return total


def clean_field(s):
    return " ".join(s.replace("|", " ").split())


def export_reccmp_csv(out_path):
    fm = currentProgram.getFunctionManager()
    symtab = currentProgram.getSymbolTable()
    listing = currentProgram.getListing()

    rows = ["address|name|size|type|prototype"]

    funcs = []
    itf = fm.getFunctions(True)
    while itf.hasNext() and not monitor.isCancelled():
        f = itf.next()
        sym = f.getSymbol()
        if sym is None:
            continue
        if sym.getSource() != SourceType.USER_DEFINED:
            continue
        name = f.getName(True)
        if has_ws(name):
            continue
        entry = f.getEntryPoint()
        insn = func_insn_bytes(listing, f)
        body = func_body_bytes(f)
        size = insn if insn > 0 else body
        proto = clean_field(f.getPrototypeString(True, True))
        funcs.append((entry.getOffset(), name, size, proto))

    funcs.sort(key=lambda t: t[0])
    for (addr, name, size, proto) in funcs:
        rows.append("{:x}|{}|{}|function|{}".format(addr, name, size, proto))

    sym_it = symtab.getAllSymbols(True)
    globals_ = []
    while sym_it.hasNext() and not monitor.isCancelled():
        s = sym_it.next()
        if s is None:
            continue
        if s.getSource() != SourceType.USER_DEFINED:
            continue
        if isinstance(s.getObject(), Function):
            continue
        addr = s.getAddress()
        if not addr.isMemoryAddress():
            continue
        name = s.getName(True)
        if has_ws(name):
            continue
        globals_.append((addr.getOffset(), name))
    globals_.sort(key=lambda t: t[0])
    for (addr, name) in globals_:
        rows.append("{:x}|{}||global|".format(addr, name))

    write_bytes(out_path, ("\n".join(rows) + "\n").encode("utf-8"))
    print("reccmp CSV export: {}".format(out_path))
    print("  function rows: {}".format(len(funcs)))
    print("  global rows: {}".format(len(globals_)))


def namespace_parts(namespace):
    parts = []
    ns = namespace
    while ns is not None and not ns.isGlobal():
        n = ns.getName()
        if n and n != "Global":
            parts.append(n)
        ns = ns.getParentNamespace()
    parts.reverse()
    return parts


def namespace_to_relpath(parts):
    if not parts:
        return "global.cpp"
    safe = [sanitize_path_component(p) for p in parts]
    if len(safe) == 1:
        return safe[0] + ".cpp"
    return "/".join(safe[:-1] + [safe[-1] + ".cpp"])


def relpath_with_part(relpath, part_idx):
    rel = normalize_relpath(relpath)
    parent = os.path.dirname(rel)
    name = os.path.basename(rel)
    stem = name[:-4] if name.lower().endswith(".cpp") else name
    part_name = "{}_part{:03d}.cpp".format(stem, part_idx)
    return part_name if not parent else normalize_relpath(parent + "/" + part_name)


def split_bucket(relpath, entries, max_functions_per_file):
    if max_functions_per_file <= 0 or len(entries) <= max_functions_per_file:
        return [(relpath, entries)]
    chunks = []
    idx = 1
    for off in range(0, len(entries), max_functions_per_file):
        chunk_entries = entries[off : off + max_functions_per_file]
        chunks.append((relpath_with_part(relpath, idx), chunk_entries))
        idx += 1
    return chunks


def build_decomp_file_text(module_name, program_name, relpath, entries):
    out = []
    out.append("// AUTOGENERATED FROM GHIDRA. DO NOT EDIT.\n")
    out.append("// Script: SyncExports_Ghidra.py\n")
    out.append("// Program: {}\n".format(program_name))
    out.append("// Bucket: {}\n\n".format(relpath))
    for entry in entries:
        out.append("// FUNCTION: {} 0x{:08X}\n".format(module_name, entry["address"]))
        out.append("// GHIDRA_NAME: {}\n".format(entry["name"]))
        out.append("// GHIDRA_PROTO: {}\n".format(entry["prototype"]))
        if entry["ok"]:
            out.append(entry["c"].rstrip())
            out.append("\n\n")
        else:
            out.append("/* DECOMPILATION FAILED: {} */\n\n".format(entry["error"]))
    return "".join(out)


def export_decompiled_bodies(out_dir, max_functions_per_file):
    manifest_path = os.path.join(out_dir, "_manifest.json")
    index_path = os.path.join(out_dir, "index.csv")
    old_files = load_old_files(manifest_path, "generated_cpp_files")
    remove_old_generated_files(out_dir, old_files)

    module_name = os.path.splitext(currentProgram.getName())[0].upper()
    program_name = currentProgram.getName()
    fm = currentProgram.getFunctionManager()

    decomp = DecompInterface()
    decomp.toggleCCode(True)
    decomp.toggleSyntaxTree(False)
    decomp.setSimplificationStyle("decompile")
    decomp.openProgram(currentProgram)

    bucket_map = {}
    index_rows = ["address|name|prototype|file|status"]
    count_total = 0
    count_fail = 0
    count_skipped_nonuser = 0
    count_skipped_ws = 0

    it = fm.getFunctions(True)
    while it.hasNext() and not monitor.isCancelled():
        func = it.next()
        sym = func.getSymbol()
        if sym is None:
            continue
        if sym.getSource() != SourceType.USER_DEFINED:
            count_skipped_nonuser += 1
            continue
        name = func.getName(True)
        if has_ws(name):
            count_skipped_ws += 1
            continue

        relpath = namespace_to_relpath(namespace_parts(func.getParentNamespace()))
        addr = func.getEntryPoint().getOffset()
        proto = clean_field(func.getPrototypeString(True, True))

        res = decomp.decompileFunction(func, DEFAULT_DECOMPILER_TIMEOUT_SECONDS, monitor)
        ok = False
        decomp_c = ""
        error = ""
        if res is not None and res.decompileCompleted():
            df = res.getDecompiledFunction()
            if df is not None:
                c = df.getC()
                if c is not None:
                    decomp_c = c
                    ok = True
        if not ok:
            count_fail += 1
            if res is not None:
                error = clean_field(str(res.getErrorMessage()))
            if not error:
                error = "unknown decompiler failure"

        entry = {
            "address": addr,
            "name": clean_field(name),
            "prototype": proto,
            "ok": ok,
            "c": decomp_c,
            "error": error,
        }
        bucket_map.setdefault(relpath, []).append(entry)
        count_total += 1

    generated_files = []
    for relpath in sorted(bucket_map.keys()):
        entries = bucket_map[relpath]
        entries.sort(key=lambda e: e["address"])
        split_files = split_bucket(relpath, entries, max_functions_per_file)
        for out_relpath, chunk_entries in split_files:
            text = build_decomp_file_text(module_name, program_name, out_relpath, chunk_entries)
            full_path = safe_join(out_dir, out_relpath)
            write_bytes(full_path, text.encode("utf-8"))
            generated_files.append(normalize_relpath(out_relpath))
            for entry in chunk_entries:
                status = "ok" if entry["ok"] else "failed"
                index_rows.append(
                    "{:x}|{}|{}|{}|{}".format(
                        entry["address"],
                        entry["name"],
                        entry["prototype"],
                        out_relpath,
                        status,
                    )
                )

    write_bytes(index_path, ("\n".join(index_rows) + "\n").encode("utf-8"))
    payload = {
        "generated_cpp_files": generated_files,
        "program": program_name,
        "module": module_name,
        "function_count": count_total,
        "failed_count": count_fail,
    }
    write_bytes(
        manifest_path,
        (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    remove_empty_dirs(out_dir)

    print("Decompiled body export: {}".format(out_dir))
    print("  files: {}".format(len(generated_files)))
    print("  functions: {}".format(count_total))
    print("  failures: {}".format(count_fail))
    print("  max per file: {}".format(max_functions_per_file))


def dtype_kind(dt):
    if isinstance(dt, Structure):
        return "structure"
    if isinstance(dt, Union):
        return "union"
    if isinstance(dt, Enum):
        return "enum"
    if isinstance(dt, TypeDef):
        return "typedef"
    if isinstance(dt, FunctionDefinition):
        return "function_definition"
    return "other"


def should_export_dtype(dt):
    return (
        isinstance(dt, Structure)
        or isinstance(dt, Union)
        or isinstance(dt, Enum)
        or isinstance(dt, TypeDef)
        or isinstance(dt, FunctionDefinition)
    )


def category_to_base_relpath(category_path):
    if category_path is None or category_path.isRoot():
        return "root_types.h"
    elems = [sanitize_path_component(x) for x in category_path.asList()]
    return "/".join(elems) + ".h"


def dedupe_relpath(base_relpath, used_relpaths):
    if base_relpath not in used_relpaths:
        used_relpaths.add(base_relpath)
        return base_relpath
    base_dir = os.path.dirname(base_relpath)
    name = os.path.basename(base_relpath)
    stem = name[:-2] if name.lower().endswith(".h") else name
    idx = 2
    while True:
        cand = "{}_{}.h".format(stem, idx)
        rel = cand if not base_dir else base_dir + "/" + cand
        if rel not in used_relpaths:
            used_relpaths.add(rel)
            return rel
        idx += 1


def render_header_text(program_name, category_path_text, data_types, dtm):
    arr = ArrayList()
    for dt in data_types:
        arr.add(dt)
    sw = StringWriter()
    writer = DataTypeWriter(dtm, sw, True)
    writer.write(arr, monitor)
    rendered = sw.toString()
    out = []
    out.append("// AUTOGENERATED FROM GHIDRA. DO NOT EDIT.\n")
    out.append("// Script: SyncExports_Ghidra.py\n")
    out.append("// Program: {}\n".format(program_name))
    out.append("// Category: {}\n\n".format(category_path_text))
    out.append("#pragma once\n\n")
    out.append(rendered)
    if not rendered.endswith("\n"):
        out.append("\n")
    return "".join(out)


def export_type_headers(out_dir):
    manifest_path = os.path.join(out_dir, "_manifest.json")
    index_path = os.path.join(out_dir, "index.csv")
    all_types_path = os.path.join(out_dir, "all_types.h")
    old_files = load_old_files(manifest_path, "generated_header_files")
    remove_old_generated_files(out_dir, old_files)

    dtm = currentProgram.getDataTypeManager()
    local_archive = dtm.getLocalSourceArchive()
    local_data_types = dtm.getDataTypes(local_archive)

    buckets = {}
    skipped_nonmatching = 0
    for dt in local_data_types:
        if not should_export_dtype(dt):
            skipped_nonmatching += 1
            continue
        cp = dt.getCategoryPath()
        cp_text = cp.getPath() if cp is not None else "/"
        if cp_text not in buckets:
            buckets[cp_text] = {"path_obj": cp, "types": []}
        buckets[cp_text]["types"].append(dt)

    used_relpaths = set()
    generated_files = []
    index_rows = ["category|datatype|kind|header"]
    total_types = 0

    for cp_text in sorted(buckets.keys()):
        bucket = buckets[cp_text]
        types = bucket["types"]
        types.sort(key=lambda d: d.getName().lower())
        rel_base = category_to_base_relpath(bucket["path_obj"])
        relpath = dedupe_relpath(rel_base, used_relpaths)
        try:
            text = render_header_text(currentProgram.getName(), cp_text, types, dtm)
        except Exception as exc:
            print("Skipping type category {}: {}".format(cp_text, exc))
            continue
        write_bytes(safe_join(out_dir, relpath), text.encode("utf-8"))
        generated_files.append(normalize_relpath(relpath))
        for dt in types:
            index_rows.append(
                "{}|{}|{}|{}".format(cp_text, dt.getPathName(), dtype_kind(dt), relpath)
            )
            total_types += 1

    all_types_lines = []
    all_types_lines.append("// AUTOGENERATED FROM GHIDRA. DO NOT EDIT.\n")
    all_types_lines.append("#pragma once\n\n")
    for rel in sorted(generated_files):
        all_types_lines.append('#include "{}"\n'.format(rel))
    write_bytes(all_types_path, "".join(all_types_lines).encode("utf-8"))

    write_bytes(index_path, ("\n".join(index_rows) + "\n").encode("utf-8"))
    payload = {
        "generated_header_files": sorted(generated_files + ["all_types.h"]),
        "program": currentProgram.getName(),
        "category_count": len(generated_files),
        "type_count": total_types,
    }
    write_bytes(
        manifest_path,
        (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    remove_empty_dirs(out_dir)

    print("Type header export: {}".format(out_dir))
    print("  headers: {}".format(len(generated_files)))
    print("  exported types: {}".format(total_types))
    print("  skipped non-selected types: {}".format(skipped_nonmatching))


def require_nonempty(value, name):
    if value is None or str(value).strip() == "":
        raise RuntimeError("Missing required argument: {}".format(name))
    return value


symbols_txt = require_nonempty(get_arg(0, None), "symbols_txt_path")
symbols_csv = require_nonempty(get_arg(1, None), "symbols_csv_path")
decomp_dir = require_nonempty(get_arg(2, None), "decomp_output_dir")
types_dir = require_nonempty(get_arg(3, None), "types_output_dir")
max_per_file = int(get_arg(4, str(DEFAULT_MAX_FUNCTIONS_PER_FILE)))
expected_version = get_arg(5, DEFAULT_EXPECTED_GHIDRA_VERSION)
expected_release = get_arg(6, DEFAULT_EXPECTED_GHIDRA_RELEASE)

enforce_ghidra_version(expected_version, expected_release)

export_user_symbols(symbols_txt)
export_reccmp_csv(symbols_csv)
export_decompiled_bodies(decomp_dir, max_per_file)
export_type_headers(types_dir)

print("Unified export finished.")
