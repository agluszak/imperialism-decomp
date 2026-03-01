#!/usr/bin/env python3
"""
Comprehensive quality-control health pass.

Runs all sanity checks in a single Ghidra session and prints a structured
summary.  Exits with code 1 if any critical gate fails.

Checks performed:
  1. Class assignment progress  (thiscall attributed vs Global)
  2. Strict super-lane gate      (named fn calling only generic callees)
  3. Stale thunk names           (thunk_Foo where JMP target is no longer Foo)
  4. Stale wrapper names         (WrapperFor_Foo_At<addr> where target renamed)
  5. FID_conflict leftovers      (names still prefixed FID_conflict:)
  6. Duplicate names per class   (potential junk-drawer signals)
  7. Unknown calling conventions (should always be 0)

Usage:
  uv run impk run_qc_pass [--project-root <path>]
  uv run impk run_qc_pass --out-csv tmp_decomp/qc_report.csv
"""

from __future__ import annotations

import argparse
import csv
import re
from collections import Counter, defaultdict
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program

_WRAPPER_RE = re.compile(r"^WrapperFor_(.+)_At([0-9a-fA-F]{8})$")
_THUNK_AT_RE = re.compile(r"_At[0-9a-fA-F]{8}$")

GENERIC_PREFIXES = (
    "FUN_", "thunk_FUN_", "Cluster_", "DAT_", "PTR_",
    "OrphanVtableAssignStub_", "OrphanRetStub_",
    "OrphanLeaf_", "OrphanCallChain_",
    "NoOpPaddingStub_", "WrapperFor_FreeHeapBufferIfNotNull_At",
    "WrapperFor_ftol_At",
    "thunk_ForwardStructuredExceptionDispatchThroughFrameInfo_At",
    "thunk_scalar_deleting_destructor_",
    "thunk_OrphanCallChain_", "thunk_OrphanLeaf_", "thunk_OrphanRetStub_",
    "thunk_OrphanVtableAssignStub_",
    "thunk_WrapperFor_FreeHeapBufferIfNotNull_At",
    "thunk_WrapperFor_ftol_At",
    "FID_conflict:",
)


def _is_generic(name: str) -> bool:
    for p in GENERIC_PREFIXES:
        if name.startswith(p):
            return True
    return False


def _has_indirect_call(fn, listing):
    """Return True if fn body contains any CALL instruction with no resolved target.

    Indirect calls (through vtable pointers, function-pointer variables) don't
    produce a reference in Ghidra's reference manager.  If present they indicate
    real semantic callees beyond what getCalledFunctions() can see.
    """
    body = fn.getBody()
    if body is None:
        return False
    ins_iter = listing.getInstructions(body, True)
    while ins_iter.hasNext():
        ins = ins_iter.next()
        mnem = str(ins.getMnemonicString()).upper()
        if mnem != "CALL":
            continue
        refs = ins.getReferencesFrom()
        has_resolved = any(
            not ref.getToAddress().isExternalAddress() for ref in refs
        )
        if not has_resolved:
            return True  # unresolved CALL = indirect dispatch
    return False


def _detect_single_forward_target(fn, fm, listing):
    """Return the single forward JMP/CALL target of fn, or None."""
    body = fn.getBody()
    if body is None:
        return None
    ins_iter = listing.getInstructions(body, True)
    ins = []
    while ins_iter.hasNext():
        ins.append(ins_iter.next())
        if len(ins) > 3:
            break

    mnemonic0 = str(ins[0].getMnemonicString()).upper() if ins else ""

    if len(ins) == 1 and mnemonic0 == "JMP":
        flows = ins[0].getFlows()
        if flows and len(flows) == 1:
            tgt = fm.getFunctionAt(flows[0])
            if tgt is not None and not tgt.getEntryPoint().isExternalAddress():
                return tgt

    if len(ins) == 2 and mnemonic0 == "CALL":
        if str(ins[1].getMnemonicString()).upper() == "RET":
            refs = ins[0].getReferencesFrom()
            for ref in refs:
                callee = fm.getFunctionAt(ref.getToAddress())
                if callee is not None and not callee.getEntryPoint().isExternalAddress():
                    return callee

    return None


def main() -> int:
    ap = argparse.ArgumentParser(description="Comprehensive QC health pass.")
    ap.add_argument("--project-root", default=default_project_root())
    ap.add_argument("--out-csv", default="", help="Optional path for machine-readable issues CSV")
    ap.add_argument("--min-address", default="0x00400000")
    ap.add_argument("--max-address", default="0x00700000")
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)
    min_addr = int(args.min_address, 16)
    max_addr = int(args.max_address, 16)

    issues: list[dict[str, str]] = []

    with open_program(root) as program:
        fm = program.getFunctionManager()
        listing = program.getListing()
        global_ns = program.getGlobalNamespace()

        # ---- Collect all functions ------------------------------------------------
        all_fns = []
        fit = fm.getFunctions(True)
        while fit.hasNext():
            all_fns.append(fit.next())

        # ---- Check 1: Class assignment progress ----------------------------------
        total_thiscall = 0
        attributed_thiscall = 0
        global_thiscall = 0

        for fn in all_fns:
            ep = int(str(fn.getEntryPoint()), 16)
            if ep < min_addr or ep >= max_addr:
                continue
            cc = str(fn.getCallingConventionName())
            if cc != "__thiscall":
                continue
            total_thiscall += 1
            ns = fn.getParentNamespace()
            ns_name = "" if ns is None or ns == global_ns else ns.getName()
            if ns_name and ns_name != "Global":
                attributed_thiscall += 1
            else:
                global_thiscall += 1

        pct = attributed_thiscall / total_thiscall * 100 if total_thiscall else 0.0

        # ---- Check 2: Strict super-lane gate -------------------------------------
        # Named fn calling only generic callees (imported from existing check logic)
        strict_violations = 0
        for fn in all_fns:
            ep = int(str(fn.getEntryPoint()), 16)
            if ep < min_addr or ep >= max_addr:
                continue
            name = fn.getName()
            if _is_generic(name):
                continue
            ns = fn.getParentNamespace()
            ns_name = "" if ns is None or ns == global_ns else ns.getName()
            if not ns_name or ns_name == "Global":
                continue  # only named class methods
            # Check if all callees are generic
            callees = fn.getCalledFunctions(None)
            if callees is None:
                continue
            callee_list = list(callees)
            if not callee_list:
                continue
            all_generic = all(_is_generic(c.getName()) for c in callee_list)
            if not all_generic:
                continue
            # Skip if function has indirect calls (vtable dispatch etc.) —
            # those represent real semantic callees Ghidra can't resolve.
            if _has_indirect_call(fn, listing):
                continue
            if all_generic:
                strict_violations += 1
                issues.append({
                    "check": "strict_gate",
                    "address": f"0x{ep:08x}",
                    "name": name,
                    "namespace": ns_name,
                    "detail": f"calls {len(callee_list)} generic function(s) only",
                })

        # ---- Check 3: Stale thunk names ------------------------------------------
        # A thunk "thunk_Foo_At<addr>" (or "thunk_Foo") is stale when the function
        # it jumps/calls to is no longer named "Foo".
        # False-positive guards:
        #   - Skip if thunk and target share the same name (same-name chain)
        #   - Skip if target name is mangled (backtick or @@)
        #   - Skip if target name itself is generic (thunk of CRT/orphan stub)
        stale_thunks = 0
        for fn in all_fns:
            ep = int(str(fn.getEntryPoint()), 16)
            if ep < min_addr or ep >= max_addr:
                continue
            name = fn.getName()
            if not name.startswith("thunk_") or _is_generic(name):
                continue
            # backtick / mangled source names are not stale candidates
            if "`" in name or "@@" in name:
                continue

            tgt = _detect_single_forward_target(fn, fm, listing)
            if tgt is None:
                continue
            tgt_name = tgt.getName()

            # Skip if target is generic, mangled, or same name as source
            if _is_generic(tgt_name):
                continue
            if "`" in tgt_name or "@@" in tgt_name:
                continue
            if name == tgt_name:
                continue  # same-name thunk chain (e.g. two thunk_Foo at different addrs)

            # Extract the embedded name: strip "thunk_" prefix and optional "_At<8hex>" suffix
            embedded = name[6:]  # strip "thunk_"
            embedded = _THUNK_AT_RE.sub("", embedded)  # strip _AtXXXXXXXX

            # Also strip the same suffix from target name for comparison
            tgt_base = _THUNK_AT_RE.sub("", tgt_name)

            if embedded == tgt_base or embedded == tgt_name:
                continue  # names match

            stale_thunks += 1
            issues.append({
                "check": "stale_thunk",
                "address": f"0x{ep:08x}",
                "name": name,
                "namespace": "",
                "detail": f"embedded={embedded} target={tgt_name} target_base={tgt_base}",
            })

        # ---- Check 4: Stale wrapper names ----------------------------------------
        stale_wrappers = 0
        for fn in all_fns:
            ep = int(str(fn.getEntryPoint()), 16)
            if ep < min_addr or ep >= max_addr:
                continue
            name = fn.getName()
            m = _WRAPPER_RE.match(name)
            if not m:
                continue
            embedded_name = m.group(1)
            embedded_addr = int(m.group(2), 16)

            # Convention: At<addr> may be self-addr OR target addr.
            # Check target-addr convention first.
            tgt = _detect_single_forward_target(fn, fm, listing)
            if tgt is None:
                continue
            tgt_name = tgt.getName()
            if _is_generic(tgt_name):
                continue

            # Staleness: the embedded name doesn't match target name
            # AND the new name would not produce double-nesting
            if embedded_name != tgt_name and not tgt_name.startswith("WrapperFor_"):
                stale_wrappers += 1
                tgt_ep = int(str(tgt.getEntryPoint()), 16)
                issues.append({
                    "check": "stale_wrapper",
                    "address": f"0x{ep:08x}",
                    "name": name,
                    "namespace": "",
                    "detail": (
                        f"embedded={embedded_name} target={tgt_name}@0x{tgt_ep:08x}"
                    ),
                })

        # ---- Check 5: FID_conflict leftovers -------------------------------------
        fid_conflict = 0
        for fn in all_fns:
            ep = int(str(fn.getEntryPoint()), 16)
            if ep < min_addr or ep >= max_addr:
                continue
            name = fn.getName()
            if name.startswith("FID_conflict:"):
                fid_conflict += 1
                issues.append({
                    "check": "fid_conflict",
                    "address": f"0x{ep:08x}",
                    "name": name,
                    "namespace": "",
                    "detail": "",
                })

        # ---- Check 6: Duplicate names per class ----------------------------------
        # Collect (namespace, name) pairs and flag duplicates
        ns_name_counts: Counter = Counter()
        for fn in all_fns:
            ep = int(str(fn.getEntryPoint()), 16)
            if ep < min_addr or ep >= max_addr:
                continue
            ns = fn.getParentNamespace()
            ns_name = "" if ns is None or ns == global_ns else ns.getName()
            if not ns_name or ns_name == "Global":
                continue
            fn_name = fn.getName()
            if _is_generic(fn_name):
                continue
            ns_name_counts[(ns_name, fn_name)] += 1

        dup_groups = 0
        dup_fns = 0
        for (ns_name, fn_name), cnt in ns_name_counts.items():
            if cnt > 1:
                dup_groups += 1
                dup_fns += cnt
                issues.append({
                    "check": "dup_name",
                    "address": "",
                    "name": fn_name,
                    "namespace": ns_name,
                    "detail": f"count={cnt}",
                })

        # ---- Check 7: Unknown calling conventions --------------------------------
        # Only flag cc=unknown (not cc=default — that is the project default / __cdecl)
        # and only for named non-generic class-namespaced functions.
        unknown_cc = 0
        for fn in all_fns:
            ep = int(str(fn.getEntryPoint()), 16)
            if ep < min_addr or ep >= max_addr:
                continue
            cc = str(fn.getCallingConventionName())
            if cc != "unknown":
                continue
            fn_name = fn.getName()
            if _is_generic(fn_name):
                continue
            ns = fn.getParentNamespace()
            ns_name = "" if ns is None or ns == global_ns else ns.getName()
            if not ns_name or ns_name == "Global":
                continue  # only flag class-scoped functions
            unknown_cc += 1
            issues.append({
                "check": "unknown_cc",
                "address": f"0x{ep:08x}",
                "name": fn_name,
                "namespace": ns_name,
                "detail": f"cc={cc}",
            })

    # ---- Report -------------------------------------------------------------------
    SEP = "=" * 70
    print(SEP)
    print("IMPERIALISM RE — QUALITY PASS REPORT")
    print(SEP)

    # Gate emoji helper
    def gate(ok: bool) -> str:
        return "OK " if ok else "FAIL"

    print(f"\n[1] Class assignment progress")
    print(f"    Total __thiscall in range : {total_thiscall}")
    print(f"    Attributed to a class     : {attributed_thiscall}  ({pct:.1f}%)")
    print(f"    Still Global              : {global_thiscall}")

    print(f"\n[2] Strict super-lane gate    [{gate(strict_violations == 0)}]")
    print(f"    Named class methods whose all callees are generic: {strict_violations}")

    print(f"\n[3] Stale thunk names         [{gate(stale_thunks == 0)}]")
    print(f"    thunk_Foo where JMP target is no longer Foo: {stale_thunks}")
    if stale_thunks:
        for iss in [x for x in issues if x["check"] == "stale_thunk"][:10]:
            print(f"    {iss['address']} {iss['name']}")
            print(f"      -> {iss['detail']}")

    print(f"\n[4] Stale wrapper names       [{gate(stale_wrappers == 0)}]")
    print(f"    WrapperFor_X_AtA where target no longer named X: {stale_wrappers}")
    if stale_wrappers:
        for iss in [x for x in issues if x["check"] == "stale_wrapper"][:10]:
            print(f"    {iss['address']} {iss['name']}")
            print(f"      -> {iss['detail']}")

    print(f"\n[5] FID_conflict leftovers    [{gate(fid_conflict == 0)}]")
    print(f"    Functions still named FID_conflict:*: {fid_conflict}")

    print(f"\n[6] Duplicate names per class [{gate(dup_groups == 0)}]")
    print(f"    Duplicate (class, name) groups: {dup_groups}  ({dup_fns} functions)")
    if dup_groups:
        for iss in [x for x in issues if x["check"] == "dup_name"][:10]:
            print(f"    {iss['namespace']}::{iss['name']}  x{iss['detail'].split('=')[1]}")

    print(f"\n[7] Unknown calling conventions [{gate(unknown_cc == 0)}]")
    print(f"    Named functions with unknown/default CC: {unknown_cc}")

    print(f"\n{SEP}")

    # Critical failures
    critical = strict_violations + unknown_cc
    if critical:
        print(f"RESULT: FAIL — {critical} critical gate violation(s)")
    else:
        print("RESULT: PASS — all critical gates green")
    print(SEP)

    # ---- Optional CSV output ---------------------------------------------------
    if args.out_csv:
        out = Path(args.out_csv)
        if not out.is_absolute():
            out = root / out
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(
                fh, fieldnames=["check", "address", "name", "namespace", "detail"]
            )
            w.writeheader()
            w.writerows(issues)
        print(f"[saved] {out}  rows={len(issues)}")

    return 1 if critical else 0


if __name__ == "__main__":
    raise SystemExit(main())
