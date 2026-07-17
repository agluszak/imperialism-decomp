#!/usr/bin/env python3
"""Select the 5-10 most relevant active rules for a target or the current diff.

  just advice 0xADDR     # rules for porting this address (uses the agent-task
                         # receipt's portprep dossier when present, else func-status
                         # + symbols.csv shape signals)
  just advice --diff     # rules for the current working diff vs the merge base

The knowledge base is config/agent_rules.yml (linted by `just agent-rules-gate`).
Rules match via trigger tags derived from real evidence — portprep sections, size,
ownership, diff content — so agents get the rules that apply, not the whole
notebook. Depth (field notes, worked examples) stays in the referenced skill.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
RULES_YML = REPO_ROOT / "config" / "agent_rules.yml"
TASK_JSON = REPO_ROOT / "build-msvc500" / "agent-task.json"

MAX_RULES = 10

# Tag derivation patterns over portprep/listing text.
TEXT_TAGS: tuple[tuple[str, str], ...] = (
    (r"CString::", "cstring_calls"),
    (r"CDumpContext|operator<<", "dump_context"),
    (r"PUSH -0x1\n.*FS:\[0x0\]|__ehhandler|push -1", "eh_prologue"),
    (r"operator new", "new_expression"),
    (r"F(LD|MUL|DIV|ADD|SUB|ILD|COMP?)", "fp_ops"),
    (r"-- indirect vtable-slot calls --\n  \S", "vtable_slot_calls"),
    (r"jump table|JMP dword ptr \[\w+\*0x4", "jump_table"),
    (r"MessageBoxA", "cstring_calls"),
    (r"scalar deleting destructor|``?_G", "scalar_deleting_dtor"),
    (r"\[R\]  \?", "unlabeled_globals"),
    (r"via thunk 0x004", "ilt_thunk_call"),
    (r"\[STUB \(src/autogen", "callee_to_declare"),
    (r"MOVSX \w+,word ptr", "movsx_word_read"),
    (r"__cdecl", "ghidra_cdecl_label"),
    (r"WARNING: Unknown calling convention|in_ECX|unaff_", "broken_decompile"),
    (r"MOV ECX,dword ptr \[0x006", "caller_loads_ecx_global"),
    (r"MOV E\w\w,ECX|\[ECX \+", "callee_reads_ecx"),
    (r"MOV ECX,E\w\w\n\S+  CALL|MOV ECX,\w+\s*\n\S+  CALL", "caller_loads_ecx"),
    (r"\bs_(sz|Sz)\w+|g_sz\w+", "string_literals"),
    (r"Construct\w*BaseState", "base_ctor_call"),
    (r"::CString|CString::CString|Construct\w+", "ctor_work"),
    (r"~CString|scalar deleting|::~", "dtor_work"),
    (r"\b(memset|memcpy|strlen|_mbscmp|__all(mul|shr|div))\b", "crt_idiom"),
    (r"CList<|CPtrList|CObList|CObArray|CMap<|m_pNode(Head|Tail)", "mfc_collection_shape"),
    (r"0x51eb851f|0x66666667|0x2aaaaaab|0x38e38e39", "magic_number_division"),
    (r"SETN?[EZ] ", "bool_materialization"),
    (r"\bJL 0x", "loop_bound_signedness"),
    (r"MOV [A-D][XL],\w|MOV [A-D]X,word", "partial_register_push"),
    (r"macos_codewarrior|Mac oracle", "mac_oracle_lookup"),
    (r"stack_layout=[1-9]", "frame_size_mismatch"),
    (r"codegen=[1-9]", "branch_shape_mismatch"),
)

DIFF_TAGS: tuple[tuple[str, str], ...] = (
    (r"^\+.*//\s*(FUNCTION|SYNTHETIC|TEMPLATE|LIBRARY|GLOBAL|VTABLE):", "markers_changed"),
    (r"^\+.*reinterpret_cast<[^>]*\(\s*\w*\s*\*", "cast_at_callsite"),
    (r"^\+.*reinterpret_cast<.*>\s*\(\s*reinterpret_cast<char\s*\*>\(this\)", "raw_this_offset"),
    (r"^\+.*\bthis\)\s*\+\s*0x", "raw_this_offset"),
    (r"^\+.*\bunion\b", "union_added"),
    (r"^\+.*\bextern\b.*;", "new_extern_decl"),
    (r"^\+.*\b(float|double)\b", "fp_ops"),
    (r"^\+.*CString", "cstring_calls"),
    (r"^\+.*\bnew\s+\w+", "new_expression"),
    (r"^\+.*virtual\b", "vtable_slot_calls"),
    (r"^[+-].*// VTABLE:", "vtable_slot_calls"),
    (r"^\+.*switch\s*\(", "switch_dispatch"),
    (r"^\+.*reinterpret_cast<[^>]*\*>\(0x[0-9a-fA-F]+", "raw_address_cast"),
    (r"^\+class \w+ : public", "class_recovery"),
    (r"macos_codewarrior", "mac_oracle_lookup"),
)


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=REPO_ROOT, capture_output=True,
                          text=True).stdout


def load_rules() -> list[dict]:
    data = yaml.safe_load(RULES_YML.read_text(encoding="utf-8"))
    return [r for r in data.get("rules", []) if r.get("status") == "active"]


def tags_from_text(text: str, patterns) -> set[str]:
    tags: set[str] = set()
    for pat, tag in patterns:
        if re.search(pat, text, re.M):
            tags.add(tag)
    return tags


def tags_for_address(addr: str) -> set[str]:
    tags = {"task_start", "callee_to_declare"}
    import json
    text = ""
    if TASK_JSON.is_file():
        task = json.loads(TASK_JSON.read_text(encoding="utf-8"))
        entry = task.get("targets", {}).get(addr) or task.get("targets", {}).get(
            f"0x{int(addr, 16):08x}")
        if entry:
            text = entry.get("portprep", "")
            if entry.get("stub_owned_callees"):
                tags.add("callee_to_declare")
            if entry.get("ownership_drift"):
                tags.add("ownership_drift")
        check = task.get("check", {})
        if check.get("failures"):
            tags.add("gate_failure")
        results = check.get("results", {})
        if "detect" in check.get("failures", []) or not results.get("detect", {}).get("ok", True):
            tags.add("mass_unpairing")
        for a, score in (check.get("scores") or {}).items():
            baseline = (task.get("targets", {}).get(a) or {}).get("baseline_score")
            if isinstance(baseline, (int, float)) and score < baseline:
                tags.add("stats_drop_untouched")
        # Triage/compare tails feed the shape-mismatch tags.
        text += "\n" + "\n".join(str(r.get("tail", "")) for r in results.values())
    if not text:
        proc = subprocess.run(["just", "func-status", addr], cwd=REPO_ROOT,
                              capture_output=True, text=True)
        text = proc.stdout
    tags |= tags_from_text(text, TEXT_TAGS)
    m = re.search(r"size:\s*(\d+)B", text) or re.search(r"size=(\d+)", text)
    if m and int(m.group(1)) >= 500:
        tags.add("big_function")
    if int(addr, 16) >= 0x5F0000:
        tags.add("library_range")
    return tags


def tags_for_diff() -> set[str]:
    base = _git("merge-base", "HEAD", "origin/main").strip()
    diff = _git("diff", base) + _git("diff")
    tags = tags_from_text(diff, DIFF_TAGS)
    names = _git("diff", "--name-only", base).splitlines()
    if any(p.startswith(("src/autogen/", "src/ghidra_autogen/", "include/ghidra_autogen/"))
           for p in names):
        tags.add("generated_touched")
    if _git("status", "--porcelain").strip():
        tags.add("dirty_worktree")
    return tags


def render(rule: dict) -> str:
    lines = [f"[{rule['id']}] {rule['title']}"]
    for key, label in (("required", "DO"), ("forbidden", "DON'T"), ("tools", "tools")):
        vals = rule.get(key) or []
        if vals:
            lines.append(f"    {label}: " + "; ".join(str(v) for v in vals))
    if rule.get("skill"):
        lines.append(f"    depth: load the `{rule['skill']}` skill")
    if rule.get("examples"):
        lines.append("    evidence: " + ", ".join(str(e) for e in rule["examples"]))
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("address", nargs="?", help="target address (hex)")
    parser.add_argument("--diff", action="store_true",
                        help="derive rules from the current diff instead")
    parser.add_argument("--all-tags", action="store_true",
                        help="also print the derived trigger tags")
    args = parser.parse_args()

    if args.diff:
        tags = tags_for_diff()
        header = "current diff"
    elif args.address:
        addr = f"0x{int(args.address, 16):08x}"
        tags = tags_for_address(addr)
        header = addr
    else:
        parser.error("pass 0xADDR or --diff")

    rules = load_rules()
    scored = []
    for r in rules:
        hit = tags & set(r.get("triggers", []))
        if hit:
            scored.append((len(hit), r, hit))
    scored.sort(key=lambda t: (-t[0], t[1]["id"]))

    print(f"advice for {header} — {len(scored)} matching rule(s)"
          + (f" of {len(rules)} active" if scored else ""))
    if args.all_tags:
        print(f"  derived tags: {', '.join(sorted(tags))}")
    if not scored:
        print("  no trigger matched; run `just agent-start` first so the portprep "
              "dossier feeds the tag derivation")
        return 0
    for _, rule, hit in scored[:MAX_RULES]:
        print()
        print(render(rule))
    if len(scored) > MAX_RULES:
        print(f"\n(+{len(scored) - MAX_RULES} weaker matches suppressed)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
