#!/usr/bin/env python3
"""Silent no-op detector: empty manual bodies vs the original function's size.

src/game carries ~1000 single-line `{}` method bodies. Some are faithfully
empty in the original; an unknown number are silent placeholders that compile,
run, and do nothing — the worst gap class because nothing fails loudly (a
body with no `// FUNCTION` marker is invisible to reccmp scoring AND to the
stub pipeline). This tool finds empty (or trivial `(void)arg;`-only) bodies,
resolves each to an original address via (a) its marker, (b) a `// NOOP:`
annotation, (c) a trailing `// 0xNN 0xADDR` vtable-slot comment, or (d) a
symbols.csv name match, and classifies:

  EMPTY-VERIFIED     original is genuinely tiny (<= --max-noop-size bytes) — fine
  EMPTY-BUT-BIG      original is real code — port it (exempt: ctors/dtors,
                     whose empty source bodies legitimately emit member/base
                     construction code)
  EMPTY-UNMARKED     no marker/annotation at all — invisible to reccmp; add the
                     `// FUNCTION` marker, a `// NOOP: verified empty in
                     original 0xADDR` comment, or delete the phantom method
  EMPTY-UNRESOLVED   no address found anywhere — possibly inlined-away, possibly
                     invented; resolve or annotate
  NOOP-CONTRADICTED  a `// NOOP:` annotation whose address is NOT tiny — the
                     annotation lies; port the body

Audit mode prints every finding. Gate mode (`--baseline`) ratchets per-file
counts exactly like the construction anti-pattern gate: new files with
findings fail, per-class count increases fail, NOOP-CONTRADICTED always fails.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import tree_sitter_cpp
from tree_sitter import Language, Parser

from tools.common.ratchet import compare, read_baseline, write_baseline
from tools.common.repo import normalize_repo_relative_path, repo_root_from_file, resolve_repo_path
from tools.common.symbols import functions_by_name

# Function definitions come from a real parser (tree-sitter-cpp): error-tolerant,
# no preprocessing needed, and immune to the macro/init-list/comment pitfalls a
# textual scan has. Regexes in this file only read *comments* (markers, annotations).
_CPP = Language(tree_sitter_cpp.language())
VOID_CAST_RE = re.compile(rb"^\(\s*void\s*\)\s*\w+\s*;$")
MARKER_RE = re.compile(
    r"//\s*(?P<kind>FUNCTION|SYNTHETIC|STUB|LIBRARY):\s*\w+\s+0x(?P<addr>[0-9a-fA-F]+)"
)
NOOP_RE = re.compile(r"//\s*NOOP:.*?0x(?P<addr>[0-9a-fA-F]+)")
SLOT_COMMENT_RE = re.compile(r"//\s*0x[0-9a-fA-F]{1,3}\s+0x(?P<addr>[0-9a-fA-F]{5,8})")

VIOLATION_KINDS = ("empty_but_big", "empty_unmarked", "empty_unresolved", "noop_contradicted")

# Audit-only kinds (bd kwee): reported by the audit and `--kind`, but excluded from
# the ratchet baseline so introducing the detector does not require a policy-baseline
# update. Promote a kind into VIOLATION_KINDS together with a human-approved
# `just noop-gate-update` once its findings are triaged.
#
#   trivial_return_but_big    body is a bare `return <literal>;` while the original is
#                             real code — the same silent-no-op failure mode as
#                             empty_but_big, just spelled deceptively.
#   ctor_missing_derived_init an empty, init-list-free ctor whose original stores to
#                             offsets beyond the base-class size — the derived fields
#                             are seeded in the retail binary but not by our port.
AUDIT_KINDS = ("trivial_return_but_big", "ctor_missing_derived_init")


def sizes_by_address(symbols: dict[str, tuple[int, int]]) -> dict[int, int]:
    return {addr: size for addr, size in symbols.values()}


def is_ctor_or_dtor(qual: str, name: str) -> bool:
    if name.startswith("~"):
        return True
    classes = [c for c in qual.split("::") if c]
    return bool(classes) and name == classes[-1]


def classify_finding(
    *,
    marker_kind: str | None,
    marker_addr: int | None,
    noop_addr: int | None,
    resolved_addr: int | None,
    size: int | None,
    ctor_dtor: bool,
    max_noop_size: int,
) -> str | None:
    """Return a violation kind, 'EMPTY-VERIFIED' (ok), or None (skip)."""
    if marker_kind in ("STUB", "LIBRARY"):
        return None  # not a manual body claim
    if noop_addr is not None:
        if size is not None and size > max_noop_size:
            return "noop_contradicted"
        return "EMPTY-VERIFIED"
    if marker_kind in ("FUNCTION", "SYNTHETIC"):
        assert marker_addr is not None
        if size is not None and size > max_noop_size and not ctor_dtor:
            return "empty_but_big"  # visible to reccmp, but still a fake body
        return "EMPTY-VERIFIED"
    # No marker: invisible to reccmp scoring.
    if resolved_addr is None:
        return "empty_unresolved"
    if size is not None and size > max_noop_size and not ctor_dtor:
        return "empty_but_big"
    return "empty_unmarked"


def is_trivial_return_body(body) -> bool:
    """True when a compound_statement is exactly `return <literal>;` (+ comments)."""
    returns = 0
    for child in body.named_children:
        if child.type == "comment":
            continue
        if child.type == "expression_statement" and VOID_CAST_RE.match(
            re.sub(rb"\s+", b" ", child.text or b"")
        ):
            continue
        if child.type != "return_statement":
            return False
        expr = [c for c in child.named_children if c.type != "comment"]
        if len(expr) != 1:
            return False
        node = expr[0]
        if node.type == "unary_expression":
            inner = node.child_by_field_name("argument")
            node = inner if inner is not None else node
        if node.type not in ("number_literal", "true", "false", "null"):
            return False
        returns += 1
    return returns == 1


class OriginalBinaryContext:
    """Lazy access to the retail .text bytes plus the header class/base/size maps
    needed for the ctor derived-store audit. Construction never raises: when the
    original binary is unavailable the audit silently skips (audit-only kind)."""

    CLASS_BASE_RE = re.compile(r"\bclass\s+(\w+)\s*:\s*public\s+(\w+)")
    ASSERT_SIZE_RE = re.compile(r"ASSERT_SIZE\(\s*(\w+)\s*,\s*(0x[0-9a-fA-F]+|\d+)\s*\)")

    def __init__(self, repo_root: Path):
        self.text = None
        try:
            from tools.workflow.prune_ilt_thunks import TextSection, original_exe_from_user_yml

            exe = original_exe_from_user_yml(repo_root)
            self.text = TextSection(exe.read_bytes())
        except Exception:
            return
        self.base_of: dict[str, str] = {}
        self.size_of: dict[str, int] = {}
        for path in sorted((repo_root / "include").rglob("*.h")):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for m in self.CLASS_BASE_RE.finditer(text):
                self.base_of.setdefault(m.group(1), m.group(2))
            for m in self.ASSERT_SIZE_RE.finditer(text):
                self.size_of.setdefault(m.group(1), int(m.group(2), 0))

    def base_size(self, class_name: str) -> int | None:
        base = self.base_of.get(class_name)
        return self.size_of.get(base) if base else None

    def code_bytes(self, addr: int, size: int) -> bytes | None:
        if self.text is None:
            return None
        try:
            start = self.text.raw + addr - self.text.va
            if not (self.text.va <= addr < self.text.va + self.text.vsize):
                return None
            return self.text.exe[start : start + size]
        except Exception:
            return None


def derived_store_offsets(code: bytes, addr: int, base_size: int) -> list[int]:
    """Displacements of `mov [this+disp], ...` stores at/beyond base_size.

    Tracks which registers alias `this` (ECX at entry) through simple reg-reg
    moves; calls clobber the volatile aliases. Linear scan to the first RET —
    MSVC500 ctors are single-exit, so this covers the whole body.
    """
    import capstone

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    this_regs = {"ecx"}
    out: list[int] = []
    for insn in md.disasm(code, addr):
        mnem = insn.mnemonic
        if mnem.startswith("ret"):
            break
        if mnem == "call":
            this_regs -= {"eax", "ecx", "edx"}
            continue
        ops = insn.operands
        if mnem == "mov" and len(ops) == 2:
            dst, src = ops
            if (
                dst.type == capstone.x86.X86_OP_REG
                and src.type == capstone.x86.X86_OP_REG
            ):
                dst_name = insn.reg_name(dst.reg)
                if insn.reg_name(src.reg) in this_regs:
                    this_regs.add(dst_name)
                else:
                    this_regs.discard(dst_name)
                continue
            if dst.type == capstone.x86.X86_OP_MEM and dst.mem.index == 0:
                base_name = insn.reg_name(dst.mem.base) if dst.mem.base else None
                if base_name in this_regs and dst.mem.disp >= base_size:
                    out.append(dst.mem.disp)
                continue
        if ops and ops[0].type == capstone.x86.X86_OP_REG:
            this_regs.discard(insn.reg_name(ops[0].reg))
    return sorted(set(out))


def is_empty_body(body) -> bool:
    """True when a compound_statement holds only comments / `(void)x;` casts."""
    for child in body.named_children:
        if child.type == "comment":
            continue
        if child.type == "expression_statement" and VOID_CAST_RE.match(
            re.sub(rb"\s+", b" ", child.text or b"")
        ):
            continue
        return False
    return True


def declarator_name(def_node) -> str | None:
    """Fully spelled declarator name ('TZone::~TZone', 'Slot', 'operator==')."""
    node = def_node.child_by_field_name("declarator")
    while node is not None and node.type in ("function_declarator", "pointer_declarator", "reference_declarator"):
        node = node.child_by_field_name("declarator")
    if node is None or node.text is None:
        return None
    return node.text.decode("utf-8", errors="replace")


def enclosing_class(def_node) -> str:
    node = def_node.parent
    while node is not None:
        if node.type in ("class_specifier", "struct_specifier"):
            name = node.child_by_field_name("name")
            if name is not None and name.text:
                return name.text.decode("utf-8", errors="replace")
        node = node.parent
    return ""


def scan_file(
    path: Path,
    symbols: dict[str, tuple[int, int]],
    addr_sizes: dict[int, int],
    max_noop_size: int,
    ctx: "OriginalBinaryContext | None" = None,
) -> list[dict]:
    raw = path.read_bytes()
    tree = Parser(_CPP).parse(raw)
    findings: list[dict] = []

    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        stack.extend(node.children)
        if node.type != "function_definition":
            continue
        body = node.child_by_field_name("body")
        if body is None or body.type != "compound_statement":
            continue
        empty = is_empty_body(body)
        trivial_return = not empty and is_trivial_return_body(body)
        if not empty and not trivial_return:
            continue
        has_init_list = any(c.type == "field_initializer_list" for c in node.children)
        if empty and has_init_list:
            continue  # member-initializer list — the compiler emits construction
        spelled = declarator_name(node)
        if spelled is None:
            continue
        if "::" in spelled:
            qual, _, name = spelled.rpartition("::")
            qual += "::"
        else:
            qual, name = "", spelled
            cls = enclosing_class(node)
            if cls:
                qual = f"{cls}::"

        line_no = node.start_point[0] + 1
        # Slice `raw` (tree-sitter byte offsets), not `text`: a multi-byte UTF-8
        # character (e.g. an em dash) anywhere earlier in the file desyncs a
        # byte offset from the matching index into the decoded str.
        preceding = raw[: node.start_byte].decode("utf-8", errors="replace").splitlines()[-6:]
        context = "\n".join(preceding)
        nl = raw.find(b"\n", body.end_byte)
        trailing = raw[body.end_byte : nl if nl != -1 else len(raw)].decode(
            "utf-8", errors="replace"
        )

        marker = None
        for line in reversed(preceding):
            mm = MARKER_RE.search(line)
            if mm:
                marker = mm
                break
            if line.strip() and not line.lstrip().startswith("//"):
                break
        noop = NOOP_RE.search(context) or NOOP_RE.search(trailing)
        slot = SLOT_COMMENT_RE.search(trailing) or SLOT_COMMENT_RE.search(context)

        qualified = f"{qual}{name}"
        marker_addr = int(marker.group("addr"), 16) if marker else None
        noop_addr = int(noop.group("addr"), 16) if noop else None
        slot_addr = int(slot.group("addr"), 16) if slot else None
        sym = symbols.get(qualified)
        resolved = marker_addr or noop_addr or slot_addr or (sym[0] if sym else None)
        size = addr_sizes.get(resolved) if resolved is not None else None

        marker_kind = marker.group("kind") if marker else None
        ctor_dtor = is_ctor_or_dtor(qual, name)

        if trivial_return:
            # bd kwee blind spot 2: `return 0;` over a big original is the same
            # silent no-op as an empty body, spelled deceptively.
            if (
                marker_kind not in ("STUB", "LIBRARY")
                and noop_addr is None
                and size is not None
                and size > max_noop_size
            ):
                findings.append(
                    {
                        "file": path,
                        "line": line_no,
                        "name": qualified,
                        "kind": "trivial_return_but_big",
                        "address": f"0x{resolved:x}" if resolved is not None else "",
                        "size": size,
                    }
                )
            continue

        kind = classify_finding(
            marker_kind=marker_kind,
            marker_addr=marker_addr,
            noop_addr=noop_addr,
            resolved_addr=resolved,
            size=size,
            ctor_dtor=ctor_dtor,
            max_noop_size=max_noop_size,
        )
        # bd kwee blind spot 1: the ctor exemption only holds when the original
        # ctor adds no derived-field stores of its own. Decode the original and
        # flag stores landing at/beyond the base-class size.
        if (
            ctor_dtor
            and not name.startswith("~")
            and not has_init_list
            and marker_addr is not None
            and size is not None
            and ctx is not None
            and ctx.text is not None
        ):
            base_size = ctx.base_size(name)
            code = ctx.code_bytes(marker_addr, size)
            if base_size is not None and code:
                offsets = derived_store_offsets(code, marker_addr, base_size)
                if offsets:
                    findings.append(
                        {
                            "file": path,
                            "line": line_no,
                            "name": qualified
                            + " [derived stores: "
                            + ", ".join(f"+0x{o:x}" for o in offsets)
                            + "]",
                            "kind": "ctor_missing_derived_init",
                            "address": f"0x{marker_addr:x}",
                            "size": size,
                        }
                    )
        if kind is None or kind == "EMPTY-VERIFIED":
            continue
        findings.append(
            {
                "file": path,
                "line": line_no,
                "name": qualified,
                "kind": kind,
                "address": f"0x{resolved:x}" if resolved is not None else "",
                "size": size if size is not None else "",
            }
        )
    return findings


def collect_findings(repo_root: Path, roots: list[str], max_noop_size: int) -> list[dict]:
    symbols = functions_by_name(repo_root)
    addr_sizes = sizes_by_address(symbols)
    ctx = OriginalBinaryContext(repo_root)
    findings: list[dict] = []
    for root_value in roots:
        root = resolve_repo_path(repo_root, root_value)
        if not root.exists():
            continue
        for path in sorted(root.rglob("*")):
            posix = path.as_posix()
            if "/autogen/" in posix or "/ghidra_autogen/" in posix:
                continue
            if path.suffix.lower() not in (".cpp", ".h", ".hpp", ".cc"):
                continue
            findings.extend(scan_file(path, symbols, addr_sizes, max_noop_size, ctx))
    return findings


def counts_per_file(findings: list[dict], repo_root: Path) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for f in findings:
        if f["kind"] not in VIOLATION_KINDS:
            continue  # audit-only kinds stay outside the ratchet baseline
        rel = normalize_repo_relative_path(f["file"], repo_root)
        row = out.setdefault(rel, {k: 0 for k in VIOLATION_KINDS})
        row[f["kind"]] += 1
    return out


def baseline_file_is_initialized(path: Path) -> bool:
    """A header-only baseline is a valid zero floor; a missing/empty file is not."""
    return path.is_file() and path.stat().st_size > 0


def main() -> int:
    repo_root = repo_root_from_file(__file__)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--roots", nargs="+", default=["src/game", "include/game"])
    parser.add_argument("--max-noop-size", type=int, default=16,
                        help="Largest original size (bytes) accepted as a real no-op")
    parser.add_argument("--baseline", default="",
                        help="Gate mode: compare per-file counts against this CSV")
    parser.add_argument("--write-baseline", default="",
                        help="Write current per-file counts to this CSV and exit")
    parser.add_argument("--kind", choices=VIOLATION_KINDS + AUDIT_KINDS, default="",
                        help="Audit mode: only print this violation kind")
    args = parser.parse_args()

    findings = collect_findings(repo_root, args.roots, args.max_noop_size)
    current = counts_per_file(findings, repo_root)

    if args.write_baseline:
        write_baseline(
            resolve_repo_path(repo_root, args.write_baseline),
            current,
            VIOLATION_KINDS,
            include_total=False,
            lineterminator="\n",
        )
        print(f"Wrote baseline: {args.write_baseline} ({len(current)} files)")
        return 0

    if args.baseline:
        baseline_path = resolve_repo_path(repo_root, args.baseline)
        baseline = read_baseline(baseline_path, VIOLATION_KINDS)
        if not baseline and not baseline_file_is_initialized(baseline_path):
            print(f"Baseline missing: {args.baseline}")
            print("Run `just noop-gate-update` once, then re-run the gate.")
            return 1
        # A NOOP annotation whose original is not tiny is always a failure,
        # independent of the ratchet -- flag those first, then run the shared
        # new-file / per-key-increase compare for the remaining kinds.
        violations: list[str] = [
            f"{file_key}: {counts['noop_contradicted']} NOOP "
            "annotation(s) contradicted by original size"
            for file_key, counts in sorted(current.items())
            if counts["noop_contradicted"]
        ]
        violations += compare(
            current,
            baseline,
            VIOLATION_KINDS,
            new_file_message=lambda file_key, counts: (
                f"{file_key}: new empty-body finding(s) "
                f"[{', '.join(k for k in VIOLATION_KINDS if counts[k])}]"
            ),
        )
        if violations:
            print("Empty-body (NOOP) gate failed:")
            for item in violations:
                print(f"  - {item}")
            print("Port the body, add `// NOOP: verified empty in original 0xADDR`, or "
                  "delete the phantom method. Audit: `just noop-audit`.")
            return 1
        total = sum(sum(v.values()) for v in current.values())
        print(f"Empty-body gate passed. Baseline-tracked files: {len(current)} "
              f"(total findings: {total})")
        return 0

    # Audit mode.
    by_kind: dict[str, int] = {k: 0 for k in VIOLATION_KINDS + AUDIT_KINDS}
    for f in findings:
        by_kind[f["kind"]] += 1
    for f in sorted(findings, key=lambda x: (x["kind"], -(x["size"] or 0) if isinstance(x["size"], int) else 0)):
        if args.kind and f["kind"] != args.kind:
            continue
        rel = normalize_repo_relative_path(f["file"], repo_root)
        print(f"{f['kind']:18} {rel}:{f['line']}  {f['name']}  "
              f"addr={f['address'] or '?'} size={f['size'] or '?'}")
    print("summary: " + "  ".join(f"{k}={v}" for k, v in by_kind.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
