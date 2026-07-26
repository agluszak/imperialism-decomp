#!/usr/bin/env python3
"""Find out when MSVC500 routes array construction through the vector-ctor iterator.

Background: the retail binary constructs the same source-level record three different
ways.  TArmyMgr::ReadFrom (0x4a1b80) expands both of its ``CStr32[2]`` and ``CStr255[2]``
members as inline single-byte store loops; ResolveMapOrderPairConflictStep (0x55a780)
inlines the ``CStr32[2]`` and calls ``__ehvec_ctor`` for the ``CStr255[2]`` fourteen bytes
later, in the same function; BuildArmyContextActionRecordsAndDispatchLabel (0x4a2900)
calls the helper for both.  Because two of those choices sit inside one function, the
selection cannot be a per-translation-unit compiler option, which is what earlier
attempts on this question assumed.

This probe compiles a matrix of small translation units with the exact production flags
and reads CL's own ``/FAsc`` listing back, so each case reports what the compiler
actually emitted rather than what we expect it to emit.  Run it whenever an array-of-
class local fails to reproduce the original's construction shape.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import tempfile
from pathlib import Path

from tools.common.repo import repo_root_from_file


DOCKER_IMAGE = "imperialism-msvc500:latest"

# Exactly the production compile line (CMakeCache CMAKE_CXX_FLAGS +
# CMAKE_CXX_FLAGS_RELWITHDEBINFO + the target_compile_options block in CMakeLists.txt),
# minus /Z7 which only adds debug records, plus /FAsc for the listing.
PRODUCTION_FLAGS = "/DWIN32 /D_WINDOWS /Zm1000 /GX /GR- /MT /W3 /O2 /Ob1 /Oy /DNDEBUG"

# MSVC500's three array helpers.  ??_H is the one the retail binary calls at 0x412600
# (verified byte-for-byte against this probe's own emission of it).
ITERATOR_SYMBOL = "??_H@YGXPAXIHP6EX0@Z@Z"
EH_ITERATOR_SYMBOL = "??_L@YGXPAXIHP6EX0@Z1@Z"
EH_DTOR_ITERATOR_SYMBOL = "??_M@YGXPAXIHP6EX0@Z@Z"

# Flag sets worth comparing.  The first is production; the rest vary one axis each.
FLAG_SWEEP = {
    "production (/O2 /Ob1 /GX)": "/O2 /Ob1 /Oy /GX",
    "no optimization (/Od)": "/Od /GX",
    "favor size (/O1 /Ob1)": "/O1 /Ob1 /Oy /GX",
    "no inline expansion (/O2 /Ob0)": "/O2 /Ob0 /Oy /GX",
    "full inline expansion (/O2 /Ob2)": "/O2 /Ob2 /Oy /GX",
    "EH disabled (/O2 /Ob1, no /GX)": "/O2 /Ob1 /Oy",
}
COMMON_FLAGS = "/DWIN32 /D_WINDOWS /Zm1000 /GR- /MT /W3 /DNDEBUG"

PROLOGUE = r"""
// Element types.  The "S" family defines its constructor in-class (implicitly inline,
// which /Ob1 is still allowed to expand); the "O" family declares it in-class and
// defines it out-of-line, which /Ob1 must not auto-expand.
struct S20 { char d[0x20]; S20() { d[0] = 0; } };
struct S40 { char d[0x40]; S40() { d[0] = 0; } };
struct S80 { char d[0x80]; S80() { d[0] = 0; } };
struct SFF { char d[0xff]; SFF() { d[0] = 0; } };
struct S100 { char d[0x100]; S100() { d[0] = 0; } };

struct O20 { char d[0x20]; O20(); };
O20::O20() { d[0] = 0; }
struct OFF { char d[0xff]; OFF(); };
OFF::OFF() { d[0] = 0; }

// Element shapes that might force the helper: one with a destructor (so a throw
// mid-array has to unwind the finished elements), one whose constructor is too big to
// open-code, and one that owns a sub-object needing construction.
struct D20 { char d[0x20]; D20() { d[0] = 0; } ~D20() { d[1] = 0; } };
struct DO20 { char d[0x20]; DO20(); ~DO20(); };
DO20::DO20() { d[0] = 0; }
DO20::~DO20() { d[1] = 0; }
struct Fat20 {
  char d[0x20];
  Fat20() { d[0] = 0; d[3] = 1; d[7] = 2; d[11] = 3; d[15] = 4; d[19] = 5; }
};
struct Inner { int v; Inner(); };
Inner::Inner() { v = 0; }
struct Outer20 { char d[0x1c]; Inner inner; };

extern void sink(void* p);
extern int source(void);
extern void mayThrow(void);

// The shape TArmyMgr/TNavyMgr actually declare: a record whose 0x0c..0x257 tail is a
// CStr32[2] then a CStr255[2], with and without the destructor our model gives it.
struct RecNoDtor {
  int head[3];
  S20 nameBuffer[2];
  SFF overlayLabel[2];
  short childCount[2];
  void* childRecords[2];
};

struct RecDtor {
  int head[3];
  S20 nameBuffer[2];
  SFF overlayLabel[2];
  short childCount[2];
  void* childRecords[2];
  ~RecDtor() { sink(childRecords[0]); }
};

// Same record, but the element constructors are out-of-line, so /Ob1 is not allowed to
// expand them even though the record's own implicit constructor is still expandable.
struct RecOutElems {
  int head[3];
  O20 nameBuffer[2];
  OFF overlayLabel[2];
  short childCount[2];
  void* childRecords[2];
};

// One in-class element type and one out-of-line element type -- the shape that would
// explain 0x55a780 emitting an inline store loop and an iterator call side by side.
struct RecMixed {
  int head[3];
  S20 nameBuffer[2];
  OFF overlayLabel[2];
  short childCount[2];
  void* childRecords[2];
};
"""


def _case(name: str, body: str) -> str:
    return f"void {name}(void) {{\n{body}\n}}\n"


def build_source() -> tuple[str, list[tuple[str, str]]]:
    """Return (source text, [(case name, what it varies)])."""
    cases: list[tuple[str, str]] = []
    parts: list[str] = [PROLOGUE]

    def add(name: str, varies: str, body: str) -> None:
        cases.append((name, varies))
        parts.append(_case(name, body))

    # A. element size sweep, count 2, inline ctor, bare function.
    for tag, ty in (("20", "S20"), ("40", "S40"), ("80", "S80"), ("ff", "SFF"),
                    ("100", "S100")):
        add(f"a_size_{tag}", f"element size 0x{tag}, count 2",
            f"  {ty} a[2];\n  sink(a);")

    # B. element count sweep at a fixed 0x20 stride.
    for count in (2, 3, 4, 8, 16, 64):
        add(f"b_count_{count}", f"element size 0x20, count {count}",
            f"  S20 a[{count}];\n  sink(a);")

    # C. inline vs out-of-line constructor definition.
    add("c_inline_20", "in-class ctor, size 0x20", "  S20 a[2];\n  sink(a);")
    add("c_outofline_20", "out-of-line ctor, size 0x20", "  O20 a[2];\n  sink(a);")
    add("c_outofline_ff", "out-of-line ctor, size 0xff", "  OFF a[2];\n  sink(a);")

    # D. both arrays in one function -- the 0x55a780 shape.
    add("d_two_arrays_loose", "S20[2] then SFF[2] as separate locals",
        "  S20 a[2];\n  SFF b[2];\n  sink(a);\n  sink(b);")
    add("d_record_nodtor", "both arrays inside a record without a destructor",
        "  RecNoDtor r;\n  sink(&r);")
    add("d_record_dtor", "both arrays inside a record with a destructor",
        "  RecDtor r;\n  sink(&r);")

    # E. frame size.  0x4a2900 reserves 0x458 bytes; 0x4a1b80 reserves 0x268.
    add("e_frame_small", "record + no extra frame", "  RecDtor r;\n  sink(&r);")
    add("e_frame_big", "record + 0x200 bytes of extra frame",
        "  RecDtor r;\n  int pad[0x80];\n  sink(&r);\n  sink(pad);")
    add("e_frame_huge", "record + 0x800 bytes of extra frame",
        "  RecDtor r;\n  int pad[0x200];\n  sink(&r);\n  sink(pad);")

    # F. position of the construction relative to loops and calls.
    add("f_at_entry", "construction is the first statement",
        "  RecDtor r;\n  sink(&r);")
    add("f_in_loop", "construction inside a loop body (the 0x4a1b80 shape)",
        "  int n = source();\n  while (n-- > 0) {\n    RecDtor r;\n    sink(&r);\n  }")
    add("f_after_call", "construction after an unrelated call",
        "  sink(0);\n  RecDtor r;\n  sink(&r);")

    # G. exception state: a call that can throw while the record is live.
    add("g_throwing_call", "a call that can unwind while the record is live",
        "  RecDtor r;\n  mayThrow();\n  sink(&r);")
    add("g_try_block", "construction inside a try block",
        "  try {\n    RecDtor r;\n    mayThrow();\n    sink(&r);\n  } catch (...) {\n  }")

    # H. element-type shape: destructor, oversized ctor body, sub-object member.
    add("h_elem_dtor", "element has an in-class ctor AND a destructor",
        "  D20 a[2];\n  sink(a);")
    add("h_elem_dtor_outofline", "element has out-of-line ctor AND destructor",
        "  DO20 a[2];\n  sink(a);")
    add("h_elem_fat_ctor", "element ctor body is six stores, not one",
        "  Fat20 a[2];\n  sink(a);")
    add("h_elem_subobject", "element owns a member with an out-of-line ctor",
        "  Outer20 a[2];\n  sink(a);")
    add("h_elem_dtor_throwing", "element with a dtor, live across a throwing call",
        "  D20 a[2];\n  mayThrow();\n  sink(a);")

    # J. heap arrays -- new[] cannot open-code a runtime count.
    add("j_new_runtime", "new S20[runtime count]",
        "  S20* p = new S20[source()];\n  sink(p);")
    add("j_new_fixed", "new S20[2]", "  S20* p = new S20[2];\n  sink(p);")
    add("j_new_dtor_runtime", "new D20[runtime count] (element has a dtor)",
        "  D20* p = new D20[source()];\n  sink(p);")

    # M. the combination the retail binary actually needs: a record whose own implicit
    # constructor is expandable but whose element constructors are not.
    add("m_record_outofline_elems", "record of out-of-line-ctor elements",
        "  RecOutElems r;\n  sink(&r);")
    add("m_record_mixed", "record: in-class S20[2] then out-of-line OFF[2]",
        "  RecMixed r;\n  sink(&r);")
    add("m_loose_mixed", "loose locals: in-class S20[2] then out-of-line OFF[2]",
        "  S20 a[2];\n  OFF b[2];\n  sink(a);\n  sink(b);")

    # K. count sweep with a constructor /Ob1 may not auto-expand.
    for count in (2, 8, 64):
        add(f"k_outofline_count_{count}", f"out-of-line ctor, count {count}",
            f"  O20 a[{count}];\n  sink(a);")

    return "".join(parts), cases


PROC_RE = re.compile(r"^(\S+)\s+PROC NEAR\s*(?:;\s*(.*))?$")
ENDP_RE = re.compile(r"^(\S+)\s+ENDP")
STRIDE_RE = re.compile(r"\badd\s+e[a-z][a-z],\s*(\d+)")
# The zero can arrive as an immediate or out of a register the compiler already cleared.
STORE_RE = re.compile(r"\bmov\s+BYTE PTR \[e[a-z][a-z]\], (?:0|[a-d][lh])\b")
CTOR_CALL_RE = re.compile(r"\bcall\s+(\?\?0\S+)")


def parse_listing(text: str) -> dict[str, dict]:
    """Map each listing function to what it emitted for array construction.

    MSVC500 has three shapes here, and telling them apart is the whole point of the
    probe: an open-coded store loop (the constructor body inlined into a loop), an
    open-coded loop of real constructor calls, and a call to the vector-ctor iterator
    with the constructor's address.
    """
    blocks: dict[str, list[str]] = {}
    current: str | None = None
    for raw in text.splitlines():
        line = raw.rstrip()
        proc = PROC_RE.match(line.strip())
        if proc:
            # The trailing comment carries the undecorated name; prefer it.
            name = (proc.group(2) or proc.group(1)).split(",")[0].strip()
            current = name
            blocks[name] = []
            continue
        if ENDP_RE.match(line.strip()):
            current = None
            continue
        if current is not None:
            blocks[current].append(line)

    result: dict[str, dict] = {}
    for name, body in blocks.items():
        joined = "\n".join(body)
        strides: list[int] = []
        ctor_loops: list[str] = []
        for idx, line in enumerate(body):
            window = body[idx + 1:idx + 4]
            if STORE_RE.search(line):
                # An inline construction loop stores the zero byte and then advances
                # the cursor by one element; look a few lines ahead for that stride.
                for follow in window:
                    match = STRIDE_RE.search(follow)
                    if match:
                        strides.append(int(match.group(1)))
                        break
                continue
            call = CTOR_CALL_RE.search(line)
            if call:
                for follow in window:
                    match = STRIDE_RE.search(follow)
                    if match:
                        ctor_loops.append(f"0x{int(match.group(1)):x}")
                        break
        result[name] = {
            "iterator_calls": joined.count(ITERATOR_SYMBOL),
            "eh_iterator_calls": joined.count(EH_ITERATOR_SYMBOL),
            "eh_dtor_iterator_calls": joined.count(EH_DTOR_ITERATOR_SYMBOL),
            "inline_strides": strides,
            "ctor_call_loops": ctor_loops,
        }
    return result


def classify(info: dict) -> str:
    parts = []
    if info["iterator_calls"]:
        parts.append(f"ITERATOR(??_H) x{info['iterator_calls']}")
    if info["eh_iterator_calls"]:
        parts.append(f"EH-ITERATOR(??_L) x{info['eh_iterator_calls']}")
    if info["inline_strides"]:
        parts.append("INLINE-STORE stride "
                     + ",".join(f"0x{s:x}" for s in info["inline_strides"]))
    if info["ctor_call_loops"]:
        parts.append("CALL-LOOP stride " + ",".join(info["ctor_call_loops"]))
    if not parts and info["eh_dtor_iterator_calls"]:
        parts.append("(destruction only)")
    return " + ".join(parts) if parts else "(no array construction emitted)"


def compile_listing(work_dir: Path, source: str, flags: str) -> str:
    work_dir.mkdir(parents=True, exist_ok=True)
    (work_dir / "probe.cpp").write_text(source, encoding="ascii")
    script = (
        f"wine C:/msvc/bin/CL.EXE /nologo /c {flags} /FAsc probe.cpp > cl.log 2>&1; "
        "status=$?; "
        "if [ $status -ne 0 ] || [ ! -f probe.cod ]; then "
        "tail -40 cl.log >&2; echo VECTOR_CTOR_PROBE_COMPILE_FAILED >&2; exit 1; fi; "
        "cat probe.cod"
    )
    cmd = [
        "docker", "run", "--rm", "--network", "none",
        "--entrypoint", "/bin/sh",
        "-e", r"INCLUDE=C:\dxsdk\include;C:\msvc\include;C:\msvc\mfc\include;C:\msvc\atl\include",
        "-e", r"LIB=C:\msvc\lib;C:\msvc\mfc\lib",
        "-e", r"WINEPATH=C:\msvc\bin;C:\msvc\redist",
        "-v", f"{work_dir}:/work", "-w", "/work",
        DOCKER_IMAGE, "-c", script,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"vector-ctor probe failed (rc={proc.returncode}):\n{proc.stderr[-4000:]}")
    return proc.stdout


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir",
                        help="Keep the generated source, cl.log, and .cod listing here.")
    parser.add_argument("--flags",
                        help="Compile with exactly these flags instead of the sweep.")
    parser.add_argument("--sweep", action="store_true",
                        help="Compile the matrix once per entry in FLAG_SWEEP.")
    args = parser.parse_args()

    source, cases = build_source()
    if args.flags:
        variants = {"custom": args.flags}
    elif args.sweep:
        variants = {label: f"{COMMON_FLAGS} {flags}"
                    for label, flags in FLAG_SWEEP.items()}
    else:
        variants = {"production": PRODUCTION_FLAGS}

    width = max(len(name) for name, _ in cases)
    for label, flags in variants.items():
        def run(work_dir: Path) -> str:
            return compile_listing(work_dir, source, flags)

        if args.work_dir:
            root = Path(args.work_dir).resolve()
            listing = run(root / re.sub(r"\W+", "_", label))
        else:
            with tempfile.TemporaryDirectory(prefix="vector_ctor_probe_") as tmp:
                listing = run(Path(tmp))

        emitted = parse_listing(listing)
        print(f"=== {label} -- {flags}\n")
        for name, varies in cases:
            info = emitted.get(name)
            verdict = classify(info) if info else "(function missing from listing)"
            print(f"  {name:<{width}}  {verdict}")
            if not args.sweep:
                print(f"  {'':<{width}}    {varies}")
        print()
    repo_root_from_file(__file__)  # assert we are inside the repo
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
