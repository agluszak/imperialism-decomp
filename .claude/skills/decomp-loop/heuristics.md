# Matching playbook — core process notes

The old monolithic heuristics file (120+ numbered notes) is split into **topical
skills** so the right notes load with the right task. This file keeps only the
process/pairing/build notes that belong to the porting loop itself.

**Where the notes live now** (load the skill, don't grep this file):

| Topic | Skill |
| --- | --- |
| Calling conventions, receivers, free-vs-method, mis-attribution | `calling-conventions` |
| CString/text/format/assert strings | `string-handling` |
| Ctors, dtors, EH frames/states, new-expressions, sdd | `ctors-dtors-eh` |
| Float/double codegen, FPU shapes, FP wobble | `fp-matching` |
| Loops, branches, switches, bools, int math, frame slots | `codegen-shapes` |
| Globals, tables, structs, field typing | `data-modeling` |
| Huge stubs, dispatchers, monoliths, dossier workflow | `big-functions` |
| Vtable slots, LIBRARY vtables, slot pairing | `vtable-matching` (heuristics.md) |
| Class/layout recovery, attribution | `class-recovery` (heuristics.md) |
| MFC collections, templates, dialogs, GDI | `mfc-collections` (heuristics.md) |

**Recording new lessons (decomp-loop step 9): append to the TOPICAL skill's field
notes, not here.** Give the note a bold one-line claim + 1-2 `0xADDR (NN%→MM%)`
evidence points. Only loop-process/pairing/build lessons belong in this file.

## Legacy note-number resolution

Old commits and docs cite "heuristics note N". Two numbering series existed (the
`## N.` headings and a colliding appended list); `N` = heading series, `N-L` = list
series. Resolution:

| Old note | Title (truncated) | Now in |
| --- | --- | --- |
| 1 | Confirm the target before rewriting | stays here (below) |
| 3 | Constructor matching = field-init PLACEMENT | `ctors-dtors-eh` |
| 4 | Vtable dispatch as real virtuals, not facades | `vtable-matching` |
| 5 | Calling-convention recovery | `calling-conventions` |
| 6 | ABI return contracts | `calling-conventions` |
| 7 | Data-symbol and vtable pairing infrastructure | stays here (below) |
| 8 | Scalar deleting destructors | `ctors-dtors-eh` |
| 9 | Class recovery discipline | `class-recovery` |
| 10 | Deserialization and stream shape | `data-modeling` |
| 11 | CRT idioms are intrinsics, not hand loops | `codegen-shapes` |
| 12 | Declaration-order drift bug | `vtable-matching` |
| 13 | Batch repeating templates | stays here (below) |
| 14 | General process | stays here (below) |
| 15 | Real MFC surface — call it directly, don't model it | `mfc-collections` |
| 16 | Embedded subobject → expose via its real type | `class-recovery` |
| 17 | Type safety: distinct classes, opaque slots, and cast-free | `data-modeling` |
| 18 | MFC convention/access traps + CMap embedded tables (extend | `mfc-collections` |
| 19 | Monolithic functions must be ported as one inline body — n | `big-functions` |
| 20 | "Same address in two sibling vtables" is inheritance, not  | `vtable-matching` |
| 22 | Two adjacent same-typed fields always used together are pr | `data-modeling` |
| 23 | "Same free-function name, different receiver class" — make | `calling-conventions` |
| 24 | One "table" read at five different offsets is one struct,  | `data-modeling` |
| 25 | `function_out_of_order` (decomplint) is a pure textual-reo | stays here (below) |
| 26 | Free-vs-method is decided at the CALLSITE: the ECX-load +  | `calling-conventions` |
| 27 | CList/CArray twin copies masquerade as class methods and v | `mfc-collections` |
| 28 | Field-by-field snapshot copies are a struct-recovery oracl | `data-modeling` |
| 29 | Comment reflow / formatting can silently eat reccmp annota | stays here (below) |
| 30 | Typedef-cast externs drift; audit before trusting a signat | `calling-conventions` |
| 32 | Mine reccmp diffs for global identities (`just global-xref | `data-modeling` |
| 33 | A local object with a non-trivial dtor forces MSVC's singl | `ctors-dtors-eh` |
| 34 | `extern undefined4 Foo(void)` stubs may be real methods on | `calling-conventions` |
| 35 | "Cached context singleton" globals dispatched via `[ecx+sl | `data-modeling` |
| 36 | Turn-event screen builders share one widget-block vocabula | `big-functions` |
| 37 | Two independent recoveries of one class can hide behind di | `class-recovery` |
| 38 | "Failed to find a match" after editing a marked function = | stays here (below) |
| 39 | Library vtable addresses need a decorated-symbol row, or e | `vtable-matching` |
| 40 | COM interfaces hide behind "channel/audio object" vtable d | `calling-conventions` |
| 41 | GlobalHandle/GlobalUnlock/GlobalFree pairs = windowsx.h Gl | `ctors-dtors-eh` |
| 42 | Find unknown message handlers by scanning for AFX_MSGMAP_E | `mfc-collections` |
| 43 | Two cheap recomp-side diffs to sweep in the near-miss (98– | stays here (below) |
| 44 | A `call [eax+0xNN]` vs `call [eax+0xMM]` diff = wrong virt | `vtable-matching` |
| 45 | Extractor over-extends a class vtable to swallow adjacent  | `vtable-matching` |
| 46 | stretch<T> vs MFC CArray: realloc-double-or-fallback is th | `mfc-collections` |
| 47 | All globals belong in global_data_tables — never architect | `data-modeling` |
| 48 | Big matching-heavy function: use float (not double) locals | `fp-matching` |
| 49 | Thunk-only-caller thiscall methods are frequently mis-attr | `calling-conventions` |
| 50 | Detangling a two-class "frankenclass": split by vtable, re | `class-recovery` |
| 51 | Branch-order = fall-through: read the `je`/`jne` target to | `codegen-shapes` |
| 52 | Confirm "Built target" before trusting any stats delta; th | stays here (below) |
| 53 | Recover a polymorphic NULL-abstract-slot's real receiver b | `vtable-matching` |
| 55 | Same inline function, two call shapes in one binary = per- | `codegen-shapes` |
| 54 | Cross-check a header's assumed vtable-slot order against a | `vtable-matching` |
| 56 | A non-inline wrapper for a CList AddTail/RemoveTail COMDAT | `mfc-collections` |
| 56b | Byte-Boolean materialization: `sete/setne al + test al,al` | `codegen-shapes` |
| 57 | `ret 4`/`ret 0` + caller `mov ecx, [global]` = thiscall si | `calling-conventions` |
| 58 | Turn-event packet emitters: zero-then-value store pairs an | `big-functions` |
| 59 | Giant dispatchers get their own TU | `big-functions` |
| 60 | Giant switch receive machines: transcribe per-case in bina | `big-functions` |
| 61-L | Verify shared-class inline ctors against multiple original | `ctors-dtors-eh` |
| 62-L | Never place a forward declaration between a `// VTABLE:` a | `vtable-matching` |
| 63-L | A multi-edit python splice that asserts mid-script loses A | stays here (below) |
| 64-L | A local whose live range ends at the accumulate gets `fadd | `fp-matching` |
| 65-L | `r = *rectPtr;` (struct assignment) vs member-by-member co | `codegen-shapes` |
| 66-L | A body that never touches `ecx` can still be a `__thiscall | `calling-conventions` |
| 67-L | Frame-slot packing is controlled by scope: block-scoped sa | `codegen-shapes` |
| 68-L | A `func_0x` callee with an apparently different arg count  | `calling-conventions` |
| 69-L | Retiring a `reinterpret_cast<void(__stdcall*)(...)>(StubNa | `calling-conventions` |
| 70-L | MSVC500 for-loop-declared variables leak into the enclosin | `codegen-shapes` |
| 71-L | A `Ghidra_name::WrapperFor_Construct<Class>BaseState_At0x. | `ctors-dtors-eh` |
| 72-L | A base ctor that the compiler *always inlines* (no standal | `ctors-dtors-eh` |
| 73-L | A trivial derived ctor can hard-fail reccmp pairing ("Fail | `ctors-dtors-eh` |
| 74-L | A method whose every caller loads ECX from the same global | `calling-conventions` |
| 75-L | Run `just detect` after every build completes and before a | stays here (below) |
| 76-L | A block of junk-named `return 0` virtual-slot stubs (`Virt | `vtable-matching` |
| 77-L | `abs()` matches the compiler's `cdq/xor/sub` idiom; an exp | `codegen-shapes` |
| 78-L | When a two-way branch's ELSE block is laid out inline (fal | `codegen-shapes` |
| 79-L | A callsite's `movsx ax` (16-bit) vs `movsx eax` (32-bit) r | `calling-conventions` |
| 80-L | Read a runtime-global's true value from `just datacmp -a`, | `data-modeling` |
| 81-L | An exact-matching FPU/vtable inner section validates the w | `big-functions` |
| 82-L | `static_cast<int>(int_expr * float_global + int_field)` re | `fp-matching` |
| 83-L | FourCC-dispatched turn-instruction handlers are TSimMgr __ | `big-functions` |
| 84-L | The turn-instruction tokens are big-endian (Mac/CodeWarrio | `big-functions` |
| 85-L | Two more TSimMgr turn-instruction matching details (extend | `big-functions` |
| 86-L | Empty-collection linked-list scan: match MSVC's `xor eax,e | `codegen-shapes` |
| 87-L | Verify stub attribution by field-access consistency with p | `class-recovery` |
| 88-L | `new T()` callsites are an authoritative sizeof(T) oracle  | `class-recovery` |
| 89-L | Match the compiler's `>= N` / `> N` compare form, not just | `codegen-shapes` |
| 90-L | Before acting on a triage `[call_target]` line that names  | `vtable-matching` |
| 91-L | Pointer-walk vs index-loop is an optimizer choice you can' | `codegen-shapes` |
| 92-L | A sudden mass-unpairing after editing a .cpp is almost alw | stays here (below) |
| 93-L | A low-scoring "already-ported" leaf may just carry the WRO | stays here (below) |
| 94-L | `undefined`→`void` on a vtable slot with a trailing `+xor  | `vtable-matching` |
| 95-L | A fake `(args…)` forwarder that ignores its args and tail- | `calling-conventions` |
| 96-L | A FID miss is not evidence of game code — the relocation-m | stays here (below) |
| 97-L | Moving an oracle-flagged game-code mislabel to library: tw | stays here (below) |
| 98-L | CDialog / CWnd vtable slots don't fail from ICF — MSVC500  | `vtable-matching` |
| 89 | CView/CFrameWnd-family vtable LIBRARY pass: align the RECO | `vtable-matching` |
| 90 | A game "override" that forwards to the base but isn't in t | `vtable-matching` |
| 101 | A scalar-deleting-destructor stuck below 100% often means  | `ctors-dtors-eh` |
| 102 | Name shared base vtable slots from a coherent in-file prot | `vtable-matching` |
| 103 | A baseless, vtable-less game class is a red flag: disguise | `class-recovery` |
| 104 | Auditing the binary for unrecovered vtables (two detection | `class-recovery` |
| 105 | Recovering a family of MFC dialog-template subclasses (16  | `mfc-collections` |
| 106 | Inlined virtual base destructor: watch for COMDAT-fold col | `ctors-dtors-eh` |
| 107 | Recovering an MFC GDI OnPaint (CPaintDC/CPen/CBrush/CRgn + | `mfc-collections` |
| 108 | Ghidra's provisional class namespace can mis-home a method | `class-recovery` |
| 109 | POD-only constructors: body assignments in observed store  | `ctors-dtors-eh` |
| 110 | Deeply-optimized functions may not reach a high match from | `big-functions` |
| 111 | Missing assert file/line args are a cheap, systematic scor | `string-handling` |
| 112 | Full-diff forensics beats decompile-reading on hard functi | `big-functions` |
| 113 | The dead-arg-slot assignment is one global, source-immune  | `fp-matching` |
| 114 | A "broken" Ghidra decompile (phantom register args) still  | stays here (below) |
| 115 | Big-stub triage workflow: portprep dossier + const-stores  | `big-functions` |
| 116 | Trivial-ctor factories: define the empty ctor inline in th | `ctors-dtors-eh` |
| 117 | Mac-style two-phase construction: `Construct*BaseState` ar | `ctors-dtors-eh` |
| 118 | Dual-width global reads: type by the widest reader, cast a | `data-modeling` |
| 119 | Never model overlapping views with a union: pick one model | `data-modeling` |
| 120 | nmake U1054 "cannot create inline file" = stale nn?00192 t | stays here (below) |
| 121 | Switch case bodies are emitted in source order: reorder ca | `codegen-shapes` |
| 122 | "Static member taking a node parameter" is usually a __thi | `calling-conventions` |
| 123 | Helpers the original inlines everywhere must be `static in | `codegen-shapes` |
| 124 | Small memsets: value-fills become 0x01010101 dwords; clear | `codegen-shapes` |
| 99-L | Resolve a method's real address through the vtable's ILT t | `vtable-matching` |
| 100-L | Force MSVC's callee-saved-register live-range SPLIT with a | `codegen-shapes` |
| 101-L | A small __thiscall "iterator/cursor" struct that reads `co | `calling-conventions` |
| 102-L | Claiming a small "Construct<Class>BaseState" ctor stub is  | `ctors-dtors-eh` |
| 103-L | Near-miss (95–99%) triage-bucket fix taxonomy — which are  | stays here (below) |
| 104-L | A jump-table switch dispatcher that Ghidra split into per- | `big-functions` |
| 105-L | A referenced .rdata data table Ghidra never symbolized sho | `data-modeling` |
| 106-L | Caller-side `movsx`+`push eax` of a short expression + cal | `calling-conventions` |
| 107-L | CString temp placement: a named local (`CString t(x); targ | `string-handling` |
| 108-L | Two writes at a fixed offset delta inside one bounded loop | `data-modeling` |
| 109-L | A 16-bit store spanning a byte field and its "pad" (`mov w | `data-modeling` |
| 110-L | An inlined-ctor `new` site whose field stores are NOT in d | `ctors-dtors-eh` |
| 111-L | A game class whose method bodies look like hand-inlined MF | `mfc-collections` |
| 112-L | A "cdecl" callee whose original callsites all load ECX rig | `calling-conventions` |
| 113-L | MSVC500 keeps a loop's array bound compare SIGNED (JL) whe | `codegen-shapes` |
| 114-L | Byte-flag guards that load into AL before comparing (`mov  | `codegen-shapes` |
| 115-L | The shared uninitialized `float result` of a switch-heavy  | `fp-matching` |
| 116-L | A callee-cleaned call with `mov ecx, node` inside a list w | `calling-conventions` |
| 117-L | stretch<T> containment scans are two nested inlines: `T* F | `mfc-collections` |

---

# Core process notes

### Confirm the target before rewriting
*(ex decomp-loop note 1)*


- `just compare 0xADDR` once first: a `jmp OtherFunction` diff means it's a thunk —
  implement a call-through wrapper and keep the heavy logic in the destination.
- Intra-module calls route through ILT thunks (`0x40xxxx jmp <impl>`); reccmp does
  not always auto-follow them in verbose diffs. Confirm the real target by
  disassembling the thunk in Ghidra before assuming a callsite mismatch.
- 5-byte ILT `jmp <target>` thunks (e.g. `0x004064e2 jmp TView::TView`) are
  non-semantic linker artifacts — never hand-write them with placement-new bridges,
  pointer casts, or manual vptr writes. The durable fix is real inheritance so the
  base ctor is referenced symbolically. See [[ilt-thunk-retirement]].
- **A self-`this` vtable-slot call whose arg count / `RET n` can't match the
  attributed class's slot means the function is mis-attributed.** Verify the slot by
  reading the real method body (`RET imm`, arg reads) against the callsite (count the
  `push`es before `CALL [vtbl+off]`); on mismatch, trace who loads `ECX` at the call.
  `0x4d3a60` was filed as `TCivToolbar` but its `this` is a `TCivMgr`; re-attributing
  let the finalize call become a real virtual. reccmp pairs by address, so the fix is
  moving the body to the right class file + `symbols.csv` rename — it unblocks
  real-virtual modeling rather than changing the score per se.

### Data-symbol and vtable pairing infrastructure
*(ex decomp-loop note 7)*


reccmp pairs by **name** (stripping C-linkage underscore); values are irrelevant.

- When the original references a named data symbol (`+ g_X (DATA)`, `[g_pX (DATA)]`)
  but the recomp emits a bare immediate, define the global as a real `extern "C"`
  symbol with the EXACT `symbols.csv` name (zero-fill fine) and reference it directly.
  See `src/game/global_data_tables.cpp`. Pointer globals: `void* g_pX = 0;` replaces the
  non-matching `ReadGlobalPointer(imm)` shortcut.
- To convert a `g_vtbl<Class>` manual-vptr-write ctor into a real polymorphic ctor:
  make it `class X : public Base` with a `// VTABLE:` annotation and real `override`s,
  write a plain ctor with NO manual vptr line, delete the `g_vtbl<Class>` global, and
  **delete the `g_vtbl<Class>` row from `config/symbols.csv`** — that last step is what
  makes it pair (otherwise DATA-vs-VTABLE mismatch). Caveat: only matches originals
  whose single vptr write is at the top of the derived body. See commit f6a0588 and
  AGENTS construction rules 1–2.
- Keep the manual write + DATA row only when the ctor is called by name / via jmp-thunk
  (a C++ ctor can't be addressed) or when it deliberately skips an intermediate base.

### Batch repeating templates
*(ex decomp-loop note 13)*


When a vtable region is one repeating template (e.g. TGreatPower score-factor slots
0x8e–0x9e = six shapes × {army,navy}), port it as a batch, not one-off: define the
shared float coefficients as named globals and reconstruct loop shape from the
listing's FSTP slots (Ghidra's decompile of float-heavy code is garbage). See
[[order-class-recovery-cstring-blocker]] and [[next-tgreatpower-vtable-scope]].

### General process
*(ex decomp-loop note 14)*


- Convert `just promote` output to compile-safe member-method C++ immediately; rewrite
  raw `void __thiscall Foo(T* this, ...)` blocks into real method signatures before
  building, then `just regen-stubs` → `just build`.
- If a readability cleanup drops the score, restore the higher-scoring body shape and
  keep the cleanup in helpers/typed views.
- Batch related edits, then a single build + `just compare` over the batch; don't chase
  the last few percent on architecture-correct bodies. See [[big-batch-quality-passes]].
- **Batch compare exists — never loop single `just compare` calls.** `just compare
  0xA 0xB 0xC`, `just compare --file src/game/X.cpp`, and `just compare-class X` all
  run reccmp once with `--json` (one PDB parse for any number of functions).
- (historical) `just sync-ownership` was **deletion-reconciling** (and stub regen ran it
  automatically): `marker_sync` rows whose marker disappeared are pruned; curated notes
  (e.g. `mfc_runtime_macro`) are never pruned. If a deleted function's stub still fails
  to regenerate, check for a leftover curated row. See
  [[stub-regen-thunks-alias-collision]].
- After a vtable-dump correction, verify **every** declared virtual sits at the intended
  slot index — a skipped slot in the header shifts all later entries.
- `override` is a no-op macro under MSVC500 (§12b), so the build won't complain about a
  non-overriding declaration. **`just lint` (real clang) is the only check that enforces
  it** — run it after any base-virtual rename or derived-override edit, before trusting
  `just vtable`. (Caught a TWindow slot 0x60-0x63 rename desync.)

### `function_out_of_order` (decomplint) is a pure textual-reorder fix
*(ex decomp-loop note 25)*


Marked `// FUNCTION:` bodies within one non-header `.cpp` must appear in ascending
address order (folded/by-name markers exempt). Purely cosmetic — definition order
doesn't affect codegen. Cut-and-paste whole comment+function blocks into order; leave
unmarked anonymous-namespace helpers where later code needs them textually first.
Verify with `just decomplint`; the reorder is a score no-op.
(`uv run python -m tools.workflow.reorder_marked_functions <file>` automates it.)

### Comment reflow / formatting can silently eat reccmp annotations
*(ex decomp-loop note 29)*


clang-format with `ReflowComments: true` (the LLVM default) merges an adjacent
`// VTABLE: IMPERIALISM 0x...` (or GLOBAL/FUNCTION/SYNTHETIC/LIBRARY) line into a
preceding over-long prose comment — the annotation becomes mid-sentence text that reccmp
and every gate silently ignore (7 vtables + 1 global lost with all gates green).
`.clang-format` now pins `ReflowComments: false`. After formatting, diagnose with
`grep -rnE "// .*[a-z)\.] (VTABLE|GLOBAL|FUNCTION|SYNTHETIC|LIBRARY): IMPERIALISM" include src`
plus `grep -rn "IMPERIALISM$"` (annotation split across two lines). Repair = put the
annotation back on its own line immediately above the declaration; restored vtables
pair at 100% for free (390→397).

### "Failed to find a match" after editing a marked function = detached marker, not folding
*(ex decomp-loop note 38)*


Symptom: after changing a marked function's signature/body, `just compare 0xADDR` flips to
**"Failed to find a match"** and every vtable referencing that slot drops ~2% (one slot of
~49). Before theorizing COMDAT/ICF folding, **check Hard Rule 3**: an explanatory comment
added *between* `// FUNCTION:` and the declaration detaches the marker, so the symbol
never pairs. Move the prose above the marker. `just marker-gate` catches it; bare
`compare`/`stats` do not — the "unpaired + all referencing vtables −2%" fingerprint is the
fast tell. (Folding is ruled out anyway: §52.) Evidence: `TStream::streamSlot70`
0x488c50, base + override 0%→100% once the marker sat directly on the decl.

### Two cheap recomp-side diffs to sweep in the near-miss (98–99%) band
*(ex decomp-loop note 43)*


Both surface as a *recomp-only* line in `just compare 0xADDR` (green `+`) with no
matching original line, and both are one-line source fixes on already-owned bodies —
no marker/ownership churn, so skip `regen-stubs`.

- **Trailing `+xor al,al` = a Ghidra `undefined` placeholder return that is really
  `void`.** A body written `undefined Foo() { …; return 0; }` makes MSVC emit
  `xor al,al` before the epilogue; the original returns void and emits nothing. Retype
  the decl **and** the definition to `void` and drop `return 0;`. (`undefined` is the
  1-byte placeholder; a 4-byte return would be `xor eax,eax` — at `0x5e5140` the
  original *does* `xor eax,eax` and the fix is the opposite: retype to `int`.) Swept 7
  (TDisplayMgr ×3, TMacViewMgr ×4) 94–98%→100% in one build. These are frequently
  class-introduced virtuals whose decl + definition are self-contained to change; run
  `just format` after (trailing `// slot` comments re-align).
- **Recomp-extra `test rX,rX; je …` = a null guard the original never had.** When the
  original loads a pointer and immediately dereferences it but the port wraps the call
  in `if (p != nullptr)`, delete the guard and call unconditionally.
  (`TInvadeMission::RefreshSlot40` 0x53f7d0, `TNumberText::ShallowClone` 0x4912b0,
  both →100%.)

### Confirm "Built target" before trusting any stats delta; this link does NOT fold identical functions
*(ex decomp-loop note 52)*


If one edit in a lockstep signature change silently fails, `just build` fails (C2511) —
but `just stats` still runs against the **stale** `.exe` and reports a large phantom
"-N aligned" regression. Always confirm the build printed `Built target Imperialism`
first; a whole session once mis-read this as an "ICF fold wall" and reverted correct
work. Empirical anchor: `/OPT:ICF` is **off** — two byte-identical `void f(){}` stubs
(0x596040, 0x596080) survive at distinct addresses — so byte-identical bodies never fold
here (see §20, §38); a real regression has a real cause. Related from the same cluster:

- **A "poison-pill" arg-count mismatch means the modeled arity is wrong.** The base
  no-op stub's `ret N` gives the true arg count (`ret 0xc` ⇒ 3 dwords); recover the
  signature from `ret N` + the overrides, then apply to the base and ALL overrides at
  once (five base stubs sat at 0–50% purely from being declared 0-arg).
- **A dispatcher that `CALL [EAX+byte]` after pushing args is a real virtual on `this`**
  (Hard Rules 9/10) — the 8-byte slot-0x79 dispatchers (0x51adc0/0x51c2f0) hit 100%
  once the target slot's true 3-arg arity was recovered.
- **The shared-ILT-thunk callsite is a permanent ~1-instruction miss** (recomp pairs the
  unscoped `thunk_X`, original the scoped `Class::thunk_X`) — a body whose only residual
  is that `call` caps just under 100% (0x51ad70 → 95.24%). Accept as inherent.

- **A multi-edit python splice that asserts mid-script loses ALL its edits** (the
    write happens at the end), and the failure mode is silent: the earlier "ok" prints
    never happened, the file keeps its old stubs, and compare pairs the address against
    the stale stub (1-5% scores with tiny `+0xADDR,2` recomp extents in the diff).
    After any batch splice, verify the bodies actually landed (`grep` a distinctive
    line per function) before building; prefer one write per replacement, or wrap each
    sub in its own try/write. Confirm suspicious "stub-like" scores by reading the
    recomp bytes at the paired address from build-msvc500/Imperialism.exe via the
    PE-parse pattern.

  *(ex decomp-loop list-note 63)*

- **Run `just detect` after every build completes and before any `just compare`,
    even mid-session.** Comparing against a stale PDB right after a rebuild produces
    phantom "Failed to find a match at 0xADDR" hard-fails and wildly wrong low scores
    for functions that are actually 100% -- re-running detect then compare on the same
    addresses fixed five phantom failures in one batch. Never conclude a claim is
    unverifiable from a compare that ran before detect refreshed reccmp-build.yml.

  *(ex decomp-loop list-note 75)*

- **A sudden mass-unpairing after editing a .cpp is almost always incremental-build
    line staleness — clean-rebuild before believing it.** After adding ~30 lines (four
    promoted bodies) to TForeignMinister.cpp, `just stats` reported -15 paired / -8
    aligned, with reccmp erroring `Failed to find function symbol with filename and
    line: <file>:<N> ... the compiler has probably inlined this function` for real,
    substantially-ported functions (Call8C 52%, Call90 61%) — clearly not inlined.
    Editing a file shifts every later function's line number; an incremental
    `just build` can leave the PDB's line table out of sync so reccmp can't locate the
    functions by (file, line). `rm -rf build-msvc500 && just build && just detect`
    restored every pairing and showed the true delta (+2 aligned). Do the clean rebuild
    before diagnosing a mass-unpairing as a real regression or (worse) reverting good
    ports over it. Genuine per-function phantom FP wobble (note 18/47) still applies on
    top, but it never mass-unpairs whole swaths of a TU.

  *(ex decomp-loop list-note 92)*

- **A low-scoring "already-ported" leaf may just carry the WRONG body — re-read the
    Ghidra decompile before assuming it's an inlining/codegen limit.**
    TMinor::ReturnFalseNationStateCapabilityFlag90 (0x4e45f0) sat at 9.5% with a body
    that range-checked `arg in 0xd..0x10` — logic copy-pasted from the unrelated
    IsSpecialNationInteractionResource predicate. The real body compares `arg` against
    four saved fields (diplomacySaveFields134[0..3]). Two further matching details took
    it 24% → 91.7% → 100%: (a) MSVC compiled the original as **init-to-0, set-to-1,
    single return** (`char r=0; if(...) r=1; return r;`), NOT `if(...) return 1; return
    0;` — the early-return form emits the `xor al,al` at the wrong point and flips the
    branch polarity; (b) the original loads the arg as a **word** (`mov dx, word[esp+4]`),
    proving the vtable slot param is a `short`, not the `int` the base decl carried.
    Narrowing the slot param to `short` across the base (TCountry, a return-false stub
    that ignores arg → stays 100%) and the override in lockstep produced the word load.
    Lesson: for a mispredicting boolean leaf, check body-logic first, then the init/return
    shape, then the arg width — and a return-false base is free to re-type its ignored
    param to match a derived override's real word/byte usage.

  *(ex decomp-loop list-note 93)*

- **A FID miss is not evidence of game code — the relocation-masked `.obj` matcher is
    the authoritative identity oracle.** Ghidra FID has minimum-length/score thresholds,
    so it silently skips small/aliased CRT/MFC functions (rand at 0x005e83f0 kept the
    invented name `GenerateThreadLocalRandom15`, no `_rand` symbol, no library ownership).
    The durable fix is `just build-library-oracle`: parse the vendored
    `libcmt.lib`/`nafxcw.lib` COFF members, mask each function's relocation fields and trim
    trailing 0xCC/0x90 padding to a normal form, and exact-match executable function bytes
    against it — raw bytes differ (linker-assigned addresses) but the masked bodies are
    equal. Hard-won parser details: (a) function extents come from **EXTERNAL symbols
    only** — STATIC symbols are internal jump-table labels (memmove.obj is one 821-byte
    COMDAT section full of `LeadUpVec`/`UnwindUp*` labels; bounding on them truncates the
    function to 100 bytes). (b) MS archive longnames are **NUL-terminated**, and the
    offset-0 object member is `/0` (don't skip it). (c) Ghidra function sizes exclude the
    object's trailing alignment padding, so trim both sides to the last real instruction.
    (d) **Trivial bodies collide**: an empty ctor/dtor or `return 0` is byte-identical
    across many classes, so any normal form matched by >1 executable address is
    non-discriminative — demote to review, never auto-name by body alone. (e) Auto-convert
    unowned rows to library only inside the dense range and only when the invented name is
    unreferenced in manual source (else removing its stub breaks the link). The oracle
    found ~1100 confident identities incl. 48 FID-missed conversions and 25 game-code
    mislabels (13 libcmt float internals ported as `bignum96_math.cpp`). `just
    library-identify 0xADDR` surfaces all of this; `library-identity-gate` pins it.

  *(ex decomp-loop list-note 96)*

- **Moving an oracle-flagged game-code mislabel to library: two shapes.** When
    `library-identity-gate` / `config/msvc500_library_oracle_review.csv` flags a
    high-confidence unique match owned by manual game code, first classify it:
    (a) **Whole-file / free-function CRT** with no compiled callers (e.g. the 13
    float-conversion internals in `bignum96_math.cpp` — `__RoundMan`/`___dtold`/
    `__mtold12` from intrncvt/cfout/mantold.obj) — delete the body/marker, run
    `sync-ownership` (prunes the now-marker-less rows) then `apply-library-oracle`
    (Case B claims the unowned in-range addresses as library). Clean, no caller work.
    (b) **Free function WITH callers** (e.g. `__mbscmp` at 0x5e7980, was
    `CompareAnsiStringsWithMbcsAwareness`, called by 8 files) — like the rand fix:
    replace its header declaration with `extern "C" int __cdecl _mbscmp(...)`, rename
    every callsite to the real symbol, delete the definition, then prune+convert.
    Removing a body can *cascade*: functions it called (here `_lock`/`_unlock` from
    mlock.obj) become unreferenced and auto-convert too. Verify each is a genuine
    library match (unique/high, cc=1, sensible .obj member) — the build link is the
    backstop. (c) **MFC method inherited by a game class** (`CWnd::RunModalLoop` at
    0x60a60a owned by TView, `CWnd::GetStyle`, `CRect::DeflateRect`, `CDialog`/
    `exception` ctors) — these are NOT mechanical: the address is the inherited MFC
    method's code, so the fix is real inheritance modeling (class-recovery /
    vtable-matching), not just re-marking. Leave them allowlisted in
    `config/library_oracle_gamecode_allowlist.csv` until the class model is recovered.
    Always rebuild after a move: converting rand exposed 17 callsites of its invented
    name; a removed stub with a live caller is an LNK2001.

  *(ex decomp-loop list-note 97)*

### A "broken" Ghidra decompile (phantom register args) still has a clean listing
*(ex decomp-loop note 114)*


Phantom `unaff_BX`/`unaff_SI` parameters + a bogus switch usually mean Ghidra lost stack
tracking across a __cdecl call whose `ADD ESP,N` cleanup was scheduled late — the function
itself is fine. Recover from the raw listing: real stack args are the `MOVSX/MOV reg,
[esp+4/8/0xc...]` reads at entry (count them; `RET 0x14` = 5 args), jump tables read as
`JMP [reg*4 + table]` with dense case blocks after, and consecutive-slot virtual calls
(`CALL [reg + 0x214/0x218/...]`) are just unqualified member calls on `this` that C++
regenerates verbatim from a plain switch. 527B of "undecompilable" render dispatch ported
to 86% in one pass this way (residual: one EDI/EBX assignment swap).

### nmake U1054 "cannot create inline file" = stale nn?00192 temps
*(ex decomp-loop note 120)*


A crashed docker build leaves nmake inline-file temps (nn[a-z]00192, nm?00192, a00820*)
in build-msvc500/; once the namespace is exhausted every subsequent build fails with
U1054 while `just stats`/`just compare` silently measure the STALE binary — which
presents as a phantom mass drop (dozens of functions, off-by-one-function diffs from
shifted PDB lines). If stats suddenly shows ~100 regressions in untouched code, first
verify the build actually relinked ("Built target Imperialism"), then `rm -f
build-msvc500/nn?00192 build-msvc500/nm?00192 build-msvc500/a00820*` and rebuild.

- **Near-miss (95–99%) triage-bucket fix taxonomy — which are clean single-line wins
     and which are traps.** After `just triage 0xADDR`, the bucket + one diff line usually
     tells you if it's fixable in isolation. **Reliably fixable (each a 1-line source fix
     verified this session):** (a) *missing assert args* — a `codegen` bucket showing
     `orig-only: push 0xLINE; push "D:\Ambit\...cpp"; add esp,8` means a
     `TemporarilyClearAndRestoreUiInvalidationFlag()` call is missing its `(path,line)`
     arguments; model the path as a real `// GLOBAL:` string (read it via
     `just ghidra-read-data 0xADDR str`) and pass `(g_sz...Path, 0xLINE)` (e.g. 0x4db7d0).
     (b) *literal-vs-named-constant* — a `codegen`/data line `fld [g_Named]` vs
     `fld [<OFFSET1>]` where a bare `return 0.0f;`/literal makes MSVC allocate a fresh
     constant, but the original reuses an existing zero/constant global; return the named
     global instead of the literal AND ensure that global carries its `// GLOBAL:` marker so
     reccmp pairs the data symbol (e.g. 0x53d420 → g_..._0065A9E8, which was ALSO missing its
     marker). (c) *wrong calling convention* — a `codegen` line `ret 4` vs `ret`: verify the
     callee's real `RET`/`RET 0x4` in Ghidra, then annotate the free function `__stdcall`
     (callee-cleans) on BOTH prototype and definition (e.g. 0x5a99e0 DrawHexSelectionOutline).
     **Traps — do NOT chase (verified dead ends this session):** (d) *ax-vs-eax / bx-vs-bl
     register-width `reg_alloc` on a single `movsx`/`mov`* — the types are already correct;
     MSVC's 16- vs 32-bit destination choice is register-reuse (it relies on stale high bits
     of a reused index reg), not source-controllable; flipping `short`↔`int` just moves the
     mismatch (0x5a24a0 sfx token, 0x522000). (e) *`call_target` on a LIBRARY function*
     (AfxMessageBox `(LPCTSTR,UINT,UINT)` vs `(char const*,...)`, or a thiscall method whose
     ILT thunk resolves fine but shows `(short)` vs `(void)`) — an MFC/symbols pairing
     artifact, not a codegen diff. (f) *`missing_annotation` on an end-of-array pointer
     sentinel* (`cmp esi, &table[N]` labeled as the adjacent global) — the loop-end address
     is unnamed in both binaries so reccmp can't pair it; no clean source fix. (g) *widening
     a shared struct field or a virtual's param to drop one caller's `movsx`* — correct in
     isolation but regresses the other N consumers; only do it with full multi-site + stats
     verification, never as a one-function win.

  *(ex decomp-loop list-note 103)*
