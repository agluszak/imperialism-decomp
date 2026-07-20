---
name: codegen-shapes
description: MSVC500 codegen idioms for the Imperialism decomp — loop rotation and induction (JL vs JB bounds, pointer vs index), branch layout/fall-through, switch case ordering, byte-bool materialization (sete/test al), magic-number division, abs(), memset folding, struct copies, frame-slot packing, short-parameter width tells. Load when a diff shows structural branch/loop mismatches, inverted compares, peeled iterations, sign-extension noise, or when choosing how to write a loop/switch/flag test so it compiles to the original shape.
---

# Codegen shapes (branches, loops, switches, scalar idioms)

The compiler is deterministic: nearly every "weird" instruction pattern is a specific
source shape. Match the shape, not the semantics:

- **Branch order = fall-through order.** MSVC500 lays `if/else` bodies in source
  order; a body emitted at the bottom means the source used an early return. Read the
  `je/jne` target before writing the condition.
- **Loops**: an index-based `for (i = 0; i < N; ++i) use(arr[i])` strength-reduces to
  cursor walks but keeps a SIGNED bound (`jl`); a hand-written pointer-cursor loop
  compares unsigned (`jb`). Multiple arrays indexed by one `i` become parallel
  cursors automatically — don't hand-hoist them.
- **Byte flags**: `mov al, [flags+i]; test/cmp al` means a byte LOCAL
  (`unsigned char f = flags[i];`); a direct `cmp byte ptr [...], imm` means the
  memberless form. `sete/setne al; test al, al` means a materialized `char` bool
  variable, not a plain `if`.
- **Integer division/modulo by constants** inline as magic multiplies
  (`0x51eb851f` = /100, `0x66666667` = /10 …). Write the plain `/ 100` and let the
  compiler emit the magic; hand-rolled bit-twiddles produce __allmul garbage.
- **Compare forms are literal**: original `cmp x, 0x180; jge` comes from `>= 0x180`,
  not `> 0x17f`. Match the constant AND the operator.
- **Switch cases emit in SOURCE order** — reorder your `case` bodies to the binary's
  body order, keep the `case` labels' values.

## Field notes

### CRT idioms are intrinsics, not hand loops
*(ex decomp-loop note 11)*


- A `do/while` decrementing `0xffffffff` then `~counter-1` is MSVC's `strlen`
  (`repne scasb`). Declare `extern "C" unsigned int __cdecl strlen(const char*);`,
  `#pragma intrinsic(strlen)`, call it (`0x00489070` 28.57%→100%).
- `memset`/`memmove` live at fixed CRT addresses (`memset` `0x005e9a90`, memmove-style
  `0x005e9cf0`/`0x005e8420`). Call through declared extern thunks + typed casts (rule
  14) so MSVC emits a direct `CALL rel32`; a raw-address cast emits a non-pairing
  indirect `call reg`.

### Branch-order = fall-through: read the `je`/`jne` target to pick which body is the `if`
*(ex decomp-loop note 51)*


A listing opening `cmp x,5 / je <far> / <body...>` falls through to the INEQUALITY body,
so the source is `if (x != 5) { unequal } else { equal }` — writing the "natural"
`if (x == 5)` swaps the block order and misaligns the entire function (pinned ~25% until
inverted; `TMapMgr::ResolveMapTileVariantSpriteFromAdjacencyState` 0x5108d0). The Ghidra
decompile's `if/else` nesting does NOT encode fall-through; read the actual jump target
(near vs far). Related lessons from the same cluster:

- **An `int param` + `short s = (short)param` split is real, not decompiler noise**: when
  the body sign-extends (`MOVSX ebx,si`) but keeps the full dword live in another reg,
  model BOTH and use each where the decompile does. Collapsing to one `short` param
  removes a variable the original allocated.
- **A byte-compare-only field read is `MOV AL` / `CMP AL,imm` regardless of signedness**;
  signedness only forces MOVSX/MOVZX when the byte feeds arithmetic or a switch selector.
- **Don't cache a member pointer the original re-reads.** Caching `this->terrainStateTable`
  in a local consumed a register, forced a `this` spill, and shifted every `[esp+…]`
  offset (capped 14.6%); dropping the cache matched the frame (→32%, 0x510210). Mirror
  the original's caching decisions — a "cleaner" CSE can cost more than it saves.
- **Adding ~2KB of ported code can flip which recomp address reccmp pairs near-identical
  twin accessors to** (100→~43% on untouched functions). Layout noise, not a regression;
  confirm the net stats delta and absorb into the baseline (§47).

### Same inline function, two call shapes in one binary = per-TU inline-budget exhaustion, not flags or source tricks
*(ex decomp-loop note 55)*


When an MFC/afx.inl (or any header-inline) function appears BOTH folded away
(`call ::operator new` directly) and called out-of-line (`call CObject::operator new`
COMDAT copy at 0x41b1c0) for the *same* classes, do not invent a source-side model —
no class-scope operator overrides, no per-TU visibility macros, no per-file /Ob0.
MSVC500 gives each TU a finite inline-expansion budget: once exhausted, later calls
to `inline`-marked functions are emitted out-of-line (verified with the Docker
toolchain: a generated TU flipped after ~1750 expansions; the original binary's
factory giants flip mid-function — 0x415fe0 after 39 allocs, 0x41b6d0 after 10,
0x4601b0 never). Consequences: (a) such wrappers are LIBRARY code
(mfc_heap_library.cpp), never game ports; (b) reproducing exact flip points is a
TU-composition concern (which functions share the .cpp, in what order) to be tuned
when the TU is mostly ported; (c) `just alloc-audit` prints each original function's
inlined/out-of-line allocator sequence as ground truth, and `just decode-builder`
decodes builder bodies. Diagnostic tell: the out-of-line copy sits at a game-code
address adjacent to unrelated game functions (COMDAT emitted by whichever TU called
it first), and DYNCREATE CreateObject bodies always show the inlined form (small
functions, fresh budget).

### Byte-Boolean materialization: `sete/setne al + test al,al` means an unsigned-char Boolean, and int `BOOL` folds
*(ex decomp-loop note 56b)*


When the original branches through a materialized byte (`xor eax,eax; cmp ...;
sete al; test al,al; je`) instead of comparing flags directly, the condition was
computed into a Mac-style byte Boolean (`unsigned char`/`char`), usually via a
file-local `static __inline unsigned char IsX()` helper or a byte local. Writing
the same condition as `BOOL` (int) or as a bare `if (expr)` folds to a direct
`cmp/jne` and loses ~3 instructions per site (SaveGameWithModeAndOptionalLabel
0x56da50 went 53%→92% on this fix alone). Corollary: return types the callers
test with `test al,al` are byte Booleans, not BOOL — e.g.
TryGetFileMetadataForPath (0x5d4c10) returns `(unsigned char)CFile::GetStatus(...)`.

- **`r = *rectPtr;` (struct assignment) vs member-by-member copies emit different
    code.** Struct assignment produces `lea dst` + temp-register member moves; four
    explicit `.left = p->left;` lines produce direct indexed stores. Match the
    original's shape (0x49f0c0 went 36.7% → 73.1% switching to struct assignment;
    same pattern earlier in TOneTimeAnimation's ctor). Similarly, zeroing an array
    through a named base pointer (`float* sums = arr; sums[0] = 0; ...`) reproduces
    the original's `lea` + offset stores where direct indexing does not.

  *(ex decomp-loop list-note 65)*

- **Frame-slot packing is controlled by scope: block-scoped same-size locals pack
    into one slot; a function-scope local keeps its slot live to the end.** When the
    original has two iterator slots (0x18 and 0x24) but the recomp packs all loops
    into one, the original declared the early iterator at function scope (its
    lifetime crosses the later loops) while the case-local iterators packed into the
    second slot (0x59c440, 46.8% → 68.4%). Conversely a recomp frame LARGER than the
    original means block-scoped aggregates (RECTs) that the original reused as one or
    two function-scope buffers.

  *(ex decomp-loop list-note 67)*

- **MSVC500 for-loop-declared variables leak into the enclosing block scope (C89
    rules), so two sibling `for (int count = ...)` loops in the same braces is
    `error C2374: redefinition`.** Ghidra's decompile reuses one Ghidra-local name
    (`count`) for both loops since it doesn't model C++ block scoping; give each loop
    its own name when porting (`dwordCount`, `byteCount`) instead of copying the
    Ghidra name verbatim.

  *(ex decomp-loop list-note 70)*

- **`abs()` matches the compiler's `cdq/xor/sub` idiom; an explicit sign-shift local forces
    `sar` instead.** For `abs(a-b)`, write `abs(static_cast<int>(a) - static_cast<int>(b))`
    (MSVC5 emits `sub; cdq; xor eax,edx; sub eax,edx`), NOT a named
    `int sign = delta >> 31; (delta ^ sign) - sign` which emits `mov;sar;xor;sub` and mismatches.
    Verified taking 0x522c10 from 50% -> 92%.
  *(ex decomp-loop list-note 77)*

- **When a two-way branch's ELSE block is laid out inline (fall-through) with the THEN block
    out-of-line (`cmp; jle <then>; <else>; jmp`), write the ELSE condition first.** For the
    original `cmp cx,0x6c; jle <colB>; sub ecx,0xd8; jmp after; <colB>: ...`, source
    `if (col1 <= 0x6c) { ...colB... } else { col1 -= 0xd8; }` lays THEN first and mismatches;
    flip to `if (col1 > 0x6c) { col1 -= 0xd8; } else if (col2 > 0x6c) { ... }` to match. Took
    0x522c10 from 92% -> 100%. General rule: match the block the compiler put at the
    fall-through, not the source's natural then/else order.
  *(ex decomp-loop list-note 78)*

- **Empty-collection linked-list scan: match MSVC's `xor eax,eax; jmp` null path with a
    null-case-FIRST if/else-if/else over an UNINITIALIZED result var.** For a "find the
    matching node, else null" head-scan (e.g. TTaskForce::SetTaskForceOrderSelectionByNodeId
    0x5549a0), the original emits, right after the head-load + `test`, a leading
    `jne have_head; xor eax,eax; jmp check` -- i.e. the empty-list case is the fall-through
    then-block that explicitly zeroes the result. Two C++ forms that look equivalent do NOT
    reproduce it: (a) `node = head; if (node && node->obj != t) node = ...;` drops the `xor`
    entirely (compiler knows `node` is already 0) -> 90%; (b) `if (head != null){...} else
    {node=null;}` (inverted, else-null) pushes the `xor;jmp` to the BOTTOM -> 81%. The one
    that hits 100% is the null-test-first three-way over an uninitialized var:
    `TMapOrderChildLinkNode* node; if (head == nullptr) node = nullptr; else if
    (head->object_ptr == t) node = head; else node = head->next->FindNodeMatching(t);`.
    Leave `node` uninitialized so each branch assigns it, and put the `== nullptr` branch
    first so its zero-assignment is the leading then-block. (General rule: the branch whose
    body is the compiler's fall-through is the one you write first; an uninitialized target
    forces the explicit `xor` the pre-initialized form elides.)

  *(ex decomp-loop list-note 86)*

- **Match the compiler's `>= N` / `> N` compare form, not just the semantics.**
    `if (ver > 0x16)` and `if (ver >= 0x17)` are identical semantically but MSVC5 emits
    different code: `> 0x16` -> `cmp 0x16; jle`, `>= 0x17` -> `cmp 0x17; jl`. When
    structured triage reports an `immediate_value` (`0x17` vs `0x16`) or a
    `branch_condition` at the trusted compare, the original wrote the boundary the
    other way — flip your operator to match. Cheap, codegen-faithful, safe (reccmp pairs
    by address; branch target unchanged). Do not derive this from a weak raw-diff
    alignment: if reccmp reports `inconclusive`, there is no trusted source diagnosis yet.

  *(ex decomp-loop list-note 89)*

- **Pointer-walk vs index-loop is an optimizer choice you can't reliably force from a
    source tweak.** When the orig bounds a table loop by `add edi,4; cmp edi, &table_end`
    (a literal end-of-array address, e.g. `0x6a436c` = `&g_apTerrainTypeDescriptorTable[23]`)
    while your build indexes `table[i]` with a counter compare, the original compiler
    strength-reduced the index to a pointer. MSVC5 does this only when the loop body lets
    it drop the integer index entirely; a body that also uses the index as an `int` arg
    (e.g. an eligibility call `IsEligible(i)`) pins index addressing. Rewriting the C++ as
    an explicit pointer walk rarely reproduces it cleanly and risks other regressions —
    treat this residual as expected on table-iteration loops rather than chasing it.

  *(ex decomp-loop list-note 91)*

### Switch case bodies are emitted in source order: reorder cases to the binary layout
*(ex decomp-loop note 121)*


MSVC500 lays out `switch` case BODIES in the order they appear in source (the jump table
maps values to those blocks; the blocks themselves follow source order). For a big
dispatch (TTechMgr::HandleAbilityUnlock 0x5afd00, 27 cases), writing cases in ascending
numeric order scored 47%; reordering the case blocks to the addresses in the original's
body (read the jump table, sort targets, emit `case` labels in that order) took it to
95%+ with no other change. Dump the jump table (dword array right after the dispatch),
map each target back to its case value, and write the C++ cases in target-address order.

### Helpers the original inlines everywhere must be `static inline`; spell member re-reads at the caller
*(ex decomp-loop note 123)*


When the same multi-line sequence (null-check + loop) appears verbatim inside several
original functions but is also a standalone function nowhere, it was an inline helper:
define it `static inline` in the .cpp (MSVC500 /Ob1 expands it, including loops) —
TAdmiral.cpp's RecomputeMapOrderOwnerActiveSelection took 0x552250 from 14% to 85%.
Watch the argument expression: if the original reloads `this->field` after an
intervening store (e.g. `[node+0x20]=0` then re-reads `[this+8]`), the caller passed
`this->field->member` (re-evaluated), not a saved local — write the member expression
at each call site instead of hoisting it.

### Small memsets: value-fills become 0x01010101 dwords; clears may span several named fields
*(ex decomp-loop note 124)*


`memset(p, 1, 4)` emits `mov dword [p], 0x1010101`; `memset(p, 0, 8)` two zero dword
stores; sizes >= ~26 use `rep stosd (+stosw/stosb)`. When an init function's original
shows merged dword stores of 0x01010101 or a rep-clear whose byte count crosses several
named fields (0x5aeff0: one 0x1a-byte clear covering perTechUnlockFlag180[3..] +
hasProductionOrder193 + pad194), the source was a memset over the flat span — write
exactly that memset (with a comment naming the fields it crosses) instead of per-field
stores. Also from the same function: seven-nation table inits ran as TWO separate
`for (n = 0; n < 7; ++n)` passes (different table subsets each), not one merged loop —
match the pass structure before chasing store order (24.9% -> 69.3%).

- **Force MSVC's callee-saved-register live-range SPLIT with a genuine phi variable when
    a nil-alloc pattern holds `this` across `new` AND the result across a later `MessageBoxA`.**
    The `p = new T; if (p) {construct} ; if (!p) {MessageBoxA; assert} return p;` idiom
    (CreateLinkedOrderNode 0x00552650) has TWO values needing callee-saved registers: `this`
    (live across the `new` call) and the node result (live across the assert's MessageBoxA).
    The original reuses ONE register (ESI): `this` in ESI up to `this->prev_link = node`,
    then ESI is dead and reused for the result via a `mov esi,eax` at the alloc-check merge
    (`if p==0: xor esi,esi` / else: construct-in-EAX then `mov esi,eax`). Modeling it with a
    single variable (`node = new; if (node){...}; if(!node){...}; return node;`) makes MSVC
    keep the node in ESI for its *whole* range and spill `this` into an extra EDI
    (`push edi`) → ~50%. Fix: split into a scratch `raw = new T` used only during
    construction (stays in EAX) and a distinct `result` phi assigned in BOTH branches
    (`if (raw != 0){ construct; result = raw; } else { result = 0; }`), then assert/return
    `result`. The distinct two-branch assignment materializes the phi into the callee-saved
    return register at the merge, freeing `this`'s register for reuse → 100%. Also: put the
    non-null (construction) branch FIRST as the `if (raw != 0)` fall-through so the `xor`
    null-branch lands at the end, matching the original's block order; and pass the (nil)
    result pointer as the MessageBoxA HWND (`reinterpret_cast<HWND>(result)`, what the
    original source did) rather than a literal 0. CAUTION: the construction anti-pattern gate
    regexes `\boperator\s+(?:new|delete)\s*\(` — a *comment* like "raw operator new (no init)"
    trips it; write "non-value-initializing `new`" instead.

  *(ex decomp-loop list-note 100)*

- **MSVC500 keeps a loop's array bound compare SIGNED (JL) when the source loop is
     index-based and strength-reduced, but UNSIGNED (JB) for an explicit pointer-cursor loop.**
     `for (slot = 0; slot < 7; ++slot) use(g_apNationStates[slot])` strength-reduces to the same
     add/inc/cmp-pointer shape as a hand-written cursor loop but emits `cmp esi, END; jl`;
     writing the cursor loop by hand emits `jb`. When the orig bound check is JL, write the
     indexed form and let the compiler derive the cursors (it will also derive parallel cursors
     for flags[i]/priorities[i]/nations[i] in one loop — don't hand-hoist them).

  *(ex decomp-loop list-note 113)*

- **Byte-flag guards that load into AL before comparing (`mov al, [flags+r]; cmp al, 1`) are
     a byte LOCAL in the source; a direct `cmp byte ptr [...], imm` is the memberless form.**
     0x4e9a50's region loop only matched (+11pp) after `unsigned char nodeFlag =
     mapNodeStateFlags[region]; if (nodeFlag != 1) continue;` — with the adjacent `linkRegion=-1`
     init placed BETWEEN the load and the compare, exactly where the orig schedules `or ebx,-1`.

  *(ex decomp-loop list-note 114)*
