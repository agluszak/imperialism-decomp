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

- **A "same base, different displacement" diff on two fields of one object is usually
     UNSPECIFIED EVALUATION ORDER, not a wrong field.** When the original loads `[r+A]`
     before `[r+B]` and the recomp loads `[r+B]` first, and both offsets are correct
     members, the source is handing both fields to one expression whose operand order
     C++ leaves unspecified. VC5 then picks the other order. Fix by sequencing the
     first-loaded field into a local, which is a legal, natural source form — not a
     contortion:
       `return GetPosition() >= GetLength();`  -> loads slot 0x30 before 0x28
       `int position = GetPosition(); return position >= GetLength();` -> matches
     Confirmed twice: TStream::IsAtEnd 0x00488a80 (now effective) and
     TNumberedIcon::DoPostCreate 0x005074e0 (82.35% -> 100%), the latter a `CRect(a-16,
     b-16, a, b)` constructor whose arguments MSVC evaluates right-to-left.
     Diagnose before editing: confirm BOTH displacements name real members of the same
     class. If each function uses both offsets and only the order differs, it is this;
     if one displacement has no member behind it, it is a real layout bug.
     Counter-example worth knowing: it does not always yield.
     TTurnEventDialogFactoryRegistry::RunRegisteredDialogFactoriesByEventCode 0x00491cc0
     keeps loading +0x28 before +0x24 under both operand reordering and local
     sequencing (both measured, both 92.59%) — when two forms fail, stop and leave the
     residual rather than inventing a third.
     Corollary for triage: `memory address at original` is NOT a synonym for
     "wrong field". A bulk offset-fix pass over that bucket will corrupt correct source.

### Length-prefixed collection loops are `while (count-- != 0)`, not a bottom-decrementing `for`

Every save-stream reader that consumes a count followed by that many records writes the
loop the same way, and it is not the form the port usually reaches for. The tell in the
listing is a **decrement before the test, with the pre-decrement value tested**:

```
mov eax, dword ptr [count]     ; load
mov cx, ax                     ; keep the OLD value
dec eax                        ; decrement now
test cx, cx                    ; test the old value
mov dword ptr [count], eax     ; store back
je  end
```

or, when the counter lives in a register, `mov ecx,eax / dec eax / test ecx,ecx / jz end
/ lea edi,[eax+1]` — the `lea` restoring the trip count is the same idiom with the
counter re-materialized.

That is `while (count-- != 0) { ... }`. Writing it as `for (int n = count; n != 0; --n)`
compiles to `test eax,eax / je` with the decrement at the bottom instead, and costs
5–19pp on a reader of any size. Measured on one batch:

| function | for-loop | `while (count-- != 0)` |
| --- | --- | --- |
| `TArmyMgr::ReadFrom` 0x4a1b80 | 82.7% | 92.8% |
| `TArmyMission::ReadFrom` 0x53c3d0 | 68.6% | 87.2% |
| `TTaskForce::ReadFrom` 0x552d10 | 59.9% | 68.6% |

Two companion facts from the same batch:

- **The count is an `int`, even though it arrives from `ReadInteger()` (a `short`).** The
  `movsx eax,ax` immediately after the call is the widening; a `short` counter adds a
  `cmp ax,bx` the original does not have.
- **One scratch local often serves several reads.** When consecutive `ReadBytes(&x, 2)`
  calls all target the *same* stack slot and the loop then decrements that slot in place,
  that is one reused variable, not several the compiler happened to colour together.
  `TTaskForce::ReadFrom` reads two zone ordinals and the child count into `esp+0x10` and
  counts down in it; `TCountry::ReadFrom` reads both of its trailing counts into
  `esp+0x28`. Splitting them into separate named locals grows the frame by a dword and
  shifts every later slot, which shows up as a diff on lines you did not touch.

### Act inside the search loop; a found-flag after it is a different function

A search-then-use body has two spellings, and VC5 does not treat them as equivalent:

```cpp
// costs a callee-saved register and a zero-init
TUnit* found = 0;
for (unit = it.Reset(); it.More(); unit = it.Advance()) {
  if (unit->tag == wanted) { found = unit; break; }
}
if (found != 0) { ...use found... }

// what the original emits
for (unit = it.Reset(); it.More(); unit = it.Advance()) {
  if (unit->tag != wanted) { continue; }
  ...use unit...
  break;
}
```

The tell in the diff is an extra `xor <callee-saved>,<callee-saved>` near the prologue plus a
frame one dword larger than the original's, with every later stack reference shifted by
4 — the flag variable's slot. `TArmyStack::AddFirstCountryUnitOfTypeToStack` 0x4a7a40 went
**57.89% → 100% exact** on this change alone, with no other edit.

Worth checking whenever a ported body reads "find it, then do something with it": the
original usually does the something where it found it. The same shape explains frame-size
diffs in bodies that otherwise look structurally identical.

### Array-of-class construction: three shapes, and only `/Ob0` picks the iterator

*(2026-07, `just vector-ctor-probe`, bd cinw.18)*

A local `T a[N]` where `T` has a constructor compiles to one of three shapes, and which
one you get is **not** a per-translation-unit option in the way it looks:

| shape | what it looks like | when MSVC500 emits it |
| --- | --- | --- |
| inline store loop | `mov BYTE PTR [eax],0` / `add eax,STRIDE` / `dec ecx` / `jne` | the element ctor is expandable (in-class / `inline`) and inline expansion is on |
| ctor call loop | `mov ecx,esi` / `call ??0T@@QAE@XZ` / `add esi,STRIDE` / `dec` / `jne` | the element ctor is out-of-line, `/Ob1` or `/Ob2` |
| vector-ctor iterator | `push ctor` / `push N` / `lea` / `push size` / `push base` / `call ??_H` | **`/Ob0` only** (with `/O2` or `/Od`) |

Measured across element size (0x20..0x100), count (2..64), frame size, position relative
to loops and calls, EH state, `new[]` with a runtime count, and `/Od /O1 /O2 /Ob0 /Ob1
/Ob2 /GX-`: **nothing except `/Ob0` selects the iterator.** Size and count in particular
do not — a `CStr255[2]` inlines just as readily as a `CStr32[2]`. Do not reach for
`#pragma optimize("ys")` or a TU split to chase an iterator call; both were measured and
neither works.

The reason the table reads that way: the iterator call **is** the lowering, and both loop
shapes are inline expansions of it. `/Ob0` keeps the call; `/Ob1`/`/Ob2` expand it into a
loop, and then expand the element ctor into that loop too when the ctor is expandable.

**But `/Ob0` is not what the retail binary did, so do not "fix" an iterator mismatch by
setting it.** Measured directly: `docs/reference/original_module_map.csv` puts 0x4a2900
and both CStr constructors in `Cross/UArmyMgr.cpp` (0x4a1f80..0x4a9990), so that module is
the one that would have to be `/Ob0`. Forcing `/Ob0` on exactly those 42 functions moves
20 of them down and 1 up, mean **-6.03 pp**, with four 100% functions falling to 67-76%;
the neighbouring `Cross/UAmbit.cpp` functions lose 34.64 pp on average. A module compiled
`/Ob0` would have improved, not regressed. So MSVC500 has a second route to `??_H` that
this matrix has not found yet — extend `just vector-ctor-probe` rather than reaching for
the flag.

The one thing `/Ob0` does deliver is address-taking: under it, 0x4a31c0/0x4a31e0 pair at
100%. That is not worth 20 regressions, but it confirms the bead's premise that the
constructors re-pair automatically once something takes their address.

Two corollaries worth knowing before you model an element type:

- **A destructor on the element switches `??_H` to `??_L`** (`eh vector constructor
  iterator`, five arguments) and adds a `??_M` cleanup call. So an original that calls the
  four-argument `??_H` proves its element type has **no** destructor.
- **Under `/Ob0` a record local emits a call to the record's own constructor**, with the
  member arrays going through the iterator *inside* that constructor. An original that
  shows iterator calls inline in the caller, with no enclosing ctor call, therefore had
  its enclosing construction expanded while the element ctors were not — a combination
  `/Ob0` alone does not produce.

`just vector-ctor-probe [--sweep]` re-runs the whole matrix against the real MSVC500 in
Docker and prints what the compiler actually emitted, so extend it rather than guessing
when a new array-construction mismatch turns up.

### Compiler array helpers are `??_H` / `??_L` / `??_M`, never gameplay functions

The probe emits `??_H@YGXPAXIHP6EX0@Z@Z` byte-for-byte identically to retail 0x412600,
which had been carrying the invented name `InvokeCallbackForRecordRangeWithStride`. If a
small function loads (count, base, size, callback) off its own stack, calls the callback
through a register with `ecx` set to a walking pointer, and returns `ret 0x10`, it is
`` `vector constructor iterator' `` — claim it as a compiler helper (construction Hard
Rule 6) instead of naming it after whatever the callers happen to construct.
