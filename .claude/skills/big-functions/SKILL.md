---
name: big-functions
description: Port huge Imperialism functions (500B-12KB) — monolithic bodies, giant switch dispatchers, turn-event machines, deep FP scorers. Load whenever a target stub is big or a function feels "too complex to port": size is never a reason to postpone or approximate. Covers the dossier workflow (decode the full listing first, resolve every thunk, then transcribe), per-case switch transcription, keeping monoliths in one TU, and when a structurally-correct 40-60% is the right outcome.
---

# Big-function porting

Big functions are ported like small ones, just with a decode phase first. **Never**
postpone, stub, approximate, or split a function because it is large — a
structurally-faithful port at 40–60% beats a deferred TODO every time, and most of a
big function's bulk is repetition (cases, field stores, call rows) that transcribes
mechanically.

The workflow that scales:

1. **Dossier first**: `just agent-start port 0xADDR` (which runs
   `just ghidra-portprep` — owner, callers, thunk-resolved callees + their owners,
   virtual slots, globals, jump tables, decompile), then dump the full listing to a
   scratch file (`just ghidra-listing 0xADDR` or the raw-PE/capstone fallback) and
   identify every stack local before writing C++.
2. **Transcribe in binary order** — cases, branches, stores, in the order the binary
   lays them out.
3. Port callees you meet on the way (or verify their existing models — conventions
   especially) rather than bridging around them.
4. Compare, `just triage`, fix the structural buckets, accept allocator wobble.

## Field notes

### Monolithic functions must be ported as one inline body — never split into separate-TU helpers
*(ex decomp-loop note 19)*


A big original function (e.g. a switch-based dispatcher) is a *single* function at one
address. The build uses `/Ob1`, which only inlines `inline`-marked functions and never
inlines across translation units. Decomposing case bodies into free functions in another
`.cpp` yields a thin sequence of `CALL`s that can never match — a 4 KB dispatcher stuck
at ~5%.

- **Inline the bodies into the one function** (an `#include "..._switch.inc"` fragment
  between `case` labels works well). Wrap each case in its own `{ }` so per-case locals
  don't collide (MSVC500 keeps `for`-init variables in function scope; give each loop
  its own uniquely-named control variable rather than relying on the leak).
- **Genuine helpers go file-scope `static inline`** so `/Ob1` folds them back in; trivial
  one-line wrappers are best expanded at the call site.
- **Isolate a large/disruptive function in its own TU.** Adding the inline switch + its
  includes to a shared `.cpp` perturbed that TU's codegen and regressed 9 neighbours —
  TU-codegen fragility (§16) cuts both ways. A class method can be *defined* in a separate
  `.cpp` (`src/game/<Class>_<Method>.cpp`); reccmp pairs by address, so this is free.
  Worked example: `TSimMgr::AdvanceGlobalTurnStateMachine` @0x0057da70 in its own TU.
- Remaining gap is then ordinary matching work (e.g. hoisted function-scope `CString`
  pinning `this` in `ebx` — see §33).

### Turn-event screen builders share one widget-block vocabulary
*(ex decomp-loop note 36)*


Every `turn_event_dialog_factory.cpp` screen builder (the 253KB giants, bd 1uj.51) is the
same repeating widget block — port by recipe from `just ghidra-listing`, not the decompile
(which degenerates to `func_0x0040xxxx` stubs, and some builders are split into fragments:
a listing ending without an epilogue continues in the next "function"). Per widget:
`new <WidgetClass>()` (size after `PUSH n; CALL 0x606f73` identifies the class) → parent =
`g_UiWidgetBuildStack006a13e0.GetTail()` (else head=widget) → `AddTail` →
`InitializeUiResourceEntryFrameAndParent(0, parent, offset[2], size[2], 0, 0, 1)` (0x4096b5)
→ tag/field stores → slots 0xa4/0xa8 = `SetEnabled`/`SetState` → style bytes + rect →
per-class tail call (slot 0x1c8 on pictures, `BindUiResourceTextAndStyle` 0x41b490 on text)
→ `g_pUiResourceContext = 0` (+ `RemoveTail` when the widget takes no children).
Out-of-line variants are real functions in `ui_resource_pool.cpp` (0x41b210/0x41b3a0/
0x41b450/0x41b490). First param is the `CWnd*` host; the event-code check is
`(short)nEventCode != 0xNNN → return 0`. Gotcha: MSVC schedules argument pushes early —
match pushes to callee-consumed counts, not adjacency to the nearest call.

- `just decode-builder`'s equality-case summary can miss a `CMP; JG; JE` ladder where
  the equality jump is separated from the compare. Verify the dispatch prologue in the raw
  listing before assigning case boundaries: `0x435916` is event `0x3ba`, not a continuation
  of `0x3b6`, and the same pattern hides event `0x5de` at `0x435f2b`.

### Turn-event packet emitters: zero-then-value store pairs and their folding
*(ex decomp-loop note 58)*


The original packet emitters write each NetMessage header field twice — a zero
store then the real value, interleaved by the scheduler. Writing the same double
assignments in source (`packet.eventCode = 0; packet.eventCode = 0xb;`)
reproduces this in some TU contexts (TMultiplayerMgr.cpp when 0x54b5d0 hit 100%)
but folds to single stores in others (fresh TUs, grown TUs) — a TU-composition
sensitivity like note 55's inline budget, not a source-model problem. Keep the
double-write source; accept the folded-store diffs as the known wobble family.
A NetMessage default ctor zeroing the four fields is NOT the model: it groups
the zeros at the declaration point instead of interleaving them (verified, and
it regresses every other emitter).

### Giant dispatchers get their own TU
*(ex decomp-loop note 59)*


Adding a multi-KB function to an existing TU re-shapes neighbouring functions
(store folding, register allocation) — 0x54b5d0 wobbled when 0x543910 landed in
TMultiplayerMgr.cpp. Follow the TSimMgr_AdvanceGlobalTurnStateMachine.cpp
precedent: put the monolith in its own file
(TMultiplayerMgr_HandleDiplomacyTurnEvent.cpp) so its packet structs, inline
helpers, and optimizer footprint stay isolated.

### Giant switch receive machines: transcribe per-case in binary body order
*(ex decomp-loop note 60)*


For a multi-KB `switch (packet->eventCode)` dispatcher (e.g. 0x545940, 42 cases,
11.4KB): (a) source case order must follow the binary case-BODY order, not numeric
order — MSVC5 lays bodies out in source order; (b) model the exits as plain `break`
per case + one post-switch `return 1` + `default: return 0` (the original's single
`mov al,1` / `xor al,al` tail pair comes from cross-jump-merged constant returns —
per-case `return 1;` statements compile to inline `mov al,1` copies that pair worse);
(c) give every event code its own packet-view struct derived from
NetMessage/TimelyMessageHeader/TimelyNetMessagePrefix and keep the exact store order
including double-writes; (d) an `if (x == tagA) A; else if (x == tagB) B; else C;`
chain whose bodies are emitted out-of-line with `je` jumps reproduces from
inverted-inequality nesting (`if (x != tagA) { if (x != tagB) { C } else B } else A`);
(e) accept the residual frame-size/stack-slot-order delta — VC5 slot assignment on
frames this large is not source-controllable (same anomaly class as 0x543280).
Parallelizing the asm transcription across subagents with a shared ILT->symbol map
document works well; verify every agent-supplied field/slot name against the repo
headers before splicing.

- **An exact-matching FPU/vtable inner section validates the whole model even when the
    overall score is low.** For a large function (0x518130, 643B, 33.71%) the diffusion
    `fild/fmul[global]/fiadd/ftol` and both virtual dispatches matched instruction-for-
    instruction; the low overall % was pure MSVC5 register/stack-offset scheduling (the
    original reserves a dead 6-int scratch MSVC5 elides, shifting the frame 0x14 and the
    whole allocation). Don't force dead scratch back with `volatile` (gains a few pp but
    isn't faithful and doesn't match the original's rep-stosd init) -- accept the
    scheduling residual once the semantic core is proven exact.
  *(ex decomp-loop list-note 81)*

- **FourCC-dispatched turn-instruction handlers are TSimMgr __thiscall methods reading
    big-endian tokens.** The 0x698b50 handler table is walked by
    TSimMgr::ProcessTurnInstructionStreamAndFinalizePhase (0x581e60), which is reached from
    AdvanceGlobalTurnStateMachine (TSimMgr vtable slot 0x4c) and preserves ECX across the
    `call [table+i*4]`, so every handler shares the dispatcher's `this` = g_pSimMgr. Ghidra
    parks a few of these under other classes (Civi was on TGreatPower) because their bodies
    ignore `this` -- the real owner is TSimMgr. Handler arg is a cursor whose first field is
    the current 4-byte-token read pointer (model as `struct { unsigned int* tokenCursor; }`).
  *(ex decomp-loop list-note 83)*

- **The turn-instruction tokens are big-endian (Mac/CodeWarrior on-disk format) read on
    x86 via an in-place byte swap; reproduce the swap width exactly.** Two widths seen:
      - 16-bit high value: `raw[0]=raw[3]; raw[1]=raw[2]; (short)token`  (bytes [2..3] BE)
      - 32-bit full value: single-reused-temp pair swaps
        `t=raw[0];raw[0]=raw[3];raw[3]=t; t=raw[1];raw[1]=raw[2];raw[2]=t; (int)token`
    Two simultaneous temps (`a=raw[0]; b=raw[1]; ...`) force a stack spill and drop the
    score ~70pp; the single-temp pair-swap is what MSVC5 emits. Advance ONE cursor pointer
    in place with a write-back after each read (`v=*cursor; cursor=cursor+1; c->tokenCursor
    =cursor;`) -- computing `cursor+1`/`cursor+2` off a preserved base adds a `push esi` and
    shifts every stack slot, blocking the match. Verified 100% on Year 0x582ed0 (year*4 ->
    quarterGateTick2c), Cash 0x583360 (two 32-bit BE -> treasuryValue10), Tran 0x582860,
    Tclr 0x583670 (real TGreatPower virtuals), Prov 0x582f20 (real TMapMgr virtual). For a
    16-bit token later passed as a full `int` arg, pass the whole swapped word (not
    `(short)`): the swap leaves the high half matching the original's int operand.

  *(ex decomp-loop list-note 84)*

- **Two more TSimMgr turn-instruction matching details (extends 83-84).** (a) A byte
    field compared against several constants is read/compared as a **sign-extended int**
    (`movsx` + `cmp eax,k`), so store it in an `int`, not a `char` -- a `char` local gives
    an 8-bit `cmp al,k` and drops the score. (b) A single `byte`/`unsigned char` argument
    taken from a token's high byte is produced by a **misaligned char-pointer read**
    (`reinterpret_cast<unsigned char*>(&token)[3]`), NOT a `>> 24` shift: the compiler
    passes it by loading the DWORD at the byte's address (garbage upper bytes on the push),
    which the pointer read reproduces and the shift does not. Both verified taking Deve
    0x5828f0 from 40% -> 60% -> 100%. Also: `just reorder_marked_functions <file>` after
    inserting a new `// FUNCTION:` marker keeps address order (else decomplint
    function_out_of_order fails); and a genuinely wrong Ghidra virtual signature on a stub
    (QueueDepot/QueuePortConstructionOrder declared 4-arg; `RET 8` proves 2) is safe to
    correct on the base + stub when no manual overrides/callers exist -- fixing it unblocked
    Rail/Port to 100%.

  *(ex decomp-loop list-note 85)*

### Deeply-optimized functions may not reach a high match from clean C++
*(ex decomp-loop note 110)*


A 532-byte target-cycling function (HandleTacticalCommandTag_targ) capped at ~33% despite a
verified algorithm: MSVC had fused comma-operator conditions, reused stack slots, duplicated
the reach-check inline, and DCE'd a validation block. Clean, correct C++ compiles to a
structurally different shape. When the decompile shows these optimizer fingerprints, expect a
low ceiling and budget accordingly — port it faithfully (architecture correct, callers
unblocked), document the residual, and don't sink hours chasing the last register. A 100% match
would require reverse-engineering the exact optimized instruction schedule, rarely worth it.
Also: a slot the disassembly calls virtually but that isn't a modeled callable (CObject-style
`AssertValid`, vtable slot 3) is fine to omit with a note — one missing no-op CALL.

### Full-diff forensics beats decompile-reading on hard functions
*(ex decomp-loop note 112)*


When a big function stalls below ~80%, capture the ENTIRE reccmp diff to a file
(`just compare 0xADDR > f.txt` after stripping color codes) and read it as a frame-layout
map, not line noise. Track every `[esp+N]` operand back to an E0-relative slot (E0 = ESP at
entry before the prologue; account for pushes at each site). Three payoffs seen on
TGreatPower::WriteTo: (1) a 288-line "mismatch" reduced to ONE slot-assignment difference
(identical instructions, shifted offsets — the frame size delta hides in the encodings);
(2) helper-vs-inline structure diffs are visible as cached-pointer registers + spills where
the original re-reads a member per use — write list/collection loops with repeated
`this->member->...` access, not a hoisted local, when the original does; (3) real bugs
surface (a slot-0x14 call where the original calls slot 5 = the port called the WRONG
METHOD — TransferTransportRequests vs WriteTo).

### Big-stub triage workflow: portprep dossier + const-stores extraction
*(ex decomp-loop note 115)*


Two purpose-built tools make the biggest stubs tractable in one pass each:
- `just ghidra-portprep 0xADDR` — the whole investigation in one query: current owner,
  callers (with owners), every direct call with ILT thunks chased AND the target's
  ownership (so the callee-porting cascade is visible up front), vtable-slot calls with
  slot indices, IAT imports, referenced globals with consecutive runs collapsed, jump
  tables, and the decompile. Read the "direct calls" owners column FIRST: a big stub whose
  callees are all owned (manual files) is pure logic and portable now; one with 5+ STUB
  callees is a cascade — either port the leaves first or defer.
- `just const-stores 0xADDR` — capstone over the ORIGINAL binary (no Ghidra): ordered
  address->constant store map with register constant tracking. A function whose body is
  ~all tracked stores and no untracked (indexed) stores is an unrolled TABLE INITIALIZER:
  model the target table as a typed global, then GENERATE the initializer as assignments
  in original store order (the compiler re-derives the value-grouped register caching).
  The 5KB facing-offset initializer (largest stub in the project) went 0->92.8% this way;
  batch-probing all 300B+ stubs found the complete set of such functions in one run.
Known hard case: a CRT static initializer that CALLS out-of-line ctors (e.g. 31x
CRect::CRect for file-scope CRect globals, 0x4b98b0) cannot be expressed as a plain marked
function — the ctor-on-global calls only arise from real file-scope declarations whose
compiler-generated initializer cannot carry a FUNCTION marker. Needs a dedicated
static-init modeling decision; defer rather than fake with placement-new.

- **A jump-table switch dispatcher that Ghidra split into per-case pseudo-functions: port
     the PARENT as one function, then delete every interior fragment row from symbols.csv —
     do NOT port a case fragment standalone.** The tell: a function entry with a tiny DB size
     whose body is `MOV EAX,[ECX+off]; CMP EAX,N; JA end; JMP [EAX*4 + table]` (e.g.
     FUN_0059c970, size 29), and the addresses *inside* its range each carry their own
     symbols.csv `function` row — thunk-forwarder case bodies (`CALL <ILT>; POP…; RET`, 12
     bytes), inline case bodies, and loop-tail fragments — while the parent entry itself has
     NO symbols.csv row (it was pruned as a jump thunk). Each case depends on registers the
     parent prologue set (here `MOV EBX,0x7`, resolving the `unaff_EBX`=7 mystery), so a
     standalone case port can never reach 100% (my earlier 0x59ca32 fragment capped at 62.5%).
     Fix, entirely source-side (no Ghidra DB resync needed — sync-pipeline junk taxonomy #4,
     "delete the row for marker-owned addresses"): (a) add `// FUNCTION:` for the parent entry
     in the owning class .cpp and write the whole switch (cases delegating to the real applier
     methods for ILT-thunk cases — resolve each `CALL <ILT>` to its jmp target with the
     binary-scan below — and inline loops for the inline cases); (b) add ONE symbols.csv row
     for the parent sized code+inline-jump-table (RET→end-of-table, NOT the trailing
     NOP/INT3 alignment padding: here 0x59c970..0x59ca98 = 296); (c) delete all the interior
     fragment rows (their ranges now overlap the parent — the symbols-integrity-gate's
     no-overlap check both forces and validates this); (d) `just regen-stubs` prunes the old
     fragment ownership + drops the now-orphaned stubs (stub-count falls → ratchet).
     Frequently the parent switch is a verbatim copy of an apply-switch another function
     already inlines (0x59c970's body == the mode-apply switch inside 0x59c440
     SelectAndApplyTacticalCursorModeProfile), so the case bodies can be lifted straight from
     that sibling. Result: parent 0%→100%, junk fragments gone. Scan for the parent's callers
     /ILT-thunk targets with a raw rel32 walk of the .exe (`E8/E9` at file offset O →
     `off2va(O)+5+rel32 == target`), since `just xrefs` misses address-taken/table dispatch.

  *(ex decomp-loop list-note 104)*
