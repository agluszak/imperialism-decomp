---
name: calling-conventions
description: Recover the TRUE calling convention and receiver of any Imperialism function (thiscall vs cdecl vs stdcall vs fastcall, free function vs method, which class owns it). Load BEFORE porting or declaring any callee, whenever Ghidra labels something __cdecl, when a callsite loads ECX before a CALL, when a callee's RET n disagrees with the port, when a "free function" never cleans its stack, or when a method looks attributed to the wrong class.
---

# Calling-convention and receiver recovery

Ghidra's convention attribution is frequently wrong (roughly a third of its "defined
`__cdecl`" functions are really `__thiscall`). Every convention is a hypothesis to
verify against the assembly before you write a signature. The two-line test:

1. **Callee side**: does the body read `ecx` before writing it (`mov esi, ecx`,
   `[ecx+off]`)? Does it clean its own stack (`ret N`, N = 4×stack-args) or `ret`?
2. **Caller side**: who sets `ecx`/`edx` right before the `CALL`? Does the caller
   `add esp, N` after it?

| Evidence | Model |
| --- | --- |
| body uses `ecx` as an object; `ret N` | real `__thiscall` method on the owning class |
| callers load `ecx = [global]`, body ignores `ecx`, `ret N` | `__thiscall` method (this unused) on the global's class — the singleton idiom |
| callers load `ecx = list node` inside a walk | method on the ELEMENT class |
| no `ecx` use, `ret N` | `__stdcall` free function — but check callers' ECX first |
| no `ecx` use, plain `ret`, callers clean | genuine `__cdecl` free function |
| args in `ecx`(+`edx`), nothing pushed | `__fastcall` — acceptable for a not-yet-recoverable free-function bridge only |

Never fake a convention with `reinterpret_cast` (thiscall-as-fastcall-with-dummy-edx
is the most-repeated correction in this repo; see the MSVC500 calling-convention
guardrail in AGENTS.md). If it's thiscall, find the class and declare a real method.

Verification commands: `just ghidra-listing 0xADDR` (entry + `ret`),
`just scan-cdecl-thiscall`, and disassemble one caller around the `CALL`.

## Field notes

### Calling-convention recovery
*(ex decomp-loop note 5)*


Ghidra's convention labels are hypotheses, not truth (~33% of "defined `__cdecl`" are
really `__thiscall`; `__fastcall` labels are often wrong). Verify against the listing:
who sets `ecx`/`edx`, who cleans the stack. See [[cdecl-thiscall-mislabel]],
[[no-callconv-cast-bridges]], AGENTS "MSVC500 calling-convention guardrail".

- A body opening with `mov reg,ecx` / `[ecx+off]` is a real `__thiscall` method — put
  it on the real class and call `this->Method(...)`. Never `reinterpret_cast` to a
  `__thiscall` fn pointer (MSVC500 `C4234`; enforced by `just antipattern-gate`), and
  never fake it with `__fastcall(ptr, edx_dummy, ...)`.
- A `thiscall` on a global-pointer manager (`mov ecx,[global]; call`) is a real method
  on a typed struct pointing at that global, not a `__fastcall(ptr,edx,...)` cast.
- Stale Ghidra boundaries/prototypes: a live `ghidra-listing` may report "no function"
  while `symbols.csv`/reccmp still pair the body. Trust the pushed args and `ret N`
  over the autogen `(void)` prototype.
- `just scan-cdecl-thiscall` classifies candidates: verdicts `ecx_this`/`no_ecx`/`empty`.

### ABI return contracts
*(ex decomp-loop note 6)*


- `ret N` size = signature truth. `ret 0x10` vs emitted `ret 8` is a missing-stack-arg
  signature mismatch — fix it before micro-tuning locals.
- MSVC500 returns structs (POINT/RECT) via a **hidden caller-allocated pointer** pushed
  as a stack arg, so `ret N` counts it. MFC fill methods are `T* Fill(T* out){...;
  return out;}` — they leave the out-ptr in EAX and callers chain on it. Model these as
  struct-returning / out-ptr-returning, not `void(out*)` (`GetCachedPosPoint` 16.7%→100%).
- A Ghidra `void` prototype can hide an intentional `AL` contract: if the body sets AL
  on the success/fallthrough path and a caller branches on it, model a `char`/flag
  return (`0x004ef700` reject=0/valid=1). `extraout_AL` after a call means that call
  returns the flag.
- **`ret N` as a class discriminator for a vtable receiver.** When a callsite pushes
  **A** args to `call [vtable + byteOff]` but your candidate base's body at that slot
  is `ret M` with M ≠ 4·A, the receiver is **not** that base — it's a sibling subclass
  with its own slot there (the base's no-op stub is a shared placeholder, not the real
  signature). Model the receiver as its own vtable-view/class (see §4); don't cast to
  the base and fight signatures (`0x5d57b0`).
- **An empty `ret N` body still encodes its arg count.** A no-op base virtual compiled
  as `RET 0x4` takes one stack arg; don't read the empty body as "no params". Correct
  the arity on the **base declaration and every override** (headers + defs) plus the
  `symbols.csv`/`function_name_overrides.csv` rows, or the `override` macro silently
  desyncs the slot (§14). (Fixed across TEventHandler + TEditText/TMapMaker, `0x48a710`.)

### "Same free-function name, different receiver class" — make the shared logic receiver-agnostic
*(ex decomp-loop note 23)*


A helper reading fields at fixed offsets may be called with *more than one* receiver
class that happens to carry compatible fields there (common for sibling "order node"
types used as generic queue payloads). Promoting it to a member of one class silently
miscompiles the other call site. Instead: make the shared computation a plain function
taking the **values** as parameters, and give each class a thin member wrapper
forwarding its own fields. Evidence: `ComputeNavyOrderPriorityContributionPercentByCategory`
(0x54ff00) is called on both `TShip` and `TMapOrderEntry` nodes.

### Free-vs-method is decided at the CALLSITE: the ECX-load + `ret n` test
*(ex decomp-loop note 26)*


`scan-cdecl-thiscall` on the callee alone under-detects methods whose bodies never touch
`this` (empty hooks, emitters whose state is all globals). The decisive evidence is the
caller: `MOV ECX, <global or object>` immediately before the `CALL`, plus callee-cleanup
`RET n` matching the stack-arg count, proves `__thiscall` — and the ECX source names the
owning class. Worked examples (2026-07-02): every turn-event emitter (0x5446a0..0x54c5a0)
loads ECX from `g_pGameFlowState` → TMultiplayerMgr methods; `GetActiveNationId` 0x581260
loads from `g_pLocalizationTable` → TSimMgr, exposing a repo-wide wrong-receiver bug.
Corollary: old no-arg `extern void F(void)` stubs at such addresses are the dropped-args
audit pattern ([[quickdraw-thunk-retirement-2026-07]]).

### Typedef-cast externs drift; audit before trusting a signature
*(ex decomp-loop note 30)*


The legacy typedef-cast extern pattern (`extern undefined4 Foo(void);` + per-callsite
`typedef ... (*Foo_t)(...)` cast) has no single source of truth, so signatures drift
between files (same target cast four different ways across three mission files; one
caller dropped the only argument — TBlockadePortMission::ReadFrom, 56%→100% by porting
the callee). `just typedef-cast-audit` extracts every `*_t` typedef and reports
cross-file conflicts — run it when touching any `_fn(` callsite, and prefer porting the
callee outright (targets are usually small leaves).

### `extern undefined4 Foo(void)` stubs may be real methods on a *different* receiver — read the ECX load
*(ex decomp-loop note 34)*


A free-function stub called "with no receiver" can be a real `__thiscall` behind an ILT
thunk, and the receiver is not always `this`: in one switch case, two calls used
`ecx = g_pLocalizationTable` while a third used `ecx = this` (0x57da70 case 3), and a
guard condition read a field on that *other* receiver — the old port had guessed a
similarly-named field on `this`. Always re-derive receiver + field offset from the
`MOV ECX, …` immediately before the `CALL`. Also: a `PUSH <addr>` that reccmp renders as
`push "Literal" (STRING)` is a string-literal pointer — model it as a named `s_*_00ADDR[]`
`// GLOBAL:`, not `reinterpret_cast<void*>(0xADDR)`.

### COM interfaces hide behind "channel/audio object" vtable dispatch
*(ex decomp-loop note 40)*


If a cluster calls vtable slots on an opaque object with the receiver PUSHED on the
stack (`PUSH EAX; CALL [ECX+0x34]`) instead of passed in ECX, it is a COM interface,
not a game class. Identify it by slot arithmetic against the real interface layout
plus API-specific constants (TSoundResourceManager's channels: slots 0x2c–0x50 =
IDirectSoundBuffer Lock/Play/.../Restore; 0x88780096 = DSERR_BUFFERLOST). Model it as a
minimal C++ interface class with `virtual ... __stdcall` methods in the exact retail
slot order (MSVC passes `this` as the hidden first stack arg for __stdcall members, so
codegen matches exactly); don't invent dummy-slot game classes. dsound.h isn't in the
MSVC500 toolchain — declaring the interface locally with real COM names is the right shape.

### Thunk-only-caller thiscall methods are frequently mis-attributed — reattribute by `[this+off]` field layout, not the curated name
*(ex decomp-loop note 49)*


When a `__thiscall` method's *only* xref is an ILT thunk, the `ClassName::` prefix was
guessed from weak evidence (Hard Rule 6). Recover the real receiver from the body's
`[this+off]` accesses: (1) list them; (2) grep recovered class headers for a field at
that offset with a compatible type; (3) reattribute — symbols.csv rename, move the
marker, declare on the real header. reccmp pairs by address, so reattribution never
risks the score; it unlocks typed field/virtual access. Beware: a lookup on a *global*
inside the body is NOT evidence about the receiver's class. Evidence: the
civilian-order cluster was all mislabeled `TCivToolbar::` — `CanAssignCivilianOrderToTile`
(0x4d2f60) reads `[this+4]` as a `TCivUnit*` = `TCivMgr::selectedEntry`, so the owner is
TCivMgr; `CalculateDeveloperTilePurchaseCost` (0x518b40) reads a stride-0x24 table at
+0xc = `TMapMgr::terrainStateTable`. Residual is usually register allocation — don't chase.

### `ret 4`/`ret 0` + caller `mov ecx, [global]` = thiscall singleton method with unused `this`
*(ex decomp-loop note 57)*


A "free function" whose every original callsite loads a manager singleton into
ECX and whose body never reads ECX is still a real `__thiscall` method on that
manager (callee-cleaned stack proves it): model it as a member with `this`
unused, not as `__cdecl`. Batch of five found this session:
TAssetMgr::SaveMainDocumentToPathAndMarkSaved (0x5e0030, g_pUiViewManager),
TOcean::FindFirstPortZoneContextByNation (0x563540, g_pActiveMapOrderContext),
TSimMgr::IsNationSlotEligibleForEventProcessing (0x581280, g_pSimMgr),
TNetMgr::ProbeNationReachabilityAndMarkAwolBitmask (0x5e43e0, g_pNetMgr006a6014),
TNetMgr::EnqueueOrSendTurnEventPacketToNation callers. The wrong free-function
model caps the score (~40-75%) and miscompiles every callsite (dead ECX setup +
caller cleanup).

- **A body that never touches `ecx` can still be a `__thiscall` method — check the
    callsites, not the callee.** `FreeQuickDrawSurfaceContextSlot` (0x4feb50) looked
    `__stdcall` from its body (no `this` use, `ret 4`), but every caller loads
    `mov ecx, [g_pDisplayMgr]` first: it is a real TDisplayMgr method whose `this` is
    unused. Modeling it free-function silently deletes the ecx load at every callsite
    (~2 instructions x 34 sites). When promoting, sweep all callers to
    `g_pX->Method(...)` in the same change.

  *(ex decomp-loop list-note 66)*

- **A `func_0x` callee with an apparently different arg count at each call site is
    the ILT-thunk-ambiguity smell, not evidence of two functions.** `just ghidra-listing
    0xTHUNK` resolves the single real jmp target; if the decompiled param count still
    varies by call site (one shows zero args, another shows two), that's the
    decompiler failing calling-convention attribution at that specific site, not a
    real overload — read the callee's own decompile (its declared signature is ground
    truth) rather than trusting each call site's apparent arg list. When the callee
    turns out to be a genuinely murky/deep dependency (an MFC-internal-shaped cache
    with hash buckets and `CPlex`, or a whole GDI/CDC blit branch nothing currently
    exercises), it's fine to port the caller's shape faithfully and leave that one
    branch as a documented `// TODO(class-recovery)` no-op rather than chasing three
    more levels of unrecovered class layout — confirm first that no current caller's
    arguments actually reach the branch (e.g. every caller passes the sentinel/null
    that skips it) before leaving it unmodeled.

  *(ex decomp-loop list-note 68)*

- **Retiring a `reinterpret_cast<void(__stdcall*)(...)>(StubName)` bridge is a single
    fix applied at the declaration, not N per-callsite fixes.** Grep for the bridge
    pattern repo-wide before porting a stub free function — if 5+ files already call it
    through identical casts, porting the real typed signature once and then
    mechanically stripping the cast at each site (`sed`, since the pattern is
    syntactically uniform) both retires the anti-pattern and validates the ported
    signature (every call site's literal args must satisfy it, e.g. consistent
    `unsigned int` cast confirms real `__stdcall(unsigned int)`).

  *(ex decomp-loop list-note 69)*

- **A method whose every caller loads ECX from the same global belongs to that
    global's class -- Ghidra buckets orphan thiscall methods by address proximity,
    not by receiver.** The registry pair 0x4a0d10/0x4a0d30 sat under TCivAnimation2
    (whose code neighbours them) while every call site did `mov ecx,[g_pUiAnimator]`;
    the receiver global's declared type (TAnimator*) names the true owner. Check the
    callers' ECX source before accepting any orphan method's class bucket, then move
    the marker AND fix the class prefix in symbols.csv (the earlier TTaskList lesson).

  *(ex decomp-loop list-note 74)*

- **A callsite's `movsx ax` (16-bit) vs `movsx eax` (32-bit) reveals the callee's true param
    width.** 0x522000's palette call sign-extended a byte to only 16 bits (high word left holding
    an unrelated `tileIndex*9`), proving ApplyTurnEventPaletteColorByEventCode's real parameter is
    `short`, not its declared `int` -- a 1.5% residual not worth perturbing a shared signature for,
    but a reliable width oracle when the callee is yours to retype.

  *(ex decomp-loop list-note 79)*

- **A fake `(args…)` forwarder that ignores its args and tail-calls the real `(void)`
    function silently de-pairs EVERY arg-passing call site — model the real `__cdecl`
    arg-ignoring function as variadic `(...)` instead.** TemporarilyClearAndRestoreUiInvalidationFlag
    (0x0049d620) is a bare flag toggler: it ends in plain `ret` (not `ret N`) and never reads
    `[esp+…]`, yet assert-style call sites `push line; push path; call 0x49d620; add esp,8`
    — they hand it a source path + line it discards, cleaning the stack __cdecl-style. Our
    model had TWO overloads: the real `(void)` at 0x49d620 and a second `(const char*,int)`
    that `(void)`-cast its args and forwarded. That forwarder is a *distinct* function, so
    every `f(path,line)` call paired against the forwarder's address, not 0x49d620 — a whole
    family (the five TViewMgr::HandleTurnEventDialogFactorySlot70..80, TView asserts, …) stuck
    ~97.9%. Fix: declare the real function variadic — `undefined4 f(...)` (legal in C++ with no
    named param; forced __cdecl; body ignores the varargs, needs no `va_start`, emits the same
    `ret`). Now `f()` pushes nothing and `f(path,line)` pushes two and cleans — both call
    0x49d620 directly. One edit: **+10 aligned, 52 improved** (drop the forwarder; update the
    handful of file-local `extern … (const char*,int)`/`(void)` re-decls to `(...)` or they
    become separate mangled symbols → link errors). Watch for: (a) a few small untouched TUs
    reg-schedule-wobble from the link-layout shift (accept, notes 18/47); (b) put the doc
    comment ABOVE the `// FUNCTION:` marker (Hard Rule 3), not between it and the decl.
    Smell to grep for: a `void Foo(T a,U b){ (void)a;(void)b; Foo(); }` forwarder next to a
    marked `Foo(void)`.

  *(ex decomp-loop list-note 95)*

### "Static member taking a node parameter" is usually a __thiscall method on the node
*(ex decomp-loop note 122)*


If a helper is modeled as a static/free function whose first parameter is a struct
pointer, but every original call site loads that pointer into ECX with no stack push,
it is a real __thiscall method ON THAT STRUCT — including plain non-polymorphic PODs
(TMapOrderChildLinkNode: FindNodeMatching, SetChainActiveFlag, and later
Delete/Remove/Create/PruneDefeated 0x552590/0x5525d0/0x552650/0x5526e0, four scores
41-51% -> three 100%). Null receivers are fine: the original calls with ECX=0 and the
body starts `if (this == 0)`. Two follow-on tells from the same family:
- If the recomp turns a recursive helper into a loop but the original keeps a real
  recursive CALL, the original function RETURNS A VALUE (the return in tail position
  blocks MSVC5's tail-recursion elimination) — find the per-path return values
  (0/next/this) and add the return type (0x5525d0: void->node* was the whole 20->100%).
- An alloc + guarded field-store block at a `new` site (call new; test eax; je; stores;
  result=eax / xor result) is an INLINE CONSTRUCTOR with arguments, not caller code:
  declare `T(args)` in-class and write `new T(args)` (0x552650, 47->100%), with the
  FailNilPointerWithAssert idiom for the null branch.

- **A small __thiscall "iterator/cursor" struct that reads `container->[+0x44]` then walks
    `+0/+4` links with data at `+8` is an MFC `CList`/`CObList` traversal — model it with the
    real MFC accessors, not a hand-rolled node struct.** The SelectableTextOptionEntry cursor
    family (0x004919a0 Initialize / 0x00491a00 Begin / 0x00491a70 Advance / 0x00491ab0 IsValid)
    looked like a bespoke tree walker, but `container+0x44` is a `TView::childList44`
    (`CList<TView*,TView*>*`, CObject-derived: vtable +0, `m_pNodeHead` +4, `m_pNodeTail` +8;
    `CNode{pNext +0, pPrev +4, data +8}`). The disassembly's `*(list+4)`/`*(list+8)` = Get
    Head/TailPosition, and `node->next/prev` + `node->data` = GetNext/GetPrev's inlined body.
    Modeling it as `list->GetHeadPosition()/GetNext(pos)` etc. (repo's real `<afxtempl.h>` CList)
    matched 100% — and the list-object load in `Advance` is optimised away because the inline
    GetNext/GetPrev only touch the node, not `this` (so a method whose disasm never reads the
    container still uses `ownerView->childList44->GetNext(pos)` cleanly). Sibling precedent:
    `CIterator` (Reset/More/Advance over `TSortedList::listState` CPtrList). When you see a
    ~12-20 byte cursor struct with a POSITION field + a payload field, look for the MFC list it
    walks before inventing a class. TWO codegen keys that took it from 15%/88% to 100%: (a) an
    init/"reset" method that ends with `mov eax,ecx`+`this`-in-eax-at-RET RETURNS `this` (model
    `T* Initialize(){...; return this;}`); (b) a seed-then-check that does `mov [ecx],eax` then
    re-reads `mov eax,[ecx]` stores the position to the FIELD in each branch and re-reads the
    field for the null check — don't cache it in a local (`position00 = ...; if (position00 ==
    0)`, not `pos = ...; ... = pos; if (pos == 0)`).

  *(ex decomp-loop list-note 101)*

- **Caller-side `movsx`+`push eax` of a short expression + callee reading its param as a raw
     dword (`mov ebx,[esp+..]`, no movsx) = the param is really `int`, not `short`.** Declaring
     it short makes the recomp truncate (`dec ax`/`mov cx,word`) where the orig sign-extends
     (`movsx`/`dec eax`); retype the callee param to int and every call site snaps into place
     (0x518540 scenarioIndex, TMapMgr slots 0x0e/0x2c). Conversely, a call site that RELOADS the
     raw incoming arg slot (`mov eax,[esp+argoff]; push eax`) is passing an untouched short
     param — keep that param short and pass the parameter variable itself (0x518990 →
     RemovePortZoneByTile).

  *(ex decomp-loop list-note 106)*

- **A "cdecl" callee whose original callsites all load ECX right before the CALL is a real
     __thiscall method — even when the body never touches `this`, and even for singletons.**
     The advisory-scoring sweep found five in one cluster: SumNavyOrderPriorityForNation[AndNodeType]
     (methods on TGreatPower, `cmp [ecx+0xc]`), ComputeWeightedNeighborLinkScoreForNode (TCountry,
     this unused), ComputeWeightedNeighborLinkScoreForNodeIndex (TArmyMgr singleton, this unused),
     and FindMapActionContextContainingNodeByIndex / ComputeGlobalMapActionContextNodeValueAverage
     (TOcean singleton, this unused). Tells: callee cleans its own stack (RET n) while the ported
     "free cdecl" form forces caller cleanup, and the "dead" `mov ecx, <global>` at every callsite.
     Check callee RET + one caller's ECX setup before trusting any free-function model; a wrong
     convention silently costs lines in EVERY caller, not just the callee.

  *(ex decomp-loop list-note 112)*

- **A callee-cleaned call with `mov ecx, node` inside a list walk is a method on the
     ELEMENT, not a free scorer.** TShip::ComputeOrderNodeCompositeEconomicScore (0x550b60)
     was ported as `int f(TShip*)` cdecl; the SumNavyOrderPriority loops call it with
     ecx = the ship node and no stack args. Same class of fix as note 112 but for list
     elements. Its body is also a warning about invented math: the "SignedMod100" helper
     was a hand-rolled int64 bit-twiddle where the original is a plain `short / 100`
     (magic 0x51eb851f + sar 5) — write the division and let MSVC500 emit the magic.

  *(ex decomp-loop list-note 116)*
