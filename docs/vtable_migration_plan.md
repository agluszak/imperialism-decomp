# `// VTABLE:` C++ Inheritance Migration — Plan & Findings

## Goal
Match the EH-framed base destructors (`CObArray::~` `0x601bdd`, `CPtrList::~` `0x601f7c`,
`CDocument::~` `0x6109eb`) by modeling the foundation hierarchy as real C++ classes with
`// VTABLE:` markers and virtual destructors (the pattern `TView`/`TEventHandler` already use).
`__EH_prolog`/inline-EH frames can ONLY be emitted by the C++ compiler from real
destructors (no inline asm, rule #1).

## Real vtable layouts (dumped from Imperialism.exe via pyghidra)

CObject (`0x66fec4`) — **5 slots**:
- slot0 `+0x00` GetRuntimeClass (`0x606fba`)
- slot1 `+0x04` scalar-deleting destructor (`0x401de8` thunk)
- slot2 `+0x08` `0x404aa7`  (shared)
- slot3 `+0x0c` no-op (`0x4010a0`)
- slot4 `+0x10` no-op (`0x408625`)

CObArray / TIndexAndRankList (`0x672eac`) — **5 slots** (overrides slot0/slot1 only):
- slot0 GetRuntimeClass `0x623b34`
- slot1 scalar-deleting dtor `0x601bc1` (`DestructCObArrayAndMaybeFree`)
- slot2/3/4 shared with CObject

CPtrList (`0x672eec`) — **5 slots**:
- slot0 GetRuntimeClass `0x623b3a`
- slot1 scalar-deleting dtor `0x601f40` (`DestructCPtrListAndMaybeFree`)
- slot2/3/4 shared

TSortedPtrList (`0x649068`) — **16 slots** (the rich derived array; adds slots 5..15):
- slot7 `+0x1c` `0x401159` (ResetPtrListRecordsSlot1C — dispatched by `0x488110`)
- slot9 `+0x24` `0x407da6` -> `0x488110`
- slot10 `+0x28` `0x403c65` (ShrinkCapacitySlot28 — dispatched by `0x488110`)
- slot11 `+0x2c` `0x409868` -> `0x488160`

## Consequence: current modeling is imprecise
`include/game/TIndexAndRankList.h` declares 11 virtuals (`slot00..slot28`). Those belong to
**TSortedPtrList** (16-slot vtable `0x649068`), NOT CObArray (5-slot `0x672eac`). The
`0x488110` vcall matched anyway because the over-virtualized C++ vtable happened to expose
slots at `+0x1c`/`+0x28`. A correct hierarchy moves the extra virtuals down to TSortedPtrList.

## Staged plan
1. `CObject` base: 5 virtuals (GetRuntimeClass, `~CObject`, slot2, slot3, slot4), 4 bytes
   (vptr only), `// VTABLE: IMPERIALISM 0x0066fec4`. Resolve the existing
   `TEventHandler`/`TView` use of `0x66fec4` (those were ported early and are not trusted —
   verify TEventHandler is really this CObject or a distinct 0x10-byte class).
2. `TIndexAndRankList : CObject` — drop the 11 bogus virtuals; override GetRuntimeClass + add
   `virtual ~`. `// VTABLE: 0x672eac`. Destructor `0x601bdd` = `~TIndexAndRankList`
   (frees `m_pData`); scalar-deleting `0x601bc1` becomes the compiler `??_G` (annotate with a
   `// SYNTHETIC:` marker) instead of the current manual method.
3. `CPtrList(SentinelView) : CObject` — `// VTABLE: 0x672eec`; `~` = `0x601f7c` (RemoveAll);
   scalar-deleting `0x601f40` = `??_G` SYNTHETIC.
4. `TSortedPtrList : TIndexAndRankList` — add the 11 derived virtuals (slots 5..15);
   `// VTABLE: 0x649068`. Re-verify `0x488110`/`0x488160` dispatch `+0x1c`/`+0x28`.
5. `CDocument` — derive from the CObject/CCmdTarget chain; model `~CDocument` (`0x6109eb`) +
   members (StringShared x2 + CPtrList) so the multi-state EH frame is emitted.
6. Manual ctors (`0x601f1d`, `0x601baa`) keep writing their vtable, but the address must come
   from the SAME symbol the C++ vtable resolves to (avoid duplicate `g_vtbl*` + `??_7`
   symbols at one address — unify on the C++ vtable, drop the manual `g_vtbl*`).

## Risk / scope
Touches ~20 already-100% functions (manual ctors, vcalls, scalar-deleting wrappers). Must be
done as one coherent pass with full family re-verification + `compare-canaries`. The probe
(adding `// VTABLE: 0x672eac` to the current TIndexAndRankList) built cleanly and did NOT
regress `0x601baa`/`0x488110`/`0x488160`/`0x488400`, confirming the marker is safe to layer in.
