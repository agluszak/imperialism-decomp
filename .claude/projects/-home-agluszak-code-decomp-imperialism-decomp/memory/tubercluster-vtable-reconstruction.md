---
name: tubercluster-vtable-reconstruction
description: TUberCluster vtable 0x65f210 ground truth — NOT bloated; abstract NULL tail + 3 entangled mismatches; open MSVC500 NULL-slot question
metadata:
  type: project
---

2026-06-15 investigated TUberCluster (orig vtable 0x65f210) as the lead-in to the
cluster-family reconstruction. **Corrects the prior "bloated extent" hypothesis in
[[vtable-easy-wins-session]].**

**Ground truth from `just ghidra-vtable-dump TUberCluster 0x65f210`:**
- Real function slots run 0x00 → 0x73 (offset 0x1cc). Slot 0x73 (0x1cc) = LAB_004038cd.
- Slots 0x74–0x8b (offsets **0x1d0–0x22c, 24 slots**) are literal **0x00000000 (NULL)**.
- Slot 0x8c (0x65f440) begins a DIFFERENT vtable (slot pattern restarts) — so TUberCluster's
  vtable ends at 0x8b.

**These NULL slots are REAL virtual slots, not padding.** Orig
`HandleTradeMoveControlAdjustment` @0x586e70 dispatches them through the vtable:
`CALL [EBX+0x1d0]` (= our ApplyMoveValue) and `CALL [EAX+0x1e8]` (QueryValue on the
AmtBar child object). ⇒ TUberCluster is an **abstract base**; concrete cluster subclasses
(TTradeCluster, TIndustryCluster, TShipyardCluster, TRailCluster) fill 0x1d0+.

**Three entangled mismatches keep the class off 100% (all-or-nothing, no cheap headline win):**
1. slot 0x04 — orig 0x571490 is the **scalar deleting destructor** (disasm: `CALL 0x40567d`
   real dtor; `TEST byte[ESP+8],1`/`JZ`; `CALL 0x606faf` operator delete; `RET 4`). Source
   currently mis-models it as plain `~TUberCluster()`. Fix = SYNTHETIC + backtick name in
   symbols.csv (the real ~T is 0x40567d). In-pattern, but only counts once 2+3 are done.
2. slot 0x3c — orig dispatches ILT thunk 0x4023ab → JMP 0x491650 (`DispatchPanelControlEvent`,
   a TUberCluster-specific override). We inherit TControl's 0x48e710. Needs a real override
   at 0x491650 (NOT a thunk un-import — different function from the inherited one).
3. tail 0x1d0–0x22c — our model emits 8 concrete empty stub virtuals; orig has 24 NULL slots.

**Subclass vtables mapped (resolves the tail structure):**
- slot 0x73 (0x1cc) is **concrete on TUberCluster** = LAB_004038cd (real body behind the
  thunk). Industry/Shipyard/Rail inherit 004038cd; **TradeCluster overrides** it
  (IsTradeSellControlAtMinimum). ⇒ our `vmethod_0115` empty-stub is wrong; port the real body.
- slots 0x74–0x7b (0x1d0–0x1ec) = **exactly 8 abstract slots**, NULL on TUberCluster,
  filled per-subclass:
  - TradeCluster: all 8 (0x1d0–0x1ec)
  - IndustryCluster / RailCluster: 0x1d0,0x1d4,0x1d8 (3), rest NULL
  - ShipyardCluster: 0x1d0 only, rest NULL
- slots 0x7c+ (0x1f0–0x22c) NULL in ALL subclasses ⇒ NOT virtual slots, just trailing
  zero padding before the next vtable at 0x65f440. The class's virtual extent ends at 0x7b.

So our model already has ~the right count (8 tail methods); the fixes are: (1) make slot 0x73
a real concrete virtual (not a stub), (2) make slots 0x74-0x7b **pure virtual `= 0`** so the
base emits NULL.

**RESOLVED (2026-06-15): the abstract tail is NOT cleanly fixable; pure-virtual approach is wrong.**
- Per repo convention (see `TMission.h:83`, which explicitly cites "TUberCluster's abstract-null
  region"): under MSVC500 a C++ `= 0` pure virtual emits **`_purecall`, not NULL** — so making
  the 8 tail methods pure would NOT match the original's literal-NULL slots. The convention for
  abstract-null regions is "don't declare them; the base table just ends and derived classes
  append their own virtuals." Confirmed every cluster subclass factory hand-rolls construction
  with a manual vptr write (e.g. Industry @0x588a30 `MOV [ESI],0x665ed0`) — the whole family is
  abstract, hand-constructed.
- BUT TUberCluster's own `HandleTradeMoveControlAdjustment` (0x586e70) makes a virtual call to
  slot 0x1d0 (`ApplyMoveValue`), which forces a base declaration of that virtual — and any
  declaration emits a non-NULL slot (concrete addr) or `_purecall` (pure). There is no clean C++
  way to both call slot 0x1d0 from the base AND emit NULL there. So the 8 tail slots stay
  mismatched (kept as concrete no-op stubs). TUberCluster cannot reach 100% without raw-vtable
  indexing (forbidden). Documented inline in TUberCluster.h.

**What WAS fixed this session (TUberCluster slots that now pair):** slot 0x04 (SYNTHETIC scalar
dtor @0x571490, symbols.csv backtick), slot 0x1cc (`vmethod_0115` → real `IsTradeControlAtMinimum`
@0x5714e0 body `return 1`, renamed in source + symbols incl. the TTradeCluster override @0x587900),
slot 0x3c (fixed family-wide on TCluster — see below). Remaining: only the 8-slot abstract tail.

**TCluster reached 100% this session:** slot 0x00 `GetRuntimeClass` override @0x4913e0 (+
`PTR_s_TCluster_006496c0` descriptor); slot 0x3c real `HandleEvent` override @0x491650 (renamed
from the `DispatchPanelControlEvent` callconv-cast bridge; ported the real 222-byte body). Slot
0x3c required **un-importing ILT thunk 0x4023ab** (removed from symbols.csv; repointed the 4
callers — TCivToolbar, TUberCluster, TProductionCluster, TUnitToolbarCluster — to
`this->TCluster::HandleEvent(...)`, killing their `__fastcall` bridges). Global vtable
not-matching: 76 → 75.

Related: [[ui-vtable-hierarchy-ground-truth]] [[ghidra-names-provisional]]
