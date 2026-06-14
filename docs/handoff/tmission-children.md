# Handoff: porting TMission's children

**Status as of commit `fea362b`** ("Model TMission as a real 39-slot polymorphic
base"). The base `TMission` class now exists as a real polymorphic C++ class. Your job
is to port its subclasses on top of it. Read this whole doc first, plus memory
`tmission-vtable-layout-ground-truth.md` (the authoritative layout/ownership record).

## What is already done (the base)

- `include/game/TMission.h` — `class TMission : public TObject` (so `CObject <- TObject
  <- TMission`). `// VTABLE: IMPERIALISM 0x0065a4e8`, size `0x14`.
  - Fields: `nationId04` (short @0x04), `pathMarker06` (short @0x06), `state08` (byte
    @0x08), `value0c` (int @0x0c), `flag10` (byte @0x10), `marker11` (byte @0x11).
  - 39 virtuals declared in **exact** vtable slot order, slots `0x00-0x26`. Slot
    addresses are in the trailing comment on each line.
  - Slots `0x27-0x2f` are **NULL** in the base table (abstract region). **Not
    declared** on TMission — C++ pure virtuals would emit `_purecall`, not NULL. Derived
    classes append their own virtuals starting at slot `0x27` (see below).
  - `TMissionNodeCallback` (unrelated small interface) also lives in this header — leave
    it.
- `src/game/TMission.cpp` — real ctor `0x535020`, dtor `0x535080`, SYNTHETIC scalar
  deleting dtor `0x535050`, `GetRuntimeClass` `0x534fb0`, and all 37 own-slot bodies.
  - The 16 trivial slot stubs were **relocated out of `noop_slots.cpp`** into real
    methods here. Do not re-add them to noop_slots.
  - `CreateByKindAndNodeContext` (factory `0x5350d0`) still **forwards to the thunk** —
    leave it until the concrete ctors use real inheritance (then do plan step 4).
- `src/game/global_data_tables.cpp` — `PTR_s_TMission_00697848` (RTTI descriptor) and
  `g_MissionDefaultScore_0065a468` (float 0.0, the slot 0x68-0x7C constant).

## The hierarchy to build (single inheritance, MSVC)

```
CObject <- TObject <- TMission        (done)
  TNavyMission   : TMission           vtable 0x65a818, 54 slots, alloc 0x3c
    TControlSeaZoneMission            alloc 0x3c
    TEscortMission                    alloc 0x3c
    TBlockadePortMission              alloc 0x40 (+0x3c extra ptr)
    TBeachheadMission                 alloc 0x40 (navy-shaped child of invade)
    TScatteredShipsMission            unnamed vtable @0x65a5a8
  TArmyMission   : TMission           vtable 0x65ad38, alloc 0x20 list @+0x18
    TAttackProvinceMission            alloc 0x34 (+0x30/+0x32 shorts)
    TDefendProvinceMission            vtable 0x65a680
    TInvadeMission                    alloc 0x38 (+0x34 beachhead ptr)
```

Inheritance is confirmed structurally (vtable prefix-sharing + ctor sequencing), NOT by
name. Re-verify each edge before adding it (Hard Rule 12): the derived ctor calls
`ConstructTMission`/the parent ctor then installs its own vtable, and the derived vtable
shares the base slot skeleton with selective overrides.

### Layout gotcha: paired vtables

Each mission class has TWO adjacent vtables in `.rdata`: a 12-slot
`g_vtblMissionOrderPrioritizer<X>` companion (a **separate** helper class — do NOT fold
it into the mission vtable) immediately before the main `g_vtbl<X>`. Full address map is
in the memory note.

## Recommended order (per plan)

1. **`TNavyMission : TMission`** and **`TArmyMission : TMission`** first — they explain
   most offsets. Model each as a real class; ctor calls the base ctor; declare the
   appended virtuals (slots `0x27+`) in exact order. Get vtable + ctor/dtor +
   scalar-deleting dtor pairing.
   - Note: the current `include/game/TNavyMission.h` / `src/game/TNavyMission.cpp` is a
     *standalone* class holding only two static scoring helpers
     (`ComputeOrderDistributionSimilarityScore*`). Fold those into the real
     `TNavyMission : TMission` (keep the addresses/markers).
2. The simplest concrete ctors (`TControlSeaZoneMission`, `TEscortMission`,
   `TAttackProvinceMission`, `TInvadeMission`, `TBeachheadMission`) — ctors first to
   establish sizes/vtables/fields.
3. Then `CreateByKindAndNodeContext` real switch (factory `0x5350d0`; the autogen body
   is in `src/ghidra_autogen/global_part011.cpp` ~line 11260, cases by mission kind).
4. Then serializers (`SerializeTArmyMission`/`DeserializeTArmyMission`,
   `SerializeTNavyMissionCommon`/`DeserializeTNavyMissionCommon`), then scoring.

## Workflow (per class)

`just ghidra-vtable-dump`, then resolve slot bodies with the thunk-resolver pattern used
in commit fea362b (see below). Map every slot to its body address + name, declare
virtuals in order, port bodies. Then:
`just sync-ownership` → `just regen-stubs` → `just build` → `just detect` →
`just compare 0xADDR` → `just gates` + `just format <files>`. Commit on `main`.

Thunk→body resolver (read-only), run with `.env` loaded:
```
just ghidra-vtable-dump <Class> 0x<vtable> > /tmp/vt.csv   # then JMP-follow entry_addr
```
(The inline resolver script used for the base is reproducible from
`tools/ghidra/create_vtable_body_functions.py`'s `resolve()`; load `.env` so
`GHIDRA_INSTALL_DIR` is set, and run with `PYTHONPATH=.`.)

## KNOWN OPEN ISSUE — the base vtable reports 0.00%

The recomp `TMission::vftable` is structurally **correct** (right functions, right order;
verified in the compare diff), and **37/39 slot bodies match 100% individually**. But
`just compare 0x0065a4e8` reports the vftable as 0.00% similar.

Diagnosis so far:
- The diff shows every orig slot as a thunk (`0x40xxxx`, the ILT jmp table) with
  "no recomp", and every recomp slot as a body — i.e. reccmp is not aligning the two
  lists at all (full `-`/`+`, no LCS match).
- This is **not** simply "orig uses thunks": TControl's orig vtable also uses `0x40xxxx`
  thunks and matches 100%, so reccmp *can* resolve vtable thunks.
- Recomp side shows 3 genuinely-unpaired slots: `0x01` scalar-deleting dtor ("no orig" —
  SYNTHETIC not pairing), `0x02` Seritalize (recomp inherits `CObject::Serialize`
  `0x412bd0` but orig wants `TEventHandler::Serialize` `0x485e90` — a COMDAT-folded
  shared body), and `0x08`/`0x09` generic forwarders (`0x4798d0` TZone / `0x415ce0`
  TEventHandler) that did **not** linker-fold (got own recomp addresses, "no orig").

Hypotheses to chase (not yet resolved — user deferred it):
1. The all-`-`/all-`+` total misalignment smells like reccmp matching by raw pointer and
   not thunk-resolving the orig side *for the % computation* in this particular case —
   possibly tied to the "ILT thunk retirement / reccmp fork branch awaiting push" note
   in memory. Compare against a known-good vtable's internals to see whether its recomp
   slots are thunks vs bodies.
2. Fix the 3-4 unpaired slots and re-measure — if the % jumps off 0.00, the misalignment
   was being triggered by unpaired anchors:
   - `0x01`: make the SYNTHETIC scalar-deleting dtor pair (check the exact demangled
     recomp `??_G` name vs the `symbols.csv` backtick entry at `535050`).
   - `0x02`: the orig slot is the folded `TEventHandler::Serialize` `0x485e90`. To match,
     TMission's slot 0x02 must resolve to a body folded onto `0x485e90` (give TMission a
     `Serialize` override with a body byte-identical to `TEventHandler::Serialize`), OR
     accept the single-slot miss. This is the cross-hierarchy COMDAT-folding question.
   - `0x08`/`0x09`: generic class-independent forwarders. Either get them to fold onto
     `0x4798d0`/`0x415ce0` (byte-identical bodies) or accept two slot misses.

Children vtables will hit the **same** 0.00% phenomenon, so resolving it on the base
first will save repeating it. If it turns out to be a reccmp tooling limitation, the
class model is still correct (Hard Rule 11: correct architecture beats a local score)
and the per-body matches still count.
