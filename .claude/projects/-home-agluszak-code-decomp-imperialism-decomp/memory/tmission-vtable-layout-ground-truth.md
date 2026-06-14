---
name: tmission-vtable-layout-ground-truth
description: TMission family vtable layout — 48-slot abstract base, paired MissionOrderPrioritizer companion vtables, exact rdata order
metadata:
  type: project
---

Ground-truth rdata layout of the TMission hierarchy vtables (verified via
`tools.ghidra.vtable_extent`, single-inheritance MSVC, slot index = byte/4).

**Each mission class has TWO adjacent vtables**: a small 12-slot
`g_vtblMissionOrderPrioritizer<X>` companion (a *separate* helper class, NOT part
of the mission vtable) immediately preceding the main `g_vtbl<X>`.

rdata order & addresses:
- 0x65a4e8 **TMission main vtable = 48 slots (0x00-0x2f)**. Slots 0x00-0x26 real;
  **slots 0x27-0x2f are NULL = pure virtuals** → TMission is abstract.
- 0x65a5a8 unnamed vtable = **TScatteredShipsMission** (navy-family child; has
  SerializeTNavyMissionCommon @slot 0x05, ResetScatteredShips @slot 0x0c).
- 0x65a650 g_vtblMissionOrderPrioritizerDefendProvince (12 slots)
- 0x65a680 g_vtblTDefendProvinceMission
- 0x65a7e8 g_vtblMissionOrderPrioritizerNavy
- 0x65a818 **g_vtblTNavyMission = 54 slots (0x00-0x35)**. Fills base pure-virtuals
  0x27-0x2b with real fns; appends 0x30-0x35; its own pure-virtuals 0x2c-0x35.
  Followed by a float constant pool at 0x65a8f0 (1.0/0.8/0.9/10.0/0.5/0.33...).
- 0x65ab58 g_vtblMissionOrderPrioritizerBeachhead / 0x65ab88 g_vtblTBeachheadMission
- 0x65ac30 g_vtblMissionOrderPrioritizerBlockadePort / 0x65ac60 g_vtblTBlockadePortMission
- 0x65ad08 g_vtblMissionOrderPrioritizerArmy / 0x65ad38 g_vtblTArmyMission

Inheritance CONFIRMED structurally (not by name): all main vtables share an
identical slot skeleton — slots 0x02/0x03/0x04 same thunks, 0x08/0x09 same;
overrides at slot 0x00 (class-name getter), 0x05/0x06 (serialize/deserialize:
TMission→TNavyMissionCommon→TArmyMission). Ctor sequencing agrees:
ConstructTArmyMissionWithNodeKey calls ConstructTMission then installs the army
vtable; navy inlines the same base-field block.

Base layout: vptr+0x00, byte+0x08=2, int+0x0c=0, byte+0x11=0xff. Navy adds
context+0x14, clears +0x18..0x38 (alloc 0x3c). Army: short node-key+0x14, list
ptr+0x18 (TList alloc 0x20). See [[next-tgreatpower-vtable-scope]] for the
analogous large-vtable staging approach. TMission base ctor 0x535020, dtor
0x535080 (resets vptr to CObject sentinel 0x66fec4 → rooted in MFC CObject tree,
see [[mfc-rtti-getruntimeclass-family]]).

Plan chosen by user: model TMission/TNavyMission/TArmyMission as real classes with
the FULL vtable via real inheritance (no manual vptr writes). Brief's "one
~0x90-slot vtable" was wrong — it conflated the paired prioritizer tables + the
interleaved ScatteredShips table.

**TMission base 48-slot body map** (resolved thunk→body via vtable_extent + JMP
resolver). Slots 0x00-0x04 = MFC CObject/TObject prefix:
- 0x00 GetTMissionClassNamePointer 0x534fb0 (=GetRuntimeClass override)
- 0x01 DeletingDestructTMission 0x535050 (scalar-deleting dtor, SYNTHETIC ??_G); dtor
  body DestructTMission 0x535080, ctor ConstructTMission 0x535020.
- 0x02 Serialize 0x485e90, 0x03 0x412bf0, 0x04 0x412c10
Slots 0x05-0x26 = TMission's own 34 virtuals; 0x05 SerializeTMission 0x535820,
0x06 DeserializeTMission 0x5358a0, 0x07 0x4798b0, 0x08 0x4798d0, 0x09 0x415ce0,
0x0a-0x26 = tiny default stubs 0x534c00-0x534f90 (ReturnFalse/Zero/NoOp/
ReturnConstantFloat(=_DAT_0065a468)/Set field). 0x27-0x2f pure virtual.

**BLOCKER for full C++-emitted vtable (needs maintainer decision):** build compiles
only src/game + src/autogen/stubs (NOT src/ghidra_autogen), so no TMission vtable is
currently emitted/paired. To emit it, ALL 48 slots must be real methods. But several
slot bodies are owned by OTHER files via linker COMDAT-folding of identical tiny
bodies: 0x02 0x485e90 & 0x09 0x415ce0 owned by TEventHandler.cpp; 0x08 0x4798d0 owned
by TZone.cpp; 0x03/0x04 by CObject.cpp; the 0x534cxx stubs (slots 0x0a-0x26) owned as
FREE functions in noop_slots.cpp. Emitting TMission's vtable means giving TMission
real methods with byte-identical bodies that the MSVC500 linker folds to those same
addresses — which collides with one-owner-per-address (Hard Rule 4). Repo has no
established annotation for folded vtable slots across unrelated hierarchies (SYNTHETIC
is for compiler scalar dtors only). Clean part: relocate the noop_slots stubs into a
real TMission class + own ctor/dtor/RTTI/Serialize+Deserialize. See
[[teventhandler-real-base]] for the in-hierarchy (non-folded) precedent.
