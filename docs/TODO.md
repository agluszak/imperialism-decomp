# TODO / follow-ups

## Missing RTTI-evidenced vtables (audit 2026-06-27)

Audit method: mine all 458 MFC `CRuntimeClass` descriptors from the binary
(`scratchpad` scripts `dump_rtti_vtables.py` / `vdiff.py` reuse
`tools/ghidra/apply_mfc_rtti.py` helpers), resolve each to its vtable via the
getter→ILT→vtable chain (193 resolved), and diff against our `// VTABLE:`
annotations. **Cat B (5 classes) is DONE** (commit "annotate 5 RTTI-evidenced
class vtables"). Cat C / Cat D remain.

### Cat C — classes that exist only as forward-decl structs in `root_types.h`

Each has a raw `src/ghidra_autogen/<Class>.cpp` dump (GHIDRA_FUNCTION, banned
scaffolding — reference only, NOT reccmp-paired) but no real
`include/game/<Class>.h`. Recovery recipe per class: create the class header
`class TX : public TBase` + `// VTABLE: IMPERIALISM <addr>`, declare the
override slots (addresses below) as real virtuals in slot order, port honest
bodies into a manual `src/game/TX.cpp` with `// FUNCTION:` markers (no manual
vptr writes / `*AndMaybeFree` / `FreeHeapBufferIfNotNull` scaffolding), then
`just sync-ownership` → `just regen-stubs` → `just build` → `just vtable TX`.
The autogen struct in `root_types.h` can stay (separate TU; same name/layout,
MSVC tags don't affect mangling). Slot 0x00 = `GetRuntimeClass`, slot 0x01 =
scalar deleting destructor (claim via SYNTHETIC + symbols.csv backtick name;
verify it isn't COMDAT-folded across vtables first, à la TAmbitApplication).

Tractable (single inheritance, primary vtable, modest override counts):

| Class | vtable | base (vtable) | override slots |
|---|---|---|---|
| TShipOrder | 0x0064f738 | TProductionOrder (0x0064fa18) | 9: 0x00,0x01,0x0b,0x0c,0x0d,0x10,0x11,0x12,0x13 |

Note: `TShipOrder` is not a mechanical scaffold in the current tree: slots
0x11/0x12/0x0c/0x0b/0x0d/0x10 currently resolve to addresses already manually
owned by `src/game/TCapacityOrder.cpp` (0x004b85a0, 0x004b8630, 0x004b86d0,
0x004b8800, 0x004b8970, 0x004b8b80). Recover it by first deciding whether those
bodies need to move to a shared production-order subtype/helper or whether the
RTTI vtable chain resolved a sibling table; do not duplicate `// FUNCTION:`
markers under `TShipOrder`.

Done:

| Class | vtable | base (vtable) | override slots |
|---|---|---|---|
| TCityProductionView | 0x0064fc20 | TNoHilitePicture (0x006606e8) | 17: 0x00,0x01,0x07,0x0f,0x35,0x37,0x44,0x47,0x68,0x74,0x75,0x76,0x77,0x78,0x79,0x7a,0x7b |

`TCityProductionView` recovered 2026-06-27 as a real
`TNoHilitePicture` subclass with 15 manually owned function bodies moved out of
generated stubs; `just vtable TCityProductionView` passes (one vtable found).


Done:

- **TDiplomacyMapView** recovered 2026-06-27 as a real `TPicture` subclass with
  primary vtable **0x00655b68**. Constructor listing calls `TPicture::TPicture`
  (`0x0048efc0`), not `TPictureButton`; this keeps slot 0x73 as an introduced
  one-argument legend/render virtual instead of conflicting with
  `TPictureButton::IsSelected()`. The stale 0x0066f16c vtable row was renamed
  to `g_TViewMgrTurnEventDispatchTable` as a data boundary; it is a turn-event
  dispatch/data table or RTTI-resolver mis-hop, not an object vtable. `just
  vtable TDiplomacyMapView` passes.

Hard:

- **TBattleReportView** (base TDiplomacyMapView, size 0x24d0). Constructor
  evidence calls the TDiplomacyMapView base-state constructor, initializes a
  small derived tail at offset 0x24c8, then writes the complete-object vfptr to
  **0x0063efa8**. Treat this as derived from TDiplomacyMapView's 0x00655b68
  table; do not compare it against 0x0066f16c. Open issue: slot 0x01 points at
  the generic heap-free helper `0x00430a30` rather than a normal class
  scalar-deleting destructor, while slot 0x07 points at the class cleanup body
  `0x004ad560`. Audit that destructor/Free slot shape before adding a C++ class
  header, rather than forcing a fake destructor model.

### Cat D — RTTI vtable addr disagrees with our current annotation

- **CMcWindow** — RTTI resolves 0x00649e74 (slot0 `DestroyChildResourceWindowAndDetach`);
  memory note records the host CWnd vtable as 0x0064b7c8. Likely host-vs-UI
  vtable; reconcile which is the object's primary. Recovery is in progress.
- **TSortedPtrList** — RTTI 0x00649010, but the class already annotates
  0x00649068/0x00654d90/0x00657040. 0x649010 is almost certainly an adjacent
  embedded-collection (sub-object) vtable; confirm and annotate as secondary if real.
- **TPortZone** — RTTI 0x0065c7e4 vs annotated 0x0065c758 (Δ0x8c). Likely a
  resolver mis-hop or a second vtable; verify slot0 before touching.
- **TAutoGreatPower** — RTTI 0x0065c484 vs annotated 0x00654088 (entirely
  different). **TGreatPower TU is codegen-fragile** (symmetric x87 leaves flip
  100%↔42.86% on recompile — see memory [[tgreatpower-tu-codegen-fragility]]).
  Investigate read-only; do not annotate without isolating the TU risk.

## `IsSelected` (slot 0x73) per-branch arity reconciliation — DONE 2026-06-27

Slot 0x73 (`IsSelected`, offset 0x1cc) is **not a single shared virtual**. The
source now models the verified branch arities:

| Branch | Body addr | Verified arity |
|---|---:|---:|
| TToggleButton / T2PictToggleButton | 0x571330 / 0x5849b0 | 0 |
| TPictureButton (+ inherited button subclasses) | 0x5708c0 | 0 |
| TUpDownPictureButton (+ TCivilianButton, TTextPictureButton, TRadioPictureButton, TMadnessButton, TCzechBox) | 0x571690 | 0 |
| TCivReport / TCombatReportView | 0x590cb0 / 0x58c950 | 1 |
| TArmyInfoView / TArmyPlacard / THQButton / TPlacard | varied | 2 |

Verification notes: Ghidra listing showed `TPictureButton::IsSelected` returns
with plain `RET`; `TUpDownPictureButton::SetControlStateFlagAndMaybeRefresh`
calls slot 0x1cc with no argument pushes; `TCivReport` and
`TCombatReportView` both return with `RET 0x4`. `just build` passed, and
filtered `just vtable` checks for `TPictureButton`, `TUpDownPictureButton`,
`TCivReport`, and `TCombatReportView` were 100%.
