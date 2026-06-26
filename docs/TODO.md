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
| TPictureNumberText | 0x0066c740 | TNumberText (0x0063e8b0) | 2: 0x00,0x01 (0x5b51c0,0x5b5210) |
| TRearFloatWindow | 0x00655928 | TFloatWindow (0x0064b340) | 3: 0x00,0x01,0x46 (0x4f38c0,0x4f3910,0x4f3960) |
| TFloatWindow | 0x0064b340 | TWindow (0x00649e58) | 4: 0x00,0x01,0x28,0x77 (0x491f90,0x492110,0x492330,0x492310) — prereq for TRearFloatWindow; has no header yet |
| TNumberText | 0x0063e8b0 | TEditText (0x0064ad90) | 5: 0x00,0x01,0x08,0x79,0x7a (0x491040,0x429530,0x4912b0,0x4910e0,0x4911c0) — prereq for TPictureNumberText |
| TShipOrder | 0x0064f738 | TProductionOrder (0x0064fa18) | 9: 0x00,0x01,0x0b,0x0c,0x0d,0x10,0x11,0x12,0x13 |
| TCityProductionView | 0x0064fc20 | TNoHilitePicture (0x006606e8) | 17 (slot list in `scratchpad/vdiff2.err`) |

Dependency order: TFloatWindow→TRearFloatWindow; TNumberText→TPictureNumberText.

Hard — secondary/aspect-vtable complication (do NOT treat as simple annotate):

- **TDiplomacyMapView** (base TPicture, size 0x24c8). The RTTI-resolved vtable
  **0x0066f16c is NOT the primary TObject-rooted vtable** — its slot 0x02 is
  `GetPendingTurnOverlayCode` (0x5d6c10), not the inherited `Serialize`
  (0x485e90). It is a ~50-slot **turn-event dispatch (secondary) vtable**. The
  primary TView-style vtable is elsewhere and must be located first
  (`vtable_extent.py` + the descriptor getter chain) before annotating. Has
  `src/game/TDiplomacyMapView.cpp` already.
- **TBattleReportView** (base TDiplomacyMapView, size 0x24d0). RTTI-resolved
  **0x0063efa8 IS a full 122-slot primary vtable** (slot 0x02 = `Serialize`),
  so it and TDiplomacyMapView's secondary are mismatched vtable *kinds*; the
  122-slot diff vs 0x66f16c is apples-to-oranges. Recover TDiplomacyMapView's
  primary+secondary first, then this one.

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

## `IsSelected` (slot 0x73) per-branch arity reconciliation

Slot 0x73 (`IsSelected`, offset 0x1cc) is **not a single shared virtual** — it is
introduced independently by several `TPicture` subclasses, each with its **own arity**.
Batch-disassembling the bodies (via `tools.ghidra.listing_one`, classify by `RET imm`)
gave:

| Class | Body addr | `RET` | Arity |
|---|---|---|---|
| TToggleButton | 0x571330 | tail-JMP | 0-arg ✅ fixed |
| T2PictToggleButton | 0x5849b0 | RET 0 | 0-arg ✅ fixed |
| TPictureButton | 0x5708c0 | RET 0 | 0-arg — **paradox, see below** |
| TTransportPicture | 0x5921c0 | RET 0 | 0-arg — pending |
| TUpDownPictureButton | 0x571690 | tail-JMP | TBD (need caller evidence) |
| TCivReport | 0x590cb0 | RET 0x4 | 1-arg — pending |
| TCombatReportView | 0x58c950 | RET 0x4 | 1-arg — pending |
| TArmyInfoView / TArmyPlacard / THQButton / TPlacard | … | RET 0x8 | 2-arg (already correct) |

**Done:** TToggleButton branch (TToggleButton + T2PictToggleButton override; TBoycottButton
and TPictureRadioButton inherit) changed from the wrong `IsSelected(short=-1, bool=true)` to
the real 0-arg `IsSelected()`.

**Remaining work — must verify each branch's call sites against its body before flipping
(unlike TToggleButton, these branches have real arg-passing callers):**

- **TPictureButton branch paradox:** body `0x5708c0` is `RET 0` (0-arg) yet
  `src/game/TPictureButton.cpp:29` calls `this->IsSelected(-1, true)` (2-arg). Disassemble
  the line-29 call site (and the other inheritors: TCloseButton, TOnOffRadioButton,
  TAlwaysPictureButton, T2PictureButton, TScrollerButton, TClosePicture) to decide the real
  arity, then fix the introducing class + all overrides + call sites together.
- **TCivReport / TCombatReportView:** bodies are `RET 0x4` (1-arg) but declared 2-arg —
  change to `IsSelected(<one arg>)` and fix callers.
- **TUpDownPictureButton branch** (+ TCivilianButton, TTextPictureButton, TRadioPictureButton,
  TMadnessButton, TCzechBox): body `0x571690` is a tail-JMP (arity ambiguous from the body) —
  determine arity from call sites.

Note: the bodies that are pure tail-`JMP` forwarders (e.g. `0x571330`) are codegen-capped by
call-vs-jmp regardless of arity; the arity fix's value is in the **callers** (it removes the
spurious default-arg pushes), not the 8-byte forwarder body itself.
