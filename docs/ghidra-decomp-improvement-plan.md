# Ghidra decomp improvement plan

Roadmap for raising the quality of the Ghidra database (and therefore the
decompiled output the porting loop reads). Ordered by value vs. risk. Numbers
come from a survey of the live project (June 2026): 517 recovered class
namespaces, 5282 `__thiscall` / 61 `__cdecl` / 47 `__fastcall` functions, 323
unnamed `FUN_`/`SUB_` functions.

Mechanisms already in place that several of these items reuse:

- `config/recovered_globals.csv` + `config/recovered_fields.csv` — evidence-curated
  typed globals / interior class fields, applied by `apply_mfc_rtti.py` (step 7).
- `config/dissolve_namespaces.csv` — placeholder pseudo-class namespaces dissolved
  back into Global by `apply_mfc_rtti.py`.
- The decompiler `this`-argument resolver prototype (measured low yield for fully
  automatic inference, so curated tables are preferred for now).

## Tier 1 — high value, low risk, mechanism exists

### 1a. Type the recovered singleton globals
The `typed-recovered-globals` rule already calls these out. As of the Tier-1
pass they are recorded in `config/recovered_globals.csv` and applied by
`apply_mfc_rtti.py` (optional `object_size` column seeds a minimal struct when
the class namespace exists but RTTI did not emit one, e.g. `Config`):

| global | typed as |
| --- | --- |
| `g_apNationStates` | `TGreatPower *[7]` |
| `g_pGameFlowState` | `Config *` |
| `g_pNationInteractionStateManager` | `TTradeMgr *` |
| `g_pDiplomacyTurnStateManager` | `TDiplomacyMgr *` |
| `g_pGlobalMapState` | `TMapMgr *` (manual port: `TGlobalMapState`) |
| `g_pCityOrderCapabilityState` | `TTechMgr *` |
| `g_pSelectedCivilianOrderState` | `CivilianMapInteractionManager *` (manual: `TSelectedCivilianOrderState`) |
| `g_pNavyOrderManager` | `TNavyMgr *` |

**Next:** scan for more `g_p*` / `g_ap*` singletons and tables (e.g.
`g_pInterNationEventQueueManager`, `g_pSfxPlaybackSystem`, `g_apTerrainTypeDescriptorTable`)
using the same writer-evidence recipe.

### 1b. Grow `recovered_fields.csv`
Started with `TGreatPower+0x894 → TCity* (city)`; extended with view classes that
pass a `TCity*` into `GetCityBuildingProductionValueBySlot`
(`TBuildingConstructionView+0x90`, `TIndustryView+0x94`). Keep adding rows for
every `field_0x...` in hot structs (`TCity`, `TGreatPower`, `TControl`, view/dialog
classes) using unanimous resolver evidence + offset-fits-object-size gating; never
overwrite an already-typed field.

## Tier 2 — bounded cleanup, same family as the dissolve work

### 2a. Triage the remaining address-named pseudo-classes
Ten more `T...State_<hexaddr>` Class namespaces of the same kind we dissolved
(`TRuntimeLinkedBlockChainState_0063E880/_0066FA50`):

```
TLinkedBlockChainState_00650A50          TRuntimeHeapBufferOwnerState_0066FA68
TCViewOwnedBufferChainState_00648578     TCViewOwnedBufferRegistryState_00648560
TModuleLibraryCacheTableStateA_0064BA68  TModuleLibraryCacheTableStateB_0064BA80
TCommandLineParseContextState_0066FEA4   TApplicationUiRootControllerState_00648CA8
TCityDialogModalState_00649A50           TTurnEventDialogFactoryRegistryState_0064B328
```

Per-case triage required: most are vtable-write-in-destructor artifacts and go
into `config/dissolve_namespaces.csv`; a few (e.g. `TCityDialogModalState`) may be
salvageable real classes and should be renamed/attributed instead of dissolved.

### 2b. Fix mislabeled calling conventions
MSVC500 app code essentially never used `__fastcall`, so the 47 `__fastcall`
functions are almost certainly mislabeled `__thiscall` (e.g. the destructors seen
during the dissolve work were `__fastcall(undefined4 *param_1)`). Correcting them
gives each a typed `this`, improving both the decomp and reccmp matching. Also
review the 61 `__cdecl`. Use `just scan-cdecl-thiscall` to classify by who sets
`ecx`. Verify against the assembly — never trust the Ghidra label.

## Tier 3 — bigger levers, more effort

- **Interior field recovery at scale.** Most class structs are `{vftable}` + a sea
  of `field_0x...`. Recovering scalar/array/embedded members (evidence-driven:
  consistent access widths/strides) is the biggest readability lever but the
  hardest and most error-prone — keep it curated/gated to avoid corrupting layouts.
- **Vtable slots → named virtuals + signatures.** Decompiles still show
  `(*this->vftable[0x3a].slot_0x04)(...)`. Naming/typing slots resolves virtual
  call sites and feeds the matching loop.
- **Name the 323 `FUN_`/`SUB_` functions.** Extend the existing locality/caller
  attribution heuristics in `apply_mfc_rtti.py`.
- **Reclassify misidentified data.** Labels like
  `s_doofrbafbmulepapeetsleuftolcnruf_006960e0` are treated as strings but indexed
  as tables (`+ sVar3*4 + 0x28`) — they are structs/arrays, not strings.

## Validation

Calling-convention and field-type changes directly affect the C++ port, so route
impactful changes through `just build` + reccmp (`just compare` / `just stats`) to
confirm they help (or at least don't regress) the match, not just readability.
