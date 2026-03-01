# macOS Binary Debug Symbols Reference

## Binary Overview

`Imperialism_macos` is the Power Macintosh port of Imperialism, compiled with Metrowerks
CodeWarrior. Unlike the Windows builds (stripped MSVC 5.0 PEs), this binary ships with full
Cfront-style C++ debug symbols embedded in its Ghidra analysis.

| Property | Value |
|---|---|
| Architecture | PowerPC BE 32-bit |
| Compiler | Metrowerks CodeWarrior |
| Image base | `0x10000000` |
| Ghidra program path | `/Imperialism_macos` |
| Total functions | 3,441 |
| Named functions | 3,320 |
| Unique classes | 508 |
| Class methods | 2,210 |
| Global functions | 1,040 |

## Ghidra Namespaces

The binary has two non-global Ghidra namespaces:

- **`.debug`** — 2,774 functions with Cfront-mangled C++ names. This is the primary vocabulary source.
- **`.glue`** — 545 PowerPC branch island stubs (trampolines for far calls). Not useful for naming.

## Name Mangling Format (Cfront / CodeWarrior)

Cfront encodes class and type information directly in the symbol name:

```
.MethodName__NClassNameFparams
```

- `N` = decimal length of the class name
- `F` separates the class from the parameter list
- `C` before `F` = `const` method
- Constructors: `.__ct__NClassNameFparams`
- Destructors: `.__dt__NClassNameFv`

Examples:

| Raw symbol | Decoded |
|---|---|
| `.IndustrialCostToBuildShip__11TGreatPowerCFs` | `TGreatPower::IndustrialCostToBuildShip(short) const` |
| `.__ct__12BestFitBlockFiil` | `BestFitBlock::BestFitBlock(int, int, long)` |
| `.ReadFrom__12BattleRecordFP7TStream` | `BattleRecord::ReadFrom(TStream*)` |

## Reference Files

All files live under `tmp_decomp/`:

| File | Rows | Description |
|---|---|---|
| `macos_debug_symbols.csv` | 3,441 | Raw full dump: `address, full_name, class, method, params` |
| `macos_class_methods.csv` | 2,210 | Class→method mapping: `class, method, params, address, full_name` |
| `macos_global_functions.csv` | 1,040 | Non-class functions: `address, method, params, full_name` |
| `macos_rename_candidates.csv` | 43 | BSim cross-arch candidates (see caveats below) |

## Cross-Validation with Windows

338 of the 508 macOS class names appear verbatim in the Windows main binary, confirming the
shared codebase. The macOS binary provides ground-truth method inventories for all of them.

**Stub/blocker classes** — classes present in Windows but not yet fully analyzed — now have
canonical method lists from macOS:

| Class | macOS methods | Sample methods |
|---|---|---|
| TMultiplayerMgr | 77 | AttemptSave, CancelGameOptions, CheckInPlayer, ... |
| TMapMgr | 60 | ActivateMarchingArrow, AddGhostRail, AreNeighbors, ... |
| TTaskForce | 59 | Add, AttemptToEvade, BattleWith, CancelOrders, ... |
| TShip | 47 | Capture, ComputeValueForMission, Damage, ... |
| TTacticalBattle | 44 | BeginFighting, CanFireOn, CheckForVictory, ... |
| TGreatPower | 40 | AddColony, AddNoticeFrom, AddProvince, ... |
| TNavyMgr | 28 | ActionCursor, AssignEscorts, CarryOutOrders, ... |
| TArmyMgr | 27 | ActionCursor, AddBattleRecord, AttackOrder, ... |
| TCountry | 26 | AddProvince, BecomeColonyOf, ChangeMaster, ... |
| TOcean | 21 | AssembleUIForce, BuildPort, EnumerateBeaches, ... |
| TCivMgr | 20 | ActionCursor, CanDeployUnit, DeployUnit, ... |
| TTechMgr | 16 | ActivateAdvance, ActivateLandUnit, CancelPurchase, ... |
| TNavyMission | 16 | CombineForce, ComputeSeaZoneImportance, ... |
| THelpMgr | 18 | CheckAdvice, CheckCityEntryWarning, CheckEndTurnWarnings, ... |
| TDiplomacyMgr | ~14 | (see macos_class_methods.csv) |

## How to Use This Reference

**Correct use — vocabulary lookup:** When renaming an unresolved thiscall function in the
Windows binary, check `macos_class_methods.csv` for known method names of the candidate
class. This tells you what methods *should* exist, helping validate or suggest names.

```bash
# What methods does TNavyMgr have?
grep "^TNavyMgr," tmp_decomp/macos_class_methods.csv | cut -d, -f2 | sort
```

**Correct use — class membership check:** Confirm whether a class name is real (appears in
macOS) before assigning an unresolved function to it.

```bash
grep "^TFooBar," tmp_decomp/macos_class_methods.csv | head -3
```

## BSim Cross-Architecture Caveats

BSim matched 56 Windows↔macOS function pairs (27 at sim≥0.9). **Do not apply these as
renames without manual semantic validation.** Cross-architecture (x86 vs PowerPC) BSim
matching is unreliable for short or structurally generic functions:

- `global_unwind2` in macOS matched `TMultiplayerMgr::SendTradeBook` in Windows at sim=1.0
  — a clear false positive caused by both being tiny stub-like functions.
- Even sim=1.0 cross-arch matches can be semantically wrong.

The file `macos_rename_candidates.csv` lists the 43 candidates. Treat each as a hint to
investigate in Ghidra, not as an authoritative rename source. The `is_ambiguous` column
flags matches where multiple Windows functions map to the same macOS symbol (extra caution
required).
