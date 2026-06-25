# Construction cleanup — remaining work (2026-06-23)

Session landed **Problems 1–2** from the construction-cleanup plan and a partial **Problem 3**
tier-1 pass. Verified with `just gates`, `just build`, `just stats`.

## Done this session

- **Real ctor chains:** `TSoundPlayer` uses `: TEventHandler()` (not header-default helper in ctor).
  `InitializeUiResourceEntryBaseHeaderDefaults` @ `0x48a100` kept as a standalone binary helper for
  fork receivers that still call it directly.
- **In-place construction:** `TArmyToolbar`, `TProductionCluster`, `TAutoGreatPower` (`Construct*`
  → `::new (this) T…()`), `TSoundPlayer` ctor member-init list.
- **Factory split:** `CreateAutoGreatPowerNationState` @ `0x4e6a70` in
  `src/game/tauto_great_power_factory.cpp` (separate TU — avoids vtable slot collision with the
  empty `UpdateGreatPowerPressureState…` stub @ `0x4e6b10`).
- **ILT retirement:** ctor ILTs marked `retired-ilt` in `docs/ilt_inventory.csv`; `TAmtBar`
  `0x401e65` bridge removed.
- **Tier-1 shape ports:** `TInfoBarText` @ `0x5b66b0`, `TInfoBarPictureText` @ `0x5b5cb0`.

## Still TBD

### Constructors vs vtable slot-0x11 “Construct*BaseState” names

`TPopGrowthOrder` @ `0x4b8160`, `TFoodProcessingOrder` @ `0x4b7e80`, siblings in
`TProductionOrder` hierarchy: Ghidra labels these `Construct*BaseState`, but the binary allocates
with manual vptr write + `vtable+0x44` dispatch (see `global_part006.cpp` city init). Mac oracle
has `TPopGrowthOrder::IPopGrowthOrder(TCity*)` and `_DefaultConstructor()`.

**Target model:** `explicit TPopGrowthOrder(TCity* city) : TProductionOrder(), …` (see
`TCapacityOrder` for the pattern) plus, if needed, a typed `InitializeCityProductionState_Impl`
vtable slot for the manual-alloc path — **not** a misnamed `Construct*BaseState` virtual.

### Problem 3 — remaining `Construct*BaseState` stubs

| Tier | Address | Class | Notes |
|------|---------|-------|-------|
| 1 | `0x4aa540` | `TSuperArmyRoster` | Large; needs `TPageView` field recovery + real virtuals |
| 2 | `0x486650` | `TCommandHandler` | |
| 2 | `0x4b8160` | `TPopGrowthOrder` | See constructor note above |
| 2 | `0x5b62a0` | `TDeluxeText` | Signature `(int, undefined4)`; vtable-sensitive |
| 2 | `0x5bc780` | `TDealTabControl` | Signature `(int, char)`; vtable-sensitive |
| 2 | `0x59efc0` | `TNavyHumanPlayer` | |
| 3 | various | treaty dialogs, `TRailheadDialog`, `TSuperCivRoster`, `TNumberedIcon` | Large stubs |

Partial tier-2 ports were **reverted** before commit because wrong virtual signatures scrambled
vtables (`TDealTabControl`, `TDeluxeText`, `TPopGrowthOrder`).

### Construction gate baseline

`config/construction_gate_baseline.csv` ratcheted for intentional `operator new` in
`tauto_great_power_factory.cpp` and in-place `::new (this)` helpers.

### Follow-up compares

Run per-address `just compare` on construction fixes when chasing scores:
`0x58dee0`, `0x593370`, `0x586920`, `0x4e6b50`, `0x4e6a70`, `0x48a100`, `0x5b66b0`, `0x5b5cb0`.
