# TGreatPower blockers

Living register for `TGreatPower::vftable` (orig `0x00653938`, 184 slots) recovery.
Scores and commands go in `docs/worklog.md`; structural blockers and decisions live here.

## Baseline (2026-06-16, refreshed after `2366322`)

| Check | Result |
|-------|--------|
| `just vtable TGreatPower` | **100% match** (deep-slot alignment complete, including `vtable+0xfc` and `vtable+0x2ac`) |
| Orig vtable | `0x00653938`, slots `0x00`–`0xb7` (184); `0xb3`–`0xb7` NULL |
| Recomp vtable | `0x00468648` |
| Architecture | `TGreatPower : public TObject` |

### Canary `just compare` scores

| Address | Symbol | Score |
|---------|--------|-------|
| `0x4d89d0` | `GetTGreatPowerClassNamePointer` / slot 0 | 50% |
| `0x4d8c20` | scalar deleting dtor | 72% |
| `0x4d9160` | `Free` | 41% |
| `0x4d92e0` | `ReadFrom` | 18% |
| `0x4da500` | `SerializeNationOrderStateToArchive` | 95% |
| `0x4da3e0` | `DeserializeNationOrderStateFromArchive` | 89% |

### Prefix/lifecycle summary

`TGreatPower` now uses the expected inherited prefix:
- `vtable+0x00`: `GetRuntimeClass` (`0x4d89d0`)
- `vtable+0x04`: scalar deleting dtor (`0x4d8c20`, `// SYNTHETIC`)
- `vtable+0x08..0x10`: inherited `Serialize`/`AssertValid`/`Dump`
- `vtable+0x14..0x1c`: `WriteTo`/`ReadFrom`/`Free`
- `vtable+0x20..0x24`: inherited `ShallowClone`/`ShallowFree`

---

## Blocker register

| ID | Blocker | Status | Unblocks |
|----|---------|--------|----------|
| B1 | **Deep-table drift** beyond lifecycle prefix (`vtable+0x68+` and selected auto overrides) | resolved on base | Full 100% `TGreatPower` vtable alignment |
| B2 | **`TGREATPOWER_VTABLE_SLOT` macro** emitted competing empty bodies | resolved | macro deleted; slots promoted to named virtuals |
| B3 | **NULL orig tail slots** (`0xb3`–`0xb7`): C++ virtuals inflate recomp vtable | resolved on base | TAutoGreatPower owns tail via `EscalateNeedSlot2C8`/`CallSlotB3` |
| B4 | **Layout tail `0x964+`** — `missionQueue`/`mapNodeStateFlags` on base, alloc derived `0xb64` | open | `just stackcmp 0x4d89f0` shows ctor epilogue structural mismatch; `offsetof` probes pass, `ASSERT_SIZE(0x964)` deferred |
| B5 | **Minister ctors** — roster `0x4d92e0` constructs `TForeignMinister`/`TDefenseMinister`/`TCityInteriorMinister` | open | Phase 3a (`0x4d92e0` at 18%) |
| B6 | **TMission hierarchy** — mission queue slots need `TMission`/`TTrackedObject` recovery | open | Phase 4 / `PruneInvalidTrackedEntries` |
| B7 | **Parallel nation vtables** (`TMinor` Model B) — same offset, different entries | open | Phase 2 per-class only |
| B8 | **Duplicate slot 0** — cdecl global + static `GetTGreatPowerClassNamePointer` | resolved | `GetRuntimeClass()` virtual anchor retained |
| B9 | **Declaration-order drift** — some virtuals (e.g. `AssignNeedSlotFromSourceSlot19C`) sit mid-table but map to high indices (`0x19c`); comment labels ≠ slot indices | resolved on base | Full 100% match after stub sweep |

---

## Decisions (do not regress)

1. **Keep `public TObject` on `TGreatPower`** — this is now the settled architecture.
2. **Slot 0** — `GetRuntimeClass()` virtual owns `0x4d89d0`; remove duplicate cdecl helper.
3. **Slot 1** — `// SYNTHETIC` scalar deleting dtor `0x4d8c20`; dtor body `0x4d8c50`.
4. **NULL tail** — `EscalateNeedSlot2C8` / `CallSlotB3` belong on `TAutoGreatPower` only (`0x402112`, `0x40360c`).
5. **Slots 173–174** (`0x2b4`/`0x2b8`) — promote `OrphanRetStub_004d8bc0`/`004d8be0`, not delete.
6. **Slot 177** (`0x2c4`) — `BuildGreatPowerTurnMessageSummaryAndDispatch` (`0x4e2b70`).

---

## Milestones

| Milestone | Target | Status |
|-----------|--------|--------|
| M1 | Recomp vtable same size as orig; prefix slots 0–9 match lifecycle contract | **done** |
| M2 | ≥80% slot address match | in progress — major stub sweep done; declaration-order drift (B9) blocks full count |
| M3 | 100% | **done (`just vtable TGreatPower`)** |
| M4 | Canary bodies `0x4d9160`, `0x4d92e0`, `0x4da500` ≥90% | pending |
| M5 | `just vtable TAutoGreatPower` 100% | pending (remaining drift isolated to TAuto-only tail slots `0x2c8/0x2cc`) |

## Tail layout status

- Current asserted base tail offsets in `TGreatPower.cpp`:
  - `actionMetricByQuarter` = `0x964`
  - `mapNodeStateFlags` = `0x970`
  - `portZoneStateFlags` = `0xAF0`
  - `missionQueue` = `0xB60`
- Allocation model remains: base constructor path allocates `0x964`; derived `TAutoGreatPower`
  state extends to `0xB64`. Keep this split documented while map-action/mission ownership
  is gradually migrated.
