# TGreatPower blockers

Living register for `TGreatPower::vftable` (orig `0x00653938`, 184 slots) recovery.
Scores and commands go in `docs/worklog.md`; structural blockers and decisions live here.

## Baseline (2026-06-16)

| Check | Result |
|-------|--------|
| `just vtable TGreatPower` | **0%** match; recomp vtable **larger** than orig |
| Orig vtable | `0x00653938`, slots `0x00`–`0xb7` (184); `0xb3`–`0xb7` NULL |
| Recomp vtable | `0x00469648` |
| Architecture | Standalone nation class — **not** `TObject`/`CObject` inheritance |

### Canary `just compare` scores

| Address | Symbol | Score |
|---------|--------|-------|
| `0x4d89d0` | `GetTGreatPowerClassNamePointer` / slot 0 | 50% |
| `0x4d8c20` | scalar deleting dtor | 72% |
| `0x4d9160` | `ReleaseOwnedGreatPowerObjectsAndDeleteSelf` | 41% |
| `0x4d92e0` | `InitializeGreatPowerMinisterRosterAndScenarioState` | 18% |
| `0x4da500` | `SerializeNationOrderStateToArchive` | 95% |
| `0x4da3e0` | `DeserializeNationOrderStateFromArchive` | 89% |

### Root cause summary

~23 `TGREATPOWER_VTABLE_SLOT(n)` empty stubs occupy vtable slots while real bodies
live as separate non-virtual methods. Three extra tail virtuals (`VTableIndex177`,
`EscalateNeedSlot2C8`, `CallSlotB3`) inflate recomp past orig NULL tail (`0x2c8`/`0x2cc`).

---

## Blocker register

| ID | Blocker | Status | Unblocks |
|----|---------|--------|----------|
| B1 | **ILT thunk region** (`0x40xxxx`): claiming thunk addrs prevents reccmp jmp resolution for slots 2–4, 8–9 | open | Phase 1c Serialize/AssertValid/Dump/ShallowClone/ShallowFree |
| B2 | **`TGREATPOWER_VTABLE_SLOT` macro** emits competing empty bodies | resolved | macro deleted; all slots named |
| B3 | **NULL orig tail slots** (`0xb3`–`0xb7`): C++ virtuals inflate recomp vtable | resolved on base | TAutoGreatPower owns tail via `EscalateNeedSlot2C8`/`CallSlotB3` |
| B4 | **Layout tail `0x964+`** — `missionQueue`/`mapNodeStateFlags` on base, alloc derived `0xb64` | open | `just stackcmp 0x4d89f0` shows ctor epilogue structural mismatch; `offsetof` probes pass, `ASSERT_SIZE(0x964)` deferred |
| B5 | **Minister ctors** — roster `0x4d92e0` constructs `TForeignMinister`/`TDefenseMinister`/`TCityInteriorMinister` | open | Phase 3a (`0x4d92e0` at 18%) |
| B6 | **TMission hierarchy** — mission queue slots need `TMission`/`TTrackedObject` recovery | open | Phase 4 / `PruneInvalidTrackedEntries` |
| B7 | **Parallel nation vtables** (`TMinor` Model B) — same offset, different entries | open | Phase 2 per-class only |
| B8 | **Duplicate slot 0** — cdecl global + static `GetTGreatPowerClassNamePointer` | resolved | `GetRuntimeClass()` virtual on base + derived |
| B9 | **Declaration-order drift** — some virtuals (e.g. `AssignNeedSlotFromSourceSlot19C`) sit mid-table but map to high indices (`0x19c`); comment labels ≠ slot indices | open | Full 100% match after stub sweep |

---

## Decisions (do not regress)

1. **No `public TObject` on `TGreatPower`** — would corrupt 184-slot layout and minister offsets.
2. **Slot 0** — `GetRuntimeClass()` virtual owns `0x4d89d0`; remove duplicate cdecl helper.
3. **Slot 1** — `// SYNTHETIC` scalar deleting dtor `0x4d8c20`; dtor body `0x4d8c50`.
4. **NULL tail** — `EscalateNeedSlot2C8` / `CallSlotB3` belong on `TAutoGreatPower` only (`0x402112`, `0x40360c`).
5. **Slots 173–174** (`0x2b4`/`0x2b8`) — promote `OrphanRetStub_004d8bc0`/`004d8be0`, not delete.
6. **Slot 177** (`0x2c4`) — `BuildGreatPowerTurnMessageSummaryAndDispatch` (`0x4e2b70`).

---

## Milestones

| Milestone | Target | Status |
|-----------|--------|--------|
| M1 | Recomp vtable same size as orig; prefix slots 0–7 match | **partial** — size fixed; slot 0/1/6/7/14 green; slots 2–5/8–9 thunk-resolution pending (B1) |
| M2 | ≥80% slot address match | in progress — major stub sweep done; declaration-order drift (B9) blocks full count |
| M3 | 100% | pending |
| M4 | Canary bodies `0x4d9160`, `0x4d92e0`, `0x4da500` ≥90% | pending |
| M5 | `just vtable TAutoGreatPower` 100% | pending |
