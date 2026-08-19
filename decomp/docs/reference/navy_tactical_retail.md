# Windows retail naval combat path

The Windows retail executable does not enter `TNavyBattle` from the production military phase.
Its recovered tactical navy classes are dormant code, so they cannot currently serve as a live
behavior oracle for deployment geometry or toolbar layout.

## Direct executable observation

Retail executable SHA-256:
`6afab8495db715fd9e719cffa74abe5ede4dd763428ff65d73be4edf16c9e691`.

A save containing an active-nation patrol (nation 6, order 3) and a hostile blockade (nation 0,
order 6) at the same zone was loaded by the original executable. The war relation was fixed in the
isolated retail process before invoking the production `TSimMgr::DoMilitary` body at `0x0057f280`.
GDB breakpoints observed this exact original-executable sequence:

1. `TNavyMgr::CarryOutOrders` (`0x005578a0`)
2. `TTaskForce::TryToSpot` (`0x00555720`)
3. `TTaskForce::ResolveEncounterWith` (`0x00555920`)
4. `TTaskForce::BattleWith` (`0x00555d10`)
5. return from `DoMilitary`

No breakpoint fired at `TNavyBattle::InitTacticalBattle` (`0x005a5540`),
`TNavyAutoPlayer::StartBattle` (`0x0059f110`), or
`TNavyBattle::DeployTacticalUnitToTile` (`0x005a55c0`). This is direct retail execution evidence;
the encounter save is only the deterministic trigger and is not itself claimed as a retail fixture.

## Why retail always resolves strategically

Both player-involved encounter gates in the original listings read word `[g_pSimMgr + 0x4a]`:

- `TTaskForce::Encounter`, `0x0055562c`
- `TTaskForce::BattleWith`, `0x00555d51`

`TSimMgr::preferenceValues` begins at `+0x48`, so `+0x4a` is slot 1, not slot 3. The settings
initializer at `0x00581400` clears that word on both paths (`0x00581430` and `0x005814c0`). With
slot 1 zero, `BattleWith` calls `TNavyMgr::ResolveStrategicBattle`; the turn state machine then calls
`StartNextPhase` after `DoMilitary` returns.

The reconstruction previously read `preferenceValues[3]` (master volume at `+0x4e`). That field
attribution was wrong and made the dormant tactical branch appear reachable.

## Dormant-code contradiction

The original listings still contain mutually incompatible tactical fragments:

- `TNavyBattle::InitTacticalBattle` sets 180 tiles and neighbor stride 6.
- `TNavyBattle::DeployTacticalUnitToTile` divides tile indices by 29.
- `TNavyAutoPlayer::StartBattle` begins at tile 41 and decrements.
- the recovered Windows UI resource inventory has `TTacArmyView` but no navy battle view or
  production navy-toolbar layout.

Because production never constructs the battle, Windows retail provides no active-nation side
mapping, initial selection, accepted deployment cells, visual-to-tactical mapping, move, or fire
observation. Choosing among those dormant fragments would invent behavior. Rust production must
therefore keep strategic resolution; the recovered headless tactical branch is not a direct Windows
retail-equivalence claim.
