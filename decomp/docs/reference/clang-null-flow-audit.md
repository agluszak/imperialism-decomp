# clang-analyzer null-flow audit (core.CallAndMessage / core.NullDereference)

Reviewed record for the 282 clang-analyzer LLVM19 null-flow warnings over
`src/game` collected in the 8mo.23 profile run (2026-07-23). Every finding was
classified by reading the flagged flow in source together with the containing
function's reccmp baseline match percentage
(`config/baselines/reccmp_progress_baseline.functions.csv`); a function at/near
100% is byte-faithful to the retail binary, so its flagged flow is by definition
the original's. No analyzer suppressions were added and no source was changed:
the C rows are verification candidates for the orchestrator, not applied fixes.

## Classes

- **A — listing-faithful retail behavior.** The retail binary really has this
  flow; the "null path" is the original's own unchecked dereference.
- **B — proven non-null contract.** The pointer is non-null by a construction or
  startup invariant the analyzer cannot see; the contract is named per row.
- **C — candidate source-model defect.** Plausibly a porting slip; needs Ghidra
  listing verification before any edit (shortlist at the end).
- **D — analyzer artifact / out of scope.**

## Rationale codes

- **A1** — containing function is at/near 100% baseline match: byte-faithful,
  so the flagged flow is exactly the retail flow. No further proof needed.
- **A2** — retail assert-then-continue. The game's nil-pointer reporter
  (`FailNilPointer*` / `GAME_FAIL_NIL_POINTER` / `MessageBoxA` +
  `TemporarilyClearAndRestoreUiInvalidationFlag`) is not noreturn; retail pops
  the assert box and then dereferences the pointer unconditionally. Our source
  transcribes that exact shape (`if (p == 0) Fail(...); p->Method(...)`),
  which is what teaches the analyzer the null path. This is the dominant UI
  pattern (`ResolveControlByTag` / `ResolveTurnEventDialogNodeByMessageContext`).
- **A3** — retail inlined-accessor ternary. The original inlines accessors as
  `p != 0 ? p->field : 0` (e.g. the `AfxGetMainWnd()` expansion, `nation->city`,
  `GetCityState()`), producing a possibly-null local that retail then
  dereferences unguarded. The ternary is the original's codegen shape, not our
  guard; the follow-on unchecked deref is retail behavior.
- **A4** — transcribed selector with no default: `bufferBase` stays null when the
  network poke packet selector is neither 0 nor 1; retail has the same two-way
  `if`/`else if` and would fault identically on a malformed packet.
- **A5** — flow is explicitly documented in source as faithful retail null
  behavior (e.g. `IMPERIALISM_BEGIN_RETAIL_NULL_THIS_CHECK`, "latent original
  bug, kept as-is", "the original invokes this ... even when it is null").
- **B1** — list/count invariant: the record buffer is sized from a count computed
  by walking the same linked list that the indexing loop walks (or the list
  member is allocated unconditionally in the constructor), so the flagged index
  path implies a non-null buffer.
- **B2** — startup-initialized singleton (`g_pDiplomacyTurnStateManager`,
  `g_pSimMgr`): created during game init before any caller of this code runs;
  a null-check on a *different* global earlier in the function teaches the
  analyzer that manager globals can be null.
- **B3** — factored helper contract: `BackingArchive()` is our own inline helper;
  every caller passes the stream's backing-adapter member, which is set at
  stream construction.
- **B4** — proven-by-prior-walk: an immediately preceding walk of the same
  `g_pMapActionContextListHead` chain already break-ed out unless a matching
  `TPortZone` node exists, so the second identical walk cannot end at null.
- **C1/C2/C3** — see the shortlist below.
- **D1** — warning is inside the vendored MFC header (`afxtempl.h`), i.e. library
  template code we must not model or patch; the null path is an analyzer state
  merge through game-side instantiation, out of scope for manual source.

## Findings

| file:line | check | function addr / match | class | rationale |
| --- | --- | --- | --- | --- |
| `src/game/CDib.cpp:492` | NullDereference | 0x47bde0 17.9% | **A** | C1 (verified) |
| `src/game/CDib.cpp:495` | NullDereference | 0x47bde0 17.9% | **A** | C1 (verified) |
| `src/game/CDib.cpp:511` | NullDereference | 0x47bde0 17.9% | **A** | C1 (verified) |
| `src/game/CDib.cpp:511` | NullDereference | 0x47bde0 17.9% | **A** | C1 (verified) |
| `src/game/CDib.cpp:517` | NullDereference | 0x47bde0 17.9% | **A** | C1 (verified) |
| `src/game/CDib.cpp:517` | NullDereference | 0x47bde0 17.9% | **A** | C1 (verified) |
| `src/game/CIncludeView.cpp:258` | CallAndMessage | 0x483750 91.2% | **A** | A2 |
| `src/game/CMcWindow.cpp:30` | NullDereference | 0x493470 41.7% | **A** | A2 |
| `src/game/ImperialismApp.cpp:150` | CallAndMessage | 0x412a70 100.0% | **A** | A1 |
| `src/game/ImperialismApp.cpp:424` | CallAndMessage | 0x4140f0 45.3% | **A** | A2 |
| `src/game/ImperialismApp.cpp:518` | NullDereference | 0x4146d0 60.5% | **A** | A5 |
| `src/game/TAmtBarCluster.cpp:47` | CallAndMessage | 0x586d60 63.3% | **A** | A2 |
| `src/game/TAmtBarCluster.cpp:59` | CallAndMessage | 0x586e70 32.0% | **A** | A2 |
| `src/game/TAmtBarCluster.cpp:65` | CallAndMessage | 0x586e70 32.0% | **A** | A2 |
| `src/game/TAmtBarCluster.cpp:74` | CallAndMessage | 0x586e70 32.0% | **A** | A2 |
| `src/game/TApplication.cpp:111` | NullDereference | 0x486ba0 84.5% | **A** | A3 |
| `src/game/TApplication.cpp:125` | NullDereference | 0x486ba0 84.5% | **A** | A3 |
| `src/game/TApplication.cpp:139` | NullDereference | 0x486ba0 84.5% | **A** | A3 |
| `src/game/TApplication.cpp:144` | NullDereference | 0x486ba0 84.5% | **A** | A3 |
| `src/game/TApplication.cpp:149` | NullDereference | 0x486ba0 84.5% | **A** | A3 |
| `src/game/TApplication.cpp:154` | NullDereference | 0x486ba0 84.5% | **A** | A3 |
| `src/game/TApplication.cpp:159` | NullDereference | 0x486ba0 84.5% | **A** | A3 |
| `src/game/TArmoryView.cpp:68` | CallAndMessage | 0x4cf350 57.8% | **A** | A2 |
| `src/game/TArmoryView.cpp:73` | CallAndMessage | 0x4cf350 57.8% | **A** | A2 |
| `src/game/TArmyMgr.cpp:2025` | NullDereference | 0x4a6ef0 40.0% | **B** | B1 |
| `src/game/TArmyMgr.cpp:246` | CallAndMessage | 0x4a1b80 51.0% | **A** | A2 |
| `src/game/TArmyMgr.cpp:607` | NullDereference | 0x4a3200 70.5% | **A** | A3 |
| `src/game/TArmyMgr.cpp:724` | NullDereference | 0x4a35e0 59.7% | **A** | A3 |
| `src/game/TArmyPlayer.cpp:284` | CallAndMessage | 0x59b830 87.0% | **A** | A2 |
| `src/game/TArmyUnitView.cpp:184` | CallAndMessage | 0x4a9ca0 51.1% | **A** | A2 |
| `src/game/TAssetMgr.cpp:262` | NullDereference | 0x5e0520 91.3% | **A** | A3 |
| `src/game/TAutomatedPlayDialog.cpp:29` | CallAndMessage | 0x5b46c0 100.0% | **A** | A1 |
| `src/game/TBoycottButton.cpp:31` | CallAndMessage | 0x584800 88.9% | **A** | A2 |
| `src/game/TBuildingConstructionView.cpp:39` | CallAndMessage | 0x4ca8f0 65.4% | **A** | A2 |
| `src/game/TBuildingConstructionView.cpp:41` | NullDereference | 0x4ca8f0 65.4% | **A** | A2 |
| `src/game/TBuildingExpansionView.cpp:36` | CallAndMessage | 0x4cebb0 62.7% | **A** | A2 |
| `src/game/TBuildingExpansionView.cpp:38` | NullDereference | 0x4cebb0 62.7% | **A** | A2 |
| `src/game/TCityBarCluster.cpp:53` | CallAndMessage | 0x5866b0 42.3% | **A** | A2 |
| `src/game/TCityBarCluster.cpp:59` | CallAndMessage | 0x5866b0 42.3% | **A** | A2 |
| `src/game/TCityBarCluster.cpp:65` | CallAndMessage | 0x5866b0 42.3% | **A** | A2 |
| `src/game/TCityInteriorMinister.cpp:2472` | NullDereference | 0x4c4fe0 10.3% | **A** | A3 |
| `src/game/TCityInteriorMinister.cpp:395` | CallAndMessage | 0x4bf770 70.2% | **A** | A2 |
| `src/game/TCityInteriorMinister.cpp:582` | NullDereference | 0x4bff80 42.2% | **A** | A3 |
| `src/game/TCityInteriorMinister.cpp:927` | CallAndMessage | 0x4c0e50 31.6% | **A** | A2 |
| `src/game/TCityProductionView.cpp:165` | CallAndMessage | 0x4bc0b0 36.2% | **A** | A2 |
| `src/game/TCityProductionView.cpp:172` | CallAndMessage | 0x4bc0b0 36.2% | **A** | A2 |
| `src/game/TCityProductionView.cpp:179` | CallAndMessage | 0x4bc0b0 36.2% | **A** | A2 |
| `src/game/TCityProductionView.cpp:186` | CallAndMessage | 0x4bc0b0 36.2% | **A** | A2 |
| `src/game/TCityProductionView.cpp:200` | CallAndMessage | 0x4bc0b0 36.2% | **A** | A2 |
| `src/game/TCityProductionView.cpp:95` | CallAndMessage | 0x4badd0 82.9% | **A** | A2 |
| `src/game/TCivToolbar.cpp:109` | CallAndMessage | 0x58ec50 58.6% | **A** | A2 |
| `src/game/TCivToolbar.cpp:122` | CallAndMessage | 0x58ec50 58.6% | **A** | A2 |
| `src/game/TCivToolbar.cpp:137` | CallAndMessage | 0x58ec50 58.6% | **A** | A2 |
| `src/game/TCivToolbar.cpp:142` | CallAndMessage | 0x58ec50 58.6% | **A** | A2 |
| `src/game/TCivToolbar.cpp:147` | CallAndMessage | 0x58ec50 58.6% | **A** | A2 |
| `src/game/TCombatReportView.cpp:104` | CallAndMessage | 0x58c950 40.7% | **A** | A2 |
| `src/game/TCombatReportView.cpp:150` | CallAndMessage | 0x58c950 40.7% | **A** | A2 |
| `src/game/TCombatReportView.cpp:175` | CallAndMessage | 0x58c950 40.7% | **A** | A2 |
| `src/game/TCombatReportView.cpp:348` | CallAndMessage | 0x58d950 65.8% | **A** | A2 |
| `src/game/TCombatReportView.cpp:383` | CallAndMessage | 0x58d950 65.8% | **A** | A2 |
| `src/game/TCountry.cpp:405` | CallAndMessage | 0x4d7b20 63.6% | **B** | B2 |
| `src/game/TCountry.cpp:423` | CallAndMessage | 0x4d7c00 64.1% | **B** | B2 |
| `src/game/TDealBookPicture.cpp:147` | CallAndMessage | 0x5baf70 48.2% | **A** | A2 |
| `src/game/TDealBookPicture.cpp:151` | CallAndMessage | 0x5baf70 48.2% | **A** | A2 |
| `src/game/TDealBookPicture.cpp:159` | CallAndMessage | 0x5baf70 48.2% | **A** | A2 |
| `src/game/TDealBookPicture.cpp:163` | CallAndMessage | 0x5baf70 48.2% | **A** | A2 |
| `src/game/TDealBookPicture.cpp:69` | CallAndMessage | 0x5bac50 84.3% | **A** | A2 |
| `src/game/TDiplomacyMgr.cpp:1240` | NullDereference | 0x4f1760 73.2% | **A** | A3 |
| `src/game/TEscortMission.cpp:88` | NullDereference | 0x539ca0 57.1% | **A** | A3 |
| `src/game/TFileStream.cpp:20` | NullDereference | NOMARKER ?? | **B** | B3 |
| `src/game/TGPTreatyDialog.cpp:46` | CallAndMessage | 0x5b3be0 74.0% | **A** | A2 |
| `src/game/TGPTreatyDialog.cpp:52` | CallAndMessage | 0x5b3be0 74.0% | **A** | A2 |
| `src/game/TGPTreatyDialog.cpp:56` | CallAndMessage | 0x5b3be0 74.0% | **A** | A2 |
| `src/game/TGreatPower.cpp:3288` | CallAndMessage | 0x4dfd30 57.4% | **A** | A5 |
| `src/game/TGreatPower.cpp:4229` | CallAndMessage | 0x4e2880 87.9% | **A** | A2 |
| `src/game/THelpMgr.cpp:730` | NullDereference | 0x502b60 100.0% | **A** | A1 |
| `src/game/THelpMgr.cpp:845` | CallAndMessage | 0x503420 59.1% | **A** | A2 |
| `src/game/THelpMgr.cpp:951` | CallAndMessage | 0x503ac0 100.0% | **A** | A1 |
| `src/game/timer_slots.cpp:32` | NullDereference | 0x5e0460 84.6% | **A** | A3 |
| `src/game/TIncludeView.cpp:46` | NullDereference | 0x48cf10 100.0% | **A** | A1 |
| `src/game/TIndustryAmtBar.cpp:49` | NullDereference | 0x589260 34.1% | **A** | A3 |
| `src/game/TIndustryCluster.cpp:101` | CallAndMessage | 0x588c60 39.3% | **A** | A2 |
| `src/game/TIndustryCluster.cpp:116` | NullDereference | 0x588c60 39.3% | **A** | A2 |
| `src/game/TIndustryCluster.cpp:156` | CallAndMessage | 0x588ff0 37.7% | **A** | A2 |
| `src/game/TIndustryCluster.cpp:168` | CallAndMessage | 0x588ff0 37.7% | **A** | A2 |
| `src/game/TIndustryCluster.cpp:31` | NullDereference | NOMARKER ?? | **A** | A2 |
| `src/game/TIndustryCluster.cpp:66` | NullDereference | 0x588b70 27.4% | **A** | A3 |
| `src/game/TMacViewMgr.cpp:1004` | CallAndMessage | 0x50bc50 60.3% | **A** | A2 |
| `src/game/TMacViewMgr.cpp:1016` | CallAndMessage | 0x50be30 96.0% | **A** | A2 |
| `src/game/TMacViewMgr.cpp:1084` | NullDereference | 0x50bea0 20.9% | **A** | A3 |
| `src/game/TMacViewMgr.cpp:1099` | NullDereference | 0x50bea0 20.9% | **A** | A3 |
| `src/game/TMacViewMgr.cpp:1116` | NullDereference | 0x50bea0 20.9% | **A** | A3 |
| `src/game/TMacViewMgr.cpp:1132` | NullDereference | 0x50bea0 20.9% | **A** | A3 |
| `src/game/TMacViewMgr.cpp:1144` | NullDereference | 0x50bea0 20.9% | **A** | A3 |
| `src/game/TMacViewMgr.cpp:1160` | NullDereference | 0x50bea0 20.9% | **A** | A3 |
| `src/game/TMacViewMgr.cpp:1176` | NullDereference | 0x50bea0 20.9% | **A** | A3 |
| `src/game/TMacViewMgr.cpp:1192` | NullDereference | 0x50bea0 20.9% | **A** | A3 |
| `src/game/TMacViewMgr.cpp:1208` | NullDereference | 0x50bea0 20.9% | **A** | A3 |
| `src/game/TMacViewMgr.cpp:1226` | NullDereference | 0x50bea0 20.9% | **A** | A3 |
| `src/game/TMacViewMgr.cpp:1239` | NullDereference | 0x50bea0 20.9% | **A** | A3 |
| `src/game/TMacViewMgr.cpp:1259` | NullDereference | 0x50bea0 20.9% | **A** | A3 |
| `src/game/TMacViewMgr.cpp:1276` | NullDereference | 0x50bea0 20.9% | **A** | A3 |
| `src/game/TMacViewMgr.cpp:1285` | NullDereference | 0x50bea0 20.9% | **A** | A3 |
| `src/game/TMacViewMgr.cpp:1417` | CallAndMessage | 0x50d360 68.6% | **A** | A2 |
| `src/game/TMacViewMgr.cpp:1443` | CallAndMessage | 0x50d470 38.8% | **A** | A2 |
| `src/game/TMacViewMgr.cpp:1462` | CallAndMessage | 0x50d5b0 100.0% | **A** | A1 |
| `src/game/TMacViewMgr.cpp:1558` | CallAndMessage | 0x50d950 80.7% | **A** | A2 |
| `src/game/TMacViewMgr.cpp:990` | CallAndMessage | 0x50bc50 60.3% | **A** | A2 |
| `src/game/TMacViewMgr.cpp:997` | CallAndMessage | 0x50bc50 60.3% | **A** | A2 |
| `src/game/TMapDialog.cpp:614` | CallAndMessage | 0x51b1c0 66.1% | **A** | A2 |
| `src/game/TMapDialog.cpp:653` | CallAndMessage | 0x51b1c0 66.1% | **A** | A2 |
| `src/game/TMapDialog.cpp:662` | CallAndMessage | 0x51b1c0 66.1% | **A** | A5 |
| `src/game/TMapDialog.cpp:696` | CallAndMessage | 0x51b1c0 66.1% | **A** | A2 |
| `src/game/TMapMgr.cpp:2374` | CallAndMessage | 0x5145b0 60.8% | **A** | A2 |
| `src/game/TMapMgr.cpp:2408` | CallAndMessage | 0x5147d0 64.9% | **A** | A2 |
| `src/game/TMapUberPicture.cpp:1017` | NullDereference | 0x599cf0 58.8% | **A** | A2 |
| `src/game/TMapUberPicture.cpp:1064` | NullDereference | 0x599fd0 72.9% | **A** | A2 |
| `src/game/TMapUberPicture.cpp:1081` | CallAndMessage | 0x599fd0 72.9% | **A** | A2 |
| `src/game/TMapUberPicture.cpp:1094` | CallAndMessage | 0x59a180 83.1% | **A** | A2 |
| `src/game/TMapUberPicture.cpp:515` | CallAndMessage | 0x597f80 75.9% | **A** | A2 |
| `src/game/TMapUberPicture.cpp:705` | CallAndMessage | 0x598e10 93.1% | **A** | A2 |
| `src/game/TMapUberPicture.cpp:784` | CallAndMessage | 0x599090 64.3% | **A** | A2 |
| `src/game/TMilitaryPageView.cpp:86` | CallAndMessage | 0x564a60 39.4% | **A** | C3 (verified) |
| `src/game/TMinisterView.cpp:39` | CallAndMessage | 0x4f2d10 100.0% | **A** | A1 |
| `src/game/TMinisterView.cpp:45` | CallAndMessage | 0x4f2d10 100.0% | **A** | A1 |
| `src/game/TMinorRelationshipDialog.cpp:39` | CallAndMessage | 0x5b3400 52.9% | **A** | A2 |
| `src/game/TMinorRelationshipDialog.cpp:43` | CallAndMessage | 0x5b3400 52.9% | **A** | A2 |
| `src/game/TMinorTradeBidsDialog.cpp:33` | CallAndMessage | 0x5b2aa0 79.5% | **A** | A2 |
| `src/game/TMinorTreatyDialog.cpp:47` | CallAndMessage | 0x5b4090 70.9% | **A** | A2 |
| `src/game/TMinorTreatyDialog.cpp:51` | CallAndMessage | 0x5b4090 70.9% | **A** | A2 |
| `src/game/TMovieView.cpp:32` | CallAndMessage | 0x5e2230 100.0% | **A** | A1 |
| `src/game/TMovieView.cpp:55` | CallAndMessage | 0x5e2320 66.7% | **A** | A2 |
| `src/game/TMultiplayerMgr.cpp:1259` | CallAndMessage | 0x545940 41.6% | **A** | A2 |
| `src/game/TMultiplayerMgr.cpp:1393` | CallAndMessage | 0x545940 41.6% | **A** | A5 |
| `src/game/TMultiplayerMgr.cpp:1461` | NullDereference | 0x545940 41.6% | **A** | A4 |
| `src/game/TMultiplayerMgr.cpp:1473` | NullDereference | 0x545940 41.6% | **A** | A4 |
| `src/game/TMultiplayerMgr.cpp:1486` | NullDereference | 0x545940 41.6% | **A** | A4 |
| `src/game/TMultiplayerMgr.cpp:1724` | NullDereference | 0x545940 41.6% | **A** | A3 |
| `src/game/TNavyMgr.cpp:1425` | NullDereference | 0x558960 36.0% | **B** | B1 |
| `src/game/TNavyMgr.cpp:229` | NullDereference | 0x54f110 35.1% | **B** | B1 |
| `src/game/TNavyMission.cpp:402` | CallAndMessage | 0x537090 40.3% | **B** | B1 |
| `src/game/TNewTownView.cpp:96` | CallAndMessage | 0x4bdc10 100.0% | **A** | A1 |
| `src/game/TOcean.cpp:177` | CallAndMessage | 0x5621e0 100.0% | **A** | A1 |
| `src/game/TOcean.cpp:225` | CallAndMessage | 0x562340 39.0% | **B** | B4 |
| `src/game/TOfferDeskPicture.cpp:263` | CallAndMessage | 0x5bf930 75.4% | **A** | A2 |
| `src/game/TOfferDeskPicture.cpp:269` | CallAndMessage | 0x5bf930 75.4% | **A** | A2 |
| `src/game/TOfferDeskPicture.cpp:305` | CallAndMessage | 0x5bf930 75.4% | **A** | A2 |
| `src/game/TOfferDeskPicture.cpp:310` | CallAndMessage | 0x5bf930 75.4% | **A** | A2 |
| `src/game/TOfferDeskPicture.cpp:387` | CallAndMessage | 0x5c04f0 81.1% | **A** | A2 |
| `src/game/TOfferDeskPicture.cpp:392` | CallAndMessage | 0x5c04f0 81.1% | **A** | A2 |
| `src/game/TOfferDeskPicture.cpp:399` | CallAndMessage | 0x5c04f0 81.1% | **A** | A2 |
| `src/game/TOffersPanelView.cpp:243` | CallAndMessage | 0x4f9a60 89.9% | **A** | A2 |
| `src/game/TOrderView.cpp:110` | CallAndMessage | 0x506f90 100.0% | **A** | A1 |
| `src/game/TOrderView.cpp:118` | CallAndMessage | 0x506f90 100.0% | **A** | A1 |
| `src/game/TOrderView.cpp:126` | CallAndMessage | 0x506f90 100.0% | **A** | A1 |
| `src/game/TOrderView.cpp:133` | CallAndMessage | 0x506f90 100.0% | **A** | A1 |
| `src/game/TOrderView.cpp:141` | CallAndMessage | 0x506f90 100.0% | **A** | A1 |
| `src/game/TOrderView.cpp:149` | CallAndMessage | 0x506f90 100.0% | **A** | A1 |
| `src/game/TOrderView.cpp:160` | NullDereference | 0x507240 100.0% | **A** | A2 |
| `src/game/TOrderView.cpp:30` | NullDereference | 0x506b00 66.5% | **A** | A3 |
| `src/game/TOrderView.cpp:39` | CallAndMessage | 0x506b00 66.5% | **A** | A2 |
| `src/game/TOrderView.cpp:48` | CallAndMessage | 0x506b00 66.5% | **A** | A2 |
| `src/game/TOrderView.cpp:57` | CallAndMessage | 0x506b00 66.5% | **A** | A2 |
| `src/game/TOrderView.cpp:66` | CallAndMessage | 0x506b00 66.5% | **A** | A2 |
| `src/game/TOrderView.cpp:73` | CallAndMessage | 0x506b00 66.5% | **A** | A2 |
| `src/game/TOrderView.cpp:82` | CallAndMessage | 0x506b00 66.5% | **A** | A2 |
| `src/game/TOrderView.cpp:91` | CallAndMessage | 0x506b00 66.5% | **A** | A2 |
| `src/game/TPortZone.cpp:81` | CallAndMessage | 0x5618b0 100.0% | **A** | A1 |
| `src/game/TPurchaseCluster.cpp:57` | CallAndMessage | 0x4cc550 68.4% | **A** | A2 |
| `src/game/TRailAmtBar.cpp:62` | NullDereference | 0x58a020 45.7% | **A** | A3 |
| `src/game/TRailCluster.cpp:141` | CallAndMessage | 0x5899f0 34.3% | **A** | A2 |
| `src/game/TRailCluster.cpp:156` | NullDereference | 0x5899f0 34.3% | **A** | A2 |
| `src/game/TRailCluster.cpp:196` | CallAndMessage | 0x589da0 29.6% | **A** | A2 |
| `src/game/TRailCluster.cpp:208` | CallAndMessage | 0x589da0 29.6% | **A** | A2 |
| `src/game/TRailCluster.cpp:30` | NullDereference | NOMARKER ?? | **A** | A2 |
| `src/game/TRailCluster.cpp:62` | NullDereference | 0x5897b0 33.5% | **A** | A3 |
| `src/game/TRailheadDialog.cpp:30` | CallAndMessage | 0x4bd040 84.0% | **A** | A2 |
| `src/game/TRailheadDialog.cpp:37` | CallAndMessage | 0x4bd040 84.0% | **A** | A2 |
| `src/game/TRailheadDialog.cpp:44` | CallAndMessage | 0x4bd040 84.0% | **A** | A2 |
| `src/game/TRailheadDialog.cpp:51` | CallAndMessage | 0x4bd040 84.0% | **A** | A2 |
| `src/game/TRailheadDialog.cpp:58` | CallAndMessage | 0x4bd040 84.0% | **A** | A2 |
| `src/game/TRailheadDialog.cpp:71` | CallAndMessage | 0x4bd260 100.0% | **A** | A1 |
| `src/game/TRelationshipDialog.cpp:38` | CallAndMessage | 0x5b2da0 63.9% | **A** | A2 |
| `src/game/TRelationshipDialog.cpp:42` | CallAndMessage | 0x5b2da0 63.9% | **A** | A2 |
| `src/game/TShipAmtBar.cpp:36` | NullDereference | 0x58abf0 91.2% | **A** | A3 |
| `src/game/TShip.cpp:553` | CallAndMessage | 0x5509c0 75.8% | **A** | C2 (verified) |
| `src/game/TShipView.cpp:156` | CallAndMessage | 0x565a40 67.5% | **A** | A2 |
| `src/game/TShipyardCluster.cpp:104` | CallAndMessage | 0x58a940 48.2% | **A** | A2 |
| `src/game/TShipyardCluster.cpp:117` | CallAndMessage | 0x58a940 48.2% | **A** | A2 |
| `src/game/TShipyardCluster.cpp:39` | NullDereference | 0x58a610 91.3% | **A** | A3 |
| `src/game/TShipyardCluster.cpp:52` | CallAndMessage | 0x58a690 54.1% | **A** | A2 |
| `src/game/TShipyardCluster.cpp:67` | NullDereference | 0x58a690 54.1% | **A** | A2 |
| `src/game/TShipyardCluster.cpp:69` | NullDereference | 0x58a690 54.1% | **A** | A2 |
| `src/game/TSimMgr.cpp:1547` | NullDereference | 0x582120 100.0% | **A** | A1 |
| `src/game/TSimMgr.cpp:1599` | NullDereference | 0x5822c0 73.5% | **A** | A3 |
| `src/game/TSimMgr.cpp:1642` | NullDereference | 0x5823e0 72.3% | **A** | A3 |
| `src/game/TSimMgr.cpp:1764` | NullDereference | 0x582720 97.5% | **A** | A3 |
| `src/game/TSimMgr.cpp:650` | CallAndMessage | 0x57cda0 53.2% | **A** | A2 |
| `src/game/TSimMgr.cpp:729` | CallAndMessage | 0x57cda0 53.2% | **A** | A2 |
| `src/game/TSimMgr.cpp:739` | CallAndMessage | 0x57cda0 53.2% | **A** | A2 |
| `src/game/TStatusPicture.cpp:225` | NullDereference | 0x594900 40.9% | **A** | A3 |
| `src/game/TStatusPicture.cpp:230` | NullDereference | 0x594900 40.9% | **A** | A3 |
| `src/game/TTacArmyView.cpp:164` | NullDereference | 0x5a9d90 62.8% | **A** | A2 |
| `src/game/TTacticalBattle.cpp:1357` | NullDereference | 0x5a1ee0 67.4% | **A** | A3 |
| `src/game/TTaskForce.cpp:337` | NullDereference | 0x552d10 59.9% | **A** | A3 |
| `src/game/TTaskForce.cpp:346` | NullDereference | 0x552d10 59.9% | **A** | A3 |
| `src/game/TTaskForce.cpp:833` | CallAndMessage | 0x553bc0 65.4% | **A** | A2 |
| `src/game/TTaskForce.cpp:973` | CallAndMessage | 0x553fe0 77.8% | **A** | C2 (verified) |
| `src/game/TToolBarCluster.cpp:570` | CallAndMessage | 0x5dc560 100.0% | **A** | A1 |
| `src/game/TTown.cpp:234` | CallAndMessage | 0x5b7570 71.3% | **A** | A2 |
| `src/game/TTown.cpp:242` | CallAndMessage | 0x5b7570 71.3% | **A** | A2 |
| `src/game/TTown.cpp:252` | CallAndMessage | 0x5b7570 71.3% | **A** | A2 |
| `src/game/TTown.cpp:268` | CallAndMessage | 0x5b7570 71.3% | **A** | A2 |
| `src/game/TTownNameDialog.cpp:40` | CallAndMessage | 0x51bb90 94.4% | **A** | A2 |
| `src/game/TTradeCluster.cpp:124` | CallAndMessage | 0x587130 27.8% | **A** | A2 |
| `src/game/TTradeCluster.cpp:134` | CallAndMessage | 0x587130 27.8% | **A** | A2 |
| `src/game/TTradeCluster.cpp:135` | CallAndMessage | 0x587130 27.8% | **A** | A2 |
| `src/game/TTradeCluster.cpp:167` | CallAndMessage | 0x5873e0 26.7% | **A** | A2 |
| `src/game/TTradeCluster.cpp:182` | CallAndMessage | 0x5873e0 26.7% | **A** | A2 |
| `src/game/TTradeCluster.cpp:197` | CallAndMessage | 0x5873e0 26.7% | **A** | A2 |
| `src/game/TTradeCluster.cpp:249` | CallAndMessage | 0x5873e0 26.7% | **A** | A2 |
| `src/game/TTradeCluster.cpp:262` | CallAndMessage | 0x5873e0 26.7% | **A** | A2 |
| `src/game/TTradeCluster.cpp:274` | CallAndMessage | 0x5873e0 26.7% | **A** | A2 |
| `src/game/TTradeCluster.cpp:313` | NullDereference | 0x587980 52.6% | **A** | A2 |
| `src/game/TTradeCluster.cpp:334` | NullDereference | 0x587a10 47.5% | **A** | A2 |
| `src/game/TTradeCluster.cpp:358` | CallAndMessage | 0x587aa0 86.9% | **A** | A2 |
| `src/game/TTradeCluster.cpp:384` | CallAndMessage | 0x587bb0 46.5% | **A** | A2 |
| `src/game/TTradeCluster.cpp:407` | CallAndMessage | 0x587bb0 46.5% | **A** | A2 |
| `src/game/TTradeCluster.cpp:408` | CallAndMessage | 0x587bb0 46.5% | **A** | A2 |
| `src/game/TTradeCluster.cpp:409` | CallAndMessage | 0x587bb0 46.5% | **A** | A2 |
| `src/game/TTradeCluster.cpp:427` | CallAndMessage | 0x587dd0 68.8% | **A** | A2 |
| `src/game/TTradeCluster.cpp:452` | CallAndMessage | 0x587dd0 68.8% | **A** | A2 |
| `src/game/TTradeCluster.cpp:453` | CallAndMessage | 0x587dd0 68.8% | **A** | A2 |
| `src/game/TTradeCluster.cpp:454` | CallAndMessage | 0x587dd0 68.8% | **A** | A2 |
| `src/game/TTradeCluster.cpp:473` | CallAndMessage | 0x588030 54.2% | **A** | A2 |
| `src/game/TTradeCluster.cpp:511` | CallAndMessage | 0x588030 54.2% | **A** | A2 |
| `src/game/TTradeCluster.cpp:512` | CallAndMessage | 0x588030 54.2% | **A** | A2 |
| `src/game/TTradeCluster.cpp:513` | CallAndMessage | 0x588030 54.2% | **A** | A2 |
| `src/game/TTradePolicyCluster.cpp:34` | CallAndMessage | 0x584320 100.0% | **A** | A1 |
| `src/game/TTradeScreenPicture.cpp:69` | NullDereference | 0x5ba7a0 66.8% | **A** | A2 |
| `src/game/TTransportView.cpp:32` | CallAndMessage | 0x4bd3e0 63.8% | **A** | A2 |
| `src/game/TTransportView.cpp:36` | CallAndMessage | 0x4bd3e0 63.8% | **A** | A2 |
| `src/game/TTransportView.cpp:68` | CallAndMessage | 0x4bd690 98.5% | **A** | A1 |
| `src/game/TTransportView.cpp:74` | CallAndMessage | 0x4bd690 98.5% | **A** | A1 |
| `src/game/TUnit.cpp:63` | CallAndMessage | 0x5c2530 100.0% | **A** | A1 |
| `src/game/TViewMgr.cpp:1768` | CallAndMessage | 0x5db3b0 24.2% | **A** | A2 |
| `src/game/TViewMgr.cpp:1916` | NullDereference | 0x5dc1e0 98.3% | **A** | A1 |
| `src/game/TViewMgr.cpp:1948` | CallAndMessage | 0x5dc430 100.0% | **A** | A1 |
| `src/game/TViewMgr.cpp:2076` | CallAndMessage | 0x5dcdf0 100.0% | **A** | A1 |
| `src/game/TViewMgr.cpp:2081` | CallAndMessage | 0x5dcdf0 100.0% | **A** | A1 |
| `src/game/TViewMgr.cpp:2101` | CallAndMessage | 0x5dcf20 71.0% | **A** | A2 |
| `src/game/TViewMgr.cpp:2110` | CallAndMessage | 0x5dcf20 71.0% | **A** | A2 |
| `src/game/TViewMgr.cpp:2115` | CallAndMessage | 0x5dcf20 71.0% | **A** | A2 |
| `src/game/TViewMgr.cpp:2136` | CallAndMessage | 0x5dd0a0 100.0% | **A** | A1 |
| `src/game/TViewMgr.cpp:2158` | CallAndMessage | 0x5dd180 100.0% | **A** | A1 |
| `src/game/TViewMgr.cpp:2174` | CallAndMessage | 0x5dd220 100.0% | **A** | A1 |
| `src/game/TViewMgr.cpp:2185` | CallAndMessage | 0x5dd220 100.0% | **A** | A1 |
| `src/game/TViewMgr.cpp:2198` | CallAndMessage | 0x5dd340 100.0% | **A** | A1 |
| `src/game/TViewMgr.cpp:2203` | CallAndMessage | 0x5dd340 100.0% | **A** | A1 |
| `src/game/TViewMgr.cpp:2225` | CallAndMessage | 0x5dd450 67.4% | **A** | A2 |
| `src/game/TViewMgr.cpp:2230` | NullDereference | 0x5dd450 67.4% | **A** | A2 |
| `src/game/TViewMgr.cpp:2285` | CallAndMessage | 0x5dd770 100.0% | **A** | A1 |
| `src/game/TViewMgr.cpp:2296` | CallAndMessage | 0x5dd770 100.0% | **A** | A1 |
| `src/game/TViewMgr.cpp:2301` | CallAndMessage | 0x5dd770 100.0% | **A** | A1 |
| `src/game/TViewMgr.cpp:2319` | CallAndMessage | 0x5dd900 100.0% | **A** | A1 |
| `src/game/TViewMgr.cpp:2326` | CallAndMessage | 0x5dd900 100.0% | **A** | A1 |
| `src/game/TViewMgr.cpp:2352` | CallAndMessage | 0x5dda30 85.4% | **A** | A2 |
| `src/game/TViewMgr.cpp:2357` | NullDereference | 0x5dda30 85.4% | **A** | A2 |
| `src/game/TViewMgr.cpp:2397` | CallAndMessage | 0x5ddd20 83.6% | **A** | A2 |
| `src/game/TViewMgr.cpp:2402` | NullDereference | 0x5ddd20 83.6% | **A** | A2 |
| `src/game/TViewMgr.cpp:2449` | CallAndMessage | 0x5de010 73.6% | **A** | A2 |
| `src/game/TViewMgr.cpp:2543` | CallAndMessage | 0x5de4f0 100.0% | **A** | A1 |
| `src/game/TViewMgr.cpp:2579` | CallAndMessage | 0x5de8f0 100.0% | **A** | A1 |
| `src/game/TViewMgr.cpp:374` | CallAndMessage | 0x5d57b0 56.0% | **A** | A2 |
| `src/game/TViewMgr.cpp:492` | CallAndMessage | 0x5d5d30 90.8% | **A** | A2 |
| `src/game/TViewMgr.cpp:759` | CallAndMessage | 0x5d69b0 35.3% | **A** | A2 |
| `src/game/TViewMgr.cpp:846` | CallAndMessage | 0x5d6cd0 100.0% | **A** | A1 |
| `src/game/TViewMgr.cpp:864` | CallAndMessage | 0x5d6d70 100.0% | **A** | A1 |
| `src/game/TViewMgr.cpp:890` | CallAndMessage | 0x5d6e50 100.0% | **A** | A1 |
| `src/game/TViewMgr.cpp:911` | CallAndMessage | 0x5d6f10 100.0% | **A** | A1 |
| `src/game/TViewMgr.cpp:932` | CallAndMessage | 0x5d6fd0 100.0% | **A** | A1 |
| `/root/.wine/drive_c/msvc/mfc/include/afxtempl.h:749` | CallAndMessage | NOMARKER ?? | **D** | D1 |

## Summary

- Class A: 273 (264 + 9 reclassified after listing verification)
- Class B: 8
- Class C: 0 (all candidates verified listing-faithful)
- Class D: 1
- Total findings: 282 (282 warning lines; duplicate-line CDib rows counted individually)

## C-candidate shortlist — RESOLVED 2026-07-23 (Ghidra listing verification)

All three candidates verified against the original listing and reclassified
**A** (listing-faithful): C1 — retail computes the same null clip pointers and
enters the copy loops with no guard (decompile at 0x47bde0 shows
`pcVar = 0` joins straight into the blit loops); C2 — retail loads the
possibly-null `next` into ECX and calls 0x404692 unguarded
(`00550a1b MOV ECX,EBX / CALL 0x00404692`), identical in both functions;
C3 — retail's tail reload + Release (`piVar4 = *piVar6;
call [piVar4]+4`) sits outside the `*piVar6 != 0` branch exactly as ported.
The class-A totals above include these reclassified rows. Original shortlist
text kept below for the verification trail.

- **C1 — `CDib::BlitSurfaceRectSkippingTransparentColor` 0x0047bde0 (17.9%),
  `src/game/CDib.cpp:492/495/511/517`.** The clip computation deliberately sets
  `srcPtr`/`destPtr` to 0 when the source/dest rect is out of bounds, and the
  blit loops then dereference them unconditionally. At 17.9% the port is far
  from proven; the retail routine may early-return (or never reach the loops)
  when either pointer is null. Verify: `just ghidra listing 0x47bde0` — check
  for a null test / early exit between the pointer computation and the copy
  loops. If retail has a guard our port lost, add it; if not, reclassify A.
- **C2 — `TShip::Sink` 0x005509c0 (75.8%) `src/game/TShip.cpp:553` and
  `TTaskForce::SinkOrSwimShips` 0x00553fe0 (77.8%) `src/game/TTaskForce.cpp:973`.**
  Both unlink a defeated head node with `next` null-guarded for the pointer
  surgery (`if (next != 0) next->prev = ...`), then immediately call
  `next->PruneDefeatedMapOrderChildrenAndReturnHead()` outside the guard. If
  `next` can be null (tail deletion), the call runs with a null receiver. The
  identical shape in two functions suggests transcription, and a null-this
  walk may be tolerated by the callee, but the guarded/unguarded asymmetry is
  worth confirming against the listings (0x5509c0, 0x553fe0): does retail
  really make the call unconditionally?
- **C3 — `TMilitaryPageView::PrepareUnitCache` 0x00564a60 (39.4%),
  `src/game/TMilitaryPageView.cpp:86`.** The first use of `*loaderHandle` is
  wrapped in `if (loader != 0)`, but the reload after the blit block
  (`loader = *loaderHandle; loader->ReleaseBitmapResource();`) is unguarded.
  Verify against `just ghidra listing 0x564a60` whether the retail epilogue is
  also unguarded (then A) or sits inside the same non-null branch (then our
  control flow is flattened wrongly and the tail belongs inside the guard).

No class-C fix was unambiguous from source alone, so none was applied.
