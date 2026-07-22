# Next porting targets (survey 2026-07-12)

> **Stale snapshot** — several rows have since been ported (e.g. 0x4d4390 lives in
> `TCivMgr.cpp`). Verify each row with `just func-status 0xADDR` before claiming.

Landed this session: DrawHexNeighborConnectionMask 0x522cf0 (0->64.6%, b5aeab1).

## Ready, tractable (all callees ported, recovered receivers)
- **0x4d4390 ApplyCompletedCivWorkOrderToMapState** (680B, 0%) __cdecl(int* pCivUnitOrderState).
  Branches by orderType at pOrderState+0x08 (switch orderType-5). Dispatches all on
  g_pGlobalMapState (TMapMgr, named slots: SetHexAdjacencyDirectionFlagsForTilePair,
  QueueDepotConstructionOrder, QueuePortConstructionOrder, GetTileCivilianWorkOrderCostClassNibble,
  SetProvinceCapitalTileFlagBit08) and g_apNationStates[pOrderState[6]] (TCountry). Needs the
  civ-order record fields modeled (pOrderState[3]=?, [6]=nationId, [8]=orderType). func_0x405619,
  0x403b34, 0x405baf(=ComputeHexNeighborTileIndices), 0x40375b resolved-check needed.

## Clean rendering family (my strong suit; no EH, QuickDraw primitives)
- More TMapDialog guide/connection functions near 0x520000-0x523000.

## Hard (defer): vftable[1] second-base dispatch or MFC/EH-heavy
- 0x51eb40 RenderStrategicMapTileCell (5.4KB) -- g_pGlobalMapState vtable + this->vftable[1] 2nd base.
- 0x520670 RenderMapDialogBilateralRelationMarkers (527B) -- this->vftable[1] 10-way switch, lost calling conv.
- 0x57f5b0 FormatSignedIntWithSingleThousandsSeparator (655B) -- MFC CString + 11 EH states.

## Near-done but compiler-quirk residual (low yield)
- 0x53d4a0 ComputeArmyMissionCandidateVectorDistanceScore (69.2%) -- fcomp-vs-fcompp FP compare codegen.

## Update (window 2)
Landed: 0x522c10 DrawMapDialogWrappedTileConnectionMarker (100%), 0x522000
DrawMapDialogOwnershipMarkerForNation (98.5%), 0x562af0
RelaxMapTileCostFieldByNeighborTerrain (77.9%, bridge retired). Heuristics 77-79 added
(abs->cdq, else-first branch layout, movsx-width param oracle).

### Winning lane confirmed
Small (<300B) TMapDialog/map-cost functions built from ported QuickDraw primitives
(SetQuickDrawTextOriginWithContextOffset / DrawCenteredGuideLineOnMapDc) or pure
integer/array logic, no vtable[1]/EH. abs()+else-first branch shaping gets them to
90-100%.

### Defer (poor match candidates)
- 0x5114b0 CheckTilePatternMaskAllowedByModeFlag (268B) -- returns a dirty AX (short
  return with `& 0xffff0000` high-word-passthrough artifact); register-return semantics
  hard to reproduce from clean C++. Pure table logic otherwise.
- 0x51d380 MarkHexTileAndNeighborsDirtyAndNotify -- Ghidra artifacts (mystery receiver,
  `(*pcVar5)()` garbage where pcVar5 is a loop counter).

### Still ready
- 0x4d4390 ApplyCompletedCivWorkOrderToMapState (680B) -- garbled vtable-call args, needs
  each g_pGlobalMapState virtual's real signature + civ-order struct modeled.
- More small DrawMapDialog* / guide-pattern siblings near 0x520000-0x524000.

## Update (window 3) -- 96-bit big-integer family (new src/game/bignum96_math.cpp)
Ported the whole small family as clean __cdecl free functions, retiring autogen stubs:
AddUintWithCarryOutFlag 100%, Add96BitIntegerWithCarry 100%, Copy96BitIntegerWords 100%eff,
Zero96BitIntegerWords 100%eff, SetBitIn96BitIntegerWithCarry 88.9% (returns carry),
Is96BitIntegerZero 62%, Is96BitIntegerZeroAtOrAboveBitIndex 87%,
ShiftLeft96BitIntegerBy1 42%, ShiftRight96BitIntegerBy1 62%,
Truncate96BitIntegerAtBitWithRounding 49%, ShiftRight96BitIntegerByBitCount 34%.
Also this window: ConvertScreenPointToHexGridCoordClamped 71%, AdjustTacticalUnitVerticalOffset 100%,
DrawMapDialogWrappedTileConnectionMarker 100%, DrawMapDialogOwnershipMarkerForNation 98.5%,
RelaxMapTileCostFieldByNeighborTerrain 77.9%, Copy64x64TileBlockWithStrideAdjustment 30%.

### Lesson: pure-math free-function families are a rich clean lane
Small __cdecl arithmetic helpers (bignum, coordinate, bit-twiddling) port to correct
behavior fast; the sub-100% ones are dominated by MSVC5 register-naming (callee-saved
ESI/EDI vs volatile ECX/EDX) and instruction scheduling that isn't source-controllable.
signed `% 32` (not `& 0x1f`) matches the abs/re-sign modulo sequence.

### Remaining 96-bit family (larger, likely similar low-match)
- 0x5f4a80 ConvertFpMantissaTo96BitIntegerAndExponent (190B)
- 0x5f7930 Build96BitIntegerFromDigitBytesAndNormalize (241B)

## Update (window 4)
Landed: ConvertFpMantissaTo96BitIntegerAndExponent 0x5f4a80 (23%, IEEE double->extended).
The small 96-bit family is essentially complete (only Build96BitIntegerFromDigitBytesAndNormalize
0x5f7930 241B remains, likely similar low-match register-scheduling).

### Observations on target scarcity
Many remaining small 0% functions fall into hard/low-match buckets:
- dirty-AX/high-byte returns (CanQueueMapOrderForProvinceContext 0x554590,
  ContainsCityStatePointerInZoneArrayByCityIndex 0x55f440) -- register-return artifact.
- vftable[1] 2nd-base dispatch (UpdateMapDialogProjectedTileMarkerAndInvalidate 0x51a900,
  WrapperFor_SetQuickDrawFillColor 0x523060).
- unidentified receiver (RefreshTaskForceSelectionFlagsForCurrentNationOrders 0x5539c0 in_ECX).
- already-ported-but-scheduling-bound (DrawMapDialogGuidePatternSetF 0x521090 = 40.5%, source
  already exact-matches decompile; the guide-pattern family caps ~40% due to shared-x1/x2 tail).

### Next clean candidates to try (need raw-level care)
- TMapDialog::Free 0x519c90 (127B): decompile abstracts globals that the raw listing shows
  differently (MOV ECX,[0x6a2158] before the free-buffer wrapper); needs raw-listing-driven
  port. Fields quickDrawSurface350/field35c already declared; field35c->Free() is slot 7
  (byte 0x1c). base-Free chain = 0x48b0b0 + 0x4a0f80.
- Build96BitIntegerFromDigitBytesAndNormalize 0x5f7930 (241B): decimal-string -> 96-bit.

## Update (window 5) -- clean-lane thinning; next tier needs setup
Surveyed math/compute/format functions; the quick-clean fruit in the 0x51xxxx-0x5fxxxx
ranges is largely exhausted. The remaining small low-match functions need non-trivial
setup before a clean port -- mapped here so a future window can pre-stage it:

- **ComputeOrderNodeDerivedScoreFromQuantityAndWord18 0x550840 (67B)**: math is simple
  `((short)(node->field30 / 100) + 5 + g_Navy_Order_Priority_LookupTable_00698118[node->order_type*9]*10) / 10`
  (MSVC's /100 magic multiply will match `/100`). BLOCKERS: (1) receiver is a TTaskForce
  order node (order_type at +4, quantity at +0x30) but passed via the bridge chain
  WrapperFor_...At5a6290 <- FUN_0059ec20; (2) g_Navy_Order_Priority_LookupTable_00698118 is
  in symbols.csv but NOT declared as a usable array in global_data_tables.h -- and a struct
  at 0x698108 already claims +0x10 as navyPriorityWeight, so declaring it as an array risks a
  duplicate-global collision. Needs the table-of-records global modeled/reconciled first
  (sync-pipeline type-flip work).

- **ComputeMissionQueuedOrderSimilarityForTargetNation 0x537eb0 (108B)**: TNavyMission float
  similarity ratio sum(sqrt(w_i*ref_i))/sum(param+ref_i), mirroring the existing
  ComputeNavyOrderCategorySimilarityRatio helper. Depends on the
  BuildNavyOrderCategoryVectorForNationWithExclusion 0x537900 __fastcall bridge (still a
  stub); port that helper first, then this scorer reuses it cleanly.

### Recommended next-window strategy
Either (a) do the global/bridge pre-staging above then port the dependent scorers, or
(b) shift to a fresh untouched address range / a small class-recovery to open a new clean
lane, rather than more single-function hunting in the mined ranges.

## Update (window 6) -- Ghidra live in cloud + hex home-tile family
Set up + verified live Ghidra in cloud (Ghidra 12.1.2 @ /opt/ghidra_12.1.2_PUBLIC, LFS
gzf pulled, `just restore-project` + `just ghidra-decompile` work; export
GHIDRA_INSTALL_DIR in fresh shell). Fixed the stale AGENTS.md/CLAUDE.md note.

Landed (clean): NormalizeWrappedMapCoord108x60 (0x513050, 85%) + fixed sibling 217x60
75->95% via else-first branch (heuristic 78) + retired 3 reinterpret_cast thunk bridges.
LookupHexNeighborRowDeltaByDirection (0x5128f0, 100% eff -- was Ghidra
'ReturnIfTileIndexNegative'; return short so only ax matters).
ComputeTileIndexFromHexColumnX2AndRow (0x512850, ~31%; was 'NoOpMapTilePredicateStub';
columnX2/2 + row*108; param_1 is int not short (cdq/sub/sar proves signed round-to-zero);
capped by a non-standard eax-first calling convention MSVC5 C++ cannot express).

### DEFERRED (rabbit hole): IsValidSecondaryNationHomeTileCandidate (0x513980, 632B)
Fully analyzed, receiver = TMapMgr (thiscall, short tileIndex). terrainStateTable
(TTerrainStateRecordView*, +0x0c). Structure: reject if terrainType00 in {2,3}; else scan
6 hex neighbors (colX2 = row%2 + (idx%108)*2 inlined from SplitTileIndex...; colDelta from
g_Build_Hex_Area_LookupTable_00696E70; rowDelta from LookupHexNeighborRowDeltaByDirection;
NormalizeWrappedMapCoord217x60; ComputeTileIndexFromHexColumnX2AndRow; clamp to [0,0x194f]).
If a neighbor tile terrainType00==5, set result=1, then scan ITS 6 neighbors: if any
neighbor2.ownerNationTag04 < 0x17 && != this tile's owner -> result=0. Also if
neighbor.pad16 (offset 0x16) != -1 -> result=0. Fallback: if result==0 &&
tile.riverSpriteCode
(0x02) != 0 && EvaluateTerrainFlowCrossNationBoundaryToSea(idx)==0 -> result=1.
All 3 hex helpers now ported (call directly, ignore ILT thunks 0x40676c/0x40907f/0x402338).
**BLOCKER**: the fallback calls 0x563b70 (below), still a `(void)` stub -- must be ported
(promote-to-unblock) or given a matching signature first, else the call won't compile with
the tileIndex arg.

### DEFERRED (rabbit hole): EvaluateTerrainFlowCrossNationBoundaryToSea (0x563b70, 436B)
Free function (uses g_pGlobalMapState, not this), char(short tileIndex). River/terrain-flow
tracer. Needs modeling: DAT_0065c668 / DAT_0065c66a (paired short flow-direction lookup
tables, stride 4), plus a short table hidden right AFTER TOcean::classTOcean CRuntimeClass
(`&TOcean::classTOcean.m_lpszClassName + n*2 + 2`), plus thunk func_0x00403968 (hex-step in
direction). Terrain-type buckets: sVar in {0xb..0x1a} indexes the TOcean-adjacent table;
{0x1b..0x2a} pass-through; {0x2b..0x3a} -> return 0xff. Non-standard conventions likely.
Attempt only as a dedicated effort; not the clean lane.

## Update (window 7) -- navy-order priority family
Landed: InitializeNavyOrderPriorityTables (0x556610, 79.17%) -- seeds+selection-sorts three
14-entry order-type ranking tables (added globals g_NavyResolveOrderRanking 0x6a3e28,
g_NavyMissionOrderRanking 0x6a3e50, g_NavyPriorityOrderRanking 0x6a3e90) by descriptor
weight columns (read as dwords). Also landed earlier this session: RecomputeTileStrategicScoreHeatmap
(0x518130, 33.71% but FPU/vtable-exact), + the NormalizeWrappedMapCoord/hex-helper batch.

### NEXT (navy-order manager chain -- receiver = g_pNavyOrderManager @ 0x6a43e4, a TNavyMgr):
- 0x557040 TNavyMgr::ClearAllTransientOrders (Mac oracle): `this->field4 =
  PruneNavyOrderIfUnserviceableOrNoChildren(); for (TShip* s=g_pNavyPrimaryOrderListHead;
  s; s=s->next24) if (s->field34==1) s->field34=0;`. Called by AdvanceGlobalTurnStateMachine
  with `mov ecx,[0x6a43e4]`. BLOCKER: calls 0x555090 (still a stub) -- port both together.
- 0x555090 PruneNavyOrderIfUnserviceableOrNoChildren (159B): __thiscall on a navy-order NODE
  (in_ECX[4]=child list, in_ECX[2]=order-type switch, vtable slot 7 = Free). RECURSIVE (calls
  itself via ILT thunk 0x4063b1). case 5 dispatches g_pDiplomacyTurnStateManager->vtable[9] and
  reads g_pGlobalMapState->cityScoreTable[...] terrainType. Needs the navy-order-node class +
  its vtable slot 7 modeled. Medium-hard; do as a dedicated 2-function batch.
- Siblings still stubbed: 0x556850 ResetNavyOrderListsAndManagerOwner (walks two global order
  lists calling vtable dtors), 0x556410 UpdateNavyOrderMapMarkerByOrderType, 0x557320
  BuildNavyOrderPromptTextByLocalizationMode (MFC text -- defer).
