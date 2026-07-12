# Next porting targets (survey 2026-07-12)

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
