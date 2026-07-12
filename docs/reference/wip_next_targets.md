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
