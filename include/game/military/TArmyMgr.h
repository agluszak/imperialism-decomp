#pragma once

#include "compat.h"

#include "game/app/TObject.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_diplomacy.h"
#include "game/map_order_battle_snapshot.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TStream;
class TSortedList;
class TArmyStack;
struct TextStyle;

// 0x268-byte POD record copied into the TSortedPtrList pointed to by
// TArmyMgr::mapContextActionRecordList04.
// Field evidence from the battle-report layout hook (0x4acb60): the first bytes are a
// small nation-id array indexed by participantIndex02; actionType04 selects how
// tileOrObject08 is interpreted (0/3/4 -> index into g_pGlobalMapState's stride-0xa8
// table; otherwise a pointer whose short at +0xc is the map cell). The +0x258 tail is
// the report-marker placement state stamped by that hook.
// +0x08 tagged payload of MapContextActionRecord, discriminated by actionType04: a
// tile/record index for actionType04 in {0,3,4} (index into g_pGlobalMapState's stride-0xa8
// table), otherwise a map-object pointer (its short at +0xc is the map cell / a TZone*).
// All members alias the same 4 bytes, so accessing the right one is codegen-identical to the
// old raw int while making the discriminated intent explicit.
struct MapContextActionRecord {
  unsigned char nationIds[2];       // +0x00
  unsigned char participantIndex02; // +0x02
  // +0x03 -- read/written by ReadFrom/WriteTo like every other field here, so it is a
  // real serialized byte rather than compiler padding, even though no reader has been
  // found for it yet.
  unsigned char reservedByte03;
  int actionType04; // +0x04 (0..4; 2 widens the marker sprite code)
  MapOrderBattleSnapshot::TargetContext tileOrObject08; // +0x08 (tagged by actionType04)
  // +0xc..+0x24f -- per-side (0/1) working state, laid out exactly like the tail of
  // MapOrderBattleSnapshot (map_order_battle_snapshot.h): a fixed name buffer, a fixed
  // overlay-label buffer, a child-record count, then (after a 2-byte alignment pad) the
  // child-record array pointer. Ground truth: MapContextActionRecord::ReadFrom (0x4a13c0).
  CStr32 nameBuffer0c[2];    // +0x0c/+0x2c
  CStr255 overlayLabel4c[2]; // +0x4c/+0x14b
  short childCount24a[2];    // +0x24a/+0x24c
  unsigned char pad24e[2];   // +0x24e (alignment pad before the pointer array)
  // Per-side heap arrays built while resolving an army/navy order conflict. The copied
  // report record owns both buffers until CleanUpStacks releases the arrays.
  MapOrderBattleSideChildRecord* sideChildRecords250[2]; // +0x250/+0x254
  int markerPixelX258;                                   // +0x258
  int markerPixelY25c;                                   // +0x25c
  unsigned char placedFlag260;                           // +0x260
  unsigned char pad261;                                  // +0x261
  short markerSpriteCode262;                             // +0x262
  short listOrdinal264;                                  // +0x264
  unsigned char pad266[0x268 - 0x266];

  // Frees the per-side child-record arrays; ground truth for this is the EH unwind frame
  // TArmyMgr::ReadFrom (0x4a1b80) wraps around its per-iteration stack-local record --
  // the local always transfers array ownership into mapContextActionRecordList04 and
  // nulls its own copies before falling out of scope, so this normally deletes null.
  ~MapContextActionRecord() {
    delete[] sideChildRecords250[0];
    delete[] sideChildRecords250[1];
  }

  // 0x4a13c0 -- reads one record from `stream`: the fixed header fields, resolving
  // tileOrObject08 either as a raw tile/record index or (via FindMapActionContextByNodeId)
  // a live TZone* depending on actionType04, then for each side allocates and reads its
  // MapOrderBattleSideChildRecord array.
  void ReadFrom(TStream* stream);
  void WriteTo(TStream* stream); // 0x4a1640
};

// VTABLE: IMPERIALISM 0x0064c928
class TArmyMgr : public TObject {
public:
  DECLARE_DYNCREATE(TArmyMgr)
  virtual ~TArmyMgr() override;                    // slot 0x01 (scalar deleting destructor)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x4a1dd0
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x4a1b80
  virtual void Free() override;                    // slot 0x07 0x4a1a00
  // Retail Mac identities, confirmed against the Windows call chain and bodies.
  virtual void DoCombatMoves(); // slot 0x0a 0x4a1e40
  virtual void FormStacks();    // slot 0x0b 0x4a1f80
  // Walks pendingUnitPool0c's TArmyStack entries starting at nextStackOrdinal10: for
  // each stack whose categoryFlag8 matches regionAffinityTable1c[ownerNationCodeE],
  // relocates every unit on its embedded chain (VTableSlot10 + SetOrders);
  // otherwise tries TryCreateTacticalBattleViewForTileArmies. Stops early on the first
  // battle view created; always re-releases the 3 cached objects up front and, when the
  // pass fully completes without creating one, via ReleaseThreeLinkedObjectsAndReset-
  // TerrainDescriptorFlags at the end (ground truth duplicates that release inline
  // rather than calling out to it, so this mirrors that instead of extracting a helper).
  virtual void ResolveNextMove();                            // slot 0x0c 0x4a2390
  virtual void ClearPendingStacksAndFinalizeMilitaryUnits(); // slot 0x0d 0x4a2500
  // Ground truth (RET 0x8, 2 stack args) proves the previous 0-arg declaration was a
  // poison-pill arity mismatch. Called from ResolveNextMove
  // when a TArmyStack's categoryFlag8 doesn't match
  // TArmyMgr::perTileOwnerNationCodeCache1c[ownerNationCodeE]. Partitions stack's unit
  // chain into an "our stack" (units matching ownerNationCode) and, if any were found, an
  // "enemy stack" (units garrisoned at that same slot in cityScoreTable); depending on
  // TDiplomacyMgr::IsNationPairRelationTurnStampOutOfDate and whether the enemy stack is
  // nonempty, either relocates our stack peacefully or creates a real tactical battle view.
  virtual bool
  TryCreateTacticalBattleViewForTileArmies(TArmyStack* stack,
                                           short ownerNationCode); // slot 0x0e 0x4a3200
  // stack is the same TArmyStack the tile-army-composition pass (0x4a1f80) builds and
  // ResolveNextMove (0x4a2390) iterates. Picks a random adjacent region
  // matching the stack's head unit's field_18 tag and relocates every movable unit there
  // (TUnit::SetOrders), or resets them if none qualifies.
  virtual void
  RedistributeUnitOrderQueueToRandomAdjacentRegion(TArmyStack* stack,
                                                   short tileIndex); // slot 0x0f 0x4a35e0
  // Ground truth doesn't touch `this` at all -- stack is the same TArmyStack shape,
  // relocating every unit on its embedded chain to stack->tileIndex10 unless already there.
  virtual void RelocateStackUnitsToStackTile(TArmyStack* stack); // slot 0x10 0x4a37b0
  // Ground truth (RET 0x8, 2 stack args) proves the previous 0-arg declaration was a
  // poison-pill arity mismatch. Snapshots each stack's units' field_34 into field_3C and
  // resets their blink-mask bits, then repeatedly finds an eligible pair (one unit per
  // stack whose field_34 still exceeds half its snapshot) to accumulate/decay a shared
  // meter across, until one side runs out; the side that ran out gets a flat meter boost
  // instead. Returns whether any eligible pairing was ever found.
  virtual bool UpdateDualLinkedEntryMetersAndBlinkState(TArmyStack* stack1,
                                                        TArmyStack* stack2); // slot 0x11 0x4a3830
  virtual void DoOwnershipChanges();                                         // slot 0x12 0x4a3bc0
  // Ground truth (RET 0x8, 2 stack args) proves the previous 1-arg declaration was a
  // poison-pill arity mismatch. actionKind selects between the slot-0x14/0x15 dispatch
  // (1/4 -> SelectMovableUnitOnCurrentTileAndPlaySfx, 7 -> CommitCityActionGateCostIfAffordable)
  // before the shared tile-unit tail runs.
  virtual void DispatchTileActionByKind(int contextArg,
                                        short actionKind); // slot 0x13 0x4a3d90
  // Ground truth (RET 0x4) proves the previous 0-arg declaration was a poison-pill arity
  // mismatch; contextArg is forwarded as TUnit::SetOrders's payload. Returns
  // whether a movable unit was found and commanded (BL in the ground truth, matching
  // TCivMgr's directly-analogous HandleCivilianTileSelectionOrReportClick/
  // HandleCivilianTileOrderAction shape) -- not a meaningless `undefined` stub value.
  virtual bool SelectMovableUnitOnCurrentTileAndPlaySfx(int contextArg); // slot 0x14 0x4a3e50
  // Ground truth (RET 0x4) proves the previous 0-arg declaration was a poison-pill arity
  // mismatch. Returns whether the tile's unit-move cost was affordable and committed
  // (AL in the ground truth) -- not a meaningless `undefined` stub value.
  virtual bool CommitCityActionGateCostIfAffordable(int contextArg); // slot 0x15 0x4a3f30
  virtual void SetOrdersForIdleUnitsOnPendingTile(int mode);         // slot 0x16 0x4a4260
  // Ground truth (RET 0x8, 2 stack args) proves the previous 0-arg declaration was a
  // poison-pill arity mismatch. Dispatches on the free-function ComputeMapCursorStateIndex
  // classification: 2 -> map-interaction-mode switch + SetActiveProvinceSelection, 6 -> a
  // directional-order-overlay rebuild, 8 -> a blocked-order hint message.
  virtual bool HandleMapClickByComputedCursorState(short tileIndex,
                                                   short mode); // slot 0x17 0x4a4870
  // Ground truth (RET 0x8, 2 stack args) proves the previous 0-arg declaration was a
  // poison-pill arity mismatch. Civilian-order counterpart of the above: dispatches on
  // ComputeCivilianMapCursorStateIndex's classification, falling through to an
  // adjacency check (SelectMovableUnitOnCurrentTileAndPlaySfx vs.
  // CommitCityActionGateCostIfAffordable) for the two "in range" codes.
  virtual bool HandleMapClickByCivilianCursorState(short tileIndex,
                                                   short mode); // slot 0x18 0x4a4ad0

  // 0x004a5aa0 — weighted sum (g_WeightedNeighborScoreByUnitType table at 0x6955f0)
  // over the military units stationed on cityScoreTable[nodeIndex]'s tile chain.
  // Real __thiscall on the TArmyMgr singleton (ret 4; both original callsites,
  // 0x004d8390 and 0x004d83c0, load g_pMapContextActionManager into ecx); `this`
  // is unused by the body.
  int ComputeWeightedNeighborLinkScoreForNodeIndex(int nodeIndex);

  // Object size 0x3a8 confirmed by RTTI. Only +0x31c is confirmed so far (read from three
  // independent call sites: TArmyPlacard::DoEvent, TArmyToolbar's equivalent, and
  // TWorldView::RenderMapContextOverlayWithScopedClipAndSurface) -- a pending map-order/
  // action index, -1 when none selected, otherwise used both as a tile index
  // (ActivateFirstActiveTacticalUnitByCategoryAtTile) and as an index into the terrain
  // descriptor table (g_pGlobalMapState-relative), so it is genuinely a shared "current
  // selection" slot rather than two coincidentally-aliased meanings.
  // NOTE: TObject's own vptr occupies the object's first 4 bytes (ASSERT_SIZE(TObject,
  // 0x4)), so every "+0xNN" comment below is an absolute this-relative offset and this
  // pad must be 4 bytes short of its target to land the next field correctly.
  // +0x04 -- pointer to a TSortedPtrList of copied map-context action records (battle
  // markers etc.). Its recordSize14 is set to sizeof(MapContextActionRecord) == 0x268 by
  // InitializeMapContextActionManager. Walked ordinally by the battle-report layout hook
  // (0x4acb60).
  class TSortedPtrList* mapContextActionRecordList04;
  // +0x08 -- read by GetByteFlagAtOffset8 (0x4a6dd0, a bare `this+8` thiscall getter);
  // sole call site is TSimMgr::AdvanceGlobalTurnStateMachine case 0xd, gating whether the
  // terrain-eligibility branch runs. No confirmed writer site yet.
  unsigned char flag8;
  unsigned char pad09[0x0c - 0x09];
  // +0x0c -- a TSortedList (GetCount/GetEntryByOrdinal evidence from
  // FormStacks's ground truth); freed at the top of
  // ClearPendingStacksAndFinalizeMilitaryUnits via FreePayloads.
  // The original ctor installs TArmyStackList's vtable here (0x4a193a), so this is the
  // sorted stack list, not a plain TSortedList; its payloads are TArmyStack*.
  class TArmyStackList* pendingUnitPool0c;
  // +0x10 -- one-based stack ordinal initialized by DoCombatMoves and advanced by
  // ResolveNextMove as it walks pendingUnitPool0c.
  int nextStackOrdinal10;
  // +0x14/+0x18 -- static lookup-table pointers installed by
  // InitializeMapContextActionManager (0x695448 / 0x695428); consumers not yet mapped.
  const void* staticTable14;
  const void* staticTable18;
  // +0x1c..+0x31b -- one entry per map tile (0x180 = 384 tiles, confirmed by
  // FormStacks's own fill loop at 0x4a1f80, which
  // writes exactly 0x180 consecutive shorts starting here via
  // TMapMgr::ResolveTileOwnerNationCodeNormalized) -- a per-tile owner-nation-code cache,
  // read elsewhere indexed by a region/order-target id rather than a literal tile index
  // (RedistributeUnitOrderQueueToRandomAdjacentRegion, ResolveNextMove) so its exact
  // addressing convention isn't fully pinned down.
  short perTileOwnerNationCodeCache1c[0x180];
  short pendingMapActionIndex; // +0x31c
  unsigned char pad31e[0x39a - 0x31e];
  // +0x39a -- set when a terrain-descriptor refresh is pending; consumed and cleared by
  // EndBattlePhase (0x4a1eb0).
  unsigned char needsTerrainRefreshFlag39a;
  unsigned char pad39b;
  // +0x39c/+0x3a0/+0x3a4 -- three cached objects released (TObject::Free) and cleared by
  // EndBattlePhase. Typed from
  // CreateTacticalBattleViewAndInitializeBattleSetup's own construction evidence (best-
  // effort argument order derived from calling-convention analysis, not yet confirmed by
  // a passing `just compare` on that function).
  class TArmyStack* ourStackBattle39c;
  class TArmyStack* enemyStackBattle3a0;
  class TArmyBattle* activeBattleView3a4;

  // Map hotkey 'N': clear active order modes on the nation's stationed army units,
  // then advance the map interaction selection when no selection remains. 0x004a7590.
  void ClearNationArmyActionModesAndCycleSelection(int nationId);

  // Retail Mac EndBattlePhase. Releases the 3 cached battle objects, performs the
  // slot-0x0d unit cleanup and DoOwnershipChanges, refreshes nation clip regions when
  // needed, then advances the simulation phase. 0x004a1eb0, __thiscall, no args.
  void EndBattlePhase();

  // Selects the first matching unit in the requested state at tileIndex and returns
  // the number of matching units left in the opposite toolbar state. Both methods are
  // real __thiscall members even though their bodies do not read `this`: all four
  // original callers load g_pMapContextActionManager into ECX before calling them.
  short ActivateFirstIdleTacticalUnitByCategoryAtTile(short categoryId, short tileIndex);
  short ActivateFirstActiveTacticalUnitByCategoryAtTile(short categoryId, short tileIndex);

  // Walks the region's stationed-unit chain (Province::stationedUnitChain98,
  // via TUnit::nextOnTile) for one whose unitOrder is idle and whose
  // TMilitaryUnit::GetCategory() is nonzero. 0x004a4550, __thiscall (this unused --
  // operates purely off g_pGlobalMapState), 1 arg.
  bool HasEligibleStationedUnitInRegion(short regionId);

  // Sums TMilitaryUnit::GetArmsCarried() over the same eligible-unit walk as
  // CommitCityActionGateCostIfAffordable (idle unit, nonzero movement class) for
  // pendingMapActionIndex's tile, without the affordability/commit side effects --
  // used purely to display the pending action-gate cost. 0x004a41d0, __thiscall
  // (this used only for pendingMapActionIndex), 0 args, ret 0.
  int ComputeSelectedTileCityActionGateSum();

  // Sets pendingMapActionIndex (the shared "current map selection" slot) and, unless
  // clearing the selection (-1), resets the order mode of every stationed unit at that
  // tile whose tactical category is nonzero (g_awTacticalUnitCategoryCodeBySlot); always
  // notifies the active map-uber-picture's slot-0x75 handler at the end. 0x004a45e0,
  // __thiscall, 1 arg. Called both by TArmyMgr's own map-click dispatchers and by other
  // classes on the g_pMapContextActionManager singleton (e.g. the map-interaction-mode
  // and province-cycling handlers).
  void SetActiveProvinceSelection(short cityRecordIndex);
  // Clear pending military highlights for one nation and reset the province cursor.
  // The nation's militaryUnitList44 contains the same TUnit-derived entries walked by
  // SetActiveProvinceSelection. 0x004a46d0, __thiscall.
  void ClearProvinceSelectionHighlightsForNation(short nationId);
  // Starting at pendingMapActionIndex (or zero when it is -1), find the next owned/allied
  // province containing an idle mobile military unit. Returns -1 after city record 383.
  // 0x004a4760, __thiscall.
  short FindNextSelectableProvinceForNation(short nationId);

  // Cursor-resource lookups for the two map-click state classifiers. Both are real
  // __thiscall members on the global army/map-context manager; their bodies only use
  // global state, but every caller loads this manager into ECX.
  unsigned short LookupMapCursorTokenByStateIndex(short tileIndex, short mode); // 0x4a4930
  unsigned short LookupCivilianMapCursorTokenByStateIndex(short tileIndex,
                                                          short mode); // 0x4a4aa0

  // Civilian-order counterpart of the free-function ComputeMapCursorStateIndex (this one
  // genuinely reads/writes `this`, e.g. pendingMapActionIndex). 0x004a4c80, 641 bytes.
  int ComputeCivilianMapCursorStateIndex(short tileIndex, short mode);
  // 0x004a5080, 1407 bytes, __thiscall, 1 arg (cityRecordIndex), returns bool; signature
  // verified via the HandleMapClickByCivilianCursorState callsite disassembly.
  bool ValidateOrderPlacementPrerequisitesForSelectedTile(short cityRecordIndex);
  // 0x004a5760, 656 bytes, __thiscall, 1 arg (tileIndex). Builds directional
  // order-overlay controls from the tile's adjacent-region list.
  // Mac oracle: MarchSelectedArmies(short).
  void MarchSelectedArmies(short tileIndex);
  // 0x004a5b10, 243 bytes, __thiscall, 3 args (ourStack, enemyStack, ownerNationCodeInt).
  // Called from TryCreateTacticalBattleViewForTileArmies when a real tactical battle
  // should be created (SEH-framed).
  void CreateTacticalBattleViewAndInitializeBattleSetup(TArmyStack* ourStack,
                                                        TArmyStack* enemyStack,
                                                        int ownerNationCodeInt);
  // Mac oracle: ShowSpyReport(long).
  void ShowSpyReport(int cityRecordIndex);

  // Builds two localized summary strings for cityRecordIndex's garrison/order state;
  // returns false when there's nothing to show (both outputs untouched in that case).
  // 0x004a5ec0, __thiscall, 1580 bytes.
  //
  // The previous 2-arg `TextStyle*` signature was never verified against
  // the callee's body and is wrong: the caller (ShowSpyReport) constructs FOUR
  // TextStyle locals (styleA-D) via
  // InitializeUiTextStyleDescriptor/BuildUiTextStyleDescriptor, but the raw disassembly
  // of the call site (0x4a67b1, ILT thunk 0x408c79) pushes the addresses of two
  // separately-constructed CString locals (real `CString::CString()` calls at
  // 0x4a678c/0x4a679a), not styleC/styleD -- those two TextStyle locals are
  // consumed later, in the still-unported widget-dispatch tail of the caller.
  //
  // outDefenderSummary: "<leading unit/admiral name or city name>" -- Phase 1 scans
  // cityScoreTable[cityRecordIndex]'s adjacent regions (adjacentRegionIds0A[0..
  // adjacentRegionCount08)) owned by the active nation (TMapMgr::
  // ResolveTileOwnerNationCodeNormalized == TSimMgr::GetActiveNationId), and over their
  // stationedUnitChain98 picks the highest-scoring General TMilitaryUnit
  // (score = field_38/100 + 1); ties keep the first found. If no adjacent region is
  // owned (or none qualifies), falls back to the region's own city display name
  // (TMapMgr::AssignCityRecordDisplayName). Phase 2 separately scans
  // TShip::GetFirst() for a TShip owned by the active nation whose zone
  // (field08) contains cityRecordIndex (TZone::ContainsCityStatePointerInZoneArrayBy-
  // CityIndex), reducing over TShip::Finest; if
  // found, its admiral (admiral) can override outDefenderSummary with
  // "Adm. <name>" when the admiral's experiencePoints/100+1 score beats Phase 1's, or (only if
  // Phase 1 found nothing at all -- zero adjacent regions) falls back to the ship's own
  // name.
  //
  // outGarrisonSummary: a comma-separated "<count> <resource type name>" list (or a
  // "nothing garrisoned" fallback) built from cityScoreTable[cityRecordIndex]'s
  // stationedUnitChain98: each unit rolls twice against a per-strength-tier probability
  // table (g_MapOrderResourceRollWeightTable, keyed by Phase 1/2's winning score) seeded
  // from cityRecordIndex+TSimMgr::GetEconomicTurn()+GetActiveNationId(): the first roll
  // picks a 0-2 "point cost". The second result is biased by 3: selector 4 uses the
  // fixed "misc" bucket, selector 5 rolls uniformly over buckets 0-9, and the default
  // uses the unit's GetCategory(). Singular/plural localized names come from
  // string group 0x2726 (offset i vs i+11). Returns false only when Phase 1/2 found
  // nothing at all (bestScore == -1, i.e. zero adjacent regions AND no owned ship in
  // zone).
  // Mac oracle: GenerateSpyReport(long, CStr255&, CStr255&); CString is the Windows
  // counterpart of the Mac CStr255 outputs.
  bool GenerateSpyReport(int cityRecordIndex, CString& outDefenderSummary,
                         CString& outGarrisonSummary);

  // Called from RefreshMapOrderBattleSideSnapshot's type-5 (ship-order) tail. 0x004a6ef0,
  // 897 bytes.
  //
  // nationId carries TTaskForce::nation, which every navy-order reader
  // treats as the entry's owning nation slot (see RemoveMatchingTaskForceOrders in
  // TNavyMgr.cpp) -- used as a g_apNationStates index. The function has no explicit
  // `side` parameter; it recovers `side` implicitly by comparing nationId
  // against snapshot->nationIds[0]: side 0's own call always matches trivially
  // (side = 0), while side 1's call only diverges -- and only then runs the trim pass --
  // when the two sides' nation-slot bytes differ.
  //
  // Body:
  //  - Allocates a scratch `TList` (0x20 bytes, already-recovered class), CIterator-walks
  //    g_apNationStates[nationId]'s order list (TCountry::militaryUnitList44, a
  //    TSortedList* of TMilitaryUnit*), and AddTail()s every entry whose tileIndex06
  //    isn't a movement-class tile (TileHasMovementClassId) for cityIndex when its
  //    field_C == cityIndex, summing GetArmsCarried per entry into a budget.
  //  - Subtracts g_pNavyOrderManager->GetInvasionCapacity(
  //    nationId, &g_pGlobalMapState->cityScoreTable[cityIndex], 0) from that
  //    budget; if the remainder is positive, randomly evicts entries from the TList
  //    (rand() % GetCount() + 1 via GetEntryByOrdinal) until the remainder is <= 0, each
  //    time looking the evicted TMilitaryUnit* up in the TList's underlying CPtrList via
  //    CPtrList::Find/RemoveAt, re-subtracting its GetArmsCarried, and stamping
  //    TUnit::field_34 to 0xffaa as a scratch "evicted" marker (field_34 is otherwise a
  //    persisted strength scalar -- reused here since the unit is about to be destroyed).
  //  - Grows snapshot->childRecords[side] (MapOrderBattleSideChildRecord array,
  //    map_order_battle_snapshot.h) by the evicted count, reallocating via operator new,
  //    copying the old records over the front, zero-filling every new record's
  //    nameBuffer[0] (including the copied-over front, harmlessly overwritten by the
  //    copy), then re-scanning the whole militaryUnitList44 once per evicted unit
  //    (an original redundancy -- only the first pass finds any 0xffaa-marked entries,
  //    since the marker is cleared as each is processed, but every pass rescans from the
  //    head) appending one new MapOrderBattleSideChildRecord per marked-evicted
  //    TMilitaryUnit (resourceType = orderType, stockOrRequired = 0xffaa, nameBuffer =
  //    name24 clamped to 0x20 chars, detail category = 'army' ("army"), and
  //    strengthBucket = field_38 / 100) before DetachUnitOrderFromOwnerAndReset()
  //    + Free()ing the evicted unit. The old childRecords array is never freed here --
  //    reproduced as a faithful leak, matching this file's other acknowledged leaks.
  void TrimExcessNavyOrderSupportAndRebuildOrderBuffer(char nationId, int cityIndex,
                                                       struct MapOrderBattleSnapshot* snapshot);

  // Bare `this+8` accessor; sole caller is TSimMgr::AdvanceGlobalTurnStateMachine
  // (g_pMapContextActionManager->GetByteFlagAtOffset8()). 0x4a6dd0.
  unsigned char GetByteFlagAtOffset8();

  // Mac oracle: CleanUpStacks. Frees the two owned side-child buffers in every copied
  // map-context action record, clears the record list, and resets flag8. 0x004a6df0.
  void CleanUpStacks();

  // Called by TArmyBattle::FinalizeTacticalBattleOutcome once a tactical battle's
  // outcome is decided (sideWonFlag = whether ourStack's side won). Dispatches the
  // army-context report, then applies the win/loss aftermath to both stacks: the
  // winning stack's units settle into their tile (VTableSlot10 + SetOrders)
  // while the losing stack is redistributed to a random adjacent region (sideWonFlag
  // != 0) or relocated back to its origin tile (sideWonFlag == 0, via
  // RelocateStackUnitsToStackTile); both stacks then grow unit quality
  // (field_38, capped at 400) -- +35 for the winner, +20 for the loser -- before
  // re-running the pending-army-stack pass (slot 0x0c). 0x004a5ca0, __thiscall, ret 0x10.
  void ApplyPostBattleStackOutcomeAndGrowUnitMeters(TArmyStack* ourStack, TArmyStack* enemyStack,
                                                    int sideWonFlag, int battleSiteIndex);

  // Appends the built map-context battle record to mapContextActionRecordList04 (via its
  // sorted-insert virtual, slot 0x0f), clears the record's scratch working fields, and
  // marks flag8. `unusedArg2` is present only for stack-cleanup fidelity (RET 8) -- the
  // body never reads it. 0x4a6e80, __thiscall.
  void AppendMapContextActionRecordAndResetWorkingFields(struct MapOrderBattleSnapshot* record,
                                                         int unusedArg2);
  void InitializeMapContextActionManager();

  // Scans mapContextActionRecordList04 from its last entry down to the first for a
  // record whose nationIds[0] or nationIds[1] matches activeNationId; returns true on the
  // first match, or as soon as g_bRandomMapDeveloperCheatFlag is set (the developer-cheat
  // gate short-circuits the scan the same way it does elsewhere). Sole caller:
  // TDefenseMinisterView::DoEvent's 'cann' branch. 0x4a6d40.
  bool ScanMapContextActionEntriesForCodeMatch(short activeNationId);

  TArmyMgr();
};
ASSERT_SIZE(TArmyMgr, 0x3a8);
