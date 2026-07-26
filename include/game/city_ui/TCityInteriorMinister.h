#pragma once

#include "compat.h"

#include "game/city_ui/TInteriorMinister.h"

class TCity;
class TGreatPower;
class TLongintList;
class TList;
class TShortintList;
class TTaskList;
class TUnit;
class TFuzzySet;

// Player city interior minister — derives from TInteriorMinister (shares slots 0x48-0x50)
// and overrides serialization/Free/NotifySlot44 plus a long city-policy virtual run.
// VTABLE: IMPERIALISM 0x006508a8
class TCityInteriorMinister : public TInteriorMinister {
public:
  virtual ~TCityInteriorMinister() override; // slot 0x01 (scalar deleting destructor)
  short GetRankingCriterionForGP(short nationSlot) override; // slot 0x0a 0x4bee20
  virtual void MakeNewCity(TCity* city) override;            // slot 0x11 0x4c0d90
  virtual void FillOrders() override;                        // slot 0x15 0x4bf770
  virtual void PleaseBuildShip(short arg) override;          // slot 0x1a 0x4beeb0
  virtual void IndustryOrder(short industrySlot) override;   // slot 0x1b 0x4beee0
  virtual void PleaseBuildLandUnit(short unitType) override; // slot 0x1c 0x4bef30
  virtual short GetExteriorNeedFor(int arg) override;        // slot 0x1d 0x4be7b0
  virtual short GetHistoricalNeedFor(int arg) override;      // slot 0x1e 0x4be7d0
  virtual void ResetHistoricalNeedFor(int arg) override;     // slot 0x1f 0x4be7f0
  virtual void FillLists();                                  // slot 0x20 0x4bed60
  // Reports orderMetricTable40 deltas to the owner's foreign minister (index 0 as a
  // 25%-chance roll gated on either of the paired trigger slots [0]/[1], indices 2..6
  // forwarded directly when nonzero), then picks a (resultCode, magnitude) pair from
  // the city's population-vs-stock shortage state (TPopulationMgr's
  // PretendToEat substitution/starvation pair, else cityStockSteelCC/cityStockLumberC8/
  // cityStockCannedFoodC4 vs TPopulationMgr::populationCount08) and reports it via
  // SetInteriorMinisterBid, unless no condition qualified.
  virtual void EvaluateCityShortagesAndNotifyForeignMinister(TCity* city); // slot 0x21
                                                                           // 0x4bf8a0
  // Dispatches production-order-queueing helpers for `city`: exactly one of
  // QueueCityProductionCommand17Or18FromSupportRatio (lowProductionFlag7c set,
  // lowStockFlag7d clear) / DistributeCityProductionCommandBudgetAndQueueOrders
  // (the reverse), then unconditionally QueueCityProductionCommand33From
  // AccumulatedDeficit / QueueShipProductionCommandIfMissing /
  // QueuePendingRecruitmentProductionCommand / QueuePendingUnitProductionCommand,
  // then always
  // QueueCityProductionRebalanceCommandsByThresholds.
  virtual void QueueCityProductionPolicyCommands(TCity* city,
                                                 TTaskList* commandQueue); // slot 0x22 0x4bfa50
  virtual void
  QueueCityProductionRebalanceCommandsByThresholds(TCity* city,
                                                   TTaskList* commandQueue); // slot 0x23 0x4bfb20
  // Verified empty in the original: `ret 8` only, no reads/writes. Ghidra's
  // "GetTEventHandlerClassNamePointer" name is a misattribution shared by several
  // no-op/near-no-op slots in this class; renamed to reflect the real (empty) body.
  virtual void NoOpProductionCommandHook24(int unusedArg1, int unusedArg2); // slot 0x24 0x4bff60
  virtual void
  QueueCityProductionCommand17Or18FromSupportRatio(TCity* city,
                                                   TTaskList* commandQueue); // slot 0x25 0x4c02c0
  virtual void DistributeCityProductionCommandBudgetAndQueueOrders(
      TCity* city, TTaskList* commandQueue); // slot 0x26 0x4c0090
  virtual void
  QueueRandomCityProductionCommand19To1C(TCity* city,
                                         TTaskList* commandQueue); // slot 0x27 0x4c04e0
  virtual void QueueShipProductionCommandIfMissing(TCity* city,
                                                   TTaskList* commandQueue); // slot 0x28 0x4c05a0
  virtual void
  QueuePendingRecruitmentProductionCommand(TCity* city,
                                           TTaskList* commandQueue); // slot 0x29 0x4c0690
  virtual void QueuePendingUnitProductionCommand(TCity* city,
                                                 TTaskList* commandQueue); // slot 0x2a 0x4c0730
  virtual void
  QueueCityProductionCommand33FromAccumulatedDeficit(TCity* city,
                                                     TTaskList* commandQueue); // slot 0x2b 0x4bff80
  virtual void DistributeCityProductionAcrossOrderTemplatesAndBackfillDeficits(
      TCity* city);                                                    // slot 0x2c 0x4c07d0
  virtual void SelectRecruitmentProductionCommand(short commandIndex); // slot 0x2d 0x4bef10
  virtual short RaiseNeedTargetWithinAvailableSurplus(short resourceType, short requestedAmount,
                                                      short allocationLimit); // slot 0x2e 0x4c0de0
  virtual short
  RebuildNeedTargetsAndQueueProductionShortfalls(TCity* city,
                                                 TTaskList* commandQueue); // slot 0x2f 0x4c0e50
  // Scores every valid owned tile through a temporary TTown resource projection and
  // returns the best home-city TILE index. An existing capital-site flag wins with a
  // score of 32000. Mac/curated name: SelectBestSecondaryHomeTileByFrogCityScore.
  virtual int SelectBestSecondaryHomeTileByFrogCityScore();        // slot 0x30 0x4c11c0
  virtual void RebuildMapTileNeighborBucketsForInteriorMinister(); // slot 0x31 0x4c1ac0
  virtual void RequestMissingCivilianOrderTypes();                 // slot 0x32 0x4c2010
  virtual void AutoAssignProspectingOrdersByTileHeuristics();      // slot 0x33 0x4c2120
  virtual void AutoAssignProspectingOrdersFromSeedTileNeighbors(); // slot 0x34 0x4c2a30
  virtual void ProcessUnitOrders();                                // slot 0x35 0x4c1510; Mac oracle
  virtual void SeekLostTowns(char* primaryDistanceMap,
                             char* secondaryDistanceMap); // slot 0x36 0x4c2d50
  virtual void ContinueRailheadProject(TUnit* order, char* primaryDistanceMap,
                                       char* secondaryDistanceMap); // slot 0x37 0x4c2e10
  virtual void StartRailheadProject(short orderType, TShortintList* ownedTiles,
                                    char* primaryDistanceMap,
                                    char* secondaryDistanceMap); // slot 0x38 0x4c3170
  virtual short EvaluateResources(short tileIndex);              // slot 0x39 0x4c3490
  virtual int ScoreResource(int amount, int unusedResourceType,
                            int scorePerUnit); // slot 0x3a 0x4c3620; Mac oracle name
  virtual char* CreateSeaDistanceMap(TShortintList* ownedTiles); // slot 0x3b 0x4c3640
  virtual char*
  BuildFrogCityDistanceMapFromReachableSeaCandidates(TShortintList* ownedTiles); // slot 0x3c
                                                                                 // 0x4c3910
  virtual void RebalanceCityOrderAllocationTargets(TCity* city);        // slot 0x3d 0x4c3c00
  virtual void ProcessCityOrderStateTickAndApplyCapabilitySelection();  // slot 0x3e 0x4c3d60
  virtual void RebalanceCitySupportAndLaborAllocations();               // slot 0x3f 0x4c40c0
  virtual void ChooseAndMarkNextCityProductionCommand();                // slot 0x40 0x4c4370
  virtual void ComputeCityProductionCommandLimitsFromBuildingOutputs(); // slot 0x41 0x4c4690
  virtual void RebuildCityOrderCommandAvailabilityAndPriorityCycle();   // slot 0x42 0x4c4840
  virtual void
  UpdateMinisterProductionMetricsForResourceIndex(short orderSlot);        // slot 0x43 0x4c49f0
  virtual short RaisePowerPlantOrderToReachLaborTarget(short targetLabor); // slot 0x44 0x4c4d40
  virtual void FillRemainingNeedCapacityAndReducePowerPlantOrder();        // slot 0x45 0x4c4e60
  virtual short RequestResource(short resourceType, short requestedAmount,
                                short flags); // slot 0x46 0x4c4fe0; Mac oracle
  virtual void SeekResources(TShortintList* ownedTiles,
                             char* primaryDistanceMap); // slot 0x47 0x4c5240
  void DispatchBuilders();                              // 0x4c1990
  TCityInteriorMinister();
  // 0x4be8d0: allocate and reset this minister's city-policy state -- the interior-minister
  // analogue of TForeignMinister::IForeignMinister(owner). Links the base order
  // array to the owning great power, allocates the tracked-list members and the city-policy
  // TFuzzySet, and seeds the fuzzy set with four policy curves.
  // The base half of the MacApp two-phase construction: each personality subclass has
  // its own attested initializer (ISteelCityMinister / IShipBuilderCityMinister /
  // IEvenCityMinister / IRailCityMinister, all (TGreatPower*)) whose entire body is a
  // chain call to this one. By MacApp convention this would be ICityInteriorMinister,
  // but that symbol is NOT attested anywhere in the Mac oracle, so the invented name
  // stays rather than being swapped for a guessed one.
  void InitializeCityInteriorState(TGreatPower* owner);
  float GetAiDevelopmentResourceBudgetScale(int* resourcePools);
  int GetAverageDevelopmentOrderAllocation();
  bool TryApplyCityOrderCapabilitySelectionBySlot(short capabilitySlot); // 0x004c56e0

  DECLARE_DYNCREATE(TCityInteriorMinister)
  void WriteTo(TStream* stream) override;  // slot 0x14
  void ReadFrom(TStream* stream) override; // slot 0x18
  void Free() override;                    // slot 0x1c

  // Own fields at +0x28..+0x1c4. RTTI proves the whole TCityInteriorMinister family
  // shares this size; serialization establishes the exact short widths and array
  // extents below, while live readers establish the per-resource/per-production-slot
  // indexing domains.
  TLongintList* list28;                   // +0x28  (new TLongintList, vtable 0x650a08)
  TLongintList* list2c;                   // +0x2c  (new TLongintList)
  short nextProductionBuildingOrdinal30;  // +0x30  1-based cursor into list2c
  short pendingShipType32;                // +0x32  ship type queued at city slot 0x2b
  short field34;                          // +0x34
  short pendingRecruitmentCommandIndex36; // +0x36  maps to city order slot 0x22 + value
  short pendingUnitCommandIndex38;        // +0x38  maps to city order slot 0x19 + value
  short resource15ProductionPercent3a;    // +0x3a  init 50
  short field3c;                          // +0x3c  init -1
  short accumulatedUnmetNeed3e;           // +0x3e  queued via command 0x33
  // +0x40..0xba -- per-resource-index foreign-minister counter deltas, read/written
  // one short at a time (EvaluateCityShortagesAndNotifyForeignMinister reads
  // orderMetricTable40[0]/[1] as a paired "any nonzero" trigger and [2]..[6]
  // individually). Index 60 is the low-skill labor shortfall; serialization proves
  // this is one 61-entry table rather than a separate trailing field.
  short orderMetricTable40[61];   // +0x40..0xba  (zeroed on init)
  short orderShortTableBA[16];    // +0xba..0xda
  short deferredLaborShortfallDA; // +0xda
  short orderShortTableDC[16];    // +0xdc..0xfc
  // Three parallel short[23] order-type tables, all cleared together by
  // InitializeCityInteriorState. GetExteriorNeedFor reads +0x12a;
  // GetHistoricalNeedFor reads and ResetHistoricalNeedFor clears +0x158.
  short orderTypeTableFC[23];           // +0xfc..0x12a
  short orderTypeTable12A[23];          // +0x12a..0x158 (exterior need by order type)
  short orderTypeTable158[23];          // +0x158..0x186 (historical need by order type)
  short temporarilyReservedShipArms186; // +0x186
  TFuzzySet* cityPolicyFuzzySet;        // +0x188 (new TFuzzySet, 4 policy curves)
  TList* orderList18c;                  // +0x18c (new TList; ctor 0x4be840 nulls it)
  TLongintList* list190;                // +0x190 (new TLongintList)
  // Per-resource demand/capacity values consulted when deciding which missing
  // civilian order classes must be requested. One short per resource type.
  short civilianOrderDemandByResourceType194[23]; // +0x194
  short temporaryFurnitureSubstituteLumber1c2;    // +0x1c2

  short& LowSkillLaborShortfall() {
    return orderMetricTable40[60];
  }
};
ASSERT_SIZE(TCityInteriorMinister, 0x1c4);
