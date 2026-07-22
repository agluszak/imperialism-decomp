#pragma once

#include "game/TInteriorMinister.h"

class TCity;
class TGreatPower;
class TLongintList;
class TList;
class TShortintList;
class TUnit;
class TFuzzySet;

// Player city interior minister — derives from TInteriorMinister (shares slots 0x48-0x50)
// and overrides serialization/Free/NotifySlot44 plus a long city-policy virtual run.
// VTABLE: IMPERIALISM 0x006508a8
class TCityInteriorMinister : public TInteriorMinister {
public:
  virtual ~TCityInteriorMinister() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  short GetRankingCriterionForGP(short nationSlot) override; // slot 0x0a 0x4bee20
  // slot 0x0b RebuildTerrainPreferenceEntriesAndAssignRanks inherited unchanged (0x52ed50)
  // slot 0x0c MapTerrainTypeToPreferenceRank inherited unchanged (0x52ee20)
  // slot 0x0d MapPreferenceRankToTerrainType inherited unchanged (0x52eea0)
  // slot 0x0e GetPreferenceTerrainTypeByEntryIndex inherited unchanged (0x52ef80)
  // slot 0x0f GetPreferenceGroupRankByEntryIndex inherited unchanged (0x52ef20)
  // slot 0x10 GetPreferenceScoreByEntryIndex inherited unchanged (0x52ef50)
  virtual void MakeNewCity(TCity* city) override; // slot 0x11 0x4c0d90
  // slot 0x12 OrphanCallChain_C11_I88_004874b0 inherited unchanged (0x4be450)
  // slot 0x13 VTableSlot13 inherited unchanged (0x4be4f0)
  // slot 0x14 SetForeignMinisterReadyFlag14 inherited unchanged (0x4be520)
  virtual void FillOrders() override; // slot 0x15 0x4bf770
  // slot 0x16 GetTEventHandlerClassNamePointer inherited unchanged (0x4be480)
  // slot 0x17 VTableSlot17 inherited unchanged (0x4be4c0)
  // slot 0x18 OrphanCallChain_C11_I88_004874b0 inherited unchanged (0x4be650)
  // slot 0x19 OrphanLeaf_NoCall_Ins07_004d8920 inherited unchanged (0x4be690)
  virtual void InteriorSlot1A(short arg) override;         // slot 0x1a 0x4beeb0
  virtual void IndustryOrder(short industrySlot) override; // slot 0x1b 0x4beee0
  virtual void InteriorSlot1C(short arg) override;         // slot 0x1c 0x4bef30
  virtual short InteriorSlot1D(int arg) override;          // slot 0x1d 0x4be7b0
  virtual short InteriorSlot1E(int arg) override;          // slot 0x1e 0x4be7d0
  virtual void InteriorSlot1F(int arg) override;           // slot 0x1f 0x4be7f0
  virtual void FillLists();                                // slot 0x20 0x4bed60
  // Reports orderMetricTable40 deltas to the owner's foreign minister (index 0 as a
  // 25%-chance roll gated on either of the paired trigger slots [0]/[1], indices 2..6
  // forwarded directly when nonzero), then picks a (resultCode, magnitude) pair from
  // the city's population-vs-stock shortage state (TPopulationMgr's
  // GetRecentStormImpactMetrics pair, else cityStockSteelCC/cityStockLumberC8/
  // cityStockCannedFoodC4 vs TPopulationMgr::populationCount08) and reports it via
  // SetInteriorMinisterBid, unless no condition qualified.
  virtual undefined EvaluateCityShortagesAndNotifyForeignMinister(TCity* city); // slot 0x21
                                                                                // 0x4bf8a0
  // Dispatches production-order-queueing helpers for `city`: exactly one of
  // QueueCityProductionCommand17Or18FromSupportRatio (lowProductionFlag7c set,
  // lowStockFlag7d clear) / DistributeCityProductionCommandBudgetAndQueueOrders
  // (the reverse), then unconditionally QueueCityProductionCommand33From
  // AccumulatedDeficit / QueueCityProductionCommand2BIfMissingAndResetValue /
  // QueueSingleCityProductionCommandFromField36 / ...Field38 (each gated on this
  // minister's own field3e/field32/field36/field38), then always
  // QueueCityProductionRebalanceCommandsByThresholds.
  virtual undefined GetTEventHandlerClassNamePointer_22(TCity* city,
                                                        int* arg2); // slot 0x22 0x4bfa50
  virtual undefined
  QueueCityProductionRebalanceCommandsByThresholds(TCity* city, int* arg2); // slot 0x23 0x4bfb20
  // Verified empty in the original: `ret 8` only, no reads/writes. Ghidra's
  // "GetTEventHandlerClassNamePointer" name is a misattribution shared by several
  // no-op/near-no-op slots in this class; renamed to reflect the real (empty) body.
  virtual void NoOpProductionCommandHook24(int unusedArg1, int unusedArg2); // slot 0x24 0x4bff60
  virtual undefined
  QueueCityProductionCommand17Or18FromSupportRatio(void* arg1, int* arg2); // slot 0x25 0x4c02c0
  virtual undefined
  DistributeCityProductionCommandBudgetAndQueueOrders(TCity* city,
                                                      void* arg2); // slot 0x26 0x4c0090
  virtual undefined QueueRandomCityProductionCommand19To1C(void* arg1,
                                                           void* arg2); // slot 0x27 0x4c04e0
  virtual undefined
  QueueCityProductionCommand2BIfMissingAndResetValue(int arg1, int* arg2); // slot 0x28 0x4c05a0
  virtual undefined QueueSingleCityProductionCommandFromField36(void* arg1,
                                                                void* arg2); // slot 0x29 0x4c0690
  virtual undefined QueueSingleCityProductionCommandFromField38(void* arg1,
                                                                void* arg2); // slot 0x2a 0x4c0730
  // NOT YET PORTED (raw disassembly investigated): arg1 is TCity* (matches the ESP+0x20
  // read, confirmed via lowProductionFlag7c-style offsets at the caller). arg2 is NOT an
  // `int` -- it is dereferenced as a vtable pointer (`MOV EAX,[arg2]; CALL [EAX+0x7c]`
  // with a pushed short constant, e.g. 0x33, and the bool return tested via TEST AL,AL).
  // Checked TCity (slot 0x7c = MouseTrap, a real no-arg no-op -- wrong shape) and
  // TSortedList (slot 0x7c is null, past its vtable end) -- arg2's real class is still
  // unidentified. Needs its own class-recovery pass before this can be ported; the
  // accumulated-deficit sum (23-entry loop over `field_0x10e`) and the
  // the 0x14-byte heap allocation + TCityTask-shaped field stores later in the body are already
  // understood (see TCityTask.h/.cpp), it's specifically this one vtable receiver that's
  // blocking completion.
  virtual undefined
  QueueCityProductionCommand33FromAccumulatedDeficit(TCity* arg1,
                                                     int* arg2); // slot 0x2b 0x4bff80
  virtual undefined DistributeCityProductionAcrossOrderTemplatesAndBackfillDeficits(
      TCity* city);                     // slot 0x2c 0x4c07d0
  virtual void VTableSlot2D(short arg); // slot 0x2d 0x4bef10
  virtual undefined SetForeignMinisterReadyFlag14_2e(short arg1, short arg2,
                                                     short arg3); // slot 0x2e 0x4c0de0
  virtual undefined
  ReconcileCityProductionQueueAgainstTargetsAndAdjustOrders(int* arg1,
                                                            int unusedArg2); // slot 0x2f 0x4c0e50
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
  virtual void RebalanceCityOrderAllocationTargets(TCity* city);             // slot 0x3d 0x4c3c00
  virtual undefined ProcessCityOrderStateTickAndApplyCapabilitySelection();  // slot 0x3e 0x4c3d60
  virtual undefined RebalanceCitySupportAndLaborAllocations();               // slot 0x3f 0x4c40c0
  virtual undefined ChooseAndMarkNextCityProductionCommand();                // slot 0x40 0x4c4370
  virtual undefined ComputeCityProductionCommandLimitsFromBuildingOutputs(); // slot 0x41 0x4c4690
  virtual undefined RebuildCityOrderCommandAvailabilityAndPriorityCycle();   // slot 0x42 0x4c4840
  virtual undefined UpdateMinisterProductionMetricsForResourceIndex();       // slot 0x43 0x4c49f0
  virtual undefined CityMinisterSlot44();                                    // slot 0x44 0x4c4d40
  virtual undefined CityMinisterSlot45();                                    // slot 0x45 0x4c4e60
  virtual short RequestResource(short resourceType, short requestedAmount,
                                short flags); // slot 0x46 0x4c4fe0; Mac oracle
  virtual undefined SeekResources(TShortintList* ownedTiles,
                                  char* primaryDistanceMap); // slot 0x47 0x4c5240
  void DispatchBuilders();                                   // 0x4c1990
  TCityInteriorMinister();
  // 0x4be8d0: allocate and reset this minister's city-policy state -- the interior-minister
  // analogue of TForeignMinister::InitializeStateAndCounters(owner). Links the base order
  // array to the owning great power, allocates the tracked-list members and the city-policy
  // TFuzzySet, and seeds the fuzzy set with four policy curves.
  void InitializeCityInteriorState(TGreatPower* owner);
  float GetAiDevelopmentResourceBudgetScale(int* resourcePools);
  int GetAverageDevelopmentOrderAllocation();

  DECLARE_DYNCREATE(TCityInteriorMinister)
  void WriteTo(TStream* stream) override;  // slot 0x14
  void ReadFrom(TStream* stream) override; // slot 0x18
  void Free() override;                    // slot 0x1c

  // Own fields at +0x28..+0x1c4 (RTTI m_nObjectSize proves the whole
  // TCityInteriorMinister-family shares this size -- TSteelCityMinister/
  // TShipBuilderCityMinister/TEvenCityMinister/TRailCityMinister add zero bytes of
  // their own). Most of this block is still unrecovered city-production-order state;
  // InteriorSlot1D/1E/1F (0x4be7b0/0x4be7d0/0x4be7f0) index short arrays inside it at
  // +0x12a and +0x158 via raw this+offset access (callers pass order-type codes up to
  // 6 -- TAutoGreatPower.cpp ~L1035/1049), not yet promoted to named array fields.
  TLongintList* list28; // +0x28  (new TLongintList, vtable 0x650a08)
  TLongintList* list2c; // +0x2c  (new TLongintList)
  short field30;        // +0x30  set to 1 by InitializeCityInteriorState
  short field32;        // +0x32
  short field34;        // +0x34
  short field36;        // +0x36  init -1
  short field38;        // +0x38  init -1
  short field3a;        // +0x3a  init 50
  short field3c;        // +0x3c  init -1
  short field3e;        // +0x3e
  // +0x40..0xb8 -- per-resource-index foreign-minister counter deltas, read/written
  // one short at a time (EvaluateCityShortagesAndNotifyForeignMinister reads
  // orderMetricTable40[0]/[1] as a paired "any nonzero" trigger and [2]..[6]
  // individually), not as packed ints.
  short orderMetricTable40[60]; // +0x40..0xb8  (zeroed on init)
  short fieldB8;                // +0xb8
  short orderShortTableBA[16];  // +0xba..0xda
  short fieldDA;                // +0xda
  short orderShortTableDC[16];  // +0xdc..0xfc
  // Three parallel short[23] order-type tables (InteriorSlot1D/1E/1F index +0x12a/+0x158
  // by order-type code); all cleared together by InitializeCityInteriorState.
  short orderTypeTableFC[23];    // +0xfc..0x12a
  short orderTypeTable12A[23];   // +0x12a..0x158
  short orderTypeTable158[23];   // +0x158..0x186
  short field186;                // +0x186
  TFuzzySet* cityPolicyFuzzySet; // +0x188 (new TFuzzySet, 4 policy curves)
  TList* orderList18c;           // +0x18c (new TList; ctor 0x4be840 nulls it)
  TLongintList* list190;         // +0x190 (new TLongintList)
  // Per-resource demand/capacity values consulted when deciding which missing
  // civilian order classes must be requested. One short per resource type.
  short civilianOrderDemandByResourceType194[23]; // +0x194
  short field1c2;                                 // +0x1c2
};
