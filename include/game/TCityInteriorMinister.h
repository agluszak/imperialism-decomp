#pragma once

#include "game/TInteriorMinister.h"

undefined4 thunk_InitializeCityInteriorMinister(void);

// Player city interior minister — derives from TInteriorMinister (shares slots 0x48-0x50)
// and overrides serialization/Free/NotifySlot44 plus a long city-policy virtual run.
// VTABLE: IMPERIALISM 0x006508a8
class TCityInteriorMinister : public TInteriorMinister {
public:
// === BEGIN GENERATED DECLS (TCityInteriorMinister) — refreshed by recover-class; do not hand-edit ===
  virtual ~TCityInteriorMinister() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  short DispatchNationStateEventCode10(short nationSlot) override; // slot 0x0a 0x4bee20
  // slot 0x0b RebuildTerrainPreferenceEntriesAndAssignRanks inherited unchanged (0x52ed50)
  // slot 0x0c MapTerrainTypeToPreferenceRank inherited unchanged (0x52ee20)
  // slot 0x0d MapPreferenceRankToTerrainType inherited unchanged (0x52eea0)
  // slot 0x0e GetPreferenceTerrainTypeByEntryIndex inherited unchanged (0x52ef80)
  // slot 0x0f GetPreferenceGroupRankByEntryIndex inherited unchanged (0x52ef20)
  // slot 0x10 GetPreferenceScoreByEntryIndex inherited unchanged (0x52ef50)
  virtual void NoOpForeignMinisterUtilityStub(void* receiver) override; // slot 0x11 0x4c0d90
  // slot 0x12 OrphanCallChain_C11_I88_004874b0 inherited unchanged (0x4be450)
  // slot 0x13 VTableSlot13 inherited unchanged (0x4be4f0)
  // slot 0x14 SetForeignMinisterReadyFlag14 inherited unchanged (0x4be520)
  virtual void Call54() override; // slot 0x15 0x4bf770
  // slot 0x16 GetTEventHandlerClassNamePointer inherited unchanged (0x4be480)
  // slot 0x17 VTableSlot17 inherited unchanged (0x4be4c0)
  // slot 0x18 OrphanCallChain_C11_I88_004874b0 inherited unchanged (0x4be650)
  // slot 0x19 OrphanLeaf_NoCall_Ins07_004d8920 inherited unchanged (0x4be690)
  virtual void InteriorSlot1A() override; // slot 0x1a 0x4beeb0
  virtual void InteriorSlot1B() override; // slot 0x1b 0x4beee0
  virtual void InteriorSlot1C() override; // slot 0x1c 0x4bef30
  virtual void InteriorSlot1D() override; // slot 0x1d 0x4be7b0
  virtual void InteriorSlot1E() override; // slot 0x1e 0x4be7d0
  virtual void InteriorSlot1F() override; // slot 0x1f 0x4be7f0
  virtual void CityInteriorSlot20(); // slot 0x20 0x4bed60
  virtual undefined VTableSlot21(); // slot 0x21 0x4bf8a0
  virtual undefined GetTEventHandlerClassNamePointer_22(); // slot 0x22 0x4bfa50
  virtual undefined QueueCityProductionRebalanceCommandsByThresholds(); // slot 0x23 0x4bfb20
  virtual undefined GetTEventHandlerClassNamePointer_24(); // slot 0x24 0x4bff60
  virtual undefined QueueCityProductionCommand17Or18FromSupportRatio(); // slot 0x25 0x4c02c0
  virtual undefined DistributeCityProductionCommandBudgetAndQueueOrders(); // slot 0x26 0x4c0090
  virtual undefined QueueRandomCityProductionCommand19To1C(); // slot 0x27 0x4c04e0
  virtual undefined QueueCityProductionCommand2BIfMissingAndResetValue(); // slot 0x28 0x4c05a0
  virtual undefined QueueSingleCityProductionCommandFromField36(); // slot 0x29 0x4c0690
  virtual undefined QueueSingleCityProductionCommandFromField38(); // slot 0x2a 0x4c0730
  virtual undefined QueueCityProductionCommand33FromAccumulatedDeficit(); // slot 0x2b 0x4bff80
  virtual undefined DistributeCityProductionAcrossOrderTemplatesAndBackfillDeficits(); // slot 0x2c 0x4c07d0
  virtual undefined VTableSlot2D(); // slot 0x2d 0x4bef10
  virtual undefined SetForeignMinisterReadyFlag14_2e(); // slot 0x2e 0x4c0de0
  virtual undefined ReconcileCityProductionQueueAgainstTargetsAndAdjustOrders(); // slot 0x2f 0x4c0e50
  virtual int GetHomeCityRecordIndexSlotC0(); // slot 0x30 0x4c11c0
  virtual undefined RebuildMapTileNeighborBucketsForInteriorMinister(); // slot 0x31 0x4c1ac0
  virtual undefined GetTEventHandlerClassNamePointer_32(); // slot 0x32 0x4c2010
  virtual undefined AutoAssignProspectingOrdersByTileHeuristics(); // slot 0x33 0x4c2120
  virtual undefined AutoAssignProspectingOrdersFromSeedTileNeighbors(); // slot 0x34 0x4c2a30
  virtual void CallD4(); // slot 0x35 0x4c1510
  virtual undefined IterateLinkedListCursorEntries_004c2d50(); // slot 0x36 0x4c2d50
  virtual undefined HandleFrogCityTileSelectionAndDispatchOrders(); // slot 0x37 0x4c2e10
  virtual undefined SelectBestFrogCityTileFromCandidateSet(); // slot 0x38 0x4c3170
  virtual undefined ComputeFrogCityCandidateScoreFromNationNeeds(); // slot 0x39 0x4c3490
  virtual undefined GetTEventHandlerClassNamePointer_3a(); // slot 0x3a 0x4c3620
  virtual undefined BuildFrogCityDistanceMapFromPrimarySeedSet(); // slot 0x3b 0x4c3640
  virtual undefined BuildFrogCityDistanceMapFromReachableSeaCandidates(); // slot 0x3c 0x4c3910
  virtual undefined RebalanceCityOrderAllocationTargets(); // slot 0x3d 0x4c3c00
  virtual undefined ProcessCityOrderStateTickAndApplyCapabilitySelection(); // slot 0x3e 0x4c3d60
  virtual undefined RebalanceCitySupportAndLaborAllocations(); // slot 0x3f 0x4c40c0
  virtual undefined ChooseAndMarkNextCityProductionCommand(); // slot 0x40 0x4c4370
  virtual undefined ComputeCityProductionCommandLimitsFromBuildingOutputs(); // slot 0x41 0x4c4690
  virtual undefined RebuildCityOrderCommandAvailabilityAndPriorityCycle(); // slot 0x42 0x4c4840
  virtual undefined UpdateMinisterProductionMetricsForResourceIndex(); // slot 0x43 0x4c49f0
  virtual undefined CityMinisterSlot44(); // slot 0x44 0x4c4d40
  virtual undefined CityMinisterSlot45(); // slot 0x45 0x4c4e60
  virtual undefined CityMinisterSlot46(); // slot 0x46 0x4c4fe0
  virtual undefined BuildFrogCityTerrainCountsAndOverlayStats(); // slot 0x47 0x4c5240
// === END GENERATED DECLS (TCityInteriorMinister) ===
  TCityInteriorMinister();
  void InitializeCityInteriorState();

  DECLARE_DYNCREATE(TCityInteriorMinister)
  void WriteTo(TStream* stream) override;          // slot 0x14
  void ReadFrom(TStream* stream) override;         // slot 0x18
  void Free() override;                            // slot 0x1c
};

