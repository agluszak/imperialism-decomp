#pragma once

#include "game/TInteriorMinister.h"

class TCity;
class TGreatPower;
class TLongintList;
class TList;
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
  virtual void InteriorSlot1A(short arg) override; // slot 0x1a 0x4beeb0
  virtual void InteriorSlot1B(short arg) override; // slot 0x1b 0x4beee0
  virtual void InteriorSlot1C(short arg) override; // slot 0x1c 0x4bef30
  virtual short InteriorSlot1D(int arg) override;  // slot 0x1d 0x4be7b0
  virtual short InteriorSlot1E(int arg) override;  // slot 0x1e 0x4be7d0
  virtual void InteriorSlot1F(int arg) override;   // slot 0x1f 0x4be7f0
  virtual void CityInteriorSlot20();               // slot 0x20 0x4bed60
  virtual undefined VTableSlot21(int arg);         // slot 0x21 0x4bf8a0
  virtual undefined GetTEventHandlerClassNamePointer_22(int arg1,
                                                        int unusedArg2); // slot 0x22 0x4bfa50
  virtual undefined
  QueueCityProductionRebalanceCommandsByThresholds(TCity* city, int* arg2); // slot 0x23 0x4bfb20
  virtual undefined GetTEventHandlerClassNamePointer_24(int unusedArg1,
                                                        int unusedArg2); // slot 0x24 0x4bff60
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
  virtual undefined
  QueueCityProductionCommand33FromAccumulatedDeficit(int* arg1,
                                                     int unusedArg2); // slot 0x2b 0x4bff80
  virtual undefined DistributeCityProductionAcrossOrderTemplatesAndBackfillDeficits(
      TCity* city);                          // slot 0x2c 0x4c07d0
  virtual undefined VTableSlot2D(short arg); // slot 0x2d 0x4bef10
  virtual undefined SetForeignMinisterReadyFlag14_2e(short arg1, short arg2,
                                                     short arg3); // slot 0x2e 0x4c0de0
  virtual undefined
  ReconcileCityProductionQueueAgainstTargetsAndAdjustOrders(int* arg1,
                                                            int unusedArg2); // slot 0x2f 0x4c0e50
  virtual int GetHomeCityRecordIndexSlotC0();                                // slot 0x30 0x4c11c0
  virtual undefined RebuildMapTileNeighborBucketsForInteriorMinister();      // slot 0x31 0x4c1ac0
  virtual undefined GetTEventHandlerClassNamePointer_32();                   // slot 0x32 0x4c2010
  virtual undefined AutoAssignProspectingOrdersByTileHeuristics();           // slot 0x33 0x4c2120
  virtual undefined AutoAssignProspectingOrdersFromSeedTileNeighbors();      // slot 0x34 0x4c2a30
  virtual void CallD4();                                                     // slot 0x35 0x4c1510
  virtual undefined IterateLinkedListCursorEntries_004c2d50(int arg1,
                                                            int arg2); // slot 0x36 0x4c2d50
  virtual undefined HandleFrogCityTileSelectionAndDispatchOrders(int* arg1, int arg2,
                                                                 int arg3); // slot 0x37 0x4c2e10
  virtual undefined SelectBestFrogCityTileFromCandidateSet(short arg1, int arg2, int arg3,
                                                           int arg4);      // slot 0x38 0x4c3170
  virtual undefined ComputeFrogCityCandidateScoreFromNationNeeds(int arg); // slot 0x39 0x4c3490
  virtual undefined GetTEventHandlerClassNamePointer_3a(int arg1, int arg2,
                                                        int unusedArg3); // slot 0x3a 0x4c3620
  virtual undefined BuildFrogCityDistanceMapFromPrimarySeedSet(int arg); // slot 0x3b 0x4c3640
  virtual undefined
  BuildFrogCityDistanceMapFromReachableSeaCandidates(int arg);               // slot 0x3c 0x4c3910
  virtual undefined RebalanceCityOrderAllocationTargets(int* arg);           // slot 0x3d 0x4c3c00
  virtual undefined ProcessCityOrderStateTickAndApplyCapabilitySelection();  // slot 0x3e 0x4c3d60
  virtual undefined RebalanceCitySupportAndLaborAllocations();               // slot 0x3f 0x4c40c0
  virtual undefined ChooseAndMarkNextCityProductionCommand();                // slot 0x40 0x4c4370
  virtual undefined ComputeCityProductionCommandLimitsFromBuildingOutputs(); // slot 0x41 0x4c4690
  virtual undefined RebuildCityOrderCommandAvailabilityAndPriorityCycle();   // slot 0x42 0x4c4840
  virtual undefined UpdateMinisterProductionMetricsForResourceIndex();       // slot 0x43 0x4c49f0
  virtual undefined CityMinisterSlot44();                                    // slot 0x44 0x4c4d40
  virtual undefined CityMinisterSlot45();                                    // slot 0x45 0x4c4e60
  virtual undefined CityMinisterSlot46();                                    // slot 0x46 0x4c4fe0
  virtual undefined BuildFrogCityTerrainCountsAndOverlayStats();             // slot 0x47 0x4c5240
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
  TLongintList* list28;        // +0x28  (new TLongintList, vtable 0x650a08)
  TLongintList* list2c;        // +0x2c  (new TLongintList)
  short field30;               // +0x30  set to 1 by InitializeCityInteriorState
  short field32;               // +0x32
  short field34;               // +0x34
  short field36;               // +0x36  init -1
  short field38;               // +0x38  init -1
  short field3a;               // +0x3a  init 50
  short field3c;               // +0x3c  init -1
  short field3e;               // +0x3e
  int orderMetricTable40[30];  // +0x40..0xb8  city-order metric table (zeroed on init)
  short fieldB8;               // +0xb8
  short orderShortTableBA[16]; // +0xba..0xda
  short fieldDA;               // +0xda
  short orderShortTableDC[16]; // +0xdc..0xfc
  // Three parallel short[23] order-type tables (InteriorSlot1D/1E/1F index +0x12a/+0x158
  // by order-type code); all cleared together by InitializeCityInteriorState.
  short orderTypeTableFC[23];                        // +0xfc..0x12a
  short orderTypeTable12A[23];                       // +0x12a..0x158
  short orderTypeTable158[23];                       // +0x158..0x186
  short field186;                                    // +0x186
  TFuzzySet* cityPolicyFuzzySet;                     // +0x188 (new TFuzzySet, 4 policy curves)
  TList* orderList18c;                               // +0x18c (new TList; ctor 0x4be840 nulls it)
  TLongintList* list190;                             // +0x190 (new TLongintList)
  unsigned char cityMinisterState194[0x1c2 - 0x194]; // +0x194 (unrecovered)
  short field1c2;                                    // +0x1c2
};
