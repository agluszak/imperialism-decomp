#pragma once

#include "game/TInteriorMinister.h"

undefined4 thunk_InitializeCityInteriorMinister(void);

// Player city interior minister — derives from TInteriorMinister (shares slots 0x48-0x50)
// and overrides serialization/Free/NotifySlot44 plus a long city-policy virtual run.
// VTABLE: IMPERIALISM 0x006508a8
class TCityInteriorMinister : public TInteriorMinister {
public:
// === BEGIN GENERATED DECLS (TCityInteriorMinister) — refreshed by recover-class; do not hand-edit ===
  virtual ~TCityInteriorMinister(); // slot 0x01 (scalar deleting destructor)
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

  CRuntimeClass* GetRuntimeClass() const override; // slot 0x00
  void WriteTo(TStream* stream) override;          // slot 0x14
  void ReadFrom(TStream* stream) override;         // slot 0x18
  void Free() override;                            // slot 0x1c
};

// === BEGIN GENERATED (TCityInteriorMinister) — refreshed by `just gen-class TCityInteriorMinister`; do not hand-edit ===
// clang-format off
// vtable @ 0x006508a8 (67 slots), object size 0x1c4, base TInteriorMinister
//   slot 0x00  byte 0x00  0x004be820  override  GetTMinisterClassNamePointer
//   slot 0x01  byte 0x04  0x004be880  override  DeletingDestructTMinister
//   slot 0x02  byte 0x08  0x00485e90  inherited GetTTaskClassNamePointer
//   slot 0x03  byte 0x0c  0x00412bf0  inherited ConstructTTaskBaseState
//   slot 0x04  byte 0x10  0x00412c10  inherited GetTEventHandlerClassNamePointer
//   slot 0x05  byte 0x14  0x004bef60  override  VTableSlot05
//   slot 0x06  byte 0x18  0x004bf390  override  SetForeignMinisterReadyFlag14
//   slot 0x07  byte 0x1c  0x004becd0  override  VTableSlot07
//   slot 0x08  byte 0x20  0x004798d0  inherited DeserializeCityProductionQueueCommand
//   slot 0x09  byte 0x24  0x00415ce0  inherited OrphanRetStub_0059add0
//   slot 0x0a  byte 0x28  0x004bee20  override  GetTEventHandlerClassNamePointer
//   slot 0x0b  byte 0x2c  0x0052ed50  inherited VTableSlot0B
//   slot 0x0c  byte 0x30  0x0052ee20  inherited GetTEventHandlerClassNamePointer
//   slot 0x0d  byte 0x34  0x0052eea0  inherited VTableSlot0D
//   slot 0x0e  byte 0x38  0x0052ef80  inherited GetTEventHandlerClassNamePointer
//   slot 0x0f  byte 0x3c  0x0052ef20  inherited VTableSlot0F
//   slot 0x10  byte 0x40  0x0052ef50  inherited OrphanCallChain_C11_I88_004874b0
//   slot 0x11  byte 0x44  0x004c0d90  override  OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x12  byte 0x48  0x004be450  inherited OrphanCallChain_C11_I88_004874b0
//   slot 0x13  byte 0x4c  0x004be4f0  inherited VTableSlot13
//   slot 0x14  byte 0x50  0x004be520  inherited SetForeignMinisterReadyFlag14
//   slot 0x15  byte 0x54  0x004bf770  override  VTableSlot15
//   slot 0x16  byte 0x58  0x004be480  inherited GetTEventHandlerClassNamePointer
//   slot 0x17  byte 0x5c  0x004be4c0  inherited VTableSlot17
//   slot 0x18  byte 0x60  0x004be650  inherited OrphanCallChain_C11_I88_004874b0
//   slot 0x19  byte 0x64  0x004be690  inherited OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x1a  byte 0x68  0x004beeb0  override  OrphanCallChain_C11_I88_004874b0
//   slot 0x1b  byte 0x6c  0x004beee0  override  OrphanCallChain_C7_I57_004be5b0
//   slot 0x1c  byte 0x70  0x004bef30  override  SetForeignMinisterReadyFlag14
//   slot 0x1d  byte 0x74  0x004be7b0  override  VTableSlot1D
//   slot 0x1e  byte 0x78  0x004be7d0  override  GetTEventHandlerClassNamePointer
//   slot 0x1f  byte 0x7c  0x004be7f0  override  VTableSlot1F
//   slot 0x20  byte 0x80  0x004bed60  new       GetTEventHandlerClassNamePointer
//   slot 0x21  byte 0x84  0x004bf8a0  new       VTableSlot21
//   slot 0x22  byte 0x88  0x004bfa50  new       GetTEventHandlerClassNamePointer
//   slot 0x23  byte 0x8c  0x004bfb20  new       VTableSlot23
//   slot 0x24  byte 0x90  0x004bff60  new       GetTEventHandlerClassNamePointer
//   slot 0x25  byte 0x94  0x004c02c0  new       UpdateDiplomatProgressFromProductionSlots2And4
//   slot 0x26  byte 0x98  0x004c0090  new       SerializeTMinisterBaseOrderArrayHeader
//   slot 0x27  byte 0x9c  0x004c04e0  new       SerializeTMinisterBaseOrderArrayHeader
//   slot 0x28  byte 0xa0  0x004c05a0  new       GetTEventHandlerClassNamePointer
//   slot 0x29  byte 0xa4  0x004c0690  new       VTableSlot29
//   slot 0x2a  byte 0xa8  0x004c0730  new       DispatchNationStateEventCode10
//   slot 0x2b  byte 0xac  0x004bff80  new       OrphanRetStub_0059add0
//   slot 0x2c  byte 0xb0  0x004c07d0  new       GetTEventHandlerClassNamePointer
//   slot 0x2d  byte 0xb4  0x004bef10  new       VTableSlot2D
//   slot 0x2e  byte 0xb8  0x004c0de0  new       SetForeignMinisterReadyFlag14
//   slot 0x2f  byte 0xbc  0x004c0e50  new       VTableSlot2F
//   slot 0x30  byte 0xc0  0x004c11c0  new       GetTEventHandlerClassNamePointer
//   slot 0x31  byte 0xc4  0x004c1ac0  new       VTableSlot31
//   slot 0x32  byte 0xc8  0x004c2010  new       GetTEventHandlerClassNamePointer
//   slot 0x33  byte 0xcc  0x004c2120  new       VTableSlot33
//   slot 0x34  byte 0xd0  0x004c2a30  new       GetTEventHandlerClassNamePointer
//   slot 0x35  byte 0xd4  0x004c1510  new       VTableSlot35
//   slot 0x36  byte 0xd8  0x004c2d50  new       SetForeignMinisterReadyFlag14
//   slot 0x37  byte 0xdc  0x004c2e10  new       VTableSlot37
//   slot 0x38  byte 0xe0  0x004c3170  new       GetTEventHandlerClassNamePointer
//   slot 0x39  byte 0xe4  0x004c3490  new       VTableSlot39
//   slot 0x3a  byte 0xe8  0x004c3620  new       GetTEventHandlerClassNamePointer
//   slot 0x3b  byte 0xec  0x004c3640  new       VTableSlot3B
//   slot 0x3c  byte 0xf0  0x004c3910  new       GetTEventHandlerClassNamePointer
//   slot 0x3d  byte 0xf4  0x004c3c00  new       VTableSlot3D
//   slot 0x3e  byte 0xf8  0x004c3d60  new       GetTEventHandlerClassNamePointer
//   slot 0x3f  byte 0xfc  0x004c40c0  new       OrphanRetStub_004be6d0
//   slot 0x40  byte 0x100  0x004c4370  new       OrphanCallChain_C11_I88_004874b0
//   slot 0x41  byte 0x104  0x004c4690  new       OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x42  byte 0x108  0x004c4840  new       OrphanCallChain_C11_I88_004874b0
// object size 0x1c4 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TCityInteriorMinister) ===
