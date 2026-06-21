#pragma once

#include "game/TMinor.h"

// Network multiplayer minor nation row: same nation prefix as TMinor with remote-only
// tail state and a few divergent nation virtuals (immediate dispatch, map-cell label hook).
// VTABLE: IMPERIALISM 0x0065bde0
class TRemoteMinor : public TMinor {
public:
// === BEGIN GENERATED DECLS (TRemoteMinor) — refreshed by recover-class; do not hand-edit ===
  virtual ~TRemoteMinor(); // slot 0x01 (scalar deleting destructor)
  virtual void Serialize(CArchive& archive); // slot 0x02 0x485e90
  virtual void AssertValid() const; // slot 0x03 0x412bf0
  virtual void Dump(CDumpContext &); // slot 0x04 0x412c10
  virtual undefined SerializeDiplomacyNationStateToStream(); // slot 0x05 0x4e4390
  virtual undefined DeserializeDiplomacyNationStateFromStream(); // slot 0x06 0x4e41c0
  virtual void Free(); // slot 0x07 0x4d6ba0
  virtual undefined InvokeObjectVtableMethod24(); // slot 0x08 0x4798d0
  virtual TObject* ShallowFree(); // slot 0x09 0x415ce0
  virtual undefined OrphanLeaf_NoCall_Ins06_004d87b0_0a(); // slot 0x0a 0x4d70e0
  virtual undefined SelectCandidateTilesWithLowGroundUnitCount_0b(); // slot 0x0b 0x4d7070
  virtual undefined SeedRecruitAndNavyOrdersForEligibleCoastalCities(); // slot 0x0c 0x4d71b0
  virtual undefined CreateAndDispatchMilitaryRecruitOrderForNationSlot(); // slot 0x0d 0x4d7770
  virtual undefined AddToNationMetricAtField10(); // slot 0x0e 0x4d7ae0
  virtual undefined PopulateSelectableEntryFlavorTextAndOrdinals(); // slot 0x0f 0x4d8000
  virtual undefined OrphanLeaf_NoCall_Ins06_004d87b0_10(); // slot 0x10 0x4d87b0
  virtual undefined SelectCandidateTilesWithLowGroundUnitCount_11(); // slot 0x11 0x4d87e0
  virtual undefined SetNationTradePolicyValueForTargetAndNotify(); // slot 0x12 0x4e4fa0
  virtual void ApplyJoinEmpireModeForTargetNation(int targetNationSlot,int mode); // slot 0x13 0x4d7b20
  virtual undefined ProcessTurnEventNationStateTransitionAndDiplomacy(); // slot 0x14 0x4e5340
  virtual undefined ApplyNationStateCode200AndQueueEvent1B(); // slot 0x15 0x4e5840
  virtual undefined ApplyJoinEmpireMode2FinalizeNationNameState(); // slot 0x16 0x4e59d0
  virtual undefined IsDiplomacyTargetClassCode200Match(); // slot 0x17 0x4d7d20
  virtual undefined RemoveRegionIdFromNationOwnedRegionList(); // slot 0x18 0x4e64a0
  virtual undefined AddRegionIdToNationOwnedRegionList(); // slot 0x19 0x4e64f0
  virtual undefined SetNationPercentFieldByModeAndDescriptorLinks(); // slot 0x1a 0x4d7dd0
  virtual undefined OrphanRetStub_004d7e90(); // slot 0x1b 0x4d7e90
  virtual undefined OrphanLeaf_NoCall_Ins02_004d7ee0(); // slot 0x1c 0x4e4630
  virtual undefined OrphanLeaf_NoCall_Ins02_004d7f00(); // slot 0x1d 0x4d7f00
  virtual undefined OrphanLeaf_NoCall_Ins02_004d7f20(); // slot 0x1e 0x4e4660
  virtual undefined OrphanLeaf_NoCall_Ins02_004d7f40(); // slot 0x1f 0x4e4680
  virtual undefined IsDiplomacyPolicyAllowedForTargetClassState(); // slot 0x21 0x4e4ee0
  virtual undefined ReturnFalseNationStateActionStub(); // slot 0x22 0x4e4f50
  virtual undefined ResolveAndApplyDiplomacyPolicyTransition(); // slot 0x23 0x4e50d0
  virtual undefined IsPolicyCodeInSpecialNationPolicySet(); // slot 0x24 0x4e45f0
  virtual undefined TriggerNationWarTransitionHandlersIfNeeded(); // slot 0x25 0x4e5300
  virtual char ReturnFalseNationStateCapabilityFlag98() override; // slot 0x26 0x4d6730
  virtual char ReturnFalseNationStateCapabilityFlag9C() override; // slot 0x27 0x4d6750
  virtual undefined SetNationSelectedRegionAndMapCellLabelAlt(); // slot 0x29 0x541d90
  virtual undefined RebuildDiplomacyEconomicPressureFromMapState(); // slot 0x2a 0x4e46a0
  virtual undefined Helper_Uses_GenerateThreadLocalRandom15_At004e4bd0(); // slot 0x2b 0x4e4bd0
  virtual undefined CanInitiateJoinEmpireProposalToTarget(); // slot 0x2c 0x4e4ff0
  virtual void HandleNetworkPortConstructionOrder(int nNationId); // slot 0x2d 0x4e5730
  virtual undefined SetNationRowDisplayValueByDiplomacyPredicate(); // slot 0x2e 0x4e5a40
  virtual undefined ClearTileActivityOverlayByProvinceId(); // slot 0x2f 0x4e5ac0
  virtual undefined QueueInterNationEvent17ForState300AffectedNations(); // slot 0x30 0x4e5be0
  virtual undefined ApplyDiplomacyRelationMaskToProvinceLinkedObjects(); // slot 0x31 0x4e5d90
  virtual undefined ReassignUnitOrdersForCountryTargetChange(); // slot 0x32 0x4e6150
  virtual undefined ReassignTileObjectOwnerAndNotifyForSelectedCells(); // slot 0x33 0x4e6040
  virtual undefined RelinkTileUnitsToCountryOrderManager(); // slot 0x34 0x4e6520
// === END GENERATED DECLS (TRemoteMinor) ===
  TRemoteMinor();

  static void* AllocateAndConstructTRemoteMinor();
  static void* GetTRemoteMinorClassNamePointer();

  CRuntimeClass* GetRuntimeClass() const override;

  void ApplyIndexedResourceDeltaAndAdjustNationTotals(int resourceIndex, int delta,
                                                      int multiplier) override;
  char ShouldDispatchImmediatelySlot28(void) override;
  void NoOpNationSelectedRegionAndMapCellLabelHook(int arg1, int arg2) override;

private:
  unsigned char remoteMinorTail[0x2dc - 0x2cc];
};

ASSERT_SIZE(TRemoteMinor, 0x2dc);

// === BEGIN GENERATED (TRemoteMinor) — refreshed by `just gen-class TRemoteMinor`; do not hand-edit ===
// clang-format off
// vtable @ 0x0065bde0 (53 slots), object size 0x2dc, base <root>
//   slot 0x00  byte 0x00  0x00541d70  new       GetTRemoteMinorClassNamePointer
//   slot 0x01  byte 0x04  0x00541cd0  new       DeletingDestructTRemoteMinor
//   slot 0x02  byte 0x08  0x00485e90  new       GetTTaskClassNamePointer
//   slot 0x03  byte 0x0c  0x00412bf0  new       ConstructTTaskBaseState
//   slot 0x04  byte 0x10  0x00412c10  new       GetTEventHandlerClassNamePointer
//   slot 0x05  byte 0x14  0x004e4390  new       SelectCandidateTilesWithLowGroundUnitCount
//   slot 0x06  byte 0x18  0x004e41c0  new       DeserializeRecruitScenarioAndInstantiateOrders
//   slot 0x07  byte 0x1c  0x004d6ba0  new       ApplyJoinEmpireModeForTargetNation
//   slot 0x08  byte 0x20  0x004798d0  new       DeserializeCityProductionQueueCommand
//   slot 0x09  byte 0x24  0x00415ce0  new       OrphanRetStub_0059add0
//   slot 0x0a  byte 0x28  0x004d70e0  new       OrphanLeaf_NoCall_Ins06_004d87b0
//   slot 0x0b  byte 0x2c  0x004d7070  new       SelectCandidateTilesWithLowGroundUnitCount
//   slot 0x0c  byte 0x30  0x004d71b0  new       OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x0d  byte 0x34  0x004d7770  new       ApplyJoinEmpireModeForTargetNation
//   slot 0x0e  byte 0x38  0x004d7ae0  new       SetNationTransferTargetCodeAndNotifyEligiblePeers
//   slot 0x0f  byte 0x3c  0x004d8000  new       ApplyJoinEmpireMode1TargetTransition
//   slot 0x10  byte 0x40  0x004d87b0  new       OrphanLeaf_NoCall_Ins06_004d87b0
//   slot 0x11  byte 0x44  0x004d87e0  new       SelectCandidateTilesWithLowGroundUnitCount
//   slot 0x12  byte 0x48  0x004e4fa0  new       OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x13  byte 0x4c  0x004d7b20  new       ApplyJoinEmpireModeForTargetNation
//   slot 0x14  byte 0x50  0x004e5340  new       SetNationTransferTargetCodeAndNotifyEligiblePeers
//   slot 0x15  byte 0x54  0x004e5840  new       ApplyJoinEmpireMode1TargetTransition
//   slot 0x16  byte 0x58  0x004e59d0  new       ApplyJoinEmpireMode2FinalizeNationNameState
//   slot 0x17  byte 0x5c  0x004d7d20  new       IsDiplomacyTargetClassCode200Match
//   slot 0x18  byte 0x60  0x004e64a0  new       RemoveRegionIdFromNationOwnedRegionList
//   slot 0x19  byte 0x64  0x004e64f0  new       AddRegionIdToNationOwnedRegionList
//   slot 0x1a  byte 0x68  0x004d7dd0  new       SetNationPercentFieldByModeAndDescriptorLinks
//   slot 0x1b  byte 0x6c  0x004d7e90  new       OrphanRetStub_004d7e90
//   slot 0x1c  byte 0x70  0x004e4630  new       OrphanLeaf_NoCall_Ins02_004d7ee0
//   slot 0x1d  byte 0x74  0x004d7f00  new       OrphanLeaf_NoCall_Ins02_004d7f00
//   slot 0x1e  byte 0x78  0x004e4660  new       OrphanLeaf_NoCall_Ins02_004d7f20
//   slot 0x1f  byte 0x7c  0x004e4680  new       OrphanLeaf_NoCall_Ins02_004d7f40
//   slot 0x20  byte 0x80  0x00541cb0  new       OrphanRetStub_00541cb0
//   slot 0x21  byte 0x84  0x004e4ee0  new       OrphanLeaf_NoCall_Ins02_004d7fc0
//   slot 0x22  byte 0x88  0x004e4f50  new       ReturnFalseNationStateActionStub
//   slot 0x23  byte 0x8c  0x004e50d0  new       OrphanRetStub_004d7fe0
//   slot 0x24  byte 0x90  0x004e45f0  new       ReturnFalseNationStateCapabilityFlag90
//   slot 0x25  byte 0x94  0x004e5300  new       OrphanRetStub_004d7f80
//   slot 0x26  byte 0x98  0x004d6730  new       ReturnFalseNationStateCapabilityFlag98
//   slot 0x27  byte 0x9c  0x004d6750  new       ReturnFalseNationStateCapabilityFlag9C
//   slot 0x28  byte 0xa0  0x00541c90  new       ReturnTrueRemoteMinorCapabilityStub
//   slot 0x29  byte 0xa4  0x00541d90  new       SetNationSelectedRegionAndMapCellLabelAlt
//   slot 0x2a  byte 0xa8  0x004e46a0  new       RebuildDiplomacyEconomicPressureFromMapState
//   slot 0x2b  byte 0xac  0x004e4bd0  new       Helper_Uses_GenerateThreadLocalRandom15_At004e4bd0
//   slot 0x2c  byte 0xb0  0x004e4ff0  new       CanInitiateJoinEmpireProposalToTarget
//   slot 0x2d  byte 0xb4  0x004e5730  new       HandleNetworkPortConstructionOrder
//   slot 0x2e  byte 0xb8  0x004e5a40  new       SetNationRowDisplayValueByDiplomacyPredicate
//   slot 0x2f  byte 0xbc  0x004e5ac0  new       ClearTileActivityOverlayByProvinceId
//   slot 0x30  byte 0xc0  0x004e5be0  new       QueueInterNationEvent17ForState300AffectedNations
//   slot 0x31  byte 0xc4  0x004e5d90  new       ApplyDiplomacyRelationMaskToProvinceLinkedObjects
//   slot 0x32  byte 0xc8  0x004e6150  new       ReassignUnitOrdersForCountryTargetChange
//   slot 0x33  byte 0xcc  0x004e6040  new       ReassignTileObjectOwnerAndNotifyForSelectedCells
//   slot 0x34  byte 0xd0  0x004e6520  new       GetTCountryClassNamePointer
// object size 0x2dc (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TRemoteMinor) ===
