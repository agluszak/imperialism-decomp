#pragma once

#include "game/TGreatPower.h"
#include "game/mfc.h"

// TODO(manifest): describe TRemoteGreatPower and its role. Base edge (TGreatPower) recovered from RTTI CRuntimeClass chain: TRemoteGreatPower -> TGreatPower -> TCountry -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0065ba80
class TRemoteGreatPower : public TGreatPower {
public:
  CRuntimeClass* GetRuntimeClass() const override;
  ~TRemoteGreatPower();

  char ShouldDispatchImmediatelySlot28(void) override;
  void NoOpNationSelectedRegionAndMapCellLabelHook(int arg1, int arg2) override;
  void RefreshGreatPowerRelationPanelsAndDispatchDeltaSummary(void) override;
  void NotifyCitySlot2C(void) override;
  void OrphanRetStub_004dcc30(void) override;
  void SortTrackedOrdersByTypePriority(void) override;
  void ClearDiplomacyState1c6ForTarget(short targetSlot) override;
  void ClearDiplomacyState1c6Block(void) override;
  void BeginTurnDiplomacyPrePassSlot1c8(void) override;
  void ApplyTurnDiplomacyStateSlot1e0(void) override;
  void ResetNationDiplomacyProposalQueue(void) override;
  void ReleaseProposalQueueSlot7F(void) override;
  void ProcessPendingDiplomacyProposalQueue(void) override;
  void SetCandidateNationFlagAndPortZoneState(int targetNation) override;
  void CallSlotA8(int targetNation) override;
  void DispatchTurnEvent11F8NoPayloadSlot2AC(void) override;
  void NoOpTailStateHookSlot2B4(void) override;
  void NoOpTailStateHookSlot2B8(int arg) override;
  void UpdateGreatPowerPressureStateAndDispatchEscalationMessage(void) override;
  virtual void OrphanRetStub_005418e0(void);

  TRemoteGreatPower();
};

// === BEGIN GENERATED (TRemoteGreatPower) — refreshed by `just gen-class TRemoteGreatPower`; do not hand-edit ===
// clang-format off
// vtable @ 0x0065ba80 (179 slots), object size 0x964, base TGreatPower
//   slot 0x00  byte 0x00  0x00541b20  override  GetTCountryClassNamePointer
//   slot 0x01  byte 0x04  0x00541a80  override  VTableSlot01
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x004d9c70  inherited HandleCityDialogHintClusterUpdate
//   slot 0x06  byte 0x18  0x004d92e0  inherited DeserializeRecruitScenarioAndInstantiateOrders
//   slot 0x07  byte 0x1c  0x004d9160  inherited ApplyJoinEmpireModeForTargetNation
//   slot 0x08  byte 0x20  0x004798d0  inherited ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x004da500  inherited OrphanLeaf_NoCall_Ins06_004d87b0
//   slot 0x0b  byte 0x2c  0x004da3e0  inherited SelectCandidateTilesWithLowGroundUnitCount
//   slot 0x0c  byte 0x30  0x004d71b0  inherited OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x0d  byte 0x34  0x004d7770  inherited ApplyJoinEmpireModeForTargetNation
//   slot 0x0e  byte 0x38  0x004d7ae0  inherited SetNationTransferTargetCodeAndNotifyEligiblePeers
//   slot 0x0f  byte 0x3c  0x004d8000  inherited ApplyJoinEmpireMode1TargetTransition
//   slot 0x10  byte 0x40  0x004d87b0  inherited OrphanLeaf_NoCall_Ins06_004d87b0
//   slot 0x11  byte 0x44  0x004d87e0  inherited SelectCandidateTilesWithLowGroundUnitCount
//   slot 0x12  byte 0x48  0x004dd040  inherited OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x13  byte 0x4c  0x004e21b0  inherited ApplyJoinEmpireModeForTargetNation
//   slot 0x14  byte 0x50  0x004de860  inherited SetNationTransferTargetCodeAndNotifyEligiblePeers
//   slot 0x15  byte 0x54  0x004d7c90  inherited ApplyJoinEmpireMode1TargetTransition
//   slot 0x16  byte 0x58  0x004d7d50  inherited ApplyJoinEmpireMode2FinalizeNationNameState
//   slot 0x17  byte 0x5c  0x004d7d20  inherited IsDiplomacyTargetClassCode200Match
//   slot 0x18  byte 0x60  0x004e2270  inherited RemoveRegionIdFromNationOwnedRegionList
//   slot 0x19  byte 0x64  0x004e22b0  inherited AddRegionIdToNationOwnedRegionList
//   slot 0x1a  byte 0x68  0x004e2330  inherited SetNationPercentFieldByModeAndDescriptorLinks
//   slot 0x1b  byte 0x6c  0x004dda20  inherited OrphanRetStub_004d7e90
//   slot 0x1c  byte 0x70  0x004dda60  inherited OrphanLeaf_NoCall_Ins02_004d7ee0
//   slot 0x1d  byte 0x74  0x004d8c00  inherited OrphanLeaf_NoCall_Ins02_004d7f00
//   slot 0x1e  byte 0x78  0x004dd740  inherited OrphanLeaf_NoCall_Ins02_004d7f20
//   slot 0x1f  byte 0x7c  0x004ddb20  inherited OrphanLeaf_NoCall_Ins02_004d7f40
//   slot 0x20  byte 0x80  0x004ddc30  inherited OrphanRetStub_004d7fa0
//   slot 0x21  byte 0x84  0x004ddd50  inherited OrphanLeaf_NoCall_Ins02_004d7fc0
//   slot 0x22  byte 0x88  0x004ddbb0  inherited ReturnFalseNationStateActionStub
//   slot 0x23  byte 0x8c  0x004defd0  inherited OrphanRetStub_004d7fe0
//   slot 0x24  byte 0x90  0x004d7f60  inherited ReturnFalseNationStateCapabilityFlag90
//   slot 0x25  byte 0x94  0x004dedf0  inherited OrphanRetStub_004d7f80
//   slot 0x26  byte 0x98  0x004d6730  inherited ReturnFalseNationStateCapabilityFlag98
//   slot 0x27  byte 0x9c  0x004d6750  inherited ReturnFalseNationStateCapabilityFlag9C
//   slot 0x28  byte 0xa0  0x00541840  override  ReturnFalseNationStateCapabilityFlagA0
//   slot 0x29  byte 0xa4  0x00541b40  override  SetNationSelectedRegionAndMapCellLabel
//   slot 0x2a  byte 0xa8  0x004da5c0  inherited NoOpNationPendingActionHook
//   slot 0x2b  byte 0xac  0x004da860  inherited PromoteNationPendingActionSlot5IfCapabilityActive
//   slot 0x2c  byte 0xb0  0x004da8a0  inherited AdvanceNationPendingActionStateMachine
//   slot 0x2d  byte 0xb4  0x004da5e0  inherited DispatchNationPendingActionEventCodes
//   slot 0x2e  byte 0xb8  0x004daa10  inherited SetNationPendingActionStateAndPayload
//   slot 0x2f  byte 0xbc  0x004daa50  inherited QueueNationOrderManagerPayloadObject
//   slot 0x30  byte 0xc0  0x004daa80  inherited ClearQueuedNationOrdersAndResetOrderManager
//   slot 0x31  byte 0xc4  0x004dab00  inherited NoOpNationQueuedOrderHook
//   slot 0x32  byte 0xc8  0x004dab20  inherited ExecuteNationPendingActionStateMachine
//   slot 0x33  byte 0xcc  0x004dae70  inherited HasQueuedCivWorkOrderType7
//   slot 0x34  byte 0xd0  0x004db7d0  inherited GetTCountryClassNamePointer
//   slot 0x35  byte 0xd4  0x004dbac0  inherited VTableSlot35
//   slot 0x36  byte 0xd8  0x00541880  override  DispatchNationStateEventCode10
//   slot 0x37  byte 0xdc  0x005418a0  override  OrphanRetStub_0059add0
//   slot 0x38  byte 0xe0  0x005418c0  override  GetTEventHandlerClassNamePointer
//   slot 0x39  byte 0xe4  0x004df810  inherited HandleCityDialogHintClusterUpdate
//   slot 0x3a  byte 0xe8  0x004dfa20  inherited DeserializeRecruitScenarioAndInstantiateOrders
//   slot 0x3b  byte 0xec  0x004dfae0  inherited ApplyJoinEmpireModeForTargetNation
//   slot 0x3c  byte 0xf0  0x004e00d0  inherited GetTEventHandlerClassNamePointer
//   slot 0x3d  byte 0xf4  0x004e0140  inherited VTableSlot3D
//   slot 0x3e  byte 0xf8  0x004e01b0  inherited OrphanLeaf_NoCall_Ins06_004d87b0
//   slot 0x3f  byte 0xfc  0x004dca80  inherited SelectCandidateTilesWithLowGroundUnitCount
//   slot 0x40  byte 0x100  0x004dcaa0  inherited OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x41  byte 0x104  0x004dcc50  inherited ApplyJoinEmpireModeForTargetNation
//   slot 0x42  byte 0x108  0x004dcca0  inherited SetNationTransferTargetCodeAndNotifyEligiblePeers
//   slot 0x43  byte 0x10c  0x004dcd10  inherited ApplyJoinEmpireMode1TargetTransition
//   slot 0x44  byte 0x110  0x004dce10  inherited OrphanLeaf_NoCall_Ins06_004d87b0
//   slot 0x45  byte 0x114  0x004dcdd0  inherited SelectCandidateTilesWithLowGroundUnitCount
//   slot 0x46  byte 0x118  0x004dce40  inherited OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x47  byte 0x11c  0x004dce70  inherited ApplyJoinEmpireModeForTargetNation
//   slot 0x48  byte 0x120  0x004dce90  inherited SetNationTransferTargetCodeAndNotifyEligiblePeers
//   slot 0x49  byte 0x124  0x004dcf10  inherited ApplyJoinEmpireMode1TargetTransition
//   slot 0x4a  byte 0x128  0x004dcf60  inherited ApplyJoinEmpireMode2FinalizeNationNameState
//   slot 0x4b  byte 0x12c  0x004dcfd0  inherited IsDiplomacyTargetClassCode200Match
//   slot 0x4c  byte 0x130  0x004e0220  inherited RemoveRegionIdFromNationOwnedRegionList
//   slot 0x4d  byte 0x134  0x004dbd20  inherited AddRegionIdToNationOwnedRegionList
//   slot 0x4e  byte 0x138  0x004dbf00  inherited SetNationPercentFieldByModeAndDescriptorLinks
//   slot 0x4f  byte 0x13c  0x004dc3f0  inherited OrphanRetStub_004d7e90
//   slot 0x50  byte 0x140  0x004dc440  inherited OrphanLeaf_NoCall_Ins02_004d7ee0
//   slot 0x51  byte 0x144  0x004dc4c0  inherited OrphanLeaf_NoCall_Ins02_004d7f00
//   slot 0x52  byte 0x148  0x004dc540  inherited OrphanLeaf_NoCall_Ins02_004d7f20
//   slot 0x53  byte 0x14c  0x004dc660  inherited OrphanLeaf_NoCall_Ins02_004d7f40
//   slot 0x54  byte 0x150  0x004dc840  inherited OrphanRetStub_004d7fa0
//   slot 0x55  byte 0x154  0x00541900  override  OrphanLeaf_NoCall_Ins02_004d7fc0
//   slot 0x56  byte 0x158  0x004e03a0  inherited ReturnFalseNationStateActionStub
//   slot 0x57  byte 0x15c  0x004e03d0  inherited OrphanRetStub_004d7fe0
//   slot 0x58  byte 0x160  0x004dd0c0  inherited ReturnFalseNationStateCapabilityFlag90
//   slot 0x59  byte 0x164  0x004dd140  inherited OrphanRetStub_004d7f80
//   slot 0x5a  byte 0x168  0x004dd1b0  inherited ReturnFalseNationStateCapabilityFlag98
//   slot 0x5b  byte 0x16c  0x004dd270  inherited ReturnFalseNationStateCapabilityFlag9C
//   slot 0x5c  byte 0x170  0x004dd310  inherited ReturnFalseNationStateCapabilityFlagA0
//   slot 0x5d  byte 0x174  0x004dd340  inherited AddAmountToAidAllocationMatrixCellAndTotal
//   slot 0x5e  byte 0x178  0x004dd3b0  inherited SumAidAllocationMatrixColumnForTarget
//   slot 0x5f  byte 0x17c  0x004dd3f0  inherited PromoteNationPendingActionSlot5IfCapabilityActive
//   slot 0x60  byte 0x180  0x004dd430  inherited AdvanceNationPendingActionStateMachine
//   slot 0x61  byte 0x184  0x004dd470  inherited DispatchNationPendingActionEventCodes
//   slot 0x62  byte 0x188  0x004dd4e0  inherited SetNationPendingActionStateAndPayload
//   slot 0x63  byte 0x18c  0x004dd770  inherited QueueNationOrderManagerPayloadObject
//   slot 0x64  byte 0x190  0x004dd7b0  inherited ClearQueuedNationOrdersAndResetOrderManager
//   slot 0x65  byte 0x194  0x004dd7f0  inherited OrphanCallChain_C1_I42_004dd7f0
//   slot 0x66  byte 0x198  0x004dda40  inherited ExecuteNationPendingActionStateMachine
//   slot 0x67  byte 0x19c  0x004dda90  inherited HasQueuedCivWorkOrderType7
//   slot 0x68  byte 0x1a0  0x004ddad0  inherited GetTCountryClassNamePointer
//   slot 0x69  byte 0x1a4  0x004ddb40  inherited VTableSlot69
//   slot 0x6a  byte 0x1a8  0x004ddb80  inherited DispatchNationStateEventCode10
//   slot 0x6b  byte 0x1ac  0x00541940  override  OrphanRetStub_0059add0
//   slot 0x6c  byte 0x1b0  0x004ddd90  inherited GetTEventHandlerClassNamePointer
//   slot 0x6d  byte 0x1b4  0x004dde80  inherited HandleCityDialogHintClusterUpdate
//   slot 0x6e  byte 0x1b8  0x004dde30  inherited DeserializeRecruitScenarioAndInstantiateOrders
//   slot 0x6f  byte 0x1bc  0x004ddeb0  inherited ApplyJoinEmpireModeForTargetNation
//   slot 0x70  byte 0x1c0  0x004ddf20  inherited GetTEventHandlerClassNamePointer
//   slot 0x71  byte 0x1c4  0x00541920  override  VTableSlot71
//   slot 0x72  byte 0x1c8  0x00541960  override  OrphanLeaf_NoCall_Ins06_004d87b0
//   slot 0x73  byte 0x1cc  0x004de2d0  inherited SelectCandidateTilesWithLowGroundUnitCount
//   slot 0x74  byte 0x1d0  0x004ddfc0  inherited OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x75  byte 0x1d4  0x004de340  inherited ApplyJoinEmpireModeForTargetNation
//   slot 0x76  byte 0x1d8  0x004de5e0  inherited SetNationTransferTargetCodeAndNotifyEligiblePeers
//   slot 0x77  byte 0x1dc  0x004de700  inherited ApplyJoinEmpireMode1TargetTransition
//   slot 0x78  byte 0x1e0  0x00541980  override  OrphanLeaf_NoCall_Ins06_004d87b0
//   slot 0x79  byte 0x1e4  0x004deca0  inherited SelectCandidateTilesWithLowGroundUnitCount
//   slot 0x7a  byte 0x1e8  0x004de790  inherited OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x7b  byte 0x1ec  0x004df010  inherited ApplyJoinEmpireModeForTargetNation
//   slot 0x7c  byte 0x1f0  0x004df370  inherited SetNationTransferTargetCodeAndNotifyEligiblePeers
//   slot 0x7d  byte 0x1f4  0x004df4b0  inherited ApplyJoinEmpireMode1TargetTransition
//   slot 0x7e  byte 0x1f8  0x005419a0  override  ApplyJoinEmpireMode2FinalizeNationNameState
//   slot 0x7f  byte 0x1fc  0x005419c0  override  IsDiplomacyTargetClassCode200Match
//   slot 0x80  byte 0x200  0x004df5c0  inherited RemoveRegionIdFromNationOwnedRegionList
//   slot 0x81  byte 0x204  0x005419e0  override  AddRegionIdToNationOwnedRegionList
//   slot 0x82  byte 0x208  0x004e2880  inherited SetNationPercentFieldByModeAndDescriptorLinks
//   slot 0x83  byte 0x20c  0x004e0400  inherited OrphanRetStub_004d7e90
//   slot 0x84  byte 0x210  0x00541a00  override  OrphanLeaf_NoCall_Ins02_004d7ee0
//   slot 0x85  byte 0x214  0x004e0440  inherited OrphanLeaf_NoCall_Ins02_004d7f00
//   slot 0x86  byte 0x218  0x004e0500  inherited OrphanLeaf_NoCall_Ins02_004d7f20
//   slot 0x87  byte 0x21c  0x004e0550  inherited OrphanLeaf_NoCall_Ins02_004d7f40
//   slot 0x88  byte 0x220  0x004e0590  inherited OrphanRetStub_004d7fa0
//   slot 0x89  byte 0x224  0x004e05d0  inherited OrphanLeaf_NoCall_Ins02_004d7fc0
//   slot 0x8a  byte 0x228  0x004e0610  inherited ReturnFalseNationStateActionStub
//   slot 0x8b  byte 0x22c  0x004e0650  inherited OrphanRetStub_004d7fe0
//   slot 0x8c  byte 0x230  0x004e0690  inherited ReturnFalseNationStateCapabilityFlag90
//   slot 0x8d  byte 0x234  0x004e0740  inherited OrphanRetStub_004d7f80
//   slot 0x8e  byte 0x238  0x004e07b0  inherited ReturnFalseNationStateCapabilityFlag98
//   slot 0x8f  byte 0x23c  0x004e0890  inherited ReturnFalseNationStateCapabilityFlag9C
//   slot 0x90  byte 0x240  0x004e09a0  inherited ReturnFalseNationStateCapabilityFlagA0
//   slot 0x91  byte 0x244  0x004e0b20  inherited AddAmountToAidAllocationMatrixCellAndTotal
//   slot 0x92  byte 0x248  0x004e0c10  inherited SumAidAllocationMatrixColumnForTarget
//   slot 0x93  byte 0x24c  0x004e0d80  inherited PromoteNationPendingActionSlot5IfCapabilityActive
//   slot 0x94  byte 0x250  0x004e0e70  inherited AdvanceNationPendingActionStateMachine
//   slot 0x95  byte 0x254  0x004e0fe0  inherited DispatchNationPendingActionEventCodes
//   slot 0x96  byte 0x258  0x004e1170  inherited SetNationPendingActionStateAndPayload
//   slot 0x97  byte 0x25c  0x004e1300  inherited QueueNationOrderManagerPayloadObject
//   slot 0x98  byte 0x260  0x004e1490  inherited ClearQueuedNationOrdersAndResetOrderManager
//   slot 0x99  byte 0x264  0x004e1620  inherited OrphanCallChain_C1_I42_004dd7f0
//   slot 0x9a  byte 0x268  0x004e1750  inherited ExecuteNationPendingActionStateMachine
//   slot 0x9b  byte 0x26c  0x004e1910  inherited HasQueuedCivWorkOrderType7
//   slot 0x9c  byte 0x270  0x004e1a40  inherited GetTCountryClassNamePointer
//   slot 0x9d  byte 0x274  0x004e1c00  inherited VTableSlot9D
//   slot 0x9e  byte 0x278  0x004e1c20  inherited DispatchNationStateEventCode10
//   slot 0x9f  byte 0x27c  0x004e1d50  inherited OrphanRetStub_0059add0
//   slot 0xa0  byte 0x280  0x004e1e40  inherited GetTEventHandlerClassNamePointer
//   slot 0xa1  byte 0x284  0x004e27f0  inherited HandleCityDialogHintClusterUpdate
//   slot 0xa2  byte 0x288  0x004e1f20  inherited DeserializeRecruitScenarioAndInstantiateOrders
//   slot 0xa3  byte 0x28c  0x004e1f40  inherited ApplyJoinEmpireModeForTargetNation
//   slot 0xa4  byte 0x290  0x004e2190  inherited GetTEventHandlerClassNamePointer
//   slot 0xa5  byte 0x294  0x004de810  inherited VTableSlotA5
//   slot 0xa6  byte 0x298  0x004e2500  inherited OrphanLeaf_NoCall_Ins06_004d87b0
//   slot 0xa7  byte 0x29c  0x004e25c0  inherited SelectCandidateTilesWithLowGroundUnitCount
//   slot 0xa8  byte 0x2a0  0x00541a20  override  OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0xa9  byte 0x2a4  0x004e2720  inherited ApplyJoinEmpireModeForTargetNation
//   slot 0xaa  byte 0x2a8  0x004e27b0  inherited SetNationTransferTargetCodeAndNotifyEligiblePeers
//   slot 0xab  byte 0x2ac  0x00541be0  override  ApplyJoinEmpireMode1TargetTransition
//   slot 0xac  byte 0x2b0  0x004e06d0  inherited OrphanLeaf_NoCall_Ins06_004d87b0
//   slot 0xad  byte 0x2b4  0x00541a40  override  SelectCandidateTilesWithLowGroundUnitCount
//   slot 0xae  byte 0x2b8  0x00541a60  override  OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0xaf  byte 0x2bc  0x00541860  override  ApplyJoinEmpireModeForTargetNation
//   slot 0xb0  byte 0x2c0  0x004e2b00  inherited SetNationTransferTargetCodeAndNotifyEligiblePeers
//   slot 0xb1  byte 0x2c4  0x004e2b70  inherited ApplyJoinEmpireMode1TargetTransition
//   slot 0xb2  byte 0x2c8  0x005418e0  new       OrphanRetStub_005418e0
// object size 0x964 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TRemoteGreatPower) ===
