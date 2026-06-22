#pragma once

#include "game/TGreatPower.h"
#include "game/mfc.h"

// TODO(manifest): describe TProxyGreatPower and its role. Base edge (TGreatPower) recovered from RTTI CRuntimeClass chain: TProxyGreatPower -> TGreatPower -> TCountry -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0065b078
class TProxyGreatPower : public TGreatPower {
public:
// === BEGIN GENERATED DECLS (TProxyGreatPower) — refreshed by recover-class; do not hand-edit ===
  virtual CRuntimeClass* GetRuntimeClass() const override; // slot 0x00 0x5409e0
  virtual ~TProxyGreatPower(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x4d9c70)
  // slot 0x06 ReadFrom inherited unchanged (0x4d92e0)
  // slot 0x07 Free inherited unchanged (0x4d9160)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a OrphanLeaf_NoCall_Ins06_004d87b0 inherited unchanged (0x4da500)
  // slot 0x0b SelectCandidateTilesWithLowGroundUnitCount_0b inherited unchanged (0x4da3e0)
  // slot 0x0c SeedRecruitAndNavyOrdersForEligibleCoastalCities inherited unchanged (0x4d71b0)
  // slot 0x0d CreateAndDispatchMilitaryRecruitOrderForNationSlot inherited unchanged (0x4d7770)
  virtual void AddToNationMetricAtField10(int amount) override; // slot 0x0e 0x540a00
  // slot 0x0f PopulateSelectableEntryFlavorTextAndOrdinals inherited unchanged (0x4d8000)
  // slot 0x10 OrphanLeaf_NoCall_Ins06_004d87b0 inherited unchanged (0x4d87b0)
  // slot 0x11 SelectCandidateTilesWithLowGroundUnitCount_11 inherited unchanged (0x4d87e0)
  virtual undefined OrphanLeaf_NoCall_Ins07_004d8920(); // slot 0x12 0x540c20
  // slot 0x13 ApplyJoinEmpireModeForTargetNation inherited unchanged (0x4e21b0)
  // slot 0x14 SetNationTransferTargetCodeAndNotifyEligiblePeers inherited unchanged (0x4de860)
  // slot 0x15 ApplyJoinEmpireMode1TargetTransition inherited unchanged (0x4d7c90)
  // slot 0x16 ApplyJoinEmpireMode2FinalizeNationNameState inherited unchanged (0x4d7d50)
  // slot 0x17 IsDiplomacyTargetClassCode200Match inherited unchanged (0x4d7d20)
  // slot 0x18 RemoveRegionIdFromNationOwnedRegionList inherited unchanged (0x4e2270)
  // slot 0x19 AddRegionIdToNationOwnedRegionList inherited unchanged (0x4e22b0)
  // slot 0x1a SetNationPercentFieldByModeAndDescriptorLinks inherited unchanged (0x4e2330)
  // slot 0x1b OrphanRetStub_004d7e90 inherited unchanged (0x4dda20)
  // slot 0x1c OrphanLeaf_NoCall_Ins02_004d7ee0 inherited unchanged (0x4dda60)
  // slot 0x1d OrphanLeaf_NoCall_Ins02_004d7f00 inherited unchanged (0x4d8c00)
  // slot 0x1e OrphanLeaf_NoCall_Ins02_004d7f20 inherited unchanged (0x4dd740)
  // slot 0x1f OrphanLeaf_NoCall_Ins02_004d7f40 inherited unchanged (0x4ddb20)
  // slot 0x20 OrphanRetStub_004d7fa0 inherited unchanged (0x4ddc30)
  // slot 0x21 OrphanLeaf_NoCall_Ins02_004d7fc0 inherited unchanged (0x4ddd50)
  virtual undefined ReturnFalseNationStateActionStub(); // slot 0x22 0x540ba0
  // slot 0x23 OrphanRetStub_004d7fe0 inherited unchanged (0x540ac0)
  // slot 0x24 ReturnFalseNationStateCapabilityFlag90 inherited unchanged (0x4d7f60)
  // slot 0x25 OrphanRetStub_004d7f80 inherited unchanged (0x4dedf0)
  virtual char ReturnFalseNationStateCapabilityFlag98() override; // slot 0x26 0x5408c0
  // slot 0x27 ReturnFalseNationStateCapabilityFlag9C inherited unchanged (0x4d6750)
  virtual undefined ReturnFalseNationStateCapabilityFlagA0(); // slot 0x28 0x5408e0
  // slot 0x29 NoOpNationSelectedRegionAndMapCellLabelHook inherited unchanged (0x4d6790)
  // slot 0x2a NoOpNationPendingActionHook inherited unchanged (0x4da5c0)
  // slot 0x2b PromoteNationPendingActionSlot5IfCapabilityActive inherited unchanged (0x4da860)
  // slot 0x2c AdvanceNationPendingActionStateMachine inherited unchanged (0x4da8a0)
  // slot 0x2d DispatchNationPendingActionEventCodes inherited unchanged (0x4da5e0)
  // slot 0x2e SetNationPendingActionStateAndPayload inherited unchanged (0x4daa10)
  virtual undefined QueueNationOrderManagerPayloadObject_2f(); // slot 0x2f 0x540c70
  // slot 0x30 ClearQueuedNationOrdersAndResetOrderManager_30 inherited unchanged (0x4daa80)
  // slot 0x31 NoOpNationQueuedOrderHook inherited unchanged (0x4dab00)
  // slot 0x32 ExecuteNationPendingActionStateMachine inherited unchanged (0x4dab20)
  // slot 0x33 HasQueuedCivWorkOrderType7 inherited unchanged (0x4dae70)
  // slot 0x34 UpdateOrderEntryAvailabilityByConnectedRegionMask inherited unchanged (0x4db7d0)
  // slot 0x35 MarkConnectedOwnedRegionsInMaskRecursive inherited unchanged (0x4dbac0)
  virtual void RefreshGreatPowerRelationPanelsAndDispatchDeltaSummary() override; // slot 0x36 0x540b80
  // slot 0x37 OrphanRetStub_0059add0 inherited unchanged (0x4dca60)
  // slot 0x38 GetTEventHandlerClassNamePointer_38 inherited unchanged (0x4dcc30)
  // slot 0x39 RebuildPrimaryNationStateForSlot_Impl inherited unchanged (0x4df810)
  // slot 0x3a DeserializeRecruitScenarioAndInstantiateOrders_3a inherited unchanged (0x4dfa20)
  // slot 0x3b CreateAndQueueFrogCityMarkerForNationTile inherited unchanged (0x4dfae0)
  // slot 0x3c DispatchGreatPowerQuarterlyStatusMessageLevel2 inherited unchanged (0x4e00d0)
  // slot 0x3d DispatchGreatPowerQuarterlyStatusMessageLevel1 inherited unchanged (0x4e0140)
  // slot 0x3e DispatchGreatPowerQuarterlyStatusMessageLevel0 inherited unchanged (0x4e01b0)
  // slot 0x3f SelectCandidateTilesWithLowGroundUnitCount_3f inherited unchanged (0x4dca80)
  // slot 0x40 OrphanLeaf_NoCall_Ins07_004d8920 inherited unchanged (0x4dcaa0)
  // slot 0x41 ApplyJoinEmpireModeForTargetNation_41 inherited unchanged (0x4dcc50)
  // slot 0x42 SetNationTransferTargetCodeAndNotifyEligiblePeers_42 inherited unchanged (0x4dcca0)
  // slot 0x43 ApplyNationResourceNeedTargetsToOrderState inherited unchanged (0x4dcd10)
  // slot 0x44 SetNationResourceNeedCurrentByType inherited unchanged (0x4dce10)
  // slot 0x45 SelectCandidateTilesWithLowGroundUnitCount_45 inherited unchanged (0x4dcdd0)
  // slot 0x46 IsNationResourceNeedCurrentAtTargetByType inherited unchanged (0x4dce40)
  // slot 0x47 GetNationResourceNeedTargetByType inherited unchanged (0x4dce70)
  // slot 0x48 TryIncrementNationResourceNeedTargetTowardCurrent inherited unchanged (0x4dce90)
  // slot 0x49 IsNationResourceNeedCurrentSumExceedingCapA6 inherited unchanged (0x4dcf10)
  // slot 0x4a ApplyJoinEmpireMode2FinalizeNationNameState inherited unchanged (0x4dcf60)
  // slot 0x4b IsDiplomacyTargetClassCode200Match_4b inherited unchanged (0x4dcfd0)
  // slot 0x4c IterateLinkedListCursorEntries_004e0220 inherited unchanged (0x4e0220)
  // slot 0x4d RebuildNationResourceYieldCountersAndDevelopmentTargets inherited unchanged (0x4dbd20)
  // slot 0x4e AdvanceOwnedRegionDevelopmentCountersAndDispatchEvents inherited unchanged (0x4dbf00)
  // slot 0x4f OrphanRetStub_004d7e90 inherited unchanged (0x4dc3f0)
  // slot 0x50 OrphanLeaf_NoCall_Ins02_004d7ee0 inherited unchanged (0x4dc440)
  // slot 0x51 OrphanLeaf_NoCall_Ins02_004d7f00 inherited unchanged (0x4dc4c0)
  // slot 0x52 CompareMissionScoreVariantsByMode inherited unchanged (0x4dc540)
  // slot 0x53 BuildGreatPowerMapContextTriggeredNationEventMessages inherited unchanged (0x4dc660)
  // slot 0x54 BuildGreatPowerEligibleNationEventMessagesFromLinkedList inherited unchanged (0x4dc840)
  // slot 0x55 OrphanLeaf_NoCall_Ins02_004d7fc0 inherited unchanged (0x4e0290)
  // slot 0x56 ReturnFalseNationStateActionStub_56 inherited unchanged (0x4e03a0)
  // slot 0x57 OrphanRetStub_004d7fe0 inherited unchanged (0x4e03d0)
  // slot 0x58 SetDiplomacyColonyBoycottFlagForTargetAndRefreshMinorNations inherited unchanged (0x4dd0c0)
  // slot 0x59 RecomputeDiplomacyAidBudgetScoreFromResourceWeights inherited unchanged (0x4dd140)
  // slot 0x5a ResetDiplomacyNeedScoresAndClearAidAllocationMatrix inherited unchanged (0x4dd1b0)
  // slot 0x5b RefreshDiplomacyNeedScoresAndClearAidAllocationMatrix inherited unchanged (0x4dd270)
  // slot 0x5c ReleaseDiplomacyTrackedObjectSlots850 inherited unchanged (0x4dd310)
  // slot 0x5d AddAmountToAidAllocationMatrixCellAndTotal_5d inherited unchanged (0x4dd340)
  // slot 0x5e SumAidAllocationMatrixColumnForTarget inherited unchanged (0x4dd3b0)
  // slot 0x5f SumAidAllocationMatrixAllCells inherited unchanged (0x4dd3f0)
  // slot 0x60 ComputeRemainingDiplomacyAidBudget inherited unchanged (0x4dd430)
  // slot 0x61 ResetDiplomacyNeedSlots7012AndRefreshIfModeGateMatches inherited unchanged (0x4dd470)
  // slot 0x62 AssignFallbackNationsToUnfilledDiplomacyNeedSlots inherited unchanged (0x4dd4e0)
  // slot 0x63 QueueNationOrderManagerPayloadObject_63 inherited unchanged (0x4dd770)
  // slot 0x64 ClearQueuedNationOrdersAndResetOrderManager_64 inherited unchanged (0x4dd7b0)
  // slot 0x65 OrphanCallChain_C1_I42_004dd7f0 inherited unchanged (0x4dd7f0)
  // slot 0x66 ExecuteNationPendingActionStateMachine_66 inherited unchanged (0x4dda40)
  // slot 0x67 AssignNeedSlotFromSourceSlot19C inherited unchanged (0x4dda90)
  // slot 0x68 GetTCountryClassNamePointer inherited unchanged (0x4ddad0)
  // slot 0x69 VTableSlot69 inherited unchanged (0x4ddb40)
  // slot 0x6a DispatchNationStateEventCode10 inherited unchanged (0x4ddb80)
  // slot 0x6b ClearDiplomacyState1c6ForTarget inherited unchanged (0x4ddd20)
  // slot 0x6c GetTEventHandlerClassNamePointer_6c inherited unchanged (0x4ddd90)
  // slot 0x6d HandleCityDialogHintClusterUpdate inherited unchanged (0x4dde80)
  // slot 0x6e DeserializeRecruitScenarioAndInstantiateOrders_6e inherited unchanged (0x4dde30)
  // slot 0x6f ApplyJoinEmpireModeForTargetNation_6f inherited unchanged (0x4ddeb0)
  // slot 0x70 GetTEventHandlerClassNamePointer_70 inherited unchanged (0x4ddf20)
  // slot 0x71 ClearFieldBlock1c6 inherited unchanged (0x4ddf90)
  // slot 0x72 BeginTurnDiplomacyPrePassSlot1c8 inherited unchanged (0x4de2b0)
  // slot 0x73 ResetDiplomacyPolicyAndGrantEntriesPreserveRecurringGrants inherited unchanged (0x4de2d0)
  // slot 0x74 ApplyDiplomacyPolicyStateForTargetWithCostChecks inherited unchanged (0x4ddfc0)
  // slot 0x75 SetDiplomacyGrantEntryForTargetAndUpdateTreasury inherited unchanged (0x4de340)
  // slot 0x76 RevokeDiplomacyGrantForTargetAndAdjustInfluenceSlot1d8 inherited unchanged (0x4de5e0)
  // slot 0x77 CanAffordDiplomacyGrantEntryForTarget inherited unchanged (0x4de700)
  // slot 0x78 OrphanLeaf_NoCall_Ins06_004d87b0 inherited unchanged (0x4de7e0)
  // slot 0x79 SelectCandidateTilesWithLowGroundUnitCount_79 inherited unchanged (0x4deca0)
  // slot 0x7a CanAffordAdditionalDiplomacyCostAfterCommitments inherited unchanged (0x4de790)
  // slot 0x7b ApplyAcceptedDiplomacyProposalCode inherited unchanged (0x4df010)
  // slot 0x7c QueueInterNationEventForProposalCode12D_130 inherited unchanged (0x4df370)
  // slot 0x7d ApplyJoinEmpireMode1TargetTransition inherited unchanged (0x4df4b0)
  // slot 0x7e ResetNationDiplomacyProposalQueue inherited unchanged (0x4df580)
  // slot 0x7f IsDiplomacyTargetClassCode200Match inherited unchanged (0x4df5a0)
  virtual void DispatchTurnEvent2103WithNationFromRecord() override; // slot 0x80 0x540aa0
  virtual void ProcessPendingDiplomacyProposalQueue() override; // slot 0x81 0x540900
  // slot 0x82 ClassifyNationProductionTotalAgainstGlobalDistribution inherited unchanged (0x4e2880)
  // slot 0x83 HasActiveCandidateNationSlots inherited unchanged (0x4e0400)
  // slot 0x84 OrphanLeaf_NoCall_Ins02_004d7ee0 inherited unchanged (0x4e0420)
  // slot 0x85 OrphanLeaf_NoCall_Ins02_004d7f00 inherited unchanged (0x4e0440)
  // slot 0x86 ComputeNavyOrderIndustryCostWeightSumForNation inherited unchanged (0x4e0500)
  // slot 0x87 OrphanLeaf_NoCall_Ins02_004d7f40 inherited unchanged (0x4e0550)
  // slot 0x88 OrphanRetStub_004d7fa0 inherited unchanged (0x4e0590)
  // slot 0x89 OrphanLeaf_NoCall_Ins02_004d7fc0 inherited unchanged (0x4e05d0)
  // slot 0x8a ReturnFalseNationStateActionStub_8a inherited unchanged (0x4e0610)
  // slot 0x8b OrphanRetStub_004d7fe0 inherited unchanged (0x4e0650)
  // slot 0x8c ReturnFalseNationStateCapabilityFlag90 inherited unchanged (0x4e0690)
  // slot 0x8d GetNationRuntimeCityBuildingProductionValueBySlot inherited unchanged (0x4e0740)
  // slot 0x8e IterateLinkedListCursorEntries_004e07b0 inherited unchanged (0x4e07b0)
  // slot 0x8f IterateLinkedListCursorAndAccumulateRoundedMetric_004e0890 inherited unchanged (0x4e0890)
  // slot 0x90 ComputeCityOrderCapabilityAggregateScore inherited unchanged (0x4e09a0)
  // slot 0x91 AddAmountToAidAllocationMatrixCellAndTotal_91 inherited unchanged (0x4e0b20)
  // slot 0x92 ComputeAdvisoryHandlerCase00Metric inherited unchanged (0x4e0c10)
  // slot 0x93 ComputeAdvisoryHandlerCase01Metric inherited unchanged (0x4e0d80)
  // slot 0x94 ComputeAdvisoryHandlerCase02Metric inherited unchanged (0x4e0e70)
  // slot 0x95 ComputeAdvisoryMetric23CNormalizedBySelectionAndPeers inherited unchanged (0x4e0fe0)
  // slot 0x96 ComputeAdvisoryMatrixRatio23CByTargetSlot inherited unchanged (0x4e1170)
  // slot 0x97 ComputeAdvisoryMetric240NormalizedBySelectionAndPeers inherited unchanged (0x4e1300)
  // slot 0x98 ComputeAdvisoryMatrixRatio240ByTargetSlot inherited unchanged (0x4e1490)
  // slot 0x99 ComputeAdvisoryHandlerCase07Metric inherited unchanged (0x4e1620)
  // slot 0x9a ComputeArmyScoreStandingRatioForNationPair inherited unchanged (0x4e1750)
  // slot 0x9b ComputeAdvisoryHandlerCase09Metric inherited unchanged (0x4e1910)
  // slot 0x9c ComputeNavyScoreStandingRatioForNationPair inherited unchanged (0x4e1a40)
  // slot 0x9d VTableSlot9D inherited unchanged (0x4e1c00)
  // slot 0x9e EvaluateJoinWarAgainstNationAndQueueEvent inherited unchanged (0x4e1c20)
  virtual undefined ExecuteAdvisoryPromptAndApplyActionType1(); // slot 0x9f 0x540cf0
  virtual undefined ExecuteAdvisoryPromptAndApplyActionType2OrFallback(); // slot 0xa0 0x540dc0
  // slot 0xa1 QueueWarTransitionAndNotifyThirdPartyIfNeeded inherited unchanged (0x4e27f0)
  // slot 0xa2 DeserializeRecruitScenarioAndInstantiateOrders_a2 inherited unchanged (0x4e1f20)
  // slot 0xa3 ComputeWarThresholdSlotA3 inherited unchanged (0x4e1f40)
  // slot 0xa4 GetTEventHandlerClassNamePointer_a4 inherited unchanged (0x4e2190)
  // slot 0xa5 ReleaseAllTrackedObjectsFromList89C inherited unchanged (0x4de810)
  // slot 0xa6 NotifyRegionEventSlot298 inherited unchanged (0x4e2500)
  // slot 0xa7 ResetNationDiplomacySlotsAndMarkRelatedNations inherited unchanged (0x4e25c0)
  // slot 0xa8 ApplyMinorNationCapabilityActionType6 inherited unchanged (0x4e2630)
  // slot 0xa9 ApplyMinorNationCapabilityActionType4 inherited unchanged (0x4e2720)
  // slot 0xaa DispatchNationDiplomacySlotActionByMode inherited unchanged (0x4e27b0)
  virtual void DispatchTurnEvent11F8NoPayloadSlot2AC() override; // slot 0xab 0x540cb0
  // slot 0xac SumNationRuntimeFiveBucketValue44 inherited unchanged (0x4e06d0)
  // slot 0xad SelectCandidateTilesWithLowGroundUnitCount_ad inherited unchanged (0x4d8bc0)
  // slot 0xae OrphanLeaf_NoCall_Ins07_004d8920 inherited unchanged (0x4d8be0)
  virtual void UpdateGreatPowerPressureStateAndDispatchEscalationMessage() override; // slot 0xaf 0x540920
  // slot 0xb0 SetNationTransferTargetCodeAndNotifyEligiblePeers_b0 inherited unchanged (0x4e2b00)
  // slot 0xb1 BuildGreatPowerTurnMessageSummaryAndDispatch inherited unchanged (0x4e2b70)
// === END GENERATED DECLS (TProxyGreatPower) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TProxyGreatPower 0xCTOR`).

  TProxyGreatPower();
};

// === BEGIN GENERATED (TProxyGreatPower) — refreshed by `just gen-class TProxyGreatPower`; do not hand-edit ===
// clang-format off
// vtable @ 0x0065b078 (178 slots), object size 0x964, base TGreatPower
//   slot 0x00  byte 0x00  0x005409e0  override  GetTCountryClassNamePointer
//   slot 0x01  byte 0x04  0x00540940  override  VTableSlot01
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
//   slot 0x0e  byte 0x38  0x00540a00  override  SetNationTransferTargetCodeAndNotifyEligiblePeers
//   slot 0x0f  byte 0x3c  0x004d8000  inherited ApplyJoinEmpireMode1TargetTransition
//   slot 0x10  byte 0x40  0x004d87b0  inherited OrphanLeaf_NoCall_Ins06_004d87b0
//   slot 0x11  byte 0x44  0x004d87e0  inherited SelectCandidateTilesWithLowGroundUnitCount
//   slot 0x12  byte 0x48  0x00540c20  override  OrphanLeaf_NoCall_Ins07_004d8920
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
//   slot 0x22  byte 0x88  0x00540ba0  override  ReturnFalseNationStateActionStub
//   slot 0x23  byte 0x8c  0x00540ac0  override  OrphanRetStub_004d7fe0
//   slot 0x24  byte 0x90  0x004d7f60  inherited ReturnFalseNationStateCapabilityFlag90
//   slot 0x25  byte 0x94  0x004dedf0  inherited OrphanRetStub_004d7f80
//   slot 0x26  byte 0x98  0x005408c0  override  ReturnFalseNationStateCapabilityFlag98
//   slot 0x27  byte 0x9c  0x004d6750  inherited ReturnFalseNationStateCapabilityFlag9C
//   slot 0x28  byte 0xa0  0x005408e0  override  ReturnFalseNationStateCapabilityFlagA0
//   slot 0x29  byte 0xa4  0x004d6790  inherited NoOpNationSelectedRegionAndMapCellLabelHook
//   slot 0x2a  byte 0xa8  0x004da5c0  inherited NoOpNationPendingActionHook
//   slot 0x2b  byte 0xac  0x004da860  inherited PromoteNationPendingActionSlot5IfCapabilityActive
//   slot 0x2c  byte 0xb0  0x004da8a0  inherited AdvanceNationPendingActionStateMachine
//   slot 0x2d  byte 0xb4  0x004da5e0  inherited DispatchNationPendingActionEventCodes
//   slot 0x2e  byte 0xb8  0x004daa10  inherited SetNationPendingActionStateAndPayload
//   slot 0x2f  byte 0xbc  0x00540c70  override  QueueNationOrderManagerPayloadObject
//   slot 0x30  byte 0xc0  0x004daa80  inherited ClearQueuedNationOrdersAndResetOrderManager
//   slot 0x31  byte 0xc4  0x004dab00  inherited NoOpNationQueuedOrderHook
//   slot 0x32  byte 0xc8  0x004dab20  inherited ExecuteNationPendingActionStateMachine
//   slot 0x33  byte 0xcc  0x004dae70  inherited HasQueuedCivWorkOrderType7
//   slot 0x34  byte 0xd0  0x004db7d0  inherited GetTCountryClassNamePointer
//   slot 0x35  byte 0xd4  0x004dbac0  inherited VTableSlot35
//   slot 0x36  byte 0xd8  0x00540b80  override  DispatchNationStateEventCode10
//   slot 0x37  byte 0xdc  0x004dca60  inherited OrphanRetStub_0059add0
//   slot 0x38  byte 0xe0  0x004dcc30  inherited GetTEventHandlerClassNamePointer
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
//   slot 0x55  byte 0x154  0x004e0290  inherited OrphanLeaf_NoCall_Ins02_004d7fc0
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
//   slot 0x6b  byte 0x1ac  0x004ddd20  inherited ClearDiplomacyState1c6ForTarget
//   slot 0x6c  byte 0x1b0  0x004ddd90  inherited GetTEventHandlerClassNamePointer
//   slot 0x6d  byte 0x1b4  0x004dde80  inherited HandleCityDialogHintClusterUpdate
//   slot 0x6e  byte 0x1b8  0x004dde30  inherited DeserializeRecruitScenarioAndInstantiateOrders
//   slot 0x6f  byte 0x1bc  0x004ddeb0  inherited ApplyJoinEmpireModeForTargetNation
//   slot 0x70  byte 0x1c0  0x004ddf20  inherited GetTEventHandlerClassNamePointer
//   slot 0x71  byte 0x1c4  0x004ddf90  inherited VTableSlot71
//   slot 0x72  byte 0x1c8  0x004de2b0  inherited OrphanLeaf_NoCall_Ins06_004d87b0
//   slot 0x73  byte 0x1cc  0x004de2d0  inherited SelectCandidateTilesWithLowGroundUnitCount
//   slot 0x74  byte 0x1d0  0x004ddfc0  inherited OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x75  byte 0x1d4  0x004de340  inherited ApplyJoinEmpireModeForTargetNation
//   slot 0x76  byte 0x1d8  0x004de5e0  inherited SetNationTransferTargetCodeAndNotifyEligiblePeers
//   slot 0x77  byte 0x1dc  0x004de700  inherited ApplyJoinEmpireMode1TargetTransition
//   slot 0x78  byte 0x1e0  0x004de7e0  inherited OrphanLeaf_NoCall_Ins06_004d87b0
//   slot 0x79  byte 0x1e4  0x004deca0  inherited SelectCandidateTilesWithLowGroundUnitCount
//   slot 0x7a  byte 0x1e8  0x004de790  inherited OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x7b  byte 0x1ec  0x004df010  inherited ApplyJoinEmpireModeForTargetNation
//   slot 0x7c  byte 0x1f0  0x004df370  inherited SetNationTransferTargetCodeAndNotifyEligiblePeers
//   slot 0x7d  byte 0x1f4  0x004df4b0  inherited ApplyJoinEmpireMode1TargetTransition
//   slot 0x7e  byte 0x1f8  0x004df580  inherited ApplyJoinEmpireMode2FinalizeNationNameState
//   slot 0x7f  byte 0x1fc  0x004df5a0  inherited IsDiplomacyTargetClassCode200Match
//   slot 0x80  byte 0x200  0x00540aa0  override  RemoveRegionIdFromNationOwnedRegionList
//   slot 0x81  byte 0x204  0x00540900  override  AddRegionIdToNationOwnedRegionList
//   slot 0x82  byte 0x208  0x004e2880  inherited SetNationPercentFieldByModeAndDescriptorLinks
//   slot 0x83  byte 0x20c  0x004e0400  inherited OrphanRetStub_004d7e90
//   slot 0x84  byte 0x210  0x004e0420  inherited OrphanLeaf_NoCall_Ins02_004d7ee0
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
//   slot 0x9f  byte 0x27c  0x00540cf0  override  OrphanRetStub_0059add0
//   slot 0xa0  byte 0x280  0x00540dc0  override  GetTEventHandlerClassNamePointer
//   slot 0xa1  byte 0x284  0x004e27f0  inherited HandleCityDialogHintClusterUpdate
//   slot 0xa2  byte 0x288  0x004e1f20  inherited DeserializeRecruitScenarioAndInstantiateOrders
//   slot 0xa3  byte 0x28c  0x004e1f40  inherited ApplyJoinEmpireModeForTargetNation
//   slot 0xa4  byte 0x290  0x004e2190  inherited GetTEventHandlerClassNamePointer
//   slot 0xa5  byte 0x294  0x004de810  inherited VTableSlotA5
//   slot 0xa6  byte 0x298  0x004e2500  inherited OrphanLeaf_NoCall_Ins06_004d87b0
//   slot 0xa7  byte 0x29c  0x004e25c0  inherited SelectCandidateTilesWithLowGroundUnitCount
//   slot 0xa8  byte 0x2a0  0x004e2630  inherited OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0xa9  byte 0x2a4  0x004e2720  inherited ApplyJoinEmpireModeForTargetNation
//   slot 0xaa  byte 0x2a8  0x004e27b0  inherited SetNationTransferTargetCodeAndNotifyEligiblePeers
//   slot 0xab  byte 0x2ac  0x00540cb0  override  ApplyJoinEmpireMode1TargetTransition
//   slot 0xac  byte 0x2b0  0x004e06d0  inherited OrphanLeaf_NoCall_Ins06_004d87b0
//   slot 0xad  byte 0x2b4  0x004d8bc0  inherited SelectCandidateTilesWithLowGroundUnitCount
//   slot 0xae  byte 0x2b8  0x004d8be0  inherited OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0xaf  byte 0x2bc  0x00540920  override  ApplyJoinEmpireModeForTargetNation
//   slot 0xb0  byte 0x2c0  0x004e2b00  inherited SetNationTransferTargetCodeAndNotifyEligiblePeers
//   slot 0xb1  byte 0x2c4  0x004e2b70  inherited ApplyJoinEmpireMode1TargetTransition
// object size 0x964 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TProxyGreatPower) ===
