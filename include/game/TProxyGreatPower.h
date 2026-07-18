#pragma once

#include "game/TGreatPower.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0065b078
class TProxyGreatPower : public TGreatPower {
public:
  DECLARE_DYNCREATE(TProxyGreatPower)
  virtual ~TProxyGreatPower() override; // slot 0x01 (scalar deleting destructor)
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
  void ResetDiplomacyLevelForNationSlot12(NationSlot nationSlot,
                                          int resetLevel) override; // slot 0x12 0x540c20
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
  char TryDispatchNationActionViaUiContextOrFallback(int arg1, int arg2, int arg3,
                                                     int arg4) override; // slot 0x22 0x540ba0
  void
  QueueDiplomacyProposalCodeForTargetNation(short proposalCode,
                                            short targetNationId) override; // slot 0x23 0x540ac0
  // slot 0x24 ReturnFalseNationStateCapabilityFlag90 inherited unchanged (0x4d7f60)
  // slot 0x25 OrphanRetStub_004d7f80 inherited unchanged (0x4dedf0)
  virtual char ReturnFalseNationStateCapabilityFlag98() override; // slot 0x26 0x5408c0
  // slot 0x27 ReturnFalseNationStateCapabilityFlag9C inherited unchanged (0x4d6750)
  char ShouldDispatchImmediatelySlot28(void) override; // slot 0x28 0x5408e0
  // slot 0x29 NoOpNationSelectedRegionAndMapCellLabelHook inherited unchanged (0x4d6790)
  // slot 0x2a NoOpNationPendingActionHook inherited unchanged (0x4da5c0)
  // slot 0x2b PromoteNationPendingActionSlot5IfCapabilityActive inherited unchanged (0x4da860)
  // slot 0x2c AdvanceNationPendingActionStateMachine inherited unchanged (0x4da8a0)
  // slot 0x2d DispatchNationPendingActionEventCodes inherited unchanged (0x4da5e0)
  // slot 0x2e SetNationPendingActionStateAndPayload inherited unchanged (0x4daa10)
  void AddNodeToMissionNodeQueue(void* node) override; // slot 0x2f 0x540c70
  // slot 0x30 ClearQueuedNationOrdersAndResetOrderManager_30 inherited unchanged (0x4daa80)
  // slot 0x31 NoOpNationQueuedOrderHook inherited unchanged (0x4dab00)
  // slot 0x32 ExecuteNationPendingActionStateMachine inherited unchanged (0x4dab20)
  // slot 0x33 HasQueuedCivWorkOrderType7 inherited unchanged (0x4dae70)
  // slot 0x34 UpdateOrderEntryAvailabilityByConnectedRegionMask inherited unchanged (0x4db7d0)
  // slot 0x35 MarkConnectedOwnedRegionsInMaskRecursive inherited unchanged (0x4dbac0)
  virtual void
  RefreshGreatPowerRelationPanelsAndDispatchDeltaSummary() override; // slot 0x36 0x540b80
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
  // slot 0x4d RebuildNationResourceYieldCountersAndDevelopmentTargets inherited unchanged
  // (0x4dbd20) slot 0x4e AdvanceOwnedRegionDevelopmentCountersAndDispatchEvents inherited unchanged
  // (0x4dbf00) slot 0x4f OrphanRetStub_004d7e90 inherited unchanged (0x4dc3f0) slot 0x50
  // OrphanLeaf_NoCall_Ins02_004d7ee0 inherited unchanged (0x4dc440) slot 0x51
  // OrphanLeaf_NoCall_Ins02_004d7f00 inherited unchanged (0x4dc4c0) slot 0x52
  // CompareMissionScoreVariantsByMode inherited unchanged (0x4dc540) slot 0x53
  // BuildGreatPowerMapContextTriggeredNationEventMessages inherited unchanged (0x4dc660) slot 0x54
  // BuildGreatPowerEligibleNationEventMessagesFromLinkedList inherited unchanged (0x4dc840) slot
  // 0x55 OrphanLeaf_NoCall_Ins02_004d7fc0 inherited unchanged (0x4e0290) slot 0x56
  // ReturnFalseNationStateActionStub_56 inherited unchanged (0x4e03a0) slot 0x57
  // OrphanRetStub_004d7fe0 inherited unchanged (0x4e03d0) slot 0x58
  // SetDiplomacyColonyBoycottFlagForTargetAndRefreshMinorNations inherited unchanged (0x4dd0c0)
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
  // slot 0x73 ResetDiplomacyPolicyAndGrantEntriesPreserveRecurringGrants inherited unchanged
  // (0x4de2d0) slot 0x74 ApplyDiplomacyPolicyStateForTargetWithCostChecks inherited unchanged
  // (0x4ddfc0) slot 0x75 SetDiplomacyGrantEntryForTargetAndUpdateTreasury inherited unchanged
  // (0x4de340) slot 0x76 RevokeDiplomacyGrantForTargetAndAdjustInfluenceSlot1d8 inherited unchanged
  // (0x4de5e0) slot 0x77 CanAffordDiplomacyGrantEntryForTarget inherited unchanged (0x4de700) slot
  // 0x78 OrphanLeaf_NoCall_Ins06_004d87b0 inherited unchanged (0x4de7e0) slot 0x79
  // SelectCandidateTilesWithLowGroundUnitCount_79 inherited unchanged (0x4deca0) slot 0x7a
  // CanAffordAdditionalDiplomacyCostAfterCommitments inherited unchanged (0x4de790) slot 0x7b
  // ApplyAcceptedDiplomacyProposalCode inherited unchanged (0x4df010) slot 0x7c
  // QueueInterNationEventForProposalCode12D_130 inherited unchanged (0x4df370) slot 0x7d
  // ApplyJoinEmpireMode1TargetTransition inherited unchanged (0x4df4b0) slot 0x7e
  // ResetNationDiplomacyProposalQueue inherited unchanged (0x4df580) slot 0x7f
  // IsDiplomacyTargetClassCode200Match inherited unchanged (0x4df5a0)
  virtual void DispatchTurnEvent2103WithNationFromRecord() override; // slot 0x80 0x540aa0
  virtual void ProcessPendingDiplomacyProposalQueue() override;      // slot 0x81 0x540900
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
  // slot 0x8f IterateLinkedListCursorAndAccumulateRoundedMetric_004e0890 inherited unchanged
  // (0x4e0890) slot 0x90 ComputeCityOrderCapabilityAggregateScore inherited unchanged (0x4e09a0)
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
  int CheckTransitionSlot27C(int targetNation, int sourceNation) override; // slot 0x9f 0x540cf0
  int PropagateWarTransitionSlot280(int targetNation, int sourceNation,
                                    int mode) override; // slot 0xa0 0x540dc0
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
  virtual char
  UpdateGreatPowerPressureStateAndDispatchEscalationMessage() override; // slot 0xaf 0x540920
  // slot 0xb0 SetNationTransferTargetCodeAndNotifyEligiblePeers_b0 inherited unchanged (0x4e2b00)
  // slot 0xb1 BuildGreatPowerTurnMessageSummaryAndDispatch inherited unchanged (0x4e2b70)

  TProxyGreatPower();
};
