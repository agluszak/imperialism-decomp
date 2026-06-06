#pragma once

#include "decomp_types.h"
#include "game/TListObject.h"

class TMinisterObject;
class TQueueObject;
class TRelationManagerObject;

#define TGREATPOWER_VTABLE_SLOT(n) virtual void VTableIndex##n##_Provisional(void) = 0

// VTABLE: IMPERIALISM 0x00653938
class TGreatPower {
public:
  TGREATPOWER_VTABLE_SLOT(00);
  virtual void DeleteSelfSlot01_Provisional(int freeFlag) = 0;
  TGREATPOWER_VTABLE_SLOT(02);
  TGREATPOWER_VTABLE_SLOT(03);
  TGREATPOWER_VTABLE_SLOT(04);
  TGREATPOWER_VTABLE_SLOT(05);
  TGREATPOWER_VTABLE_SLOT(06);
  virtual void TGreatPower_VtblSlot07(void);
  TGREATPOWER_VTABLE_SLOT(08);
  TGREATPOWER_VTABLE_SLOT(09);
  TGREATPOWER_VTABLE_SLOT(10);
  TGREATPOWER_VTABLE_SLOT(11);
  TGREATPOWER_VTABLE_SLOT(12);
  TGREATPOWER_VTABLE_SLOT(13);
  virtual void AddToNationMetricAtField10(int amount); // slot 0x0e
  TGREATPOWER_VTABLE_SLOT(15);
  virtual int GetNodeContextSlot10_Provisional(void) = 0;
  TGREATPOWER_VTABLE_SLOT(17);
  virtual void ResetDiplomacyLevelForNationSlot12_Provisional(int nationSlot, int resetLevel) = 0;
  // index 0x13 / vtable+0x04c. Evidence: 0x004df010 calls this on `this`
  // with (targetNationSlot, 1); return value ignored.
  virtual void VTableSlot13_Provisional(int targetNationSlot, int mode) = 0;
  TGREATPOWER_VTABLE_SLOT(20);
  TGREATPOWER_VTABLE_SLOT(21);
  TGREATPOWER_VTABLE_SLOT(22);
  TGREATPOWER_VTABLE_SLOT(23);
  TGREATPOWER_VTABLE_SLOT(24);
  TGREATPOWER_VTABLE_SLOT(25);
  TGREATPOWER_VTABLE_SLOT(26);
  TGREATPOWER_VTABLE_SLOT(27);
  virtual int SumDiplomacyState1c6AndRelationDeltaSnapshot(short nationSlot); // slot 0x1c
  virtual short GetDiplomacyCounterA2(void); // slot 0x1d
  // index 0x1e / vtable+0x078. Evidence: 0x004dd1b0 and 0x004dd270 call this
  // for each nation while recomputing diplomacy need baselines; returns AX.
  virtual short GetRelationManagerFieldB6(short nationSlot); // slot 0x1e
  virtual short GetDiplomacyState1C6ByTarget(short targetNationSlot); // slot 0x1f
  // index 0x20 / vtable+0x080. Evidence: base TGreatPower vtable entry
  // 0x00407392 thunks to body 0x004ddc30; TAutoGreatPower overrides this slot.
  virtual void ApplyIndexedResourceDeltaAndAdjustNationTotals(int resourceIndex, int delta,
                                                              int multiplier);
  virtual bool
  IsDiplomacyState1C6UnsetAndCounterPositiveForTarget(short targetNationSlot); // slot 0x21
  TGREATPOWER_VTABLE_SLOT(34);
  TGREATPOWER_VTABLE_SLOT(35);
  TGREATPOWER_VTABLE_SLOT(36);
  TGREATPOWER_VTABLE_SLOT(37);
  TGREATPOWER_VTABLE_SLOT(38);
  TGREATPOWER_VTABLE_SLOT(39);
  virtual char ShouldDispatchImmediatelySlot28_Provisional(void) = 0;
  TGREATPOWER_VTABLE_SLOT(41);
  TGREATPOWER_VTABLE_SLOT(42);
  TGREATPOWER_VTABLE_SLOT(43);
  TGREATPOWER_VTABLE_SLOT(44);
  TGREATPOWER_VTABLE_SLOT(45);
  virtual void SetNationPendingActionStateAndPayload(int index, short payload); // slot 0x2e
  TGREATPOWER_VTABLE_SLOT(47);
  TGREATPOWER_VTABLE_SLOT(48);
  TGREATPOWER_VTABLE_SLOT(49);
  TGREATPOWER_VTABLE_SLOT(50);
  TGREATPOWER_VTABLE_SLOT(51);
  TGREATPOWER_VTABLE_SLOT(52);
  TGREATPOWER_VTABLE_SLOT(53);
  TGREATPOWER_VTABLE_SLOT(54);
  TGREATPOWER_VTABLE_SLOT(55);
  TGREATPOWER_VTABLE_SLOT(56);
  TGREATPOWER_VTABLE_SLOT(57);
  TGREATPOWER_VTABLE_SLOT(58);
  TGREATPOWER_VTABLE_SLOT(59);
  TGREATPOWER_VTABLE_SLOT(60);
  TGREATPOWER_VTABLE_SLOT(61);
  TGREATPOWER_VTABLE_SLOT(62);
  TGREATPOWER_VTABLE_SLOT(63);
  TGREATPOWER_VTABLE_SLOT(64);
  virtual void ApplyDiplomacyState222ToRelationManagerAndClear(void);          // slot 0x41
  virtual void ApplyRelationDeltaToRelationManagerAndUpdateState1f4(void);      // slot 0x42
  TGREATPOWER_VTABLE_SLOT(67);
  TGREATPOWER_VTABLE_SLOT(68);
  virtual void UpdateNeedTargetAndAccumulateOverCap(short needIndex, short value); // slot 0x45
  virtual bool IsNeedTargetEqualCurrent(short needIndex); // slot 0x46
  virtual short GetNeedTargetByType(short needIndex); // slot 0x47
  TGREATPOWER_VTABLE_SLOT(72);
  TGREATPOWER_VTABLE_SLOT(73);
  virtual short TryDecayRelationNeedScores9AndB(void); // slot 0x4a
  virtual short TryDecayRelationNeedScores9And8(void); // slot 0x4b
  TGREATPOWER_VTABLE_SLOT(76);
  TGREATPOWER_VTABLE_SLOT(77);
  TGREATPOWER_VTABLE_SLOT(78);
  virtual char AnyNeedCurrentExceedsTargetWhenCapMismatch(void); // slot 0x4f
  TGREATPOWER_VTABLE_SLOT(80);
  TGREATPOWER_VTABLE_SLOT(81);
  TGREATPOWER_VTABLE_SLOT(82);
  TGREATPOWER_VTABLE_SLOT(83);
  TGREATPOWER_VTABLE_SLOT(84);
  TGREATPOWER_VTABLE_SLOT(85);
  TGREATPOWER_VTABLE_SLOT(86);
  TGREATPOWER_VTABLE_SLOT(87);
  TGREATPOWER_VTABLE_SLOT(88);
  // index 0x59 / vtable+0x164. Evidence: 0x004dd1b0 invokes this before
  // resetting diplomacy aid budget state; implementation at 0x004dd140.
  virtual void RecomputeDiplomacyAidBudgetScoreFromResourceWeights(void);
  TGREATPOWER_VTABLE_SLOT(90);
  TGREATPOWER_VTABLE_SLOT(91);
  virtual void ReleaseDiplomacyTrackedObjectSlots850(void); // slot 0x5c
  TGREATPOWER_VTABLE_SLOT(93);
  TGREATPOWER_VTABLE_SLOT(94);
  virtual int SumAidAllocationMatrixAllCells(void); // slot 0x5f
  TGREATPOWER_VTABLE_SLOT(96);
  TGREATPOWER_VTABLE_SLOT(97);
  TGREATPOWER_VTABLE_SLOT(98);
  virtual void SetRelationManagerFieldB6AndRefresh(short targetSlot, short value);   // slot 0x63
  virtual void AddToRelationManagerFieldB6AndRefresh(short targetSlot, short value); // slot 0x64
  TGREATPOWER_VTABLE_SLOT(101);
  virtual void DecrementDiplomacyCounterA2Slot66(int delta); // slot 0x66
  TGREATPOWER_VTABLE_SLOT(103);
  TGREATPOWER_VTABLE_SLOT(104);
  virtual void SetDiplomacyState1c6ClampedToCounterA4(short targetSlot, short value); // slot 0x69
  virtual void SnapshotDiplomacyState1c6Into250(void);                                // slot 0x6a
  TGREATPOWER_VTABLE_SLOT(107);
  virtual void DispatchFallbackActionSlot6C_Provisional(int arg0, int arg1, int arg2) = 0;
  virtual short GetTrackedSlotEntryCountLow(short targetSlot);    // slot 0x6d
  virtual char AnyTrackedSlotEntryHasZeroField4(short targetSlot); // slot 0x6e
  TGREATPOWER_VTABLE_SLOT(111);
  virtual void AssignPayloadToTrackedSlotEntryMatchingField2(int targetSlot, int matchKey,
                                                             int payload); // slot 0x70
  TGREATPOWER_VTABLE_SLOT(113);
  TGREATPOWER_VTABLE_SLOT(114);
  virtual void ResetDiplomacyPolicyAndGrantEntriesPreserveRecurringGrants(void);     // slot 0x73
  virtual void ApplyDiplomacyPolicyStateForTargetWithCostChecks(int arg1, int arg2); // slot 0x74
  virtual void SetDiplomacyGrantEntryForTargetAndUpdateTreasury(int arg1, int arg2); // slot 0x75
  TGREATPOWER_VTABLE_SLOT(118);
  virtual bool
  CanAffordDiplomacyGrantEntryForTarget(short targetNationId,
                                        unsigned short proposedGrantEntry); // slot 0x77
  TGREATPOWER_VTABLE_SLOT(120);
  virtual void DecrementNeedLevelByNationStep(short nationSlot); // slot 0x79
  virtual bool CanAffordAdditionalDiplomacyCostAfterCommitments(short additionalCost); // slot 0x7a
  virtual void ApplyAcceptedDiplomacyProposalCode(short proposalIndex);                // slot 0x7b
  virtual void
  QueueInterNationEventForProposalCode12D_130(unsigned short proposalQueueIndex); // slot 0x7c
  TGREATPOWER_VTABLE_SLOT(125);
  TGREATPOWER_VTABLE_SLOT(126);
  TGREATPOWER_VTABLE_SLOT(127);
  TGREATPOWER_VTABLE_SLOT(128);
  TGREATPOWER_VTABLE_SLOT(129);
  TGREATPOWER_VTABLE_SLOT(130);
  TGREATPOWER_VTABLE_SLOT(131);
  // index 0x84 / vtable+0x210. Evidence: 0x004e9ed0 calls this on `this`
  // with one target-nation argument; return value ignored.
  virtual void VTableSlot84_Provisional(int targetNation) = 0;
  virtual void CallSlot85_Provisional(int targetNation) = 0;
  TGREATPOWER_VTABLE_SLOT(134);
  virtual int CountMapActionContextNodesWithNationBit(void);       // slot 0x87
  virtual double ComputeMinisterSkillFloatSlot88(void);            // slot 0x88
  virtual double ComputeMinisterSkillFloatSlot89(void);            // slot 0x89
  virtual double ComputeMinisterSkillFloatSlot8A(void);            // slot 0x8a
  virtual double ComputeMinisterSkillFloatSlot8B(void);            // slot 0x8b
  virtual double ComputeMinisterSkillFloatSlot8C(void);            // slot 0x8c
  virtual int GetCityBuildingProductionViaRelationManagerSlot8D(short buildingSlot); // slot 0x8d
  TGREATPOWER_VTABLE_SLOT(142);
  TGREATPOWER_VTABLE_SLOT(143);
  TGREATPOWER_VTABLE_SLOT(144);
  TGREATPOWER_VTABLE_SLOT(145);
  TGREATPOWER_VTABLE_SLOT(146);
  TGREATPOWER_VTABLE_SLOT(147);
  TGREATPOWER_VTABLE_SLOT(148);
  TGREATPOWER_VTABLE_SLOT(149);
  TGREATPOWER_VTABLE_SLOT(150);
  TGREATPOWER_VTABLE_SLOT(151);
  TGREATPOWER_VTABLE_SLOT(152);
  TGREATPOWER_VTABLE_SLOT(153);
  TGREATPOWER_VTABLE_SLOT(154);
  TGREATPOWER_VTABLE_SLOT(155);
  TGREATPOWER_VTABLE_SLOT(156);
  TGREATPOWER_VTABLE_SLOT(157);
  TGREATPOWER_VTABLE_SLOT(158);
  TGREATPOWER_VTABLE_SLOT(159);
  TGREATPOWER_VTABLE_SLOT(160);
  // index 0xa1 / vtable+0x284. Evidence: 0x004df010 calls this on `this`
  // with (nationSlot, 2, targetNation); entry 0x00406fe1 thunks to 0x004e27f0.
  virtual void VTableSlotA1_Provisional(int nationSlot, int policyCode, int targetNation);
  TGREATPOWER_VTABLE_SLOT(162);
  TGREATPOWER_VTABLE_SLOT(163);
  TGREATPOWER_VTABLE_SLOT(164);
  virtual void CallSlotA5_Provisional(void) = 0;
  TGREATPOWER_VTABLE_SLOT(166);
  TGREATPOWER_VTABLE_SLOT(167);
  virtual void CallSlotA8_Provisional(int targetNation) = 0;
  virtual void CallSlotA9_Provisional(int targetNation) = 0;
  TGREATPOWER_VTABLE_SLOT(170);
  TGREATPOWER_VTABLE_SLOT(171);
  TGREATPOWER_VTABLE_SLOT(172);
  TGREATPOWER_VTABLE_SLOT(173);
  TGREATPOWER_VTABLE_SLOT(174);
  TGREATPOWER_VTABLE_SLOT(175);
  TGREATPOWER_VTABLE_SLOT(176);
  TGREATPOWER_VTABLE_SLOT(177);
  TGREATPOWER_VTABLE_SLOT(178);
  virtual void CallSlotB3_Provisional(void) = 0;

  unsigned char pad_04[8];
  short nationSlot;
  short encodedNationSlot;
  int pressureScore;
  short needLevelByNation[0x17];
  short field42;
  TListObject* pad_44_ptr;
  unsigned char pad_48[0x88 - 0x48];
  short ownerNationSlot;
  unsigned char pad_8a[0x90 - 0x8a];
  TListObject* ownedRegionList;
  TMinisterObject* foreignMinister;
  TMinisterObject* interiorMinister;
  TMinisterObject* defenseMinister;
  unsigned char scenarioLoadFlag;
  unsigned char pad_a1;
  short diplomacyCounterA2;
  short diplomacyCounterA4;
  short needCapA6;
  short needsOverCapFlag;
  unsigned char pad_aa[2];
  int grantTotalCost;
  short diplomacyCounterB0;
  short diplomacyPolicyByNation[0x17];
  short diplomacyGrantByNation[0x17];
  short needCurrentByType[0x17];
  short needTargetByType[0x17];
  short relationDeltaCurrent[0x17];
  short relationDeltaSnapshot[0x17];
  short diplomacyState1c6[0x17];
  short diplomacyState1f4[0x17];
  short diplomacyState222[0x17];
  short diplomacyState250[0x17];
  int aidAllocationMatrix[0x170];
  int budgetPoolBase;
  int budgetPoolDelta;
  TQueueObject* turnEventQueue;
  TQueueObject* proposalQueue;
  TQueueObject* diplomacyTrackedSlots[0x11];
  TRelationManagerObject* relationManager;
  TListObject* townMarkerList;
  TListObject* trackedObjectList;
  unsigned char candidateNationFlags[0x17];
  unsigned char scenarioInitFlag;
  unsigned char pad_8b8[0x8c8 - 0x8b8];
  unsigned char serializedStatusFlags[0x0D];
  signed char expansionAlertCounter;
  unsigned char field8d1;
  unsigned char field8d2;
  unsigned char field8d3;
  unsigned char expansionEventGate;
  unsigned char field8d5;
  short field8d6[0x0d];
  int diplomacyBudgetBase;
  signed char escalationCounter;
  unsigned char pad_8f5[3];
  int pendingCommitmentCost;
  signed char pressureCounter;
  unsigned char pad_8fd[3];
  int field900;
  unsigned char field904;
  unsigned char pad_905[3];
  TQueueObject* turnSummaryQueue;
  TListObject* missionNodeQueue;
  int field910;
  int aidAllocationTotal;
  unsigned char colonyBoycottFlags[0x17];
  unsigned char pad_92f[0x960 - 0x92f];
  int pendingAidTotal;
  // Provisional tail promoted from mixed-method imports beyond the core 0x964 block.
  short actionMetricByQuarter[6];
  unsigned char mapNodeStateFlags[0x180];
  unsigned char portZoneStateFlags[0x70];
  TListObject* missionQueue;

  unsigned int thunk_ComputeMapActionContextNodeValueAverage(void);
  char* thunk_BuildCityInfluenceLevelMap(void);
  void thunk_QueueMapActionMissionFromCandidateAndMarkState(int arg1, int arg2, int arg3, int arg4);
  float thunk_ComputeAdvisoryMapNodeScoreFactorByCaseMetric(int arg1, int arg2, int arg3, int arg4);
  void thunk_ProcessPendingDiplomacyProposalQueue_At00401cbc(void);
  void thunk_UpdateGreatPowerPressureStateAndDispatchEscalationMessage_At00402185(void);
  bool thunk_ExecuteAdvisoryPromptAndApplyActionType2OrFallback_At00402bda(int arg1, int arg2,
                                                                           int arg3);
  void thunk_PopulateCase16AdvisoryMapNodeCandidateState(void);
  void thunk_InitializeGreatPowerMinisterRosterAndScenarioState(int arg1);
  bool thunk_ExecuteAdvisoryPromptAndApplyActionType1_At00403c15(int arg1, int arg2);
  void thunk_BuildGreatPowerTurnMessageSummaryAndDispatch_At00403e04(void);
  void thunk_QueueInterNationEventIntoNationBucket(int eventCode, int payloadOrNation,
                                                   char isReplayBypass);
  void
  thunk_AddRegionIdToNationOwnedRegionListAndTriggerExpansionActionIfThresholdMet_At00404246(void);
  void thunk_ResetDiplomacyNeedScoresAndClearAidAllocationMatrix_At004048f4(void);
  void* ReplyToDiplomacyOffers(void);
  char thunk_TryDispatchNationActionViaUiContextOrFallback_At00404ce1(int arg1, int arg2, int arg3,
                                                                      int arg4);
  void thunk_QueueInterNationEventType0FForNationPairContext_At00405ac9(short targetNationSlot,
                                                                        short sourceNationSlot);
  float thunk_ComputeMapActionContextCompositeScoreForNation(int arg1);
  void thunk_OrphanCallChain_C2_I21_004e2b00_At00406a46(void);
  void thunk_RemoveRegionIdAndRunTrackedObjectCleanup_At00406b2c(void);
  void thunk_ClearFieldBlock1c6_At00406c49(void);
  void thunk_ResetNationDiplomacySlotsAndMarkRelatedNations_At00406c9e(void);
  void BuildGreatPowerRelationshipDeltaSummaryAndDispatchMessage(void);
  void thunk_ApplyDiplomacyPolicyStateForTargetWithCostChecks_At004070e5(int arg1, int arg2);
  void thunk_ApplyIndexedResourceDeltaAndAdjustNationTotals_At00407392(int arg1, int arg2,
                                                                       int arg3);
  void thunk_RefreshGreatPowerRelationPanelsAndDispatchDeltaSummary_At00407db0(void);
  void thunk_NoOpAdvisoryHandlerReturn_At00407e8c(void);
  void thunk_ResetDiplomacyNeedSlots7012AndRefreshIfModeGateMatches_At00408017(void);
  void thunk_DispatchTurnEvent2103WithNationFromRecord_At00408076(void);
  void thunk_NoOpDiplomacyWarTransitionCallback_At00408107(void);
  void thunk_HandleCityDialogHintClusterUpdate_At00408143(void* pMessage);
  void thunk_QueueDiplomacyProposalCodeForTargetNation_At004083f5(int proposalCode,
                                                                  int targetNationId);
  void thunk_WrapperFor_FreeHeapBufferIfNotNull_At004d8c20_At004085ee(void);
  void thunk_ConstructTurnOrderNavigationWindowEntryViewportAdaptive(void);
  void thunk_ApplyImmediateDiplomacyPolicySideEffects_At0040862a(int arg1, int arg2);
  void thunk_NoOpNationDiplomacyCallback_At004090b1(void);
  void thunk_InitializeNationStateRuntimeSubsystems(int arg1, int arg2);
  void thunk_DispatchGreatPowerQuarterlyStatusMessageLevel0_At004096c4(void);
  void thunk_ApplyJoinEmpireMode0GlobalDiplomacyReset_At004097fa(int arg1);
  void thunk_RebuildNationResourceYieldCountersAndDevelopmentTargets_At004097ff(void);

  // Semantic C++ wrappers:
  // - constructor behavior maps to 0x004D8CC0 InitializeNationStateRuntimeSubsystems
  // - deleting destructor behavior maps to 0x004D9160 ReleaseOwnedGreatPowerObjectsAndDeleteSelf
  TGreatPower(int arg1, int arg2);
  ~TGreatPower();

  void ReleaseOwnedGreatPowerObjectsAndDeleteSelf(void);
  static void* CreateTGreatPowerInstance(void);
  static void* GetTGreatPowerClassNamePointer(void);
  void InitializeGreatPowerMinisterRosterAndScenarioState(int arg1);
  void CompileGreatPowerRelationshipDeltaLinesAndDispatchMessage(void);
  void IsNationResourceNeedCurrentSumExceedingCapA6(void);
  void QueueMapActionMissionFromCandidateAndMarkState(int arg1, int arg2, int arg3, int arg4);
  void AddRegionIdToNationOwnedRegionListAndTriggerExpansionActionIfThresholdMet(void);
  void ApplyDiplomacyTargetTransitionAndClearGrantEntry(int targetNationSlot, int policyCode);
  void ReleaseTrackedObjectsByMapOwnerAndUnassignedEntries(int ownerClass);
  void DispatchNationDiplomacySlotActionByMode(int targetNationSlot, int mode);
  char CompareMissionScoreVariantsByMode(int mode);
  void BuildGreatPowerMapContextTriggeredNationEventMessages(void);
  void BuildGreatPowerEligibleNationEventMessagesFromLinkedList(void);
  void QueueWarTransitionAndNotifyThirdPartyIfNeeded(int targetNationSlot, int policyCode,
                                                     int sourceNationSlot);
  void ApplyNationResourceNeedTargetsToOrderState(void);
  bool ExecuteAdvisoryPromptAndApplyActionType1(int arg1, int arg2);
  void AssignFallbackNationsToUnfilledDiplomacyNeedSlots(void);
  void ResetDiplomacyNeedScoresAndClearAidAllocationMatrix(void);
  void RefreshDiplomacyNeedScoresAndClearAidAllocationMatrix(void);
  void RevokeDiplomacyGrantForTargetAndAdjustInfluence(int arg1);
  void SetNationResourceNeedCurrentByType(int needType, int currentValue);
  void TryIncrementNationResourceNeedTargetTowardCurrent(int needType);
  void AddAmountToAidAllocationMatrixCellAndTotal(int amount, short columnIndex, short rowIndex);
  int SumAidAllocationMatrixColumnForTarget(short targetNationId);
  int ComputeRemainingDiplomacyAidBudget(void);
  int GetDiplomacyExternalStateB6ByTarget(int targetNationSlot);
  void DecrementDiplomacyCounterA2ByValue(int delta);
  void ResetNationDiplomacyProposalQueue(void);
  void SetDiplomacyColonyBoycottFlagForTargetAndRefreshMinorNations(int targetNationSlot,
                                                                    int isBoycottEnabled);
  void OrphanVtableAssignStub_004ddd20(void);
  void RebuildNationResourceYieldsAndRollField134Into136(void);
  void RebuildNationResourceYieldCountersAndDevelopmentTargets(void);
  void InitializeMapActionCandidateStateAndQueueMission(int arg1);
  void SelectAndQueueAdvisoryMapMissionsCase16(void);
  void MarkNationPortZoneAndLinkedTilesForActionFlag(int arg1);
  void RefreshGreatPowerRelationPanelsAndDispatchDeltaSummary(void);
  float ComputeMapActionContextCompositeScoreForNation(int nodeType);
  unsigned int ComputeMapActionContextNodeValueAverage(void);
  float ComputeAdvisoryMapNodeScoreFactorByCaseMetric(int metricCase, int cityIndex,
                                                      int relationTargetNation,
                                                      int selectedNationSlot);
  void ApplyImmediateDiplomacyPolicySideEffects(int arg1, int arg2);
  void ProcessPendingDiplomacyProposalQueue(void);
  void InitializeNationStateRuntimeSubsystems(int arg1, int arg2);
  void QueueDiplomacyProposalCodeForTargetNation(short proposalCode, short targetNationId);
  void ResetDiplomacyNeedSlots7012AndRefreshIfModeGateMatches(void);
  void DispatchTurnEvent2103WithNationFromRecord(void);
  void ApplyJoinEmpireMode0GlobalDiplomacyReset(int arg1);
  void AdvanceOwnedRegionDevelopmentCountersAndDispatchEvents(void);
  void UpdateGreatPowerPressureStateAndDispatchEscalationMessage(void);
  void WrapperFor_HandleCityDialogHintClusterUpdate_At004e73f0(void* pMessage);
  void QueueDiplomacyProposalCodeWithAllianceGuards(int arg1, int arg2);
  void WrapperFor_TGreatPower_VtblSlot32_At004e7630(int arg1, int arg2, int arg3);
  void ForwardApplyDiplomacyPolicyStateForTargetWithCostChecks(int arg1, int arg2);
  void ApplyImmediateDiplomacyPolicySideEffectsWithSelectionHook(int arg1, int arg2);
  void QueueWarTransitionFromAdvisoryAction(int arg1, int arg2, int arg3);
  void ApplyJoinEmpireResetAndClearDiplomacyCaches(int arg1);
  void AddRegionToNationAndQueueMapActionMission(int arg1);
  char TryDispatchNationActionViaUiContextOrFallback(int arg1, int arg2, int arg3, int arg4);
  void QueueDiplomacyProposalCodeForTargetNationAndDispatchTurnEvent16(int proposalCode,
                                                                       int targetNationId);
  void TryDispatchNationActionViaUiThenTurnEvent(int arg1, int arg2, int arg3, int arg4);
  void ProcessPendingDiplomacyThenDispatchTurnEvent29A(void);
  void ApplyClientGreatPowerCommand69AndEmitTurnEvent1E(int arg1, int arg2);
  void QueueInterNationEventIntoNationBucket(int eventCode, int payloadOrNation,
                                             char isReplayBypass);
  void CommitCityRecruitmentOrderDelta(void);
  void HandleTurnInstruction_Civi_DeserializeAndCreateWorkOrder(void* pInstructionRaw);
  void BuildGreatPowerTurnMessageSummaryAndDispatch(void);
  void QueueInterNationEventType0FWithBitmaskMerge(int eventCode, int nationA, int nationB,
                                                   char isReplayBypass);
  void QueueInterNationEventType0FForNationPairContext(short targetNationSlot,
                                                       short sourceNationSlot);
  void ConstructTurnOrderNavigationWindowEntryViewportAdaptive(void);
  void DispatchNationField98CallbackD4(void);
  void DispatchNationField9CCallback4C(void);
  void DispatchNationField94Callbacks90And94(void);
};

#undef TGREATPOWER_VTABLE_SLOT
