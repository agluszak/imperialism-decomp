// Manual decompilation file.
// Seeded from ghidra autogen and normalized into compile-safe wrappers.

#include "decomp_types.h"

class TGreatPower;
typedef void* hwnd_t;
extern "C" int __stdcall MessageBoxA(hwnd_t hWnd, const char* text, const char* caption,
                                     unsigned int type);
int* InitializeSharedStringRefFromEmpty(int* dst_ref_ptr);
void ReleaseSharedStringRefIfNotEmpty(int* ref_ptr);

undefined4 ComputeMapActionContextNodeValueAverage(void);
undefined4 BuildCityInfluenceLevelMap(void);
undefined4 OrphanCallChain_C2_I10_004e03a0(void);
undefined4 DispatchGreatPowerQuarterlyStatusMessageLevel1(void);
undefined4 ProcessPendingDiplomacyProposalQueue(void);
undefined4 CompileGreatPowerRelationshipDeltaLinesAndDispatchMessage(void);
undefined4 DispatchGreatPowerQuarterlyStatusMessageLevel2(void);
undefined4 ExecuteAdvisoryPromptAndApplyActionType2OrFallback(void);
undefined4 PopulateCase16AdvisoryMapNodeCandidateState(void);
undefined4 DispatchTurnEvent11F8WithNoPayload(void);
bool __fastcall ExecuteAdvisoryPromptAndApplyActionType1(TGreatPower* self, int unusedEdx);
undefined4 BuildGreatPowerTurnMessageSummaryAndDispatch(void);
undefined4 QueueInterNationEventIntoNationBucket(void);
undefined4 AddRegionIdToNationOwnedRegionListAndTriggerExpansionActionIfThresholdMet(void);
undefined4 ResetDiplomacyNeedScoresAndClearAidAllocationMatrix(void);
undefined4 InitializeCivWorkOrderState(void);
undefined4 ReturnFalseNoOpAdvisoryHandler(void);
undefined4 NoOpDiplomacyTargetTransitionCallback(void);
undefined4 thunk_QueueInterNationEventType0FWithBitmaskMerge(void);
undefined4 thunk_CreateMissionObjectByKindAndNodeContext(void);
undefined4 thunk_GetShortAtOffset14OrInvalid(void);
undefined4 thunk_TemporarilyClearAndRestoreUiInvalidationFlag(void);
undefined4 thunk_IsNationSlotEligibleForEventProcessing(void);
undefined4 thunk_GetInt32Field30(void);
undefined4 thunk_LookupOrderCompatibilityMatrixValue(void);
undefined4 thunk_ComputeWeightedNeighborLinkScoreForNode(void);
undefined4 thunk_SumWeightedNeighborLinkScoreForLinkedNodes(void);
undefined4 thunk_SumNavyOrderPriorityForNationAndNodeType(void);
undefined4 thunk_SumNavyOrderPriorityForNation(void);
undefined4 thunk_NoOpDiplomacyPolicyStateChangedHook(void);
undefined4 thunk_CreateAndSendTurnEvent13_NationAndNineDwords(void);
undefined4 thunk_ComputeGlobalMapActionContextNodeValueAverage(void);
undefined4 GetTGreatPowerClassNamePointer(void);
void* ReplyToDiplomacyOffers(void);
void TGreatPower_VtblSlot07(void);
float ComputeMapActionContextCompositeScoreForNation(void);
void OrphanCallChain_C2_I21_004e2b00(void);
undefined4 RemoveRegionIdAndRunTrackedObjectCleanup(void);
undefined4 ClearFieldBlock1c6(void);
undefined4 ResetNationDiplomacySlotsAndMarkRelatedNations(void);
undefined4 thunk_QueueNationPairWarTransition(void);
void BuildGreatPowerRelationshipDeltaSummaryAndDispatchMessage(void);
void ApplyDiplomacyPolicyStateForTargetWithCostChecks(void);
void ApplyIndexedResourceDeltaAndAdjustNationTotals(void);
void RefreshGreatPowerRelationPanelsAndDispatchDeltaSummary(void);
void NoOpAdvisoryHandlerReturn(void);
void NoOpDiplomacyWarTransitionCallback(void);
void HandleCityDialogHintClusterUpdate(void);
void WrapperFor_FreeHeapBufferIfNotNull_At004d8c20(void);
void ConstructTurnOrderNavigationWindowEntryViewportAdaptive(void);
void NoOpNationDiplomacyCallback(void);
void DispatchGreatPowerQuarterlyStatusMessageLevel0(void);
void ApplyJoinEmpireMode0GlobalDiplomacyReset(void);
void RebuildNationResourceYieldCountersAndDevelopmentTargets(void);
undefined4 ApplyIndexedResourceDeltaAndAdjustNationTotals_Impl(void);
int AllocateWithFallbackHandler(undefined4 size_bytes);
undefined4 thunk_ConstructObArrayWithVtable654D38(void);
undefined4 thunk_InitializeObArrayVtable654D38ModeField(void);
undefined4 thunk_IsTurnCooldownCounterActiveOrResetFlag(void);
undefined4 thunk_QueueInterNationEventRecordDeduped(void);
undefined4 thunk_RebuildMinorNationDispositionLookupTables(void);
undefined4 ResetTerrainAdjacencyMatrixRowAndSymmetricLink(void);
undefined4 thunk_RemoveOrdersByNationFromPrimarySecondaryAndTaskForceLists(void);
undefined4 ApplyJoinEmpireMode0GlobalDiplomacyReset_Impl(void);
undefined4 thunk_DispatchTaggedGameStateEvent1F20(void);
undefined4 thunk_InitializeNationStateIdentityAndOwnedRegionList(void);
undefined4 thunk_InitializeCityModel(void);
undefined4 thunk_InitializeCityProductionState(void);
undefined4 WrapperFor_InitializeLinkedListSentinelNodeWithOwnerContext_At004a8640(void);
undefined4 thunk_InitializeTForeignMinisterStateAndCounters(void);
undefined4 thunk_InitializeCityInteriorMinister(void);
undefined4 thunk_InitializeTMinisterBaseOrderArrayMetrics(void);
undefined4 thunk_ConstructTForeignMinister(void);
undefined4 thunk_WrapperFor_thunk_ConstructTMinister_At004be840(void);
undefined4 thunk_ConstructTDefenseMinisterBaseState(void);
undefined4 CPtrList(void);
undefined4 thunk_DeserializeRecruitScenarioAndInstantiateOrders_At00409089(void);
undefined4 thunk_ConstructFrogCityMarker(void);
undefined4 thunk_InitializeCivUnitOrderObject(void);
undefined4 thunk_GetCityBuildingProductionValueBySlot(void);
undefined4 thunk_SetGlobalRegionDevelopmentStageByte(void);
undefined4 thunk_DispatchCityRedrawInvalidateEvent(void);

struct TDiplomacyTurnStateManager {
  void* vftable;
};

static const unsigned int kAddrUiRuntimeContextPtr = 0x006A21BC;
static const unsigned int kAddrSecondaryNationStateSlots = 0x006A4280;
static const unsigned int kAddrDiplomacyTurnStateManagerPtr = 0x006A43D0;
static const unsigned int kAddrGlobalMapStatePtr = 0x006A43D4;
static const unsigned int kAddrInterNationEventQueueManagerPtr = 0x006A43E8;
static const unsigned int kAddrEligibilityManagerPtr = 0x006A43E0;
static const unsigned int kAddrCityOrderCapabilityStatePtr = 0x006A43D8;
static const unsigned int kAddrLocalizationTablePtr = 0x006A20F8;
static const unsigned int kAddrTerrainTypeDescriptorTable = 0x006A4310;
static const unsigned int kAddrTerrainTypeDescriptorTableEnd = 0x006A436C;
static const unsigned int kAddrNationStates = 0x006A4370;
static const unsigned int kAddrNationStatesEnd = 0x006A438C;
static const unsigned int kAddrCompileGreatPowerValue = 0x00653528;
static const unsigned int kAddrNationBasePressureByLocale = 0x00653498;
static const unsigned int kAddrGreatPowerPressureMinFloor = 0x006534B0;
static const unsigned int kAddrGreatPowerPressureRiseCap = 0x006534E0;
static const unsigned int kAddrGreatPowerPressureDecayStep = 0x006534F8;
static const unsigned int kAddrGreatPowerPressureRiseStep = 0x00653510;
static const unsigned int kAddrGreatPowerPressureHardAlertThreshold = 0x00653540;
static const unsigned int kAddrNationRuntimeSubsystemCache = 0x00653558;
static const unsigned int kAddrAdvanceTurnMachineState = 0x00695278;
static const unsigned int kAddrVtblRefCountedObjectBase = 0x006485C0;
static const unsigned int kAddrVtblTArmyBattle = 0x00648F78;
static const char kNilPointerText[] = "Nil Pointer";
static const char kFailureCaption[] = "Failure";
static const char kUCountryAutoCppPath[] = "D:\\Ambit\\Cross\\UCountryAuto.cpp";
static const int kAssertLineQueueMapAction = 0x5ED;

class TGreatPower {
public:
  void** field00;
  unsigned char pad_04[8];
  short field0c;
  short field0e;
  int field10;
  unsigned char pad_14[0x44 - 0x14];
  void* pField44;
  unsigned char pad_48[0x88 - 0x48];
  short field88;
  unsigned char pad_8a[0x90 - 0x8a];
  void* pField90;
  void* pField94;
  void* pField98;
  void* pField9c;
  unsigned char fieldA0;
  unsigned char pad_a1;
  short fieldA2;
  short fieldA4;
  short fieldA6;
  short fieldA8;
  unsigned char pad_aa[2];
  int fieldAC;
  short fieldB0;
  short fieldB2[0x17];
  short fieldE0[0x17];
  short field10e[0x17];
  short field13c[0x17];
  short field16a[0x17];
  short field198[0x17];
  short field1c6[0x17];
  short field1f4[0x17];
  short field222[0x17];
  short field250[0x17];
  int field280[0x170];
  int field840;
  int field844;
  void* pField848;
  void* pField84c;
  void* pField850[0x11];
  void* pField894;
  void* pField898;
  void* pField89c;
  void* pField8a0;
  int field8a4;
  int field8a8;
  int field8ac;
  short field8b0;
  short field8b2;
  short field8b4;
  short field8b6;
  unsigned char pad_8b8[0x8d0 - 0x8b8];
  signed char field8d0;
  unsigned char pad_8d1[0x8d6 - 0x8d1];
  short field8d6[0x0d];
  int field8f0;
  signed char field8f4;
  unsigned char pad_8f5[3];
  void* pField8f8;
  signed char field8fc;
  unsigned char pad_8fd[3];
  int field900;
  unsigned char field904;
  unsigned char pad_905[3];
  void* pField908;
  void* pField90c;
  int field910;
  int field914;
  unsigned char field918[0x17];
  unsigned char pad_92f[0x960 - 0x92f];
  void* pField960;
  short field964[6];
  unsigned char field970[0x180];
  unsigned char fieldAF0[0x70];
  void* pFieldB60;

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
  bool thunk_ExecuteAdvisoryPromptAndApplyActionType1_At00403c15(void);
  void thunk_BuildGreatPowerTurnMessageSummaryAndDispatch_At00403e04(void);
  void thunk_QueueInterNationEventIntoNationBucket(int eventCode, int payloadOrNation,
                                                   char isReplayBypass);
  void
  thunk_AddRegionIdToNationOwnedRegionListAndTriggerExpansionActionIfThresholdMet_At00404246(void);
  void thunk_ResetDiplomacyNeedScoresAndClearAidAllocationMatrix_At004048f4(void);
  void* ReplyToDiplomacyOffers(void);
  void thunk_InitializeCivWorkOrderState(int nOrderType, int pOwnerContext,
                                         int nOrderOwnerNationId);
  void thunk_TryDispatchNationActionViaUiContextOrFallback_At00404ce1(int arg1, int arg2);
  void thunk_QueueInterNationEventType0FForNationPairContext_At00405ac9(short targetNationSlot,
                                                                        short sourceNationSlot);
  void TGreatPower_VtblSlot07(void);
  float thunk_ComputeMapActionContextCompositeScoreForNation(int arg1);
  void thunk_OrphanCallChain_C2_I21_004e2b00_At00406a46(void);
  void thunk_RemoveRegionIdAndRunTrackedObjectCleanup_At00406b2c(void);
  void thunk_ClearFieldBlock1c6_At00406c49(void);
  void thunk_ResetNationDiplomacySlotsAndMarkRelatedNations_At00406c9e(void);
  void BuildGreatPowerRelationshipDeltaSummaryAndDispatchMessage(void);
  void thunk_QueueWarTransitionAndNotifyThirdPartyIfNeeded_At00406fe1(int arg1, int arg2, int arg3,
                                                                      int arg4);
  void thunk_ApplyDiplomacyPolicyStateForTargetWithCostChecks_At004070e5(int arg1, int arg2);
  void thunk_ApplyIndexedResourceDeltaAndAdjustNationTotals_At00407392(int arg1, int arg2,
                                                                       int arg3);
  void thunk_RefreshGreatPowerRelationPanelsAndDispatchDeltaSummary_At00407db0(void);
  void thunk_NoOpAdvisoryHandlerReturn_At00407e8c(void);
  void thunk_ResetDiplomacyNeedSlots7012AndRefreshIfModeGateMatches_At00408017(void);
  void thunk_DispatchTurnEvent2103WithNationFromRecord_At00408076(void);
  void thunk_NoOpDiplomacyWarTransitionCallback_At00408107(void);
  void thunk_HandleCityDialogHintClusterUpdate_At00408143(void* pMessage);
  void thunk_QueueDiplomacyProposalCodeForTargetNation_At004083f5(void);
  void thunk_WrapperFor_FreeHeapBufferIfNotNull_At004d8c20_At004085ee(void);
  void thunk_ConstructTurnOrderNavigationWindowEntryViewportAdaptive(void);
  void thunk_ApplyImmediateDiplomacyPolicySideEffects_At0040862a(int arg1, int arg2);
  void thunk_NoOpNationDiplomacyCallback_At004090b1(void);
  void thunk_InitializeNationStateRuntimeSubsystems(int arg1, int arg2);
  void thunk_DispatchGreatPowerQuarterlyStatusMessageLevel0_At004096c4(void);
  void thunk_ApplyJoinEmpireMode0GlobalDiplomacyReset_At004097fa(int arg1);
  void thunk_RebuildNationResourceYieldCountersAndDevelopmentTargets_At004097ff(void);

  void ReleaseOwnedGreatPowerObjectsAndDeleteSelf(void);
  void InitializeGreatPowerMinisterRosterAndScenarioState(int arg1);
  void QueueMapActionMissionFromCandidateAndMarkState(int arg1, int arg2, int arg3, int arg4);
  void ApplyDiplomacyPolicyStateForTargetWithCostChecks(int arg1, int arg2);
  void AssignFallbackNationsToUnfilledDiplomacyNeedSlots(void);
  void SetDiplomacyGrantEntryForTargetAndUpdateTreasury(int arg1, int arg2);
  void RevokeDiplomacyGrantForTargetAndAdjustInfluence(int arg1);
  bool CanAffordDiplomacyGrantEntryForTarget(short targetNationId,
                                             unsigned short proposedGrantEntry);
  bool CanAffordAdditionalDiplomacyCostAfterCommitments(short additionalCost);
  void RebuildNationResourceYieldCountersAndDevelopmentTargets(void);
  void RefreshGreatPowerRelationPanelsAndDispatchDeltaSummary(void);
  float ComputeMapActionContextCompositeScoreForNation(int nodeType);
  float ComputeAdvisoryMapNodeScoreFactorByCaseMetric(int metricCase, int cityIndex,
                                                      int relationTargetNation,
                                                      int selectedNationSlot);
  void ApplyImmediateDiplomacyPolicySideEffects(int arg1, int arg2);
  void ProcessPendingDiplomacyProposalQueue(void);
  void InitializeNationStateRuntimeSubsystems(int arg1, int arg2);
  void QueueDiplomacyProposalCodeForTargetNation(void);
  void ApplyAcceptedDiplomacyProposalCode(short proposalIndex);
  void ResetDiplomacyNeedSlots7012AndRefreshIfModeGateMatches(void);
  void DispatchTurnEvent2103WithNationFromRecord(void);
  void ApplyJoinEmpireMode0GlobalDiplomacyReset(int arg1);
  void AdvanceOwnedRegionDevelopmentCountersAndDispatchEvents(void);
  void UpdateGreatPowerPressureStateAndDispatchEscalationMessage(void);
  void WrapperFor_HandleCityDialogHintClusterUpdate_At004e73f0(void* pMessage);
  void QueueDiplomacyProposalCodeWithAllianceGuards(int arg1, int arg2);
  void ApplyImmediateDiplomacyPolicySideEffectsWithSelectionHook(int arg1, int arg2);
  void TryDispatchNationActionViaUiContextOrFallback(int arg1, int arg2);
  void QueueInterNationEventType0FForNationPairContext(short targetNationSlot,
                                                       short sourceNationSlot);
};

typedef char(__cdecl* DiplomacyTurnStateSlot44Fn)(short);
typedef char(__fastcall* UiRuntimeSlot94Fn)(void*, int, int, int);
typedef void(__fastcall* GreatPowerSlotA1Fn)(TGreatPower*, int);
typedef char(__fastcall* GreatPowerSlot21Fn)(TGreatPower*, int);
typedef void(__fastcall* GreatPowerSlot6CFn)(TGreatPower*, int, int, int, int);
typedef void(__cdecl* UiRuntimeSlot98Fn)(int, int, int, int);
typedef void(__fastcall* SecondaryNationSlot4CFn)(void*, int, int, int);
typedef void(__fastcall* QueueInterNationEventMergeFn)(void*, int, int, int, int, char);
typedef void*(__cdecl* CreateMissionObjectFn)(int, int, int, int, int);
typedef short(__cdecl* GetShortAtOffset14Fn)(void);
typedef void(__fastcall* GreatPowerBridge0Fn)(TGreatPower*, int);
typedef void(__fastcall* GreatPowerBridge1Fn)(TGreatPower*, int, int);

static __inline void* ReadGlobalPointer(unsigned int address) {
  return *reinterpret_cast<void**>(address);
}

static __inline void** ReadGlobalPointerArray(unsigned int address) {
  return reinterpret_cast<void**>(address);
}

static __inline void* ReadGlobalPointerArraySlot(unsigned int address, int index) {
  return ReadGlobalPointerArray(address)[index];
}

static __inline signed char ReadLocaleByteStep(unsigned int baseAddress, int localeIndex) {
  return *reinterpret_cast<signed char*>(baseAddress + localeIndex * 4);
}

static __inline void SwapShortArrayBytes(void* base, int count) {
  unsigned char* bytes = reinterpret_cast<unsigned char*>(base);
  int i = 0;
  while (i < count) {
    unsigned char t = bytes[0];
    bytes[0] = bytes[1];
    bytes[1] = t;
    bytes += 2;
    ++i;
  }
}

static __inline void ReverseDwordArrayBytes(void* base, int count) {
  unsigned char* bytes = reinterpret_cast<unsigned char*>(base);
  int i = 0;
  while (i < count) {
    unsigned char t0 = bytes[0];
    unsigned char t1 = bytes[1];
    bytes[0] = bytes[3];
    bytes[1] = bytes[2];
    bytes[2] = t1;
    bytes[3] = t0;
    bytes += 4;
    ++i;
  }
}

static __inline short ProposalQueue_GetCount(void* queue) {
  return *reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(queue) + 8);
}

static __inline short* ProposalQueue_GetEntryAt1Based(void* queue, int queueIndex) {
  typedef short*(__fastcall * QueueSlot2CFn)(void*, int, int);
  void** queueVtable = *reinterpret_cast<void***>(queue);
  QueueSlot2CFn queueSlot2C = reinterpret_cast<QueueSlot2CFn>(queueVtable[0x2C / 4]);
  return queueSlot2C(queue, 0, queueIndex);
}

static __inline short Diplomacy_GetRelationTier(void* diplomacyManager, int sourceNation,
                                                int targetNation) {
  typedef short(__fastcall * DipSlot70Fn)(void*, int, int, int);
  void** diplomacyVtable = *reinterpret_cast<void***>(diplomacyManager);
  DipSlot70Fn dipSlot70 = reinterpret_cast<DipSlot70Fn>(diplomacyVtable[0x70 / 4]);
  return dipSlot70(diplomacyManager, sourceNation, targetNation, 0);
}

static __inline char Diplomacy_HasPolicyWithNation(void* diplomacyManager, int sourceNation,
                                                   int targetNation) {
  typedef char(__fastcall * DipSlot44Fn)(void*, int, int, int);
  void** diplomacyVtable = *reinterpret_cast<void***>(diplomacyManager);
  DipSlot44Fn dipSlot44 = reinterpret_cast<DipSlot44Fn>(diplomacyVtable[0x44 / 4]);
  return dipSlot44(diplomacyManager, sourceNation, targetNation, 0);
}

static __inline char UiRuntime_RequestDiplomacyDecision(void* uiRuntimeContext, int sourceNation,
                                                        int targetNation, int proposalCode) {
  typedef char(__fastcall * UiSlot90Fn)(void*, int, int, int, int);
  void** uiVtable = *reinterpret_cast<void***>(uiRuntimeContext);
  UiSlot90Fn uiSlot90 = reinterpret_cast<UiSlot90Fn>(uiVtable[0x90 / 4]);
  return uiSlot90(uiRuntimeContext, 0, sourceNation, targetNation, proposalCode);
}

static __inline char IsTurnCooldownCounterActiveOrResetFlagAsChar(void) {
  typedef char(__cdecl * CooldownActiveFn)(void);
  CooldownActiveFn isTurnCooldownActive =
      reinterpret_cast<CooldownActiveFn>(thunk_IsTurnCooldownCounterActiveOrResetFlag);
  return isTurnCooldownActive();
}

static __inline void GreatPower_CommitProposalByIndex(TGreatPower* self, int proposalIndex) {
  typedef void(__fastcall * GreatPowerSlot7BFn)(TGreatPower*, int, int);
  GreatPowerSlot7BFn applyProposalByIndex =
      reinterpret_cast<GreatPowerSlot7BFn>(self->field00[0x7B]);
  applyProposalByIndex(self, 0, proposalIndex);
}

static __inline void GreatPower_RemoveProposalByIndex(TGreatPower* self, int proposalIndex) {
  typedef void(__fastcall * GreatPowerSlot7CFn)(TGreatPower*, int, int);
  GreatPowerSlot7CFn removeProposalByIndex =
      reinterpret_cast<GreatPowerSlot7CFn>(self->field00[0x7C]);
  removeProposalByIndex(self, 0, proposalIndex);
}

static __inline void GreatPower_ApplyMutualDefenseWithNation(TGreatPower* self, int checkNation,
                                                             int sourceNation) {
  typedef void(__fastcall * GreatPowerSlotA1ApplyFn)(TGreatPower*, int, int, int, int);
  GreatPowerSlotA1ApplyFn applyPolicyToNation =
      reinterpret_cast<GreatPowerSlotA1ApplyFn>(self->field00[0xA1]);
  applyPolicyToNation(self, 0, checkNation, 0x132, sourceNation);
}

static __inline void GreatPower_FinalizeProposalQueue(TGreatPower* self) {
  typedef void(__fastcall * GreatPowerSlot73Fn)(TGreatPower*, int);
  GreatPowerSlot73Fn slot73 = reinterpret_cast<GreatPowerSlot73Fn>(self->field00[0x73]);
  slot73(self, 0);
}

static __inline void QueueObject_WritePackedIntAtSlot38(void* queue, int* packedValue) {
  typedef void(__fastcall * QueueSlot38Fn)(void*, int, int*);
  void** queueVtable = *reinterpret_cast<void***>(queue);
  QueueSlot38Fn queueSlot38 = reinterpret_cast<QueueSlot38Fn>(queueVtable[0x38 / 4]);
  queueSlot38(queue, 0, packedValue);
}

static __inline char GreatPower_ShouldDispatchImmediately(TGreatPower* self) {
  typedef char(__fastcall * GreatPowerSlot28Fn)(TGreatPower*, int);
  GreatPowerSlot28Fn slot28 = reinterpret_cast<GreatPowerSlot28Fn>(self->field00[0x28]);
  return slot28(self, 0);
}

static __inline void QueueInterNationEventWithPayload(int sourceNation, void* payload) {
  typedef void(__fastcall * QueueInterNationEventFn)(void*, int, int, int, char);
  void* queueManager = ReadGlobalPointer(kAddrInterNationEventQueueManagerPtr);
  QueueInterNationEventFn queueInterNationEvent =
      reinterpret_cast<QueueInterNationEventFn>(QueueInterNationEventIntoNationBucket);
  queueInterNationEvent(queueManager, 0, sourceNation, reinterpret_cast<int>(payload), '\0');
}

static __inline void SendTurnEvent13WithPayload(int sourceNation, void* payload) {
  typedef void(__fastcall * SendTurnEvent13Fn)(void*, int, int);
  SendTurnEvent13Fn sendTurnEvent13 =
      reinterpret_cast<SendTurnEvent13Fn>(thunk_CreateAndSendTurnEvent13_NationAndNineDwords);
  sendTurnEvent13(0, sourceNation, reinterpret_cast<int>(payload));
}

static __inline int IsNationSlotEligibleForEventProcessingFast(int nationSlot) {
  typedef int(__fastcall * IsEligibleFn)(void*, int, int);
  IsEligibleFn isNationEligible =
      reinterpret_cast<IsEligibleFn>(thunk_IsNationSlotEligibleForEventProcessing);
  return isNationEligible(0, 0, nationSlot);
}

static __inline char Diplomacy_HasFlag84ForNation(void* diplomacyManager, int nationSlot) {
  typedef char(__fastcall * DipSlot84Fn)(void*, int, int);
  void** diplomacyVtable = *reinterpret_cast<void***>(diplomacyManager);
  DipSlot84Fn slot84 = reinterpret_cast<DipSlot84Fn>(diplomacyVtable[0x84 / 4]);
  return slot84(diplomacyManager, 0, nationSlot);
}

static __inline void Diplomacy_SetRelationState(void* diplomacyManager, int sourceNation,
                                                int targetNation, int relationState) {
  typedef void(__fastcall * DipSlot7CFn)(void*, int, int, int, int);
  void** diplomacyVtable = *reinterpret_cast<void***>(diplomacyManager);
  DipSlot7CFn slot7C = reinterpret_cast<DipSlot7CFn>(diplomacyVtable[0x7C / 4]);
  slot7C(diplomacyManager, sourceNation, targetNation, relationState, 0);
}

static __inline void GreatPower_ApplyPolicyForNation(TGreatPower* self, int targetNation,
                                                     int policyCode, int sourceNation) {
  typedef void(__fastcall * GreatPowerSlotA1ApplyFn)(TGreatPower*, int, int, int, int);
  GreatPowerSlotA1ApplyFn applyPolicy =
      reinterpret_cast<GreatPowerSlotA1ApplyFn>(self->field00[0xA1]);
  applyPolicy(self, 0, targetNation, policyCode, sourceNation);
}

static __inline void ReleaseObjectAtSlot1C(void* obj) {
  typedef void(__fastcall * ReleaseObjFn)(void*, int);
  void** objectVtable = *reinterpret_cast<void***>(obj);
  ReleaseObjFn releaseFn = reinterpret_cast<ReleaseObjFn>(objectVtable[0x1C / 4]);
  releaseFn(obj, 0);
}

static __inline void TerrainDescriptor_SetResetLevel(void* terrainDescriptor, int sourceNation,
                                                     int resetLevel) {
  typedef void(__fastcall * TerrainSlot68Fn)(void*, int, int, int);
  void** terrainVtable = *reinterpret_cast<void***>(terrainDescriptor);
  TerrainSlot68Fn slot68 = reinterpret_cast<TerrainSlot68Fn>(terrainVtable[0x68 / 4]);
  slot68(terrainDescriptor, 0, sourceNation, resetLevel);
}

static __inline void NationState_NotifyAction131(void* nationState, int sourceNation) {
  typedef void(__fastcall * NationSlot94Fn)(void*, int, int, int);
  void** nationVtable = *reinterpret_cast<void***>(nationState);
  NationSlot94Fn slot94 = reinterpret_cast<NationSlot94Fn>(nationVtable[0x94 / 4]);
  slot94(nationState, 0, sourceNation, 0x131);
}

static __inline void NationState_NotifyActionCode(void* nationState, int sourceNation,
                                                  int actionCode) {
  typedef void(__fastcall * NationSlot94Fn)(void*, int, int, int);
  void** nationVtable = *reinterpret_cast<void***>(nationState);
  NationSlot94Fn slot94 = reinterpret_cast<NationSlot94Fn>(nationVtable[0x94 / 4]);
  slot94(nationState, 0, sourceNation, actionCode);
}

static __inline void NationState_AssignNeedSlotFromSource(void* nationState, int needSlot,
                                                          int sourceNation) {
  typedef void(__fastcall * NationSlot19CFn)(void*, int, int, int);
  void** nationVtable = *reinterpret_cast<void***>(nationState);
  NationSlot19CFn slot19C = reinterpret_cast<NationSlot19CFn>(nationVtable[0x19C / 4]);
  slot19C(nationState, 0, needSlot, sourceNation);
}

static __inline char NationState_IsBusyA0(void* nationState) {
  return *reinterpret_cast<char*>(reinterpret_cast<unsigned char*>(nationState) + 0xA0);
}

static __inline short GreatPower_GetNeedSlotValue(TGreatPower* self, int needSlot) {
  typedef short(__fastcall * GreatPowerSlot1FFn)(TGreatPower*, int, int);
  GreatPowerSlot1FFn slot1F = reinterpret_cast<GreatPowerSlot1FFn>(self->field00[0x1F]);
  return slot1F(self, 0, needSlot);
}

static __inline void Object_CallSlot8CNoArgs(void* obj) {
  typedef void(__fastcall * ObjectSlot8CFn)(void*, int);
  void** objectVtable = *reinterpret_cast<void***>(obj);
  ObjectSlot8CFn slot8C = reinterpret_cast<ObjectSlot8CFn>(objectVtable[0x8C / 4]);
  slot8C(obj, 0);
}

static __inline void SecondaryState_ResetDiplomacyLevel(void* secondaryState, int sourceNation,
                                                        int resetLevel) {
  typedef void(__fastcall * SecondarySlot48Fn)(void*, int, int, int);
  void** secondaryVtable = *reinterpret_cast<void***>(secondaryState);
  SecondarySlot48Fn slot48 = reinterpret_cast<SecondarySlot48Fn>(secondaryVtable[0x48 / 4]);
  slot48(secondaryState, 0, sourceNation, resetLevel);
}

static __inline void GreatPower_ResetDiplomacyLevelForNation(TGreatPower* self, int nationSlot,
                                                             int resetLevel) {
  typedef void(__fastcall * GreatPowerSetValueFn)(TGreatPower*, int, int, int);
  GreatPowerSetValueFn slot12 = reinterpret_cast<GreatPowerSetValueFn>(self->field00[0x12]);
  slot12(self, 0, nationSlot, resetLevel);
}

static __inline void GreatPower_ResetPolicyForNation(TGreatPower* self, int nationSlot,
                                                     int resetPolicyCode) {
  typedef void(__fastcall * GreatPowerSetValueFn)(TGreatPower*, int, int, int);
  GreatPowerSetValueFn slot75 = reinterpret_cast<GreatPowerSetValueFn>(self->field00[0x75]);
  slot75(self, 0, nationSlot, resetPolicyCode);
}

static __inline void GreatPower_CallSlot13(TGreatPower* self, int arg1, int arg2) {
  typedef void(__fastcall * GreatPowerSlot13Fn)(TGreatPower*, int, int, int);
  GreatPowerSlot13Fn slot13 = reinterpret_cast<GreatPowerSlot13Fn>(self->field00[0x13]);
  slot13(self, 0, arg1, arg2);
}

static __inline void GreatPower_SetPolicyForNation(TGreatPower* self, int nationSlot,
                                                   int policyCode) {
  typedef void(__fastcall * GreatPowerSetValueFn)(TGreatPower*, int, int, int);
  GreatPowerSetValueFn slot74 = reinterpret_cast<GreatPowerSetValueFn>(self->field00[0x74]);
  slot74(self, 0, nationSlot, policyCode);
}

static __inline int GreatPower_CanPayAmount(TGreatPower* self, int amount) {
  typedef int(__fastcall * GreatPowerCanPayFn)(TGreatPower*, int, int);
  GreatPowerCanPayFn slot7A = reinterpret_cast<GreatPowerCanPayFn>(self->field00[0x7A]);
  return slot7A(self, 0, amount);
}

static __inline void GreatPower_AdjustTreasury(TGreatPower* self, int amount) {
  typedef void(__fastcall * GreatPowerAdjustTreasuryFn)(TGreatPower*, int, int);
  GreatPowerAdjustTreasuryFn slot0E =
      reinterpret_cast<GreatPowerAdjustTreasuryFn>(self->field00[0x0E]);
  slot0E(self, 0, amount);
}

static __inline char GreatPower_CanSetGrantValue(TGreatPower* self, int grantValue) {
  typedef char(__fastcall * GreatPowerCanSetGrantFn)(TGreatPower*, int, int);
  GreatPowerCanSetGrantFn slot77 = reinterpret_cast<GreatPowerCanSetGrantFn>(self->field00[0x77]);
  return slot77(self, 0, grantValue);
}

static __inline short Diplomacy_ReadRelationMatrix79C(void* diplomacyManager, int sourceNation,
                                                      int targetNation) {
  int matrixIndex = sourceNation * 0x17 + targetNation;
  return *reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(diplomacyManager) + 0x79C +
                                   matrixIndex * 2);
}

static __inline short LookupOrderCompatibility(short sourceNationSlot, short targetNationSlot) {
  typedef short(__fastcall * LookupOrderCompatibilityFn)(void*, int, int, int);
  LookupOrderCompatibilityFn lookupOrderCompatibility =
      reinterpret_cast<LookupOrderCompatibilityFn>(thunk_LookupOrderCompatibilityMatrixValue);
  return lookupOrderCompatibility(ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr), 0,
                                  sourceNationSlot, targetNationSlot);
}

static __inline short TerrainDescriptor_GetEncodedNationSlot(void* terrainDescriptor) {
  return *reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(terrainDescriptor) + 0x0E);
}

static __inline short TerrainDescriptor_GetFallbackNationSlot(void* terrainDescriptor) {
  return *reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(terrainDescriptor) + 0x0C);
}

static __inline int DecodeTerrainNationSlot(short encodedNationSlot, void* terrainDescriptor) {
  if (encodedNationSlot < 200) {
    if (encodedNationSlot < 100) {
      return TerrainDescriptor_GetFallbackNationSlot(terrainDescriptor);
    }
    return encodedNationSlot - 100;
  }
  return encodedNationSlot - 200;
}

static __inline void GreatPower_CallSlot5C(TGreatPower* self) {
  typedef void(__fastcall * GreatPowerNoArgFn)(TGreatPower*, int);
  GreatPowerNoArgFn slot5C = reinterpret_cast<GreatPowerNoArgFn>(self->field00[0x5C]);
  slot5C(self, 0);
}

static __inline void GreatPower_CallSlotA5(TGreatPower* self) {
  typedef void(__fastcall * GreatPowerNoArgFn)(TGreatPower*, int);
  GreatPowerNoArgFn slotA5 = reinterpret_cast<GreatPowerNoArgFn>(self->field00[0xA5]);
  slotA5(self, 0);
}

static __inline void Diplomacy_SetFlag74(void* diplomacyManager, int sourceNation, int targetNation,
                                         int flagValue) {
  typedef void(__fastcall * DipSlot74Fn)(void*, int, int, int, int);
  void** diplomacyVtable = *reinterpret_cast<void***>(diplomacyManager);
  DipSlot74Fn slot74 = reinterpret_cast<DipSlot74Fn>(diplomacyVtable[0x74 / 4]);
  slot74(diplomacyManager, 0, sourceNation, targetNation, flagValue);
}

static __inline void Diplomacy_SetFlag28(void* diplomacyManager, int sourceNation, int targetNation,
                                         int flagValue) {
  typedef void(__fastcall * DipSlot28Fn)(void*, int, int, int, int);
  void** diplomacyVtable = *reinterpret_cast<void***>(diplomacyManager);
  DipSlot28Fn slot28 = reinterpret_cast<DipSlot28Fn>(diplomacyVtable[0x28 / 4]);
  slot28(diplomacyManager, 0, sourceNation, targetNation, flagValue);
}

static __inline void Diplomacy_SetRelationCode78(void* diplomacyManager, int sourceNation,
                                                 int targetNation, int relationCode) {
  typedef void(__fastcall * DipSlot78Fn)(void*, int, int, int);
  void** diplomacyVtable = *reinterpret_cast<void***>(diplomacyManager);
  DipSlot78Fn slot78 = reinterpret_cast<DipSlot78Fn>(diplomacyVtable[0x78 / 4]);
  slot78(diplomacyManager, sourceNation, targetNation, relationCode);
}

static __inline void QueueInterNationEventRecordDedup(int eventCode, int sourceNation,
                                                      int targetNation) {
  typedef void(__fastcall * QueueInterNationEventDedupFn)(void*, int, int, int, int, char);
  QueueInterNationEventDedupFn queueInterNationEventDedup =
      reinterpret_cast<QueueInterNationEventDedupFn>(thunk_QueueInterNationEventRecordDeduped);
  queueInterNationEventDedup(ReadGlobalPointer(kAddrInterNationEventQueueManagerPtr), 0, eventCode,
                             sourceNation, targetNation, '\0');
}

static __inline void TerrainDescriptor_CallSlot4C(void* terrainDescriptor, int sourceNation,
                                                  int modeValue) {
  typedef void(__fastcall * TerrainSlot4CFn)(void*, int, int, int);
  void** terrainVtable = *reinterpret_cast<void***>(terrainDescriptor);
  TerrainSlot4CFn slot4C = reinterpret_cast<TerrainSlot4CFn>(terrainVtable[0x4C / 4]);
  slot4C(terrainDescriptor, 0, sourceNation, modeValue);
}

static __inline void TerrainDescriptor_CallSlot38(void* terrainDescriptor, int delta) {
  typedef void(__fastcall * TerrainSlot38Fn)(void*, int, int);
  void** terrainVtable = *reinterpret_cast<void***>(terrainDescriptor);
  TerrainSlot38Fn slot38 = reinterpret_cast<TerrainSlot38Fn>(terrainVtable[0x38 / 4]);
  slot38(terrainDescriptor, 0, delta);
}

static __inline int ClampNonNegative(int value) {
  return (value < 0) ? 0 : value;
}

static __inline int DecodeGrantValue14Bit(short rawGrantEntry) {
  const unsigned short kGrantMask = 0x3FFF;
  return static_cast<int>(
      static_cast<short>(static_cast<unsigned short>(rawGrantEntry) & kGrantMask));
}

static __inline int DecodeActiveGrantValue(short rawGrantEntry) {
  if (rawGrantEntry <= 0) {
    return 0;
  }
  return DecodeGrantValue14Bit(rawGrantEntry);
}

static __inline int ComputeGrantInfluenceDelta(int grantValue) {
  switch (grantValue) {
  case 1000:
    return 2;
  case 3000:
    return 4;
  case 5000:
    return 6;
  case 10000:
    return 10;
  default:
    return 0;
  }
}

static __inline int ComputeAvailableDiplomacyBudget(const TGreatPower* self) {
  return ClampNonNegative(self->field10 + self->field8f0 / 100);
}

// FUNCTION: IMPERIALISM 0x00401172
unsigned int TGreatPower::thunk_ComputeMapActionContextNodeValueAverage(void) {
  return ComputeMapActionContextNodeValueAverage();
}

// FUNCTION: IMPERIALISM 0x00401343
char* TGreatPower::thunk_BuildCityInfluenceLevelMap(void) {
  return reinterpret_cast<char*>(BuildCityInfluenceLevelMap());
}

// FUNCTION: IMPERIALISM 0x004014A6
void TGreatPower::thunk_QueueMapActionMissionFromCandidateAndMarkState(int arg1, int arg2, int arg3,
                                                                       int arg4) {
  QueueMapActionMissionFromCandidateAndMarkState(arg1, arg2, arg3, arg4);
}

// FUNCTION: IMPERIALISM 0x004016D1
void thunk_OrphanCallChain_C2_I10_004e03a0_At004016d1(void) {
  OrphanCallChain_C2_I10_004e03a0();
}

// FUNCTION: IMPERIALISM 0x00401983
void thunk_DispatchGreatPowerQuarterlyStatusMessageLevel1_At00401983(void) {
  DispatchGreatPowerQuarterlyStatusMessageLevel1();
}

// FUNCTION: IMPERIALISM 0x00401AD2
float TGreatPower::thunk_ComputeAdvisoryMapNodeScoreFactorByCaseMetric(int arg1, int arg2, int arg3,
                                                                       int arg4) {
  return ComputeAdvisoryMapNodeScoreFactorByCaseMetric(arg1, arg2, arg3, arg4);
}

// FUNCTION: IMPERIALISM 0x00401CBC
void TGreatPower::thunk_ProcessPendingDiplomacyProposalQueue_At00401cbc(void) {
  this->ProcessPendingDiplomacyProposalQueue();
}

// FUNCTION: IMPERIALISM 0x00402185
void TGreatPower::thunk_UpdateGreatPowerPressureStateAndDispatchEscalationMessage_At00402185(void) {
  this->UpdateGreatPowerPressureStateAndDispatchEscalationMessage();
}

// FUNCTION: IMPERIALISM 0x00402919
void thunk_DispatchGreatPowerQuarterlyStatusMessageLevel2_At00402919(void) {
  DispatchGreatPowerQuarterlyStatusMessageLevel2();
}

// FUNCTION: IMPERIALISM 0x00402BDA
bool TGreatPower::thunk_ExecuteAdvisoryPromptAndApplyActionType2OrFallback_At00402bda(int arg1,
                                                                                      int arg2,
                                                                                      int arg3) {
  (void)arg1;
  (void)arg2;
  (void)arg3;
  return ExecuteAdvisoryPromptAndApplyActionType2OrFallback() != 0;
}

// FUNCTION: IMPERIALISM 0x00402E5F
void TGreatPower::thunk_PopulateCase16AdvisoryMapNodeCandidateState(void) {
  PopulateCase16AdvisoryMapNodeCandidateState();
}

// FUNCTION: IMPERIALISM 0x0040376A
void TGreatPower::thunk_InitializeGreatPowerMinisterRosterAndScenarioState(int arg1) {
  this->InitializeGreatPowerMinisterRosterAndScenarioState(arg1);
}

// FUNCTION: IMPERIALISM 0x0040389B
void thunk_DispatchTurnEvent11F8WithNoPayload_At0040389b(void) {
  DispatchTurnEvent11F8WithNoPayload();
}

// FUNCTION: IMPERIALISM 0x00403C15
bool TGreatPower::thunk_ExecuteAdvisoryPromptAndApplyActionType1_At00403c15(void) {
  return ExecuteAdvisoryPromptAndApplyActionType1(this, 0);
}

// FUNCTION: IMPERIALISM 0x00403E04
void TGreatPower::thunk_BuildGreatPowerTurnMessageSummaryAndDispatch_At00403e04(void) {
  BuildGreatPowerTurnMessageSummaryAndDispatch();
}

// FUNCTION: IMPERIALISM 0x00404007
void TGreatPower::thunk_QueueInterNationEventIntoNationBucket(int eventCode, int payloadOrNation,
                                                              char isReplayBypass) {
  (void)eventCode;
  (void)payloadOrNation;
  (void)isReplayBypass;
  QueueInterNationEventIntoNationBucket();
}

// FUNCTION: IMPERIALISM 0x00404246
void TGreatPower::
    thunk_AddRegionIdToNationOwnedRegionListAndTriggerExpansionActionIfThresholdMet_At00404246(
        void) {
  AddRegionIdToNationOwnedRegionListAndTriggerExpansionActionIfThresholdMet();
}

// FUNCTION: IMPERIALISM 0x004048F4
void TGreatPower::thunk_ResetDiplomacyNeedScoresAndClearAidAllocationMatrix_At004048f4(void) {
  ResetDiplomacyNeedScoresAndClearAidAllocationMatrix();
}

// FUNCTION: IMPERIALISM 0x00404A9D
void* TGreatPower::ReplyToDiplomacyOffers(void) {
  return reinterpret_cast<void*>(GetTGreatPowerClassNamePointer());
}

// FUNCTION: IMPERIALISM 0x00404B33
void TGreatPower::thunk_InitializeCivWorkOrderState(int nOrderType, int pOwnerContext,
                                                    int nOrderOwnerNationId) {
  (void)nOrderType;
  (void)pOwnerContext;
  (void)nOrderOwnerNationId;
  InitializeCivWorkOrderState();
}

// FUNCTION: IMPERIALISM 0x00404CE1
#if defined(_MSC_VER)
#pragma optimize("gy", on)
#endif
void TGreatPower::thunk_TryDispatchNationActionViaUiContextOrFallback_At00404ce1(int arg1,
                                                                                 int arg2) {
  TryDispatchNationActionViaUiContextOrFallback(arg1, arg2);
}
#if defined(_MSC_VER)
#pragma optimize("", on)
#endif

// FUNCTION: IMPERIALISM 0x00405826
bool __stdcall thunk_ReturnFalseNoOpAdvisoryHandler_At00405826(void) {
  return ReturnFalseNoOpAdvisoryHandler() != 0;
}

// FUNCTION: IMPERIALISM 0x00405A9C
void thunk_NoOpDiplomacyTargetTransitionCallback_At00405a9c(void) {
  NoOpDiplomacyTargetTransitionCallback();
}

// FUNCTION: IMPERIALISM 0x00405AC9
#if defined(_MSC_VER)
#pragma optimize("gy", on)
#endif
void TGreatPower::thunk_QueueInterNationEventType0FForNationPairContext_At00405ac9(
    short targetNationSlot, short sourceNationSlot) {
  QueueInterNationEventType0FForNationPairContext(targetNationSlot, sourceNationSlot);
}
#if defined(_MSC_VER)
#pragma optimize("", on)
#endif

// FUNCTION: IMPERIALISM 0x00405DE4
void TGreatPower::TGreatPower_VtblSlot07(void) {
  this->ReleaseOwnedGreatPowerObjectsAndDeleteSelf();
}

static __inline int CallSumNavyOrderPriorityForNationAndNodeType(void* nationObj, int arg);

// FUNCTION: IMPERIALISM 0x00406915
float TGreatPower::thunk_ComputeMapActionContextCompositeScoreForNation(int arg1) {
  return ComputeMapActionContextCompositeScoreForNation(arg1);
}

// FUNCTION: IMPERIALISM 0x00406A46
void TGreatPower::thunk_OrphanCallChain_C2_I21_004e2b00_At00406a46(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x00406B2C
void TGreatPower::thunk_RemoveRegionIdAndRunTrackedObjectCleanup_At00406b2c(void) {
  RemoveRegionIdAndRunTrackedObjectCleanup();
}

// FUNCTION: IMPERIALISM 0x00406C49
void TGreatPower::thunk_ClearFieldBlock1c6_At00406c49(void) {
  ClearFieldBlock1c6();
}

// FUNCTION: IMPERIALISM 0x00406C9E
void TGreatPower::thunk_ResetNationDiplomacySlotsAndMarkRelatedNations_At00406c9e(void) {
  ResetNationDiplomacySlotsAndMarkRelatedNations();
}

// FUNCTION: IMPERIALISM 0x00406CA3
void TGreatPower::BuildGreatPowerRelationshipDeltaSummaryAndDispatchMessage(void) {
  reinterpret_cast<void(__fastcall*)(TGreatPower*, int)>(
      CompileGreatPowerRelationshipDeltaLinesAndDispatchMessage)(this, 0);
}

// FUNCTION: IMPERIALISM 0x00406FE1
void TGreatPower::thunk_QueueWarTransitionAndNotifyThirdPartyIfNeeded_At00406fe1(int arg1, int arg2,
                                                                                 int arg3,
                                                                                 int arg4) {
  typedef void(__cdecl * QueueNationPairWarTransitionFn)(void*, short, short);
  typedef void(__fastcall * SecondaryNationSlot4CFn)(void*, int, int, int);
  QueueNationPairWarTransitionFn queueNationPairWarTransition =
      reinterpret_cast<QueueNationPairWarTransitionFn>(thunk_QueueNationPairWarTransition);
  queueNationPairWarTransition(reinterpret_cast<void*>(arg1), this->field0c,
                               static_cast<short>(arg2));

  short proposalCode = static_cast<short>(arg3);
  if ((proposalCode != 1) && (proposalCode != 0x132)) {
    (void)arg4;
    return;
  }

  void** secondaryNationStateSlots = reinterpret_cast<void**>(kAddrSecondaryNationStateSlots);
  void* secondaryNationState = secondaryNationStateSlots[static_cast<unsigned char>(arg2)];
  if (secondaryNationState == 0) {
    return;
  }

  short selectedSlot =
      *reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(secondaryNationState) + 0x0E);
  if (selectedSlot < 200) {
    if (selectedSlot < 100) {
      selectedSlot =
          *reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(secondaryNationState) + 0x0C);
    } else {
      selectedSlot = static_cast<short>(selectedSlot - 100);
    }
  } else {
    selectedSlot = static_cast<short>(selectedSlot - 200);
  }

  if (selectedSlot == this->field0c) {
    return;
  }

  void** secondaryVtable = *reinterpret_cast<void***>(secondaryNationState);
  SecondaryNationSlot4CFn slot4C =
      reinterpret_cast<SecondaryNationSlot4CFn>(secondaryVtable[0x4C / 4]);
  slot4C(secondaryNationState, 0, this->field0c, 1);
}

// FUNCTION: IMPERIALISM 0x004070E5
void TGreatPower::thunk_ApplyDiplomacyPolicyStateForTargetWithCostChecks_At004070e5(int arg1,
                                                                                    int arg2) {
  ApplyDiplomacyPolicyStateForTargetWithCostChecks(arg1, arg2);
}

// FUNCTION: IMPERIALISM 0x00407392
void TGreatPower::thunk_ApplyIndexedResourceDeltaAndAdjustNationTotals_At00407392(int arg1,
                                                                                  int arg2,
                                                                                  int arg3) {
  typedef void(__fastcall * GreatPowerVtableIntFn)(TGreatPower*, int, int);

  unsigned char* self = reinterpret_cast<unsigned char*>(this);
  short* resourceByType = reinterpret_cast<short*>(self + 0x198);
  short* selectedResource = resourceByType + static_cast<short>(arg1);
  short delta = static_cast<short>(arg2);
  int scaledDelta = static_cast<int>(static_cast<short>(arg3)) * static_cast<int>(delta);
  void** vtable = this->field00;

  *selectedResource = static_cast<short>(*selectedResource + delta);
  reinterpret_cast<GreatPowerVtableIntFn>(vtable[0x0E])(this, 0, -scaledDelta);

  if (delta > 0) {
    reinterpret_cast<GreatPowerVtableIntFn>(vtable[0x66])(this, 0, arg2);
    *reinterpret_cast<int*>(self + 0x844) -= scaledDelta;
    return;
  }

  *reinterpret_cast<int*>(self + 0x840) -= scaledDelta;
  if (ApplyIndexedResourceDeltaAndAdjustNationTotals_Impl() != 0) {
    *reinterpret_cast<int*>(self + 0x910) -= arg1;
  }
}

// FUNCTION: IMPERIALISM 0x00407DB0
void TGreatPower::thunk_RefreshGreatPowerRelationPanelsAndDispatchDeltaSummary_At00407db0(void) {
  RefreshGreatPowerRelationPanelsAndDispatchDeltaSummary();
}

// FUNCTION: IMPERIALISM 0x00407E8C
void TGreatPower::thunk_NoOpAdvisoryHandlerReturn_At00407e8c(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x00408017
void TGreatPower::thunk_ResetDiplomacyNeedSlots7012AndRefreshIfModeGateMatches_At00408017(void) {
  ResetDiplomacyNeedSlots7012AndRefreshIfModeGateMatches();
}

// FUNCTION: IMPERIALISM 0x00408076
void TGreatPower::thunk_DispatchTurnEvent2103WithNationFromRecord_At00408076(void) {
  DispatchTurnEvent2103WithNationFromRecord();
}

// FUNCTION: IMPERIALISM 0x00408107
void TGreatPower::thunk_NoOpDiplomacyWarTransitionCallback_At00408107(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x00408143
void TGreatPower::thunk_HandleCityDialogHintClusterUpdate_At00408143(void* pMessage) {
  (void)pMessage;
  return;
}

// FUNCTION: IMPERIALISM 0x004083F5
void TGreatPower::thunk_QueueDiplomacyProposalCodeForTargetNation_At004083f5(void) {
  QueueDiplomacyProposalCodeForTargetNation();
}

// FUNCTION: IMPERIALISM 0x004085EE
void TGreatPower::thunk_WrapperFor_FreeHeapBufferIfNotNull_At004d8c20_At004085ee(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x00408620
void TGreatPower::thunk_ConstructTurnOrderNavigationWindowEntryViewportAdaptive(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x0040862A
void TGreatPower::thunk_ApplyImmediateDiplomacyPolicySideEffects_At0040862a(int arg1, int arg2) {
  ApplyImmediateDiplomacyPolicySideEffects(arg1, arg2);
}

// FUNCTION: IMPERIALISM 0x004090B1
void TGreatPower::thunk_NoOpNationDiplomacyCallback_At004090b1(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x00409291
void TGreatPower::thunk_InitializeNationStateRuntimeSubsystems(int arg1, int arg2) {
  InitializeNationStateRuntimeSubsystems(arg1, arg2);
}

// FUNCTION: IMPERIALISM 0x004096C4
void TGreatPower::thunk_DispatchGreatPowerQuarterlyStatusMessageLevel0_At004096c4(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x004097FA
void TGreatPower::thunk_ApplyJoinEmpireMode0GlobalDiplomacyReset_At004097fa(int arg1) {
  ApplyJoinEmpireMode0GlobalDiplomacyReset(arg1);
}

// FUNCTION: IMPERIALISM 0x004097FF
void TGreatPower::thunk_RebuildNationResourceYieldCountersAndDevelopmentTargets_At004097ff(void) {
  RebuildNationResourceYieldCountersAndDevelopmentTargets();
}

// FUNCTION: IMPERIALISM 0x004D8CC0
void TGreatPower::InitializeNationStateRuntimeSubsystems(int arg1, int arg2) {
  typedef void(__fastcall * InitializeNationIdentityFn)(int, int);
  typedef void(__fastcall * InitializeCityModelFn)(void*, int);
  typedef void(__fastcall * InitializeCityProductionFn)(int, int);
  typedef void(__fastcall * InitializeLinkedListSentinelFn)(void*, int);
  typedef void(__fastcall * ConstructPtrArrayFn)(void*, int);
  typedef void(__fastcall * InitializePtrArrayModeFn)(void*, int);
  typedef void(__fastcall * ConstructForeignMinisterFn)(void*, int);
  typedef void(__fastcall * ConstructMinisterFn)(void*, int);
  typedef void*(__fastcall * ConstructDefenseMinisterFn)(void*, int);
  typedef void(__fastcall * ConstructPtrListFn)(void*, int);

  unsigned char* self = reinterpret_cast<unsigned char*>(this);
  ConstructPtrArrayFn constructPtrArray =
      reinterpret_cast<ConstructPtrArrayFn>(thunk_ConstructObArrayWithVtable654D38);
  InitializePtrArrayModeFn initializePtrArrayMode =
      reinterpret_cast<InitializePtrArrayModeFn>(thunk_InitializeObArrayVtable654D38ModeField);

  reinterpret_cast<InitializeNationIdentityFn>(
      thunk_InitializeNationStateIdentityAndOwnedRegionList)(reinterpret_cast<int>(this), arg1);

  int* localizationTable = reinterpret_cast<int*>(ReadGlobalPointer(kAddrLocalizationTablePtr));
  if (localizationTable != 0) {
    int runtimeIndex = localizationTable[0x40 / 4];
    *reinterpret_cast<int*>(self + 0x10) =
        *reinterpret_cast<int*>(kAddrNationRuntimeSubsystemCache + runtimeIndex * 4);
  } else {
    *reinterpret_cast<int*>(self + 0x10) = 0;
  }

  *reinterpret_cast<unsigned char*>(self + 0xA0) = (static_cast<short>(arg2) == 1) ? 1 : 0;

  void* cityModel = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x20));
  if (cityModel != 0) {
    reinterpret_cast<InitializeCityModelFn>(thunk_InitializeCityModel)(cityModel, 0);
    reinterpret_cast<InitializeCityProductionFn>(thunk_InitializeCityProductionState)(
        reinterpret_cast<int>(cityModel), arg1);
  }
  *reinterpret_cast<void**>(self + 0x894) = cityModel;

  void* trackedObjectList = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x20));
  if (trackedObjectList != 0) {
    reinterpret_cast<InitializeLinkedListSentinelFn>(
        WrapperFor_InitializeLinkedListSentinelNodeWithOwnerContext_At004a8640)(
        reinterpret_cast<unsigned char*>(trackedObjectList) + 4, 0);
    *reinterpret_cast<unsigned int*>(trackedObjectList) = kAddrVtblTArmyBattle;
  }
  *reinterpret_cast<void**>(self + 0x898) = trackedObjectList;

  *reinterpret_cast<int*>(self + 0xAC) = 0;
  *reinterpret_cast<short*>(self + 0xA6) = 0x0F;
  *reinterpret_cast<int*>(self + 0x900) = 0x0F;

  void* pField848 = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x18));
  if (pField848 != 0) {
    constructPtrArray(pField848, 0);
    initializePtrArrayMode(pField848, 0);
    *reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(pField848) + 0x14) = 4;
  }
  *reinterpret_cast<void**>(self + 0x848) = pField848;

  void* pField84c = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x18));
  if (pField84c != 0) {
    constructPtrArray(pField84c, 0);
    initializePtrArrayMode(pField84c, 0);
    *reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(pField84c) + 0x14) = 4;
  }
  *reinterpret_cast<void**>(self + 0x84C) = pField84c;

  if (*reinterpret_cast<unsigned char*>(self + 0xA0) != 0) {
    void* foreignMinister = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x20));
    if (foreignMinister != 0) {
      reinterpret_cast<ConstructForeignMinisterFn>(thunk_ConstructTForeignMinister)(foreignMinister,
                                                                                    0);
    }
    reinterpret_cast<void(__cdecl*)(void)>(thunk_InitializeTForeignMinisterStateAndCounters)();
    *reinterpret_cast<void**>(self + 0x94) = foreignMinister;

    void* interiorMinister = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x20));
    if (interiorMinister != 0) {
      reinterpret_cast<ConstructMinisterFn>(thunk_WrapperFor_thunk_ConstructTMinister_At004be840)(
          interiorMinister, 0);
    }
    reinterpret_cast<void(__cdecl*)(void)>(thunk_InitializeCityInteriorMinister)();
    *reinterpret_cast<void**>(self + 0x98) = interiorMinister;

    void* defenseMinister = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x20));
    if (defenseMinister != 0) {
      defenseMinister = reinterpret_cast<ConstructDefenseMinisterFn>(
          thunk_ConstructTDefenseMinisterBaseState)(defenseMinister, 0);
    }
    reinterpret_cast<void(__cdecl*)(void)>(thunk_InitializeTMinisterBaseOrderArrayMetrics)();
    *reinterpret_cast<void**>(self + 0x9C) = defenseMinister;
  }

  int listIndex = 0;
  while (listIndex < 0x11) {
    void* relationList = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x18));
    if (relationList != 0) {
      constructPtrArray(relationList, 0);
      initializePtrArrayMode(relationList, 0);
      *reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(relationList) + 0x14) = 0x0C;
    }
    *reinterpret_cast<void**>(self + 0x850 + listIndex * 4) = relationList;
    ++listIndex;
  }

  short* diplomacyNeedState = reinterpret_cast<short*>(self + 0xB2);
  short* diplomacyGrantState = reinterpret_cast<short*>(self + 0xE0);
  unsigned char* diplomacyFlags = reinterpret_cast<unsigned char*>(self + 0x918);
  int nationSlot = 0;
  while (nationSlot < 0x17) {
    diplomacyNeedState[nationSlot] = -1;
    diplomacyGrantState[nationSlot] = -1;
    diplomacyFlags[nationSlot] = 0;
    ++nationSlot;
  }

  void* pField89c = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x20));
  if (pField89c != 0) {
    *reinterpret_cast<unsigned int*>(pField89c) = kAddrVtblRefCountedObjectBase;
    reinterpret_cast<ConstructPtrListFn>(CPtrList)(reinterpret_cast<unsigned char*>(pField89c) + 4,
                                                   0);
    *reinterpret_cast<unsigned int*>(pField89c) = kAddrVtblTArmyBattle;
  }
  *reinterpret_cast<void**>(self + 0x89C) = pField89c;

  *reinterpret_cast<void**>(self + 0x8A0) = 0;
  *reinterpret_cast<int*>(self + 0x8A4) = 0;
  *reinterpret_cast<int*>(self + 0x8A8) = 0;
  *reinterpret_cast<int*>(self + 0x8AC) = 0;
  *reinterpret_cast<short*>(self + 0x8B0) = 0;
  *reinterpret_cast<short*>(self + 0x8B4) = 0;
  *reinterpret_cast<short*>(self + 0x8B6) = 0;
  *reinterpret_cast<unsigned char*>(self + 0x904) = 1;

  void* pField908 = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x18));
  if (pField908 != 0) {
    constructPtrArray(pField908, 0);
    initializePtrArrayMode(pField908, 0);
    *reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(pField908) + 0x14) = 8;
  }
  *reinterpret_cast<void**>(self + 0x908) = pField908;

  void* pField90c = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x20));
  if (pField90c != 0) {
    *reinterpret_cast<unsigned int*>(pField90c) = kAddrVtblRefCountedObjectBase;
    reinterpret_cast<ConstructPtrListFn>(CPtrList)(reinterpret_cast<unsigned char*>(pField90c) + 4,
                                                   0);
    *reinterpret_cast<unsigned int*>(pField90c) = kAddrVtblTArmyBattle;
  }
  *reinterpret_cast<void**>(self + 0x90C) = pField90c;
  *reinterpret_cast<void**>(self + 0x960) = 0;
}

// FUNCTION: IMPERIALISM 0x004D9160
void TGreatPower::ReleaseOwnedGreatPowerObjectsAndDeleteSelf(void) {
  typedef void(__fastcall * ReleaseAt1CFn)(void*, int);
  typedef void(__fastcall * ReleaseAt24Fn)(void*, int);
  typedef void(__fastcall * ReleaseAt38Fn)(void*, int);
  typedef void(__fastcall * ReleaseAt58Fn)(void*, int);
  typedef void(__fastcall * DeleteSelfFn)(TGreatPower*, int, int);

  void* pField894 = this->pField894;
  if (pField894 != 0) {
    void** pField894Vtable = *reinterpret_cast<void***>(pField894);
    reinterpret_cast<ReleaseAt1CFn>(pField894Vtable[0x1C / 4])(pField894, 0);
  }
  this->pField894 = 0;

  void* pField848 = this->pField848;
  if (pField848 != 0) {
    void** pField848Vtable = *reinterpret_cast<void***>(pField848);
    reinterpret_cast<ReleaseAt24Fn>(pField848Vtable[0x24 / 4])(pField848, 0);
  }
  this->pField848 = 0;

  void* pField84c = this->pField84c;
  if (pField84c != 0) {
    void** pField84cVtable = *reinterpret_cast<void***>(pField84c);
    reinterpret_cast<ReleaseAt24Fn>(pField84cVtable[0x24 / 4])(pField84c, 0);
  }
  this->pField84c = 0;

  void* pField94 = this->pField94;
  if (pField94 != 0) {
    void** pField94Vtable = *reinterpret_cast<void***>(pField94);
    reinterpret_cast<ReleaseAt1CFn>(pField94Vtable[0x1C / 4])(pField94, 0);
  }
  this->pField94 = 0;

  void* pField98 = this->pField98;
  if (pField98 != 0) {
    void** pField98Vtable = *reinterpret_cast<void***>(pField98);
    reinterpret_cast<ReleaseAt1CFn>(pField98Vtable[0x1C / 4])(pField98, 0);
  }
  this->pField98 = 0;

  void* pField9c = this->pField9c;
  if (pField9c != 0) {
    void** pField9cVtable = *reinterpret_cast<void***>(pField9c);
    reinterpret_cast<ReleaseAt1CFn>(pField9cVtable[0x1C / 4])(pField9c, 0);
  }
  this->pField9c = 0;

  int listIndex = 0;
  while (listIndex < 0x11) {
    void* pField850Item = this->pField850[listIndex];
    if (pField850Item != 0) {
      void** pField850Vtable = *reinterpret_cast<void***>(pField850Item);
      reinterpret_cast<ReleaseAt24Fn>(pField850Vtable[0x24 / 4])(pField850Item, 0);
    }
    this->pField850[listIndex] = 0;
    ++listIndex;
  }

  void* pField898 = this->pField898;
  if (pField898 != 0) {
    void** pField898Vtable = *reinterpret_cast<void***>(pField898);
    reinterpret_cast<ReleaseAt58Fn>(pField898Vtable[0x58 / 4])(pField898, 0);
  }
  this->pField898 = 0;

  void* pField89c = this->pField89c;
  if (pField89c != 0) {
    void** pField89cVtable = *reinterpret_cast<void***>(pField89c);
    reinterpret_cast<ReleaseAt58Fn>(pField89cVtable[0x58 / 4])(pField89c, 0);
  }
  this->pField89c = 0;

  void* pField908 = this->pField908;
  if (pField908 != 0) {
    void** pField908Vtable = *reinterpret_cast<void***>(pField908);
    reinterpret_cast<ReleaseAt24Fn>(pField908Vtable[0x24 / 4])(pField908, 0);
  }
  this->pField908 = 0;

  void* pField90c = this->pField90c;
  if (pField90c != 0) {
    void** pField90cVtable = *reinterpret_cast<void***>(pField90c);
    reinterpret_cast<ReleaseAt58Fn>(pField90cVtable[0x58 / 4])(pField90c, 0);
  }
  this->pField90c = 0;

  void* pField44 = this->pField44;
  if (pField44 != 0) {
    void** pField44Vtable = *reinterpret_cast<void***>(pField44);
    reinterpret_cast<ReleaseAt58Fn>(pField44Vtable[0x58 / 4])(pField44, 0);
  }
  this->pField44 = 0;

  void* pField90 = this->pField90;
  if (pField90 != 0) {
    void** pField90Vtable = *reinterpret_cast<void***>(pField90);
    reinterpret_cast<ReleaseAt38Fn>(pField90Vtable[0x38 / 4])(pField90, 0);
    this->pField90 = 0;
  }

  if (this != 0) {
    reinterpret_cast<DeleteSelfFn>(this->field00[1])(this, 0, 1);
  }
}

// FUNCTION: IMPERIALISM 0x004D92E0
void TGreatPower::InitializeGreatPowerMinisterRosterAndScenarioState(int arg1) {
  typedef void(__fastcall * DeserializeRecruitFn)(void*, int, int);
  typedef void(__fastcall * StreamReadAt3CFn)(void*, int, void*, int);
  typedef int(__fastcall * StreamNoArgFn)(void*, int);
  typedef void(__fastcall * StreamReadFn)(void*, int, void*, int);
  typedef char(__fastcall * StreamReadByteFn)(void*, int, void*);
  typedef char(__fastcall * GreatPowerSlot28Fn)(TGreatPower*, int);
  typedef void(__fastcall * ObjNoArgFn)(void*, int);
  typedef int(__fastcall * ObjQueryFn)(void*, int);
  typedef void(__fastcall * ObjIntFn)(void*, int, int);
  typedef void(__fastcall * ObjPtrFn)(void*, int, void*);
  typedef void(__fastcall * ConstructNoArgFn)(void*, int);
  typedef void*(__fastcall * ConstructDefenseMinisterFn)(void*, int);

  int advanceTurnState = *reinterpret_cast<int*>(kAddrAdvanceTurnMachineState);
  const int streamHandle = arg1;

  reinterpret_cast<DeserializeRecruitFn>(
      thunk_DeserializeRecruitScenarioAndInstantiateOrders_At00409089)(this, 0, arg1);

  void* stream = reinterpret_cast<void*>(streamHandle);
  void** streamVtable = *reinterpret_cast<void***>(stream);
  StreamReadAt3CFn streamSlot3C = reinterpret_cast<StreamReadAt3CFn>(streamVtable[0x3C / 4]);
  StreamNoArgFn streamSlot40 = reinterpret_cast<StreamNoArgFn>(streamVtable[0x40 / 4]);
  StreamReadFn streamRead = reinterpret_cast<StreamReadFn>(streamVtable[0]);
  StreamReadByteFn streamSlotB0 = reinterpret_cast<StreamReadByteFn>(streamVtable[0xB0 / 4]);

  streamSlot3C(stream, 0, &this->fieldA0, 1);
  streamSlot3C(stream, 0, &this->fieldA2, 2);
  streamSlot3C(stream, 0, &this->fieldA4, 2);
  streamSlot3C(stream, 0, &this->fieldA6, 2);
  streamSlot3C(stream, 0, &this->fieldA8, 2);
  if (advanceTurnState < 0x3E) {
    streamSlot3C(stream, 0, &this->fieldAC, 2);
  } else {
    streamSlot3C(stream, 0, &this->fieldAC, 4);
  }
  streamSlot3C(stream, 0, &this->fieldB0, 2);
  streamSlot3C(stream, 0, this->fieldB2, 0x2E);
  SwapShortArrayBytes(this->fieldB2, 0x17);
  streamSlot3C(stream, 0, this->fieldE0, 0x2E);
  SwapShortArrayBytes(this->fieldE0, 0x17);
  streamSlot3C(stream, 0, this->field10e, 0x2E);
  SwapShortArrayBytes(this->field10e, 0x17);
  streamSlot3C(stream, 0, this->field13c, 0x2E);
  SwapShortArrayBytes(this->field13c, 0x17);
  streamSlot3C(stream, 0, this->field16a, 0x2E);
  SwapShortArrayBytes(this->field16a, 0x17);
  streamSlot3C(stream, 0, this->field198, 0x2E);
  SwapShortArrayBytes(this->field198, 0x17);
  streamSlot3C(stream, 0, this->field1c6, 0x2E);
  SwapShortArrayBytes(this->field1c6, 0x17);

  if (advanceTurnState > 0x16) {
    streamSlot3C(stream, 0, this->field1f4, 0x2E);
    SwapShortArrayBytes(this->field1f4, 0x17);
  }

  streamSlot3C(stream, 0, this->field222, 0x2E);
  SwapShortArrayBytes(this->field222, 0x17);
  streamSlot3C(stream, 0, this->field250, 0x2E);
  SwapShortArrayBytes(this->field250, 0x17);

  streamSlot3C(stream, 0, &this->field840, 4);
  streamSlot3C(stream, 0, &this->field844, 4);
  streamSlot3C(stream, 0, this->field280, 0x5C0);
  ReverseDwordArrayBytes(this->field280, 0x170);

  streamSlot3C(stream, 0, reinterpret_cast<unsigned char*>(this) + 0x8C8, 0x0D);
  streamSlot3C(stream, 0, this->field8d6, 0x1A);
  SwapShortArrayBytes(this->field8d6, 0x0D);

  void* pField848 = this->pField848;
  void** pField848Vtable = *reinterpret_cast<void***>(pField848);
  reinterpret_cast<ObjNoArgFn>(pField848Vtable[0x18 / 4])(pField848, 0);
  void* pField84c = this->pField84c;
  void** pField84cVtable = *reinterpret_cast<void***>(pField84c);
  reinterpret_cast<ObjNoArgFn>(pField84cVtable[0x18 / 4])(pField84c, 0);
  int listIndex = 0;
  while (listIndex < 0x11) {
    void* listObj = this->pField850[listIndex];
    void** listVtable = *reinterpret_cast<void***>(listObj);
    reinterpret_cast<ObjNoArgFn>(listVtable[0x18 / 4])(listObj, 0);
    ++listIndex;
  }

  if (advanceTurnState < 0x1D) {
    if (this->field0e == -1) {
      GreatPowerSlot28Fn slot28 = reinterpret_cast<GreatPowerSlot28Fn>(this->field00[0x28]);
      char gate = slot28(this, 0);
      if (gate == 0) {
        void* pField94 = this->pField94;
        void** pField94Vtable = *reinterpret_cast<void***>(pField94);
        reinterpret_cast<ObjNoArgFn>(pField94Vtable[0x18 / 4])(pField94, 0);
        void* pField98 = this->pField98;
        void** pField98Vtable = *reinterpret_cast<void***>(pField98);
        reinterpret_cast<ObjNoArgFn>(pField98Vtable[0x18 / 4])(pField98, 0);
        void* pField9c = this->pField9c;
        void** pField9cVtable = *reinterpret_cast<void***>(pField9c);
        reinterpret_cast<ObjNoArgFn>(pField9cVtable[0x18 / 4])(pField9c, 0);
      }
      void* pField894 = this->pField894;
      void** pField894Vtable = *reinterpret_cast<void***>(pField894);
      reinterpret_cast<ObjNoArgFn>(pField894Vtable[0x18 / 4])(pField894, 0);
    } else {
      void* pField94 = this->pField94;
      if (pField94 != 0) {
        void** pField94Vtable = *reinterpret_cast<void***>(pField94);
        reinterpret_cast<ObjNoArgFn>(pField94Vtable[0x1C / 4])(pField94, 0);
      }
      this->pField94 = 0;

      void* pField98 = this->pField98;
      if (pField98 != 0) {
        void** pField98Vtable = *reinterpret_cast<void***>(pField98);
        reinterpret_cast<ObjNoArgFn>(pField98Vtable[0x1C / 4])(pField98, 0);
      }
      this->pField98 = 0;

      void* pField9c = this->pField9c;
      if (pField9c != 0) {
        void** pField9cVtable = *reinterpret_cast<void***>(pField9c);
        reinterpret_cast<ObjNoArgFn>(pField9cVtable[0x1C / 4])(pField9c, 0);
      }
      this->pField9c = 0;

      void* pField894 = this->pField894;
      if (pField894 != 0) {
        void** pField894Vtable = *reinterpret_cast<void***>(pField894);
        reinterpret_cast<ObjNoArgFn>(pField894Vtable[0x1C / 4])(pField894, 0);
      }
      this->pField894 = 0;
    }
  } else {
    int ministerMask = streamSlot40(stream, 0);

    if ((ministerMask & 1) == 0) {
      void* pField94 = this->pField94;
      if (pField94 != 0) {
        void** pField94Vtable = *reinterpret_cast<void***>(pField94);
        reinterpret_cast<ObjNoArgFn>(pField94Vtable[0x1C / 4])(pField94, 0);
      }
      this->pField94 = 0;
    } else {
      void* pField94 = this->pField94;
      if (pField94 == 0) {
        pField94 = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x20));
        if (pField94 != 0) {
          reinterpret_cast<ConstructNoArgFn>(thunk_ConstructTForeignMinister)(pField94, 0);
        }
        this->pField94 = pField94;
        reinterpret_cast<void(__cdecl*)(void)>(thunk_InitializeTForeignMinisterStateAndCounters)();
      }
      if (pField94 != 0) {
        void** pField94Vtable = *reinterpret_cast<void***>(pField94);
        reinterpret_cast<ObjNoArgFn>(pField94Vtable[0x18 / 4])(pField94, 0);
      }
    }

    if ((ministerMask & 2) == 0) {
      void* pField98 = this->pField98;
      if (pField98 != 0) {
        void** pField98Vtable = *reinterpret_cast<void***>(pField98);
        reinterpret_cast<ObjNoArgFn>(pField98Vtable[0x1C / 4])(pField98, 0);
      }
      this->pField98 = 0;
    } else {
      void* pField98 = this->pField98;
      if (pField98 == 0) {
        pField98 = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x20));
        if (pField98 != 0) {
          reinterpret_cast<ConstructNoArgFn>(thunk_WrapperFor_thunk_ConstructTMinister_At004be840)(
              pField98, 0);
        }
        reinterpret_cast<void(__cdecl*)(void)>(thunk_InitializeCityInteriorMinister)();
        this->pField98 = pField98;
      }
      if (pField98 != 0) {
        void** pField98Vtable = *reinterpret_cast<void***>(pField98);
        reinterpret_cast<ObjNoArgFn>(pField98Vtable[0x18 / 4])(pField98, 0);
      }
    }

    if ((ministerMask & 4) == 0) {
      void* pField9c = this->pField9c;
      if (pField9c != 0) {
        void** pField9cVtable = *reinterpret_cast<void***>(pField9c);
        reinterpret_cast<ObjNoArgFn>(pField9cVtable[0x1C / 4])(pField9c, 0);
      }
      this->pField9c = 0;
    } else {
      void* pField9c = this->pField9c;
      if (pField9c == 0) {
        pField9c = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x20));
        if (pField9c != 0) {
          pField9c = reinterpret_cast<ConstructDefenseMinisterFn>(
              thunk_ConstructTDefenseMinisterBaseState)(pField9c, 0);
        }
        reinterpret_cast<void(__cdecl*)(void)>(thunk_InitializeTMinisterBaseOrderArrayMetrics)();
        this->pField9c = pField9c;
      }
      if (pField9c != 0) {
        void** pField9cVtable = *reinterpret_cast<void***>(pField9c);
        reinterpret_cast<ObjNoArgFn>(pField9cVtable[0x18 / 4])(pField9c, 0);
      }
    }

    void* pField894 = this->pField894;
    if ((ministerMask & 8) == 0) {
      if (pField894 != 0) {
        void** pField894Vtable = *reinterpret_cast<void***>(pField894);
        reinterpret_cast<ObjNoArgFn>(pField894Vtable[0x1C / 4])(pField894, 0);
      }
      this->pField894 = 0;
    } else if (pField894 != 0) {
      void** pField894Vtable = *reinterpret_cast<void***>(pField894);
      reinterpret_cast<ObjNoArgFn>(pField894Vtable[0x18 / 4])(pField894, 0);
    }
  }

  void* pField898 = this->pField898;
  void** pField898Vtable = *reinterpret_cast<void***>(pField898);
  int hasItems = reinterpret_cast<ObjQueryFn>(pField898Vtable[0x48 / 4])(pField898, 0);
  if (hasItems != 0) {
    reinterpret_cast<ObjNoArgFn>(pField898Vtable[0x54 / 4])(pField898, 0);
  }
  reinterpret_cast<ObjNoArgFn>(pField898Vtable[0x18 / 4])(pField898, 0);

  int townCount = 0;
  streamSlot3C(stream, 0, &townCount, 4);

  if (townCount > 0) {
    void** pField898Vtable = *reinterpret_cast<void***>(pField898);
    ObjPtrFn pField898Slot30 = reinterpret_cast<ObjPtrFn>(pField898Vtable[0x30 / 4]);
    int townOrdinal = 1;
    while (townOrdinal <= townCount) {
      void* townMarker = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x20));
      if (townMarker != 0) {
        reinterpret_cast<ConstructNoArgFn>(thunk_ConstructFrogCityMarker)(townMarker, 0);
        void** townVtable = *reinterpret_cast<void***>(townMarker);
        reinterpret_cast<ObjNoArgFn>(townVtable[0x18 / 4])(townMarker, 0);
        pField898Slot30(pField898, 0, townMarker);
      }
      ++townOrdinal;
    }
  }

  void* pField894 = this->pField894;
  if (townCount > 0) {
    void** pField898Vtable = *reinterpret_cast<void***>(pField898);
    reinterpret_cast<ObjNoArgFn>(pField898Vtable[0x4C / 4])(pField898, 0);
    void** pField894Vtable = *reinterpret_cast<void***>(pField894);
    reinterpret_cast<ObjNoArgFn>(pField894Vtable[0x44 / 4])(pField894, 0);
  }

  void* pField89c = this->pField89c;
  void** pField89cVtable = *reinterpret_cast<void***>(pField89c);
  hasItems = reinterpret_cast<ObjQueryFn>(pField89cVtable[0x48 / 4])(pField89c, 0);
  if (hasItems != 0) {
    reinterpret_cast<ObjNoArgFn>(pField89cVtable[0x54 / 4])(pField89c, 0);
  }
  reinterpret_cast<ObjNoArgFn>(pField89cVtable[0x18 / 4])(pField89c, 0);

  int unusedOrderCount = 0;
  streamSlot3C(stream, 0, &unusedOrderCount, 4);

  int orderOrdinal = 1;
  while (orderOrdinal < 5) {
    void* civOrderObj = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x20));
    if (civOrderObj != 0) {
      reinterpret_cast<ConstructNoArgFn>(thunk_InitializeCivUnitOrderObject)(civOrderObj, 0);
      this->thunk_InitializeCivWorkOrderState(0, -1, this->field0c);
      void** civOrderVtable = *reinterpret_cast<void***>(civOrderObj);
      reinterpret_cast<ObjNoArgFn>(civOrderVtable[6])(civOrderObj, 0);
    }
    ++orderOrdinal;
  }

  streamRead(stream, 0, &this->field8f0, 4);
  streamRead(stream, 0, &this->field8f4, 1);
  streamRead(stream, 0, &this->pField8f8, 4);
  streamRead(stream, 0, &this->field8fc, 1);
  streamRead(stream, 0, &this->field900, 4);
  streamRead(stream, 0, &this->field904, 1);

  if (advanceTurnState > 0x0E) {
    void* pField90c = this->pField90c;
    void** pField90cVtable = *reinterpret_cast<void***>(pField90c);
    reinterpret_cast<ObjIntFn>(pField90cVtable[0x18 / 4])(pField90c, 0, streamHandle);

    int nodeCount = 0;
    streamRead(stream, 0, &nodeCount, 4);
    if (nodeCount > 0) {
      ObjPtrFn pField90cSlot30 = reinterpret_cast<ObjPtrFn>(pField90cVtable[0x30 / 4]);
      int nodeOrdinal = 1;
      while (nodeOrdinal <= nodeCount) {
        unsigned char hasNode = 0;
        char markerOk = streamSlotB0(stream, 0, &hasNode);
        if (markerOk != 0) {
          pField90cSlot30(pField90c, 0, 0);
        }
        ++nodeOrdinal;
      }
    }
  }

  if (advanceTurnState > 0x25) {
    streamRead(stream, 0, &this->field910, 4);
    streamRead(stream, 0, &this->field914, 4);
  }
  if (advanceTurnState > 0x2F) {
    streamRead(stream, 0, this->field918, 0x17);
  }
  if (advanceTurnState > 0x34) {
    streamRead(stream, 0, &this->pField960, 4);
  }
}

// Updates Great Power pressure/escalation state and propagates summary messages when thresholds
// cross.

// FUNCTION: IMPERIALISM 0x004DB380
void TGreatPower::UpdateGreatPowerPressureStateAndDispatchEscalationMessage(void) {
  typedef int(__fastcall * GreatPowerGetIntFn)(TGreatPower*, int);

  void* localizationTable = ReadGlobalPointer(kAddrLocalizationTablePtr);
  int localeIndex = 0;
  if (localizationTable != 0) {
    localeIndex =
        *reinterpret_cast<int*>(reinterpret_cast<unsigned char*>(localizationTable) + 0x40);
  }

  GreatPowerGetIntFn getBasePressure = reinterpret_cast<GreatPowerGetIntFn>(this->field00[0x5F]);
  int basePressure = 0;
  if (getBasePressure != 0) {
    basePressure = getBasePressure(this, 0);
  }

  basePressure += static_cast<int>(this->field13c[0x15]) * 200;
  basePressure += static_cast<int>(this->field13c[0x14]) * 500;
  basePressure += this->field840;

  int minPressure = *reinterpret_cast<int*>(kAddrNationBasePressureByLocale + localeIndex * 4);
  if (basePressure < minPressure) {
    basePressure = minPressure;
  }

  int blendedPressure = (this->field8f0 * 0x5A + basePressure * 1000) / 100;
  this->field8f0 = blendedPressure;
  int pressureBand = blendedPressure / 100;
  int relationScore = this->field10;
  signed char* pressureCounter = &this->field8f4;
  signed char* escalationCounter = &this->field8fc;

  if (relationScore < 0) {
    if (-(pressureBand / 2) == relationScore || -relationScore < pressureBand / 2) {
      *escalationCounter = 1;
    } else if (-pressureBand == relationScore || -relationScore < pressureBand) {
      if (*escalationCounter > 1) {
        int nextPressure = static_cast<int>(*pressureCounter) +
                           ReadLocaleByteStep(kAddrGreatPowerPressureRiseStep, localeIndex);
        int pressureCap = *reinterpret_cast<int*>(kAddrGreatPowerPressureRiseCap + localeIndex * 4);
        if (nextPressure > pressureCap) {
          nextPressure = pressureCap;
        }
        *pressureCounter = static_cast<signed char>(nextPressure);
      }
      *escalationCounter = 2;
    } else {
      int nextPressure = static_cast<int>(*pressureCounter) +
                         ReadLocaleByteStep(kAddrGreatPowerPressureRiseStep, localeIndex);
      int pressureCap = *reinterpret_cast<int*>(kAddrGreatPowerPressureRiseCap + localeIndex * 4);
      if (nextPressure > pressureCap) {
        nextPressure = pressureCap;
      }
      *pressureCounter = static_cast<signed char>(nextPressure);

      if (*escalationCounter < 3) {
        *escalationCounter = 3;
      } else {
        *escalationCounter = static_cast<signed char>(*escalationCounter + 1);
      }

      int escalationValue = static_cast<int>(*escalationCounter);
      int hardThreshold =
          *reinterpret_cast<int*>(kAddrGreatPowerPressureHardAlertThreshold + localeIndex * 4);
      int softThreshold = *reinterpret_cast<int*>(kAddrCompileGreatPowerValue + localeIndex * 4);
      if (escalationValue >= hardThreshold || escalationValue >= softThreshold) {
        BuildGreatPowerRelationshipDeltaSummaryAndDispatchMessage();
      }
    }
  } else {
    if (*escalationCounter != 0) {
      int nextPressure = static_cast<int>(*pressureCounter) -
                         ReadLocaleByteStep(kAddrGreatPowerPressureDecayStep, localeIndex);
      int minFloor = *reinterpret_cast<int*>(kAddrGreatPowerPressureMinFloor + localeIndex * 4);
      if (nextPressure < minFloor) {
        nextPressure = minFloor;
      }
      *pressureCounter = static_cast<signed char>(nextPressure);
    }
    *escalationCounter = 0;
  }

  relationScore = this->field10;
  if (relationScore >= 0) {
    this->pField8f8 = 0;
    return;
  }

  int drainAmount = (199 - static_cast<int>(*pressureCounter) * relationScore) / 200;
  this->pField8f8 = reinterpret_cast<void*>(drainAmount);
  this->field10 = relationScore - drainAmount;
}

// FUNCTION: IMPERIALISM 0x004DBD20
void TGreatPower::RebuildNationResourceYieldCountersAndDevelopmentTargets(void) {
  typedef char(__fastcall * GlobalMapMetricProc)(void*, int, int, int);
  typedef void(__fastcall * GreatPowerNeedUpdateProc)(TGreatPower*, int, int, int);

  const int kNeedTypeCount = 0x17;
  const int kMapRegionSlots = 0x1950;
  const int kTerrainRecordStride = 0x24;
  const int kCityRecordStride = 0xA8;
  const int kTerrainResourceTypeOffset = 0x11;
  const int kTerrainGateFlagOffset = 0x13;
  const int kTerrainCityIndexOffset = 0x14;
  const int kTerrainRoadFlagOffset = 2;
  const int kCityOwnerSlotOffset = 4;
  const int kCityDevelopmentBaseOffset = 0x82;

  short* currentNeedByType = this->field10e;
  short* developmentByType = this->field10e + 7; // +0x11c overlays this runtime array.
  short* targetNeedByType = this->field13c;
  short& controlledRegionCount = this->field10e[0x13]; // +0x134
  char* influenceByRegion = thunk_BuildCityInfluenceLevelMap();
  int* globalMapState = reinterpret_cast<int*>(ReadGlobalPointer(kAddrGlobalMapStatePtr));
  int regionOffset = 0;
  int nationSlot = 0;

  for (int i = 0; i < kNeedTypeCount; ++i) {
    currentNeedByType[i] = 0;
  }
  controlledRegionCount = 0;

  if (influenceByRegion != 0 && globalMapState != 0) {
    int terrainStateTable = globalMapState[3];
    int cityStateTable = globalMapState[4];
    void** globalMapVtable = *reinterpret_cast<void***>(globalMapState);
    GlobalMapMetricProc mapMetric =
        reinterpret_cast<GlobalMapMetricProc>(globalMapVtable[0xC4 / 4]);

    while (static_cast<short>(nationSlot) < kMapRegionSlots) {
      char influence = *influenceByRegion;
      if (influence != 0) {
        if (*reinterpret_cast<char*>(terrainStateTable + kTerrainGateFlagOffset + regionOffset) ==
            0) {
          if (influence == 2) {
            ++controlledRegionCount;
          }
        } else {
          for (int edgeIndex = 0; edgeIndex < 2; ++edgeIndex) {
            short resourceType = static_cast<short>(*reinterpret_cast<char*>(
                terrainStateTable + regionOffset + kTerrainResourceTypeOffset + edgeIndex));
            if (resourceType != -1) {
              char contribution = mapMetric(globalMapState, 0, nationSlot, edgeIndex);
              currentNeedByType[resourceType] = static_cast<short>(
                  currentNeedByType[resourceType] + static_cast<short>(contribution));
            }
          }

          if (*reinterpret_cast<char*>(terrainStateTable + kTerrainRoadFlagOffset + regionOffset) !=
                  0 &&
              influence == 2) {
            ++controlledRegionCount;
          }

          int cityRecordOffset = static_cast<int>(*reinterpret_cast<short*>(
                                     terrainStateTable + kTerrainCityIndexOffset + regionOffset)) *
                                 kCityRecordStride;
          if (*reinterpret_cast<short*>(cityStateTable + cityRecordOffset + kCityOwnerSlotOffset) ==
              static_cast<short>(nationSlot)) {
            for (int devIdx = 0; devIdx < 10; ++devIdx) {
              developmentByType[devIdx] = static_cast<short>(
                  developmentByType[devIdx] +
                  *reinterpret_cast<short*>(cityStateTable + cityRecordOffset +
                                            kCityDevelopmentBaseOffset + devIdx * 2));
            }
          }
        }
      }

      ++nationSlot;
      ++influenceByRegion;
      regionOffset += kTerrainRecordStride;
    }
  }

  GreatPowerNeedUpdateProc updateNeed =
      reinterpret_cast<GreatPowerNeedUpdateProc>(this->field00[0x45]);
  for (int typeIndex = 0; typeIndex < kNeedTypeCount; ++typeIndex) {
    if (currentNeedByType[typeIndex] < targetNeedByType[typeIndex]) {
      updateNeed(this, 0, typeIndex, currentNeedByType[typeIndex]);
    }
  }
}

// Advances per-region development counters and emits diplomacy/map events when stage changes.

// FUNCTION: IMPERIALISM 0x004DBF00
void TGreatPower::AdvanceOwnedRegionDevelopmentCountersAndDispatchEvents(void) {
  typedef int(__fastcall * RegionListCountFn)(void*, int);
  typedef int(__fastcall * RegionListGetByOrdinalFn)(void*, int, int);
  typedef short(__fastcall * LocalizationTickFn)(void*, int);
  typedef char(__fastcall * GlobalMapMetricFn)(void*, int, int, int);
  typedef int(__fastcall * GreatPowerDispatchEventFn)(TGreatPower*, int, int, int);
  typedef int(__cdecl * CityProductionFn)(void*, int);
  typedef void(__cdecl * RegionStageSetterFn)(short, unsigned char);
  typedef void(__cdecl * RegionRedrawFn)(short);

  void* regionList = this->pField90;
  if (regionList == 0) {
    return;
  }

  RegionListCountFn getRegionCount =
      reinterpret_cast<RegionListCountFn>((*reinterpret_cast<void***>(regionList))[0x28 / 4]);
  RegionListGetByOrdinalFn getRegionByOrdinal = reinterpret_cast<RegionListGetByOrdinalFn>(
      (*reinterpret_cast<void***>(regionList))[0x24 / 4]);
  CityProductionFn getProduction =
      reinterpret_cast<CityProductionFn>(thunk_GetCityBuildingProductionValueBySlot);
  RegionStageSetterFn setRegionStage =
      reinterpret_cast<RegionStageSetterFn>(thunk_SetGlobalRegionDevelopmentStageByte);
  RegionRedrawFn dispatchRedraw =
      reinterpret_cast<RegionRedrawFn>(thunk_DispatchCityRedrawInvalidateEvent);
  GreatPowerDispatchEventFn dispatchNationEvent =
      reinterpret_cast<GreatPowerDispatchEventFn>(this->field00[0x2E]);

  int totalRegions = getRegionCount(regionList, 0);
  int regionOrdinal = 1;
  while (regionOrdinal <= totalRegions) {
    short regionId = static_cast<short>(getRegionByOrdinal(regionList, 0, regionOrdinal));
    unsigned char pendingStage = 0;
    unsigned char needsRedraw = 0;

    void* globalMapState = ReadGlobalPointer(kAddrGlobalMapStatePtr);
    void* localizationTable = ReadGlobalPointer(kAddrLocalizationTablePtr);
    if (globalMapState != 0 && localizationTable != 0) {
      char* cityTable =
          *reinterpret_cast<char**>(reinterpret_cast<unsigned char*>(globalMapState) + 0x10);
      char* terrainTable =
          *reinterpret_cast<char**>(reinterpret_cast<unsigned char*>(globalMapState) + 0x0C);
      if (cityTable != 0 && terrainTable != 0) {
        char* cityRecord = cityTable + regionId * 0xA8;
        short ownerSlot = this->field88;
        if (*reinterpret_cast<short*>(cityRecord + 4) != ownerSlot) {
          LocalizationTickFn getTurnTick = reinterpret_cast<LocalizationTickFn>(
              (*reinterpret_cast<void***>(localizationTable))[0x3C / 4]);
          unsigned int turnDelta = static_cast<unsigned int>(
              static_cast<int>(getTurnTick(localizationTable, 0)) -
              static_cast<int>(*reinterpret_cast<short*>(cityRecord + 6)));

          if (turnDelta > 4) {
            int resourceSums[0x17];
            int i = 0;
            while (i < 0x17) {
              resourceSums[i] = 0;
              ++i;
            }

            int linkedCount = static_cast<signed char>(*(cityRecord + 0x3A));
            int linkedIndex = 0;
            GlobalMapMetricFn mapMetric = reinterpret_cast<GlobalMapMetricFn>(
                (*reinterpret_cast<void***>(globalMapState))[0xC4 / 4]);
            while (linkedIndex < linkedCount) {
              short linkedRegion = *reinterpret_cast<short*>(cityRecord + 0x42 + linkedIndex * 2);
              int edge = 0;
              while (edge < 2) {
                signed char resourceType = *reinterpret_cast<signed char*>(
                    terrainTable + 0x11 + edge + linkedRegion * 0x24);
                if (resourceType != -1) {
                  resourceSums[resourceType] +=
                      static_cast<int>(mapMetric(globalMapState, 0, linkedRegion, edge));
                }
                ++edge;
              }
              ++linkedIndex;
            }

            short* stage1CounterA = reinterpret_cast<short*>(cityRecord + 0x84);
            short* stage1CounterB = reinterpret_cast<short*>(cityRecord + 0x86);
            short* stage1CounterC = reinterpret_cast<short*>(cityRecord + 0x8A);
            short* stage1CounterD = reinterpret_cast<short*>(cityRecord + 0x8C);
            short* stage2CounterA = reinterpret_cast<short*>(cityRecord + 0x8E);
            short* stage2CounterB = reinterpret_cast<short*>(cityRecord + 0x90);
            short* stage2CounterC = reinterpret_cast<short*>(cityRecord + 0x92);

            if ((turnDelta & 1U) == 0) {
              int sum01 = resourceSums[0] + resourceSums[1];
              if (sum01 != 0) {
                int prod = getProduction(cityRecord, 1);
                int limit = (static_cast<int>(*stage1CounterA) +
                             ((static_cast<int>(*stage1CounterA) >> 0x1f) & 3U)) >>
                            2;
                int prodLimit = (prod + ((prod >> 0x1f) & 3U)) >> 2;
                if (limit < prodLimit && static_cast<int>(*stage1CounterA) < sum01 / 2) {
                  pendingStage = 1;
                  *stage1CounterA = static_cast<short>(*stage1CounterA + 1);
                  needsRedraw = 1;
                }
              }

              if (resourceSums[2] != 0) {
                int prod = getProduction(cityRecord, 5);
                int prodLimit = (prod + ((prod >> 0x1f) & 3U)) >> 2;
                if (static_cast<int>(*stage1CounterB) < prodLimit &&
                    static_cast<int>(*stage1CounterB) < resourceSums[2] / 2) {
                  pendingStage = 1;
                  *stage1CounterB = static_cast<short>(*stage1CounterB + 1);
                  needsRedraw = 1;
                }
              }

              if (resourceSums[3] != 0) {
                int prod = getProduction(cityRecord, 3);
                int prodLimit = (prod + ((prod >> 0x1f) & 3U)) >> 2;
                if (static_cast<int>(*stage1CounterC) < prodLimit &&
                    static_cast<int>(*stage1CounterC) < resourceSums[3] / 2) {
                  pendingStage = 1;
                  *stage1CounterC = static_cast<short>(*stage1CounterC + 1);
                  needsRedraw = 1;
                }
              }

              void* orderCapabilityState = ReadGlobalPointer(kAddrCityOrderCapabilityStatePtr);
              int capabilityScore = getProduction(cityRecord, 7);
              if (capabilityScore != 0 && orderCapabilityState != 0 &&
                  *reinterpret_cast<unsigned char*>(
                      reinterpret_cast<unsigned char*>(orderCapabilityState) + 0x193) != 0) {
                if (static_cast<int>(*stage1CounterD) < capabilityScore / 2) {
                  pendingStage = 1;
                  *stage1CounterD = static_cast<short>(*stage1CounterD + 1);
                  needsRedraw = 1;
                }
              }
            }

            if (turnDelta > 9 && (turnDelta & 1U) != 0) {
              if (*stage1CounterA != 0 &&
                  static_cast<int>(*stage2CounterA) < static_cast<int>(*stage1CounterA) / 2) {
                pendingStage = 2;
                *stage2CounterA = static_cast<short>(*stage2CounterA + 1);
                needsRedraw = 1;
              }
              if (*stage1CounterB != 0 &&
                  static_cast<int>(*stage2CounterB) < static_cast<int>(*stage1CounterB) / 2) {
                pendingStage = 2;
                *stage2CounterB = static_cast<short>(*stage2CounterB + 1);
                needsRedraw = 1;
              }
              if (*stage1CounterC != 0 &&
                  static_cast<int>(*stage2CounterC) < static_cast<int>(*stage1CounterC) / 2) {
                pendingStage = 2;
                *stage2CounterC = static_cast<short>(*stage2CounterC + 1);
                needsRedraw = 1;
              }
            }

            if (*reinterpret_cast<unsigned char*>(cityRecord + 2) < pendingStage) {
              setRegionStage(regionId, pendingStage);
              if (pendingStage == 2) {
                dispatchNationEvent(this, 0, 4, regionId);
              } else {
                dispatchNationEvent(this, 0, 3, regionId);
                if (this->field8d0 < 0x33) {
                  dispatchNationEvent(this, 0, 8, -1);
                }
              }
            }
          }

          if (*reinterpret_cast<int*>(reinterpret_cast<unsigned char*>(localizationTable) + 0x44) !=
                  0 &&
              needsRedraw != 0) {
            dispatchRedraw(regionId);
          }
        }
      }
    }

    ++regionOrdinal;
  }
}

// FUNCTION: IMPERIALISM 0x004DC9F0
void TGreatPower::RefreshGreatPowerRelationPanelsAndDispatchDeltaSummary(void) {
  typedef void(__fastcall * GreatPowerNoArgFn)(TGreatPower*);
  typedef void(__fastcall * ManagerNoArgFn)(void*);

  unsigned char* self = reinterpret_cast<unsigned char*>(this);
  if (*reinterpret_cast<void**>(self + 0x894) == 0) {
    return;
  }

  void** vtable = this->field00;
  reinterpret_cast<GreatPowerNoArgFn>(vtable[0x4D])(this);
  reinterpret_cast<GreatPowerNoArgFn>(vtable[0x4E])(this);
  reinterpret_cast<GreatPowerNoArgFn>(vtable[0x43])(this);
  BuildGreatPowerRelationshipDeltaSummaryAndDispatchMessage();
  void* relationManager = *reinterpret_cast<void**>(self + 0x894);
  void** managerVtable = *reinterpret_cast<void***>(relationManager);
  reinterpret_cast<ManagerNoArgFn>(managerVtable[0x28 / 4])(relationManager);
  reinterpret_cast<GreatPowerNoArgFn>(vtable[0x2A])(this);
}

// FUNCTION: IMPERIALISM 0x004DD470
void TGreatPower::ResetDiplomacyNeedSlots7012AndRefreshIfModeGateMatches(void) {
  typedef void(__fastcall * GreatPowerSetNeedSlotFn)(TGreatPower*, int, int, int);
  typedef void(__fastcall * GreatPowerRefreshNeedPanelsFn)(TGreatPower*, int);

  int* localizationTable = reinterpret_cast<int*>(ReadGlobalPointer(kAddrLocalizationTablePtr));
  if (localizationTable == 0) {
    return;
  }
  if (localizationTable[0x40 / 4] != 0 || localizationTable[0x08 / 4] != 2) {
    return;
  }

  GreatPowerSetNeedSlotFn setNeedSlot =
      reinterpret_cast<GreatPowerSetNeedSlotFn>(this->field00[0x69]);
  GreatPowerRefreshNeedPanelsFn refreshNeedPanels =
      reinterpret_cast<GreatPowerRefreshNeedPanelsFn>(this->field00[0x6A]);
  setNeedSlot(this, 0, 7, -1);
  setNeedSlot(this, 0, 0, -1);
  setNeedSlot(this, 0, 1, -1);
  setNeedSlot(this, 0, 2, -1);
  refreshNeedPanels(this, 0);
}

// FUNCTION: IMPERIALISM 0x004DD4E0
void TGreatPower::AssignFallbackNationsToUnfilledDiplomacyNeedSlots(void) {
  const int kMajorNationCount = 7;
  const int kNeedSlotStart = 7;
  const int kNeedSlotEndExclusive = 12;
  const int kNeedSlotFallback = 5;

  if (this->fieldA0 == 0) {
    if (this->pField94 != 0) {
      Object_CallSlot8CNoArgs(this->pField94);
    }
    return;
  }

  void** nationStates = reinterpret_cast<void**>(kAddrNationStates);
  void* diplomacyManager = ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr);

  bool hasUnfilledNeed = false;
  for (int needSlot = kNeedSlotStart; needSlot < kNeedSlotEndExclusive; ++needSlot) {
    if (GreatPower_GetNeedSlotValue(this, needSlot) < 0) {
      hasUnfilledNeed = true;
      break;
    }
  }

  if (hasUnfilledNeed) {
    for (int needSlot = kNeedSlotStart; needSlot < kNeedSlotEndExclusive; ++needSlot) {
      if (GreatPower_GetNeedSlotValue(this, needSlot) >= 0) {
        continue;
      }

      int selectedNation = -1;
      for (int majorNation = 0; majorNation < kMajorNationCount; ++majorNation) {
        if (majorNation == this->field0c) {
          continue;
        }
        void* nationState = nationStates[majorNation];
        if (nationState == 0 || NationState_IsBusyA0(nationState) != 0) {
          continue;
        }
        selectedNation = majorNation;
        break;
      }

      if (selectedNation >= 0) {
        void* selectedNationState = nationStates[selectedNation];
        if (selectedNationState != 0) {
          NationState_AssignNeedSlotFromSource(selectedNationState, needSlot, this->field0c);
        }
      }
    }
  }

  if (GreatPower_GetNeedSlotValue(this, kNeedSlotFallback) != -1) {
    return;
  }

  for (int majorNation = 0; majorNation < kMajorNationCount; ++majorNation) {
    if (majorNation == this->field0c) {
      continue;
    }
    if (IsNationSlotEligibleForEventProcessingFast(majorNation) == 0) {
      continue;
    }
    if (diplomacyManager != 0 &&
        Diplomacy_HasPolicyWithNation(diplomacyManager, majorNation, this->field0c) != 0) {
      continue;
    }

    void* nationState = nationStates[majorNation];
    if (nationState != 0) {
      NationState_AssignNeedSlotFromSource(nationState, kNeedSlotFallback, this->field0c);
    }
    break;
  }
}

// FUNCTION: IMPERIALISM 0x004DDA90
void TGreatPower::QueueInterNationEventType0FForNationPairContext(short targetNationSlot,
                                                                  short sourceNationSlot) {
  QueueInterNationEventMergeFn mergeFn = reinterpret_cast<QueueInterNationEventMergeFn>(
      thunk_QueueInterNationEventType0FWithBitmaskMerge);
  mergeFn(ReadGlobalPointer(kAddrInterNationEventQueueManagerPtr), 0, this->field0c,
          sourceNationSlot, targetNationSlot, 0);
}

// FUNCTION: IMPERIALISM 0x004DDBB0
void TGreatPower::TryDispatchNationActionViaUiContextOrFallback(int arg1, int arg2) {
  const int targetNationSlot = 0;
  void* uiRuntimeContext = ReadGlobalPointer(kAddrUiRuntimeContextPtr);
  GreatPowerSlot21Fn slot21 = reinterpret_cast<GreatPowerSlot21Fn>(this->field00[0x21]);
  char canDispatchViaUi = 0;
  if (slot21 != 0) {
    canDispatchViaUi = slot21(this, 0);
  }

  if (canDispatchViaUi != 0) {
    if (uiRuntimeContext != 0) {
      void* uiVtable = *reinterpret_cast<void**>(uiRuntimeContext);
      UiRuntimeSlot98Fn uiSlot98 =
          *reinterpret_cast<UiRuntimeSlot98Fn*>(reinterpret_cast<unsigned char*>(uiVtable) + 0x98);
      if (uiSlot98 != 0) {
        uiSlot98(this->field0c, targetNationSlot, arg1, arg2);
      }
    }
    return;
  }

  GreatPowerSlot6CFn slot6C = reinterpret_cast<GreatPowerSlot6CFn>(this->field00[0x6C]);
  if (slot6C != 0) {
    slot6C(this, 0, 1, targetNationSlot, 0);
  }
}

// FUNCTION: IMPERIALISM 0x004DDFC0
void TGreatPower::ApplyDiplomacyPolicyStateForTargetWithCostChecks(int arg1, int arg2) {
  short targetClass = static_cast<short>(arg1);
  short policyCode = static_cast<short>(arg2);
  char shouldApply = 1;

  if (policyCode < 0x12E) {
    if (policyCode != 0x12D) {
      if (policyCode == -1) {
        short previousPolicy = this->fieldB2[targetClass];
        if (previousPolicy == 0x133) {
          GreatPower_AdjustTreasury(this, 500);
        } else if (previousPolicy == 0x134) {
          GreatPower_AdjustTreasury(this, 5000);
        }
      }
      goto APPLY_POLICY_IF_ALLOWED;
    }
    if (LookupOrderCompatibility(this->field0c, targetClass) != 2) {
      shouldApply = 0;
    }
    goto APPLY_POLICY_IF_ALLOWED;
  }

  switch (policyCode - 0x12E) {
  case 0:
  case 1:
    if (LookupOrderCompatibility(this->field0c, targetClass) != 2) {
      shouldApply = 0;
    }
    break;

  case 3: {
    int* localizationTable = reinterpret_cast<int*>(ReadGlobalPointer(kAddrLocalizationTablePtr));
    if (localizationTable != 0 && localizationTable[0x08 / 4] == 6) {
      GreatPower_ApplyPolicyForNation(this, targetClass, 4, -1);
    }

    void* diplomacyManager = ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr);
    short relationTier = Diplomacy_GetRelationTier(diplomacyManager, targetClass, this->field0c);
    if (relationTier == 2) {
      Diplomacy_SetRelationState(diplomacyManager, this->field0c, targetClass, 1);
    }

    void** terrainTypeDescriptorTable = reinterpret_cast<void**>(kAddrTerrainTypeDescriptorTable);
    void* terrainDescriptor = terrainTypeDescriptorTable[targetClass];
    if (terrainDescriptor != 0) {
      short encodedNationSlot = TerrainDescriptor_GetEncodedNationSlot(terrainDescriptor);
      if (encodedNationSlot > 199) {
        int resolvedNationSlot = DecodeTerrainNationSlot(encodedNationSlot, terrainDescriptor);
        if (Diplomacy_HasPolicyWithNation(diplomacyManager, this->field0c, resolvedNationSlot) ==
            0) {
          GreatPower_SetPolicyForNation(this, resolvedNationSlot, 0x131);
        }
      }
    }

    if (this->fieldA0 != 0) {
      GreatPower_ResetPolicyForNation(this, targetClass, -1);
    }
    break;
  }

  case 5:
    if (GreatPower_CanPayAmount(this, 500) != 0) {
      GreatPower_AdjustTreasury(this, 0xFFFFFE0C);
    } else {
      shouldApply = 0;
    }
    break;

  case 6:
    if (GreatPower_CanPayAmount(this, 5000) != 0) {
      GreatPower_AdjustTreasury(this, 0xFFFFEC78);
    } else {
      shouldApply = 0;
    }
    break;

  default:
    break;
  }

APPLY_POLICY_IF_ALLOWED:
  if (shouldApply) {
    this->fieldB2[targetClass] = policyCode;
  }
  if (this->fieldA0 != 0) {
    thunk_NoOpDiplomacyPolicyStateChangedHook();
  }
}

// FUNCTION: IMPERIALISM 0x004DE340
void TGreatPower::SetDiplomacyGrantEntryForTargetAndUpdateTreasury(int arg1, int arg2) {
  const unsigned short kGrantClear = 0xFFFF;
  const unsigned short kGrantMask = 0x3FFF;
  const short kMinorNationStart = 7;
  const short kInfluenceAlertThreshold = 0x00FA;

  short targetNation = static_cast<short>(arg1);
  unsigned short newGrantRaw = static_cast<unsigned short>(arg2);
  unsigned short oldGrantRaw = static_cast<unsigned short>(this->fieldE0[targetNation]);
  bool accepted = true;

  if (newGrantRaw != oldGrantRaw) {
    if (newGrantRaw != kGrantClear && GreatPower_CanSetGrantValue(this, newGrantRaw) == 0) {
      accepted = false;
    } else {
      if (oldGrantRaw != kGrantClear) {
        int oldGrantValue = static_cast<short>(oldGrantRaw & kGrantMask);
        this->fieldAC -= oldGrantValue;
        GreatPower_AdjustTreasury(this, oldGrantValue);
      }

      if (newGrantRaw != kGrantClear) {
        int newGrantValue = static_cast<short>(newGrantRaw & kGrantMask);
        this->fieldAC += newGrantValue;
        GreatPower_AdjustTreasury(this, -newGrantValue);
      }

      this->fieldE0[targetNation] = static_cast<short>(newGrantRaw);
    }
  }

  if (this->fieldA0 == 0) {
    return;
  }

  thunk_NoOpDiplomacyPolicyStateChangedHook();

  if (!accepted || newGrantRaw == kGrantClear || targetNation < kMinorNationStart) {
    return;
  }

  void* diplomacyManager = ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr);
  if (diplomacyManager == 0) {
    return;
  }

  bool shouldDispatchAlert = false;
  for (int majorNation = 0; majorNation < kMinorNationStart; ++majorNation) {
    if (majorNation == this->field0c) {
      continue;
    }
    short relationValue =
        Diplomacy_ReadRelationMatrix79C(diplomacyManager, majorNation, targetNation);
    if (relationValue >= kInfluenceAlertThreshold) {
      shouldDispatchAlert = true;
      break;
    }
  }

  if (!shouldDispatchAlert) {
    return;
  }

  int msgRefA = 0;
  int msgRefB = 0;
  InitializeSharedStringRefFromEmpty(&msgRefA);
  InitializeSharedStringRefFromEmpty(&msgRefB);
  thunk_NoOpDiplomacyPolicyStateChangedHook();
  ReleaseSharedStringRefIfNotEmpty(&msgRefB);
  ReleaseSharedStringRefIfNotEmpty(&msgRefA);
}

// FUNCTION: IMPERIALISM 0x004DE5E0
#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif
void TGreatPower::RevokeDiplomacyGrantForTargetAndAdjustInfluence(int arg1) {
  short targetNation = static_cast<short>(arg1);
  int grantValue = DecodeActiveGrantValue(this->fieldE0[targetNation]);
  if (grantValue <= 0) {
    return;
  }

  void* terrainDescriptor =
      ReadGlobalPointerArraySlot(kAddrTerrainTypeDescriptorTable, targetNation);
  TerrainDescriptor_CallSlot38(terrainDescriptor, grantValue);

  this->fieldAC -= grantValue;

  void* diplomacyManager = ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr);
  if (LookupOrderCompatibility(targetNation, this->field0c) != 2) {
    return;
  }

  int sourceNation = this->field0c;
  int relationCode = static_cast<int>(
      Diplomacy_ReadRelationMatrix79C(diplomacyManager, sourceNation, targetNation));
  int relationDelta = ComputeGrantInfluenceDelta(grantValue);
  Diplomacy_SetFlag28(diplomacyManager, sourceNation, targetNation, relationCode + relationDelta);
}

// FUNCTION: IMPERIALISM 0x004DE700
bool TGreatPower::CanAffordDiplomacyGrantEntryForTarget(short targetNationId,
                                                        unsigned short proposedGrantEntry) {
  int proposedGrantValue = DecodeGrantValue14Bit(static_cast<short>(proposedGrantEntry));
  if (proposedGrantValue < 0) {
    return true;
  }

  int currentGrant = DecodeActiveGrantValue(this->fieldE0[targetNationId]);

  int availableBudget = ComputeAvailableDiplomacyBudget(this);
  int remainingBudget = currentGrant - proposedGrantValue + availableBudget;
  return remainingBudget >= 0;
}

// FUNCTION: IMPERIALISM 0x004DE790
bool TGreatPower::CanAffordAdditionalDiplomacyCostAfterCommitments(short additionalCost) {
  int availableBudget = ComputeAvailableDiplomacyBudget(this);
  int remainingBudget = availableBudget - this->fieldAC - static_cast<int>(additionalCost);
  return remainingBudget >= 0;
}
#if defined(_MSC_VER)
#pragma optimize("", on)
#endif

// FUNCTION: IMPERIALISM 0x004DE860
void TGreatPower::ApplyJoinEmpireMode0GlobalDiplomacyReset(int arg1) {
  typedef void(__fastcall * QueueInterNationEventDedupFn)(void*, int, int, int, int, char);
  typedef int(__fastcall * EligibilityFn)(void*, int, int);
  typedef void(__fastcall * ApplyJoinEmpireResetImplFn)(void*, int, int);
  const int kResetDiplomacyLevel = 100;
  const int kResetPolicyCode = -1;
  const int kPrimaryNationCount = 7;
  const int kNationSlotCount = 0x17;
  const int kDipFlagRelation = 6;
  const int kDipFlagPolicy = 0x31;
  const int kNationActionCode = 0x131;

  QueueInterNationEventDedupFn queueInterNationEventDedup =
      reinterpret_cast<QueueInterNationEventDedupFn>(thunk_QueueInterNationEventRecordDeduped);
  queueInterNationEventDedup(ReadGlobalPointer(kAddrInterNationEventQueueManagerPtr), 0, 0x1D,
                             this->field0c, 7, '\0');
  reinterpret_cast<void(__cdecl*)(void)>(thunk_RebuildMinorNationDispositionLookupTables)();

  unsigned char* selfBytes = reinterpret_cast<unsigned char*>(this);
  this->field0e = static_cast<short>(arg1 + 100);

  EligibilityFn isNationEligible =
      reinterpret_cast<EligibilityFn>(thunk_IsNationSlotEligibleForEventProcessing);
  void* eligibilityManager = ReadGlobalPointer(kAddrEligibilityManagerPtr);
  void** terrainTypeDescriptorCursor = reinterpret_cast<void**>(kAddrTerrainTypeDescriptorTable);
  int nationSlot = 0;
  while (reinterpret_cast<unsigned int>(terrainTypeDescriptorCursor) <
         kAddrTerrainTypeDescriptorTableEnd) {
    if (isNationEligible(eligibilityManager, 0, nationSlot) != 0 && nationSlot != this->field0c &&
        nationSlot != arg1) {
      void* terrainTypeDescriptor = *terrainTypeDescriptorCursor;
      if (terrainTypeDescriptor != 0) {
        TerrainDescriptor_SetResetLevel(terrainTypeDescriptor, this->field0c, kResetDiplomacyLevel);
      }
    }
    ++terrainTypeDescriptorCursor;
    ++nationSlot;
  }

  reinterpret_cast<void(__cdecl*)(void)>(ResetTerrainAdjacencyMatrixRowAndSymmetricLink)();

  this->field10 = 0;

  void** releaseTargets[3];
  releaseTargets[0] = &this->pField94;
  releaseTargets[1] = &this->pField98;
  releaseTargets[2] = &this->pField9c;
  int releaseIndex;
  for (releaseIndex = 0; releaseIndex < 3; ++releaseIndex) {
    void* obj = *releaseTargets[releaseIndex];
    if (obj != 0) {
      ReleaseObjectAtSlot1C(obj);
      *releaseTargets[releaseIndex] = 0;
    }
  }

  this->fieldA2 = 0;
  this->fieldA4 = 0;
  this->fieldA6 = 0;
  this->fieldA8 = 0;
  this->fieldAC = 0;
  this->fieldB0 = 0;

  int idx;
  for (idx = 0; idx < kNationSlotCount; ++idx) {
    this->fieldB2[idx] = static_cast<short>(-1);
    this->fieldE0[idx] = static_cast<short>(-1);
    *reinterpret_cast<unsigned char*>(selfBytes + 0x8A0 + idx) = 0;
    *reinterpret_cast<short*>(selfBytes + 0x14 + idx * 2) = 100;
  }

  for (idx = 0; idx < kNationSlotCount; ++idx) {
    this->field10e[idx] = 0;
    this->field13c[idx] = 0;
    this->field16a[idx] = 0;
    this->field198[idx] = 0;
    this->field1c6[idx] = 0;
    this->field1f4[idx] = 0;
    this->field222[idx] = 0;
    this->field250[idx] = 0;
    int col;
    for (col = 0; col < 0x10; ++col) {
      int matrixIndex = col * 0x17 + idx;
      this->field280[matrixIndex] = 0;
    }
  }

  this->field840 = 0;
  this->field844 = 0;

  void* proposalQueue = this->pField84c;
  if (proposalQueue != 0) {
    ReleaseObjectAtSlot1C(proposalQueue);
  }
  void* turnEventQueue = this->pField848;
  if (turnEventQueue != 0) {
    ReleaseObjectAtSlot1C(turnEventQueue);
  }

  GreatPower_CallSlot5C(this);

  void* relationPanelManager = this->pField894;
  if (relationPanelManager != 0) {
    ReleaseObjectAtSlot1C(relationPanelManager);
  }
  this->pField894 = 0;

  GreatPower_CallSlotA5(this);

  void* diplomacyManager = ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr);
  void** nationStateCursor = reinterpret_cast<void**>(kAddrNationStates);
  nationSlot = 0;
  while (reinterpret_cast<unsigned int>(nationStateCursor) < kAddrNationStatesEnd) {
    if (nationSlot != this->field0c && isNationEligible(eligibilityManager, 0, nationSlot) != 0) {
      Diplomacy_SetFlag74(diplomacyManager, this->field0c, nationSlot, kDipFlagRelation);
      Diplomacy_SetFlag28(diplomacyManager, this->field0c, nationSlot, kDipFlagPolicy);
      void* nationState = *nationStateCursor;
      if (nationState != 0 &&
          *reinterpret_cast<char*>(reinterpret_cast<unsigned char*>(nationState) + 0xA0) == 0) {
        NationState_NotifyAction131(nationState, this->field0c);
      }
      GreatPower_ResetDiplomacyLevelForNation(this, nationSlot, kResetDiplomacyLevel);
      GreatPower_ResetPolicyForNation(this, nationSlot, kResetPolicyCode);
    }
    ++nationStateCursor;
    ++nationSlot;
  }

  int secondarySlot;
  for (secondarySlot = kPrimaryNationCount; secondarySlot < kNationSlotCount; ++secondarySlot) {
    void** secondarySlots = reinterpret_cast<void**>(kAddrSecondaryNationStateSlots);
    void* secondaryState = secondarySlots[secondarySlot];
    bool directReset = true;
    if (secondaryState != 0) {
      short ownerNation =
          *reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(secondaryState) + 0x0E);
      if (ownerNation >= 200) {
        // Preserve existing effective behavior: for encoded >=200 states, normalize by subtracting
        // 200 before owner comparison.
        ownerNation = static_cast<short>(ownerNation - 200);
        directReset = ownerNation == this->field0c;
      }
    }

    if (!directReset) {
      Diplomacy_SetFlag74(diplomacyManager, this->field0c, secondarySlot, kDipFlagRelation);
      Diplomacy_SetFlag28(diplomacyManager, this->field0c, secondarySlot, kDipFlagPolicy);
    }

    GreatPower_ResetDiplomacyLevelForNation(this, secondarySlot, kResetDiplomacyLevel);
    GreatPower_ResetPolicyForNation(this, secondarySlot, kResetPolicyCode);

    void** terrainTypeDescriptorTable = reinterpret_cast<void**>(kAddrTerrainTypeDescriptorTable);
    if (terrainTypeDescriptorTable[secondarySlot] != 0 && secondaryState != 0) {
      SecondaryState_ResetDiplomacyLevel(secondaryState, this->field0c, kResetDiplomacyLevel);
    }
  }

  reinterpret_cast<void(__cdecl*)(void)>(
      thunk_RemoveOrdersByNationFromPrimarySecondaryAndTaskForceLists)();
  ApplyJoinEmpireResetImplFn applyJoinEmpireResetImpl =
      reinterpret_cast<ApplyJoinEmpireResetImplFn>(ApplyJoinEmpireMode0GlobalDiplomacyReset_Impl);
  applyJoinEmpireResetImpl(ReadGlobalPointer(kAddrGlobalMapStatePtr), 0, this->field0c);

  int* localizationTable = reinterpret_cast<int*>(ReadGlobalPointer(kAddrLocalizationTablePtr));
  if (localizationTable != 0 && localizationTable[0x44 / 4] != 0) {
    reinterpret_cast<void(__cdecl*)(void)>(thunk_DispatchTaggedGameStateEvent1F20)();
  }
}

// FUNCTION: IMPERIALISM 0x004DEDF0
#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif
void TGreatPower::ApplyImmediateDiplomacyPolicySideEffects(int arg1, int arg2) {
  struct Event13Payload {
    int marker0;
    int nationMask;
    int marker1;
    int targetMask;
  };
  const int kMajorNationCount = 7;
  const short kPolicyMutualDefense = 0x130;
  const short kPolicyTradeEmbargo = 0x12E;

  short policyCode = static_cast<short>(arg2);

  if (this->fieldA0 != 0) {
    int packedCode = (static_cast<int>(static_cast<unsigned short>(arg1)) << 16) |
                     static_cast<unsigned short>(arg2);
    void* diplomacyQueue = this->pField848;
    QueueObject_WritePackedIntAtSlot38(diplomacyQueue, &packedCode);

    Event13Payload payload;
    payload.marker0 = 1;
    payload.nationMask = 1 << (static_cast<unsigned char>(this->field0c) & 0x1F);
    payload.marker1 = 1;
    payload.targetMask = 1 << (static_cast<unsigned char>(arg1) & 0x1F);

    char immediateDispatch = GreatPower_ShouldDispatchImmediately(this);
    if (immediateDispatch == 0) {
      QueueInterNationEventWithPayload(static_cast<int>(this->field0c), &payload);
    } else {
      SendTurnEvent13WithPayload(static_cast<int>(this->field0c), &payload);
    }
  }

  void* diplomacyState = ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr);
  int nationSlot = static_cast<int>(this->field0c);

  if (policyCode == kPolicyMutualDefense &&
      Diplomacy_HasFlag84ForNation(diplomacyState, arg1) != 0) {
    for (int slot = 0; slot < kMajorNationCount; ++slot) {
      if (IsNationSlotEligibleForEventProcessingFast(slot) == 0) {
        continue;
      }

      short relationState = Diplomacy_GetRelationTier(diplomacyState, nationSlot, slot);
      if (relationState != 2) {
        continue;
      }

      if (Diplomacy_HasPolicyWithNation(diplomacyState, slot, arg1) != 0) {
        Diplomacy_SetRelationState(diplomacyState, nationSlot, slot, 1);
      }
    }
  }

  if (policyCode != kPolicyTradeEmbargo) {
    return;
  }

  for (int slot = 0; slot < kMajorNationCount; ++slot) {
    if (IsNationSlotEligibleForEventProcessingFast(slot) == 0) {
      continue;
    }

    if (Diplomacy_HasPolicyWithNation(diplomacyState, slot, arg1) == 0) {
      continue;
    }

    if (Diplomacy_HasPolicyWithNation(diplomacyState, slot, nationSlot) == 0) {
      GreatPower_ApplyPolicyForNation(this, slot, 2, static_cast<short>(arg1));
    }
  }
}
#if defined(_MSC_VER)
#pragma optimize("", on)
#endif

// FUNCTION: IMPERIALISM 0x004DEFD0
void TGreatPower::QueueDiplomacyProposalCodeForTargetNation(void) {
  typedef void(__fastcall * QueueSlot38Fn)(void*, int, void*);

  void* proposalQueue = this->pField84c;
  if (proposalQueue == 0) {
    return;
  }

  int payloadWords[2] = {0, 0};

  void** queueVtable = *reinterpret_cast<void***>(proposalQueue);
  reinterpret_cast<QueueSlot38Fn>(queueVtable[0x38 / 4])(proposalQueue, 0, payloadWords);
}

// FUNCTION: IMPERIALISM 0x004DF010
void TGreatPower::ApplyAcceptedDiplomacyProposalCode(short proposalIndex) {
  const int kMajorNationCount = 7;
  const int kEventDiplomacyReset = 3;
  const int kEventAlliance = 4;
  const int kEventNonAggression = 5;
  const int kEventWar = 2;

  int scratchA = 0;
  int scratchB = 0;
  int scratchC = 0;
  InitializeSharedStringRefFromEmpty(&scratchA);
  InitializeSharedStringRefFromEmpty(&scratchB);
  InitializeSharedStringRefFromEmpty(&scratchC);

  short* proposalEntry = ProposalQueue_GetEntryAt1Based(this->pField84c, proposalIndex);
  short proposalCode = proposalEntry[0];
  short targetNation = proposalEntry[1];
  int sourceNation = this->field0c;
  void* diplomacyManager = ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr);

  switch (proposalCode - 0x12D) {
  case 0:
    GreatPower_CallSlot13(this, targetNation, 1);
    QueueInterNationEventRecordDedup(kEventDiplomacyReset, sourceNation, targetNation);
    break;

  case 1: {
    Diplomacy_SetRelationCode78(diplomacyManager, sourceNation, targetNation, 2);
    QueueInterNationEventRecordDedup(kEventAlliance, sourceNation, targetNation);
    int nationSlot = 0;
    for (nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
      if (Diplomacy_HasPolicyWithNation(diplomacyManager, nationSlot, targetNation) != 0 &&
          Diplomacy_HasPolicyWithNation(diplomacyManager, sourceNation, nationSlot) == 0) {
        GreatPower_ApplyPolicyForNation(this, nationSlot, 2, targetNation);
      }
    }
    break;
  }

  case 2:
    Diplomacy_SetRelationCode78(diplomacyManager, sourceNation, targetNation, 3);
    QueueInterNationEventRecordDedup(kEventNonAggression, sourceNation, targetNation);
    break;

  case 3: {
    Diplomacy_SetRelationCode78(diplomacyManager, sourceNation, targetNation, 4);
    QueueInterNationEventRecordDedup(kEventWar, sourceNation, targetNation);
    if (Diplomacy_HasFlag84ForNation(diplomacyManager, targetNation) != 0) {
      int nationSlot = 0;
      for (nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
        if (IsNationSlotEligibleForEventProcessingFast(nationSlot) != 0 &&
            Diplomacy_GetRelationTier(diplomacyManager, sourceNation, nationSlot) == 2 &&
            Diplomacy_HasPolicyWithNation(diplomacyManager, nationSlot, targetNation) != 0) {
          Diplomacy_SetRelationState(diplomacyManager, sourceNation, nationSlot, 1);
        }
      }
    }
    break;
  }

  case 5: {
    void** terrainTypeDescriptorTable = reinterpret_cast<void**>(kAddrTerrainTypeDescriptorTable);
    void* terrainDescriptor = terrainTypeDescriptorTable[targetNation];
    if (terrainDescriptor != 0) {
      TerrainDescriptor_CallSlot4C(terrainDescriptor, sourceNation, 1);
    }
    QueueInterNationEventRecordDedup(kEventDiplomacyReset, targetNation, sourceNation);
    break;
  }

  default:
    break;
  }

  if (Diplomacy_HasFlag84ForNation(diplomacyManager, targetNation) != 0 &&
      IsNationSlotEligibleForEventProcessingFast(targetNation) != 0) {
    void** nationStates = reinterpret_cast<void**>(kAddrNationStates);
    void* nationState = nationStates[targetNation];
    if (nationState != 0) {
      NationState_NotifyActionCode(nationState, sourceNation, proposalCode);
    }
  }

  ReleaseSharedStringRefIfNotEmpty(&scratchC);
  ReleaseSharedStringRefIfNotEmpty(&scratchB);
  ReleaseSharedStringRefIfNotEmpty(&scratchA);
}

// FUNCTION: IMPERIALISM 0x004DF5C0
void TGreatPower::DispatchTurnEvent2103WithNationFromRecord(void) {
  typedef void(__fastcall * UiRuntimeDispatchEventFn)(void*, int, int, int);

  void* uiRuntimeContext = ReadGlobalPointer(kAddrUiRuntimeContextPtr);
  if (uiRuntimeContext == 0) {
    return;
  }

  void** uiVtable = *reinterpret_cast<void***>(uiRuntimeContext);
  reinterpret_cast<UiRuntimeDispatchEventFn>(uiVtable[0x4C / 4])(uiRuntimeContext, 0, 0x2103,
                                                                 this->field0c);
}

// FUNCTION: IMPERIALISM 0x004DF5F0
void TGreatPower::ProcessPendingDiplomacyProposalQueue(void) {
  const int kMajorNationCount = 7;
  const short kProposalTradeEmbargo = 0x12E;
  const short kProposalMutualDefense = 0x132;
  int proposalSummaryRef = 0;
  int proposalScratchRef = 0;
  int proposalIndex = 0;
  int queueIndex = 0;

  InitializeSharedStringRefFromEmpty(&proposalSummaryRef);
  InitializeSharedStringRefFromEmpty(&proposalScratchRef);

  void* proposalQueue = this->pField84c;
  short proposalCount = ProposalQueue_GetCount(proposalQueue);
  if (proposalCount != 0 && proposalCount > 0) {
    proposalIndex = 1;
    queueIndex = 1;
    void* diplomacyManager = ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr);
    void* uiRuntimeContext = ReadGlobalPointer(kAddrUiRuntimeContextPtr);

    do {
      short* proposalEntry = ProposalQueue_GetEntryAt1Based(proposalQueue, queueIndex);
      short proposalCode = proposalEntry[0];
      short targetNation = proposalEntry[1];
      char shouldApplyProposal;

      if (IsTurnCooldownCounterActiveOrResetFlagAsChar() == 0) {
        if (this->fieldB2[targetNation] == proposalCode) {
          shouldApplyProposal = 1;
        } else if (proposalCode == kProposalTradeEmbargo) {
          if (Diplomacy_GetRelationTier(diplomacyManager, this->field0c, targetNation) != 4) {
            shouldApplyProposal = 0;
          } else {
            shouldApplyProposal = UiRuntime_RequestDiplomacyDecision(
                uiRuntimeContext, this->field0c, targetNation, kProposalTradeEmbargo);
          }
        } else {
          shouldApplyProposal = UiRuntime_RequestDiplomacyDecision(uiRuntimeContext, this->field0c,
                                                                   targetNation, proposalCode);
        }

        if (shouldApplyProposal == 0) {
          GreatPower_RemoveProposalByIndex(this, proposalIndex);
        } else if (proposalCode == kProposalMutualDefense) {
          int checkNation = 0;
          do {
            if (Diplomacy_HasPolicyWithNation(diplomacyManager, targetNation, checkNation) != 0 &&
                Diplomacy_HasPolicyWithNation(diplomacyManager, this->field0c, checkNation) == 0) {
              GreatPower_ApplyMutualDefenseWithNation(this, checkNation, targetNation);
            }
            ++checkNation;
          } while (checkNation < kMajorNationCount);
        } else {
          GreatPower_CommitProposalByIndex(this, proposalIndex);
        }
      } else {
        GreatPower_RemoveProposalByIndex(this, proposalIndex);
      }

      ++proposalIndex;
      ++queueIndex;
    } while (static_cast<short>(proposalIndex) <= proposalCount);
  }

  GreatPower_FinalizeProposalQueue(this);
  ReleaseSharedStringRefIfNotEmpty(&proposalScratchRef);
  ReleaseSharedStringRefIfNotEmpty(&proposalSummaryRef);
}

// FUNCTION: IMPERIALISM 0x004E1D50
bool __fastcall ExecuteAdvisoryPromptAndApplyActionType1(TGreatPower* self, int unusedEdx) {
  (void)unusedEdx;
  const int targetNationSlot = 0;
  char result = 0;
  TDiplomacyTurnStateManager* diplomacyTurnStateManager =
      reinterpret_cast<TDiplomacyTurnStateManager*>(
          ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr));
  void* uiRuntimeContext = ReadGlobalPointer(kAddrUiRuntimeContextPtr);
  void** secondaryNationStateSlots = reinterpret_cast<void**>(kAddrSecondaryNationStateSlots);

  if (diplomacyTurnStateManager != 0 && diplomacyTurnStateManager->vftable != 0) {
    DiplomacyTurnStateSlot44Fn diplomacySlot44 = *reinterpret_cast<DiplomacyTurnStateSlot44Fn*>(
        reinterpret_cast<unsigned char*>(diplomacyTurnStateManager->vftable) + 0x44);
    if (diplomacySlot44 != 0) {
      result = diplomacySlot44(self->field0c);
    }
  }

  UiRuntimeSlot94Fn uiSlot94 = 0;
  if (uiRuntimeContext != 0) {
    void* uiVtable = *reinterpret_cast<void**>(uiRuntimeContext);
    uiSlot94 =
        *reinterpret_cast<UiRuntimeSlot94Fn*>(reinterpret_cast<unsigned char*>(uiVtable) + 0x94);
  }

  if (result == 0) {
    result = (uiSlot94 != 0) ? uiSlot94(uiRuntimeContext, 0, self->field0c, targetNationSlot) : 0;
    if (result != 0) {
      GreatPowerSlotA1Fn slotA1 = reinterpret_cast<GreatPowerSlotA1Fn>(self->field00[0xA1]);
      if (slotA1 != 0) {
        slotA1(self, 0);
      }
      return true;
    }
  } else {
    result = (uiSlot94 != 0) ? uiSlot94(uiRuntimeContext, 0, self->field0c, targetNationSlot) : 0;
    if (result != 0 && secondaryNationStateSlots != 0) {
      void* secondaryNationState = secondaryNationStateSlots[targetNationSlot];
      if (secondaryNationState != 0) {
        short stateValue = *reinterpret_cast<short*>(
            reinterpret_cast<unsigned char*>(secondaryNationState) + 0x0E);
        if (stateValue < 200) {
          if (stateValue < 100) {
            stateValue = *reinterpret_cast<short*>(
                reinterpret_cast<unsigned char*>(secondaryNationState) + 0x0C);
          } else {
            stateValue = static_cast<short>(stateValue - 100);
          }
        } else {
          stateValue = static_cast<short>(stateValue - 200);
        }
        if (stateValue != self->field0c) {
          void* secondaryVtable = *reinterpret_cast<void**>(secondaryNationState);
          SecondaryNationSlot4CFn slot4C = *reinterpret_cast<SecondaryNationSlot4CFn*>(
              reinterpret_cast<unsigned char*>(secondaryVtable) + 0x4C);
          if (slot4C != 0) {
            slot4C(secondaryNationState, 0, self->field0c, 1);
          }
        }
      }
    }
  }
  return result != 0;
}

// FUNCTION: IMPERIALISM 0x004E73F0
void TGreatPower::WrapperFor_HandleCityDialogHintClusterUpdate_At004e73f0(void* pMessage) {
  typedef void(__fastcall * MessageAppendWordFn)(void*, int, const void*);
  typedef void(__fastcall * MessageAppendZeroWordFn)(void*, int, const void*, int);
  typedef void(__fastcall * QueueApplyMessageFn)(void*, int, void*);
  typedef void(__fastcall * QueueRefreshFn)(void*, int);
  typedef int(__fastcall * QueueReadIndexFn)(void*, int, int);
  typedef void(__fastcall * MessageWriteEntryFn)(void*, int, int, int);

  thunk_HandleCityDialogHintClusterUpdate_At00408143(pMessage);

  void** messageVtable = *reinterpret_cast<void***>(pMessage);
  MessageAppendWordFn appendWord = reinterpret_cast<MessageAppendWordFn>(messageVtable[0x78 / 4]);
  for (int i = 0; i < 6; ++i) {
    short value = this->field964[i];
    appendWord(pMessage, 0, &value);
  }

  appendWord(pMessage, 0, this->field970);
  appendWord(pMessage, 0, this->fieldAF0);

  void* missionQueue = this->pFieldB60;
  void** queueVtable = *reinterpret_cast<void***>(missionQueue);
  reinterpret_cast<QueueApplyMessageFn>(queueVtable[0x14 / 4])(missionQueue, 0, pMessage);
  reinterpret_cast<QueueRefreshFn>(queueVtable[0x48 / 4])(missionQueue, 0);

  static const short kZeroWord = 0;
  reinterpret_cast<MessageAppendZeroWordFn>(messageVtable[0x78 / 4])(pMessage, 0, &kZeroWord, 4);

  MessageWriteEntryFn writeEntry = reinterpret_cast<MessageWriteEntryFn>(messageVtable[0xB4 / 4]);
  QueueReadIndexFn readQueueIndex = reinterpret_cast<QueueReadIndexFn>(queueVtable[0x4C / 4]);
  for (int j = 1; j < 0x71; ++j) {
    int value = readQueueIndex(missionQueue, 0, j);
    writeEntry(pMessage, 0, value, 0);
  }
}

// FUNCTION: IMPERIALISM 0x004E7B50
void TGreatPower::QueueDiplomacyProposalCodeWithAllianceGuards(int arg1, int arg2) {
  typedef char(__fastcall * DipSlot60Fn)(void*, int, int, int);

  short policyCode = static_cast<short>(arg2);
  switch (policyCode) {
  case 0x12D:
  case 0x12F:
    return;
  case 0x12E:
  case 0x132: {
    TDiplomacyTurnStateManager* diplomacyState = reinterpret_cast<TDiplomacyTurnStateManager*>(
        ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr));
    if (diplomacyState != 0) {
      void** diplomacyVtable = reinterpret_cast<void**>(diplomacyState->vftable);
      char hasAllianceGuard = reinterpret_cast<DipSlot60Fn>(diplomacyVtable[0x60 / 4])(
          diplomacyState, 0, arg1, this->field0c);
      if (hasAllianceGuard == 0) {
        thunk_QueueDiplomacyProposalCodeForTargetNation_At004083f5();
      }
    }
    return;
  }
  default:
    thunk_QueueDiplomacyProposalCodeForTargetNation_At004083f5();
    return;
  }
}

// FUNCTION: IMPERIALISM 0x004E7C50
void TGreatPower::ApplyImmediateDiplomacyPolicySideEffectsWithSelectionHook(int arg1, int arg2) {
  typedef void(__fastcall * GreatPowerSlot84Fn)(TGreatPower*, int, int);

  if (static_cast<short>(arg2) == 0x131) {
    reinterpret_cast<GreatPowerSlot84Fn>(this->field00[0x84])(this, 0, static_cast<short>(arg1));
  }
  thunk_ApplyImmediateDiplomacyPolicySideEffects_At0040862a(arg1, arg2);
}

// FUNCTION: IMPERIALISM 0x004E8540
void TGreatPower::QueueMapActionMissionFromCandidateAndMarkState(int arg1, int arg2, int arg3,
                                                                 int arg4) {
  typedef void(__fastcall * QueuePushMissionFn)(void*, int, void*);
  const unsigned char kNodeStateAvailable = 1;
  const unsigned char kNodeStateQueued = 2;

  if (arg2 != -1 && this->field970[arg2] != kNodeStateAvailable) {
    return;
  }

  if ((arg3 != 0) && (arg4 == -1)) {
    GetShortAtOffset14Fn getShortAtOffset14 =
        reinterpret_cast<GetShortAtOffset14Fn>(thunk_GetShortAtOffset14OrInvalid);
    short index = getShortAtOffset14();
    if (this->fieldAF0[index] != kNodeStateAvailable) {
      return;
    }
  }

  int missionKind = arg1;
  if ((arg3 != 0) && (arg2 == -1) && (arg4 == -1) && (arg1 != 4)) {
    missionKind = 3;
    arg4 = -1;
  }

  CreateMissionObjectFn createMissionObject =
      reinterpret_cast<CreateMissionObjectFn>(thunk_CreateMissionObjectByKindAndNodeContext);
  void* missionObj = createMissionObject(this->field0c, missionKind, arg2, arg3, arg4);
  if (missionObj == 0) {
    MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
    typedef void(__cdecl * UiInvalidationAssertFn)(const char*, int);
    UiInvalidationAssertFn uiInvalidationAssert = reinterpret_cast<UiInvalidationAssertFn>(
        thunk_TemporarilyClearAndRestoreUiInvalidationFlag);
    uiInvalidationAssert(kUCountryAutoCppPath, kAssertLineQueueMapAction);
  }

  void* missionQueue = this->pFieldB60;
  void* queueVtable = *reinterpret_cast<void**>(missionQueue);
  QueuePushMissionFn pushMission =
      *reinterpret_cast<QueuePushMissionFn*>(reinterpret_cast<unsigned char*>(queueVtable) + 0x30);
  pushMission(missionQueue, 0, missionObj);

  if (arg2 != -1) {
    this->field970[arg2] = kNodeStateQueued;
  }
  if (arg3 != 0) {
    if (arg3 == -1) {
      GetShortAtOffset14Fn getShortAtOffset14 =
          reinterpret_cast<GetShortAtOffset14Fn>(thunk_GetShortAtOffset14OrInvalid);
      short index = getShortAtOffset14();
      this->fieldAF0[index] = kNodeStateQueued;
    }
    if (arg3 != -1) {
      this->field970[arg3] = kNodeStateQueued;
    }
  }
}

static const double kMinusSix = -6.0;
static const float kOne = 1.0f;

typedef float(__fastcall* MetricVirtualFn)(void*);
typedef unsigned char(__fastcall* EligibilityThunkFn)(void*, int, int);
typedef int(__fastcall* GetField30ThunkFn)(void*);
typedef int(__fastcall* IntThunkWithObjectFn)(void*);
typedef int(__fastcall* IntThunkWithObjectAndArgFn)(void*, int, int);
typedef int(__fastcall* VirtualIntNoArgFn)(void*);
typedef unsigned int(__cdecl* IntThunkWithArgFn)(int);

static __inline float CallVFunc23C(void* obj) {
  void** vtable = *reinterpret_cast<void***>(obj);
  MetricVirtualFn fn = reinterpret_cast<MetricVirtualFn>(vtable[0x23C / 4]);
  return fn(obj);
}

static __inline float CallVFunc240(void* obj) {
  void** vtable = *reinterpret_cast<void***>(obj);
  MetricVirtualFn fn = reinterpret_cast<MetricVirtualFn>(vtable[0x240 / 4]);
  return fn(obj);
}

static __inline bool CallEligibilityThunkWithManager(int nationSlot) {
  EligibilityThunkFn fn =
      reinterpret_cast<EligibilityThunkFn>(thunk_IsNationSlotEligibleForEventProcessing);
  return fn(ReadGlobalPointer(kAddrEligibilityManagerPtr), 0, nationSlot) != 0;
}

static __inline int CallGetField30ThunkWithManager(void) {
  GetField30ThunkFn fn = reinterpret_cast<GetField30ThunkFn>(thunk_GetInt32Field30);
  return fn(ReadGlobalPointer(kAddrEligibilityManagerPtr));
}

static __inline int CallComputeWeightedNeighborLinkScoreForNode(void* nationObj, int arg) {
  IntThunkWithObjectAndArgFn fn =
      reinterpret_cast<IntThunkWithObjectAndArgFn>(thunk_ComputeWeightedNeighborLinkScoreForNode);
  return fn(nationObj, 0, arg);
}

static __inline int CallSumWeightedNeighborLinkScoreForLinkedNodes(void* nationObj) {
  IntThunkWithObjectFn fn =
      reinterpret_cast<IntThunkWithObjectFn>(thunk_SumWeightedNeighborLinkScoreForLinkedNodes);
  return fn(nationObj);
}

static __inline int CallSumNavyOrderPriorityForNationAndNodeType(void* nationObj, int arg) {
  IntThunkWithObjectAndArgFn fn =
      reinterpret_cast<IntThunkWithObjectAndArgFn>(thunk_SumNavyOrderPriorityForNationAndNodeType);
  return fn(nationObj, 0, arg);
}

static __inline int CallSumNavyOrderPriorityForNation(void* nationObj) {
  IntThunkWithObjectFn fn =
      reinterpret_cast<IntThunkWithObjectFn>(thunk_SumNavyOrderPriorityForNation);
  return fn(nationObj);
}

static __inline int CallVirtualIntAtOffset(void* obj, int offsetBytes) {
  void** vtable = *reinterpret_cast<void***>(obj);
  VirtualIntNoArgFn fn = reinterpret_cast<VirtualIntNoArgFn>(vtable[offsetBytes / 4]);
  return fn(obj);
}

static __inline float ComputeMetricRatioViaVirtualDispatch(int targetSlot, bool use240Virtual) {
  const int kNationSlotCount = 0x17;
  int slot = 0;
  float selected = 0.0f;
  float sum = 0.0f;
  void** nationObjects = ReadGlobalPointerArray(kAddrNationStates);

  for (; slot < kNationSlotCount; ++slot) {
    if (!CallEligibilityThunkWithManager(slot)) {
      continue;
    }

    void* nationObj = nationObjects[slot];
    float slotValue = use240Virtual ? CallVFunc240(nationObj) : CallVFunc23C(nationObj);
    sum += slotValue;
    if (slot == targetSlot) {
      selected = slotValue;
    }
  }

  if (selected == 0.0f) {
    selected = 1.0f;
  }

  int field30 = CallGetField30ThunkWithManager();
  float denominator = static_cast<float>(field30) * selected - static_cast<float>(kMinusSix);
  float numerator = sum - static_cast<float>(kMinusSix);
  return numerator / denominator;
}

#pragma optimize("y", on)  // omit frame pointer (helps match old prolog/epilog)
#pragma optimize("gt", on) // global optimizations (more likely to jump-table a dense switch)

// FUNCTION: IMPERIALISM 0x004E8750
float TGreatPower::ComputeAdvisoryMapNodeScoreFactorByCaseMetric(int metricCase, int cityIndex,
                                                                 int relationTargetNation,
                                                                 int selectedNationSlot) {
  switch (metricCase - 1) {
  case 0: {
    return ComputeMetricRatioViaVirtualDispatch(selectedNationSlot, false);
  }
  case 1: {
    return ComputeMetricRatioViaVirtualDispatch(selectedNationSlot, true);
  }
  case 2:
  case 3:
    return kOne;
  case 4: {
    TDiplomacyTurnStateManager* mgr = reinterpret_cast<TDiplomacyTurnStateManager*>(
        ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr));
    if (mgr == 0) {
      return kOne;
    }
    int relationIndex = (int)this->field0c * 0x17 + relationTargetNation;
    short relationValue = *reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(mgr) + 0x79C +
                                                    relationIndex * 2);
    if (relationValue == 0) {
      return kOne;
    }
    return 100.0f / (float)relationValue;
  }
  case 5: {
    unsigned char* globalMapState =
        reinterpret_cast<unsigned char*>(ReadGlobalPointer(kAddrGlobalMapStatePtr));
    if (globalMapState == 0) {
      return kOne;
    }
    int* mapState10 = *reinterpret_cast<int**>(globalMapState + 0x10);
    int total = *reinterpret_cast<int*>(globalMapState + 0x18);
    if (mapState10 == 0 || total == 0) {
      return kOne;
    }
    int cityValue = *reinterpret_cast<int*>(reinterpret_cast<unsigned char*>(mapState10) + 0x9C +
                                            cityIndex * 0xA8);
    return (float)cityValue / (float)total;
  }
  case 6:
  default:
    return kOne;
  }
}

// FUNCTION: IMPERIALISM 0x004E9060
float TGreatPower::ComputeMapActionContextCompositeScoreForNation(int nodeType) {
  typedef void(__fastcall * ConstructRelationshipListFn)(void*, int);
  typedef void(__fastcall * ManagerSlot88Fn)(void*, int, int, int, void*);
  typedef void*(__fastcall * ListSlot2CFn)(void*, int, int);
  typedef void(__fastcall * ListSlot24Fn)(void*);

  unsigned char* self = reinterpret_cast<unsigned char*>(this);
  unsigned char* candidateFlags = self + 0x8A0;
  int activeCandidateCount = 0;
  int selectedCandidateIndex = 0;
  float compositeScore = 0.0f;
  int i = 0;

  for (i = 0; i < 0x17; ++i) {
    if (candidateFlags[i] != 0) {
      ++activeCandidateCount;
    }
  }

  if (activeCandidateCount == 0) {
    void* relationshipList = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x18));
    if (relationshipList != 0) {
      reinterpret_cast<ConstructRelationshipListFn>(thunk_ConstructObArrayWithVtable654D38)(
          relationshipList, 0);
      reinterpret_cast<void(__fastcall*)(void*, int)>(thunk_InitializeObArrayVtable654D38ModeField)(
          relationshipList, 0);
    }

    void* diplomacyManager = ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr);
    if (diplomacyManager != 0) {
      void** diplomacyManagerVtable = *reinterpret_cast<void***>(diplomacyManager);
      reinterpret_cast<ManagerSlot88Fn>(diplomacyManagerVtable[0x88 / 4])(
          diplomacyManager, 0, this->field0c, 1, relationshipList);
    }

    if (relationshipList != 0) {
      void** relationshipListVtable = *reinterpret_cast<void***>(relationshipList);
      void* firstNode =
          reinterpret_cast<ListSlot2CFn>(relationshipListVtable[0x2C / 4])(relationshipList, 0, 1);
      if (firstNode != 0) {
        selectedCandidateIndex = static_cast<int>(*reinterpret_cast<short*>(firstNode));
      }
      reinterpret_cast<ListSlot24Fn>(relationshipListVtable[0x24 / 4])(relationshipList);
    }
  } else if (activeCandidateCount == 1) {
    while (selectedCandidateIndex < 0x17) {
      if (candidateFlags[selectedCandidateIndex] != 0) {
        break;
      }
      ++selectedCandidateIndex;
    }
  } else if (activeCandidateCount > 1) {
    short navyPriorities[7];
    for (i = 0; i < 7; ++i) {
      navyPriorities[i] = 0;
    }

    void** nationStates = ReadGlobalPointerArray(kAddrNationStates);
    for (i = 0; i < 7; ++i) {
      if (candidateFlags[i] != 0) {
        navyPriorities[i] = static_cast<short>(
            CallSumNavyOrderPriorityForNationAndNodeType(nationStates[i], nodeType));
      }
    }

    short maxPriority = 0;
    for (i = 0; i < 7; ++i) {
      if (maxPriority < navyPriorities[i]) {
        maxPriority = navyPriorities[i];
      }
    }
    if (maxPriority == 0) {
      compositeScore = 1.0f;
    }
  }

  if (compositeScore == 0.0f) {
    float factor2 = thunk_ComputeAdvisoryMapNodeScoreFactorByCaseMetric(2, -1, nodeType,
                                                                        selectedCandidateIndex);
    float factor4 = thunk_ComputeAdvisoryMapNodeScoreFactorByCaseMetric(4, -1, nodeType,
                                                                        selectedCandidateIndex);
    float factor5 = thunk_ComputeAdvisoryMapNodeScoreFactorByCaseMetric(5, -1, nodeType,
                                                                        selectedCandidateIndex);
    float factor7 = thunk_ComputeAdvisoryMapNodeScoreFactorByCaseMetric(7, -1, nodeType,
                                                                        selectedCandidateIndex);
    compositeScore = factor2 * factor4 * factor5 * factor7;
  }

  return compositeScore;
}
