// Manual decompilation file.
// Seeded from ghidra autogen and normalized into compile-safe wrappers.

#include "decomp_types.h"

class TGreatPower;
typedef void* hwnd_t;
extern "C" int __stdcall MessageBoxA(hwnd_t hWnd, const char* text, const char* caption,
                                     unsigned int type);

undefined4 ComputeMapActionContextNodeValueAverage(void);
undefined4 BuildCityInfluenceLevelMap(void);
undefined4 OrphanCallChain_C2_I10_004e03a0(void);
undefined4 DispatchGreatPowerQuarterlyStatusMessageLevel1(void);
undefined4 ProcessPendingDiplomacyProposalQueue(void);
undefined4 UpdateGreatPowerPressureStateAndDispatchEscalationMessage(void);
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

struct TDiplomacyTurnStateManager {
  void* vftable;
};

static const unsigned int kAddrUiRuntimeContextPtr = 0x006A21BC;
static const unsigned int kAddrSecondaryNationStateSlots = 0x006A4280;
static const unsigned int kAddrDiplomacyTurnStateManagerPtr = 0x006A43D0;
static const unsigned int kAddrGlobalMapStatePtr = 0x006A43D4;
static const unsigned int kAddrInterNationEventQueueManagerPtr = 0x006A43E8;
static const unsigned int kAddrEligibilityManagerPtr = 0x006A43E0;
static const unsigned int kAddrLocalizationTablePtr = 0x006A20F8;
static const unsigned int kAddrTerrainTypeDescriptorTable = 0x006A4310;
static const unsigned int kAddrTerrainTypeDescriptorTableEnd = 0x006A436C;
static const unsigned int kAddrNationStates = 0x006A4370;
static const unsigned int kAddrNationStatesEnd = 0x006A438C;
static const unsigned int kAddrCompileGreatPowerValue = 0x00653528;
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
  void RebuildNationResourceYieldCountersAndDevelopmentTargets(void);
  void RefreshGreatPowerRelationPanelsAndDispatchDeltaSummary(void);
  float ComputeMapActionContextCompositeScoreForNation(int arg1);
  float ComputeAdvisoryMapNodeScoreFactorByCaseMetric(int arg1, int arg2, int arg3, int arg4);
  void ApplyImmediateDiplomacyPolicySideEffects(int arg1, int arg2);
  void ProcessPendingDiplomacyProposalQueue(void);
  void InitializeNationStateRuntimeSubsystems(int arg1, int arg2);
  void QueueDiplomacyProposalCodeForTargetNation(void);
  void ResetDiplomacyNeedSlots7012AndRefreshIfModeGateMatches(void);
  void DispatchTurnEvent2103WithNationFromRecord(void);
  void ApplyJoinEmpireMode0GlobalDiplomacyReset(int arg1);
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
  UpdateGreatPowerPressureStateAndDispatchEscalationMessage();
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
  typedef char(__fastcall * GreatPowerSlot28Fn)(TGreatPower*, int);

  int* localizationTable = reinterpret_cast<int*>(ReadGlobalPointer(kAddrLocalizationTablePtr));
  if (localizationTable == 0) {
    return;
  }

  GreatPowerSlot28Fn slot28 = reinterpret_cast<GreatPowerSlot28Fn>(this->field00[0x28]);
  if (slot28(this, 0) != 0) {
    return;
  }

  int compileThreshold =
      *reinterpret_cast<int*>(kAddrCompileGreatPowerValue + localizationTable[0x40 / 4] * 4);
  unsigned char* self = reinterpret_cast<unsigned char*>(this);
  if (static_cast<int>(*reinterpret_cast<signed char*>(self + 0x8FC)) <= compileThreshold) {
    return;
  }

  TDiplomacyTurnStateManager* diplomacyState = reinterpret_cast<TDiplomacyTurnStateManager*>(
      ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr));
  if (diplomacyState == 0) {
    return;
  }

  short* relationMatrix =
      reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(diplomacyState) + 0x79C);
  int positiveCount = 0;
  int hostileCount = 0;
  int slot = 0;
  while (slot < 0x17) {
    if (slot != this->field0c) {
      short relationValue = relationMatrix[this->field0c * 0x17 + slot];
      if (relationValue > 0xF9) {
        ++positiveCount;
      }
      if (relationValue < 0x10) {
        ++hostileCount;
      }
    }
    ++slot;
  }

  *reinterpret_cast<short*>(self + 0x8B4) = static_cast<short>(hostileCount);
  *reinterpret_cast<short*>(self + 0x8B6) = static_cast<short>(positiveCount);
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

  unsigned char* self = reinterpret_cast<unsigned char*>(this);

  void* pField894 = *reinterpret_cast<void**>(self + 0x894);
  if (pField894 != 0) {
    void** pField894Vtable = *reinterpret_cast<void***>(pField894);
    reinterpret_cast<ReleaseAt1CFn>(pField894Vtable[0x1C / 4])(pField894, 0);
  }
  *reinterpret_cast<void**>(self + 0x894) = 0;

  void* pField848 = *reinterpret_cast<void**>(self + 0x848);
  if (pField848 != 0) {
    void** pField848Vtable = *reinterpret_cast<void***>(pField848);
    reinterpret_cast<ReleaseAt24Fn>(pField848Vtable[0x24 / 4])(pField848, 0);
  }
  *reinterpret_cast<void**>(self + 0x848) = 0;

  void* pField84c = *reinterpret_cast<void**>(self + 0x84C);
  if (pField84c != 0) {
    void** pField84cVtable = *reinterpret_cast<void***>(pField84c);
    reinterpret_cast<ReleaseAt24Fn>(pField84cVtable[0x24 / 4])(pField84c, 0);
  }
  *reinterpret_cast<void**>(self + 0x84C) = 0;

  void* pField94 = *reinterpret_cast<void**>(self + 0x94);
  if (pField94 != 0) {
    void** pField94Vtable = *reinterpret_cast<void***>(pField94);
    reinterpret_cast<ReleaseAt1CFn>(pField94Vtable[0x1C / 4])(pField94, 0);
  }
  *reinterpret_cast<void**>(self + 0x94) = 0;

  void* pField98 = *reinterpret_cast<void**>(self + 0x98);
  if (pField98 != 0) {
    void** pField98Vtable = *reinterpret_cast<void***>(pField98);
    reinterpret_cast<ReleaseAt1CFn>(pField98Vtable[0x1C / 4])(pField98, 0);
  }
  *reinterpret_cast<void**>(self + 0x98) = 0;

  void* pField9c = *reinterpret_cast<void**>(self + 0x9C);
  if (pField9c != 0) {
    void** pField9cVtable = *reinterpret_cast<void***>(pField9c);
    reinterpret_cast<ReleaseAt1CFn>(pField9cVtable[0x1C / 4])(pField9c, 0);
  }
  *reinterpret_cast<void**>(self + 0x9C) = 0;

  int listIndex = 0;
  while (listIndex < 0x11) {
    void* pField850Item = *reinterpret_cast<void**>(self + 0x850 + listIndex * 4);
    if (pField850Item != 0) {
      void** pField850Vtable = *reinterpret_cast<void***>(pField850Item);
      reinterpret_cast<ReleaseAt24Fn>(pField850Vtable[0x24 / 4])(pField850Item, 0);
    }
    *reinterpret_cast<void**>(self + 0x850 + listIndex * 4) = 0;
    ++listIndex;
  }

  void* pField898 = *reinterpret_cast<void**>(self + 0x898);
  if (pField898 != 0) {
    void** pField898Vtable = *reinterpret_cast<void***>(pField898);
    reinterpret_cast<ReleaseAt58Fn>(pField898Vtable[0x58 / 4])(pField898, 0);
  }
  *reinterpret_cast<void**>(self + 0x898) = 0;

  void* pField89c = *reinterpret_cast<void**>(self + 0x89C);
  if (pField89c != 0) {
    void** pField89cVtable = *reinterpret_cast<void***>(pField89c);
    reinterpret_cast<ReleaseAt58Fn>(pField89cVtable[0x58 / 4])(pField89c, 0);
  }
  *reinterpret_cast<void**>(self + 0x89C) = 0;

  void* pField908 = *reinterpret_cast<void**>(self + 0x908);
  if (pField908 != 0) {
    void** pField908Vtable = *reinterpret_cast<void***>(pField908);
    reinterpret_cast<ReleaseAt24Fn>(pField908Vtable[0x24 / 4])(pField908, 0);
  }
  *reinterpret_cast<void**>(self + 0x908) = 0;

  void* pField90c = *reinterpret_cast<void**>(self + 0x90C);
  if (pField90c != 0) {
    void** pField90cVtable = *reinterpret_cast<void***>(pField90c);
    reinterpret_cast<ReleaseAt58Fn>(pField90cVtable[0x58 / 4])(pField90c, 0);
  }
  *reinterpret_cast<void**>(self + 0x90C) = 0;

  void* pField44 = *reinterpret_cast<void**>(self + 0x44);
  if (pField44 != 0) {
    void** pField44Vtable = *reinterpret_cast<void***>(pField44);
    reinterpret_cast<ReleaseAt58Fn>(pField44Vtable[0x58 / 4])(pField44, 0);
  }
  *reinterpret_cast<void**>(self + 0x44) = 0;

  void* pField90 = *reinterpret_cast<void**>(self + 0x90);
  if (pField90 != 0) {
    void** pField90Vtable = *reinterpret_cast<void***>(pField90);
    reinterpret_cast<ReleaseAt38Fn>(pField90Vtable[0x38 / 4])(pField90, 0);
    *reinterpret_cast<void**>(self + 0x90) = 0;
  }

  if (this != 0) {
    reinterpret_cast<DeleteSelfFn>(this->field00[1])(this, 0, 1);
  }
}

// FUNCTION: IMPERIALISM 0x004D92E0
void TGreatPower::InitializeGreatPowerMinisterRosterAndScenarioState(int arg1) {
  typedef void(__fastcall * DeserializeRecruitFn)(void*, int, int);
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

  unsigned char* self = reinterpret_cast<unsigned char*>(this);
  int advanceTurnState = *reinterpret_cast<int*>(kAddrAdvanceTurnMachineState);

  reinterpret_cast<DeserializeRecruitFn>(
      thunk_DeserializeRecruitScenarioAndInstantiateOrders_At00409089)(this, 0, arg1);

  void* stream = reinterpret_cast<void*>(arg1);
  void** streamVtable = stream != 0 ? *reinterpret_cast<void***>(stream) : (void**)0;
  StreamNoArgFn streamSlot3C =
      streamVtable != 0 ? reinterpret_cast<StreamNoArgFn>(streamVtable[0x3C / 4]) : 0;
  StreamNoArgFn streamSlot40 =
      streamVtable != 0 ? reinterpret_cast<StreamNoArgFn>(streamVtable[0x40 / 4]) : 0;
  StreamReadFn streamRead = streamVtable != 0 ? reinterpret_cast<StreamReadFn>(streamVtable[0]) : 0;
  StreamReadByteFn streamSlotB0 =
      streamVtable != 0 ? reinterpret_cast<StreamReadByteFn>(streamVtable[0xB0 / 4]) : 0;

  if (streamSlot3C != 0) {
    int i = 0;
    while (i < 8) {
      streamSlot3C(stream, 0);
      ++i;
    }
    SwapShortArrayBytes(self + 0xB2, 0x17);
    streamSlot3C(stream, 0);
    SwapShortArrayBytes(self + 0xE0, 0x17);
    streamSlot3C(stream, 0);
    SwapShortArrayBytes(self + 0x10E, 0x17);
    streamSlot3C(stream, 0);
    SwapShortArrayBytes(self + 0x13C, 0x17);
    streamSlot3C(stream, 0);
    SwapShortArrayBytes(self + 0x16A, 0x17);
    streamSlot3C(stream, 0);
    SwapShortArrayBytes(self + 0x198, 0x17);
    streamSlot3C(stream, 0);
    SwapShortArrayBytes(self + 0x1C6, 0x17);

    if (advanceTurnState > 0x16) {
      streamSlot3C(stream, 0);
      SwapShortArrayBytes(self + 0x1F4, 0x17);
    }

    streamSlot3C(stream, 0);
    SwapShortArrayBytes(self + 0x222, 0x17);
    streamSlot3C(stream, 0);
    SwapShortArrayBytes(self + 0x250, 0x17);

    streamSlot3C(stream, 0);
    streamSlot3C(stream, 0);
    streamSlot3C(stream, 0);
    ReverseDwordArrayBytes(self + 0x280, 0x170);

    streamSlot3C(stream, 0);
    streamSlot3C(stream, 0);
    SwapShortArrayBytes(self + 0x8D6, 0x0D);
  }

  void* pField848 = *reinterpret_cast<void**>(self + 0x848);
  if (pField848 != 0) {
    void** pField848Vtable = *reinterpret_cast<void***>(pField848);
    reinterpret_cast<ObjNoArgFn>(pField848Vtable[0x18 / 4])(pField848, 0);
  }
  void* pField84c = *reinterpret_cast<void**>(self + 0x84C);
  if (pField84c != 0) {
    void** pField84cVtable = *reinterpret_cast<void***>(pField84c);
    reinterpret_cast<ObjNoArgFn>(pField84cVtable[0x18 / 4])(pField84c, 0);
  }
  int listIndex = 0;
  while (listIndex < 0x11) {
    void* listObj = *reinterpret_cast<void**>(self + 0x850 + listIndex * 4);
    if (listObj != 0) {
      void** listVtable = *reinterpret_cast<void***>(listObj);
      reinterpret_cast<ObjNoArgFn>(listVtable[0x18 / 4])(listObj, 0);
    }
    ++listIndex;
  }

  if (advanceTurnState < 0x1D) {
    if (*reinterpret_cast<short*>(self + 0x0E) == -1) {
      GreatPowerSlot28Fn slot28 = reinterpret_cast<GreatPowerSlot28Fn>(this->field00[0x28]);
      char gate = slot28 != 0 ? slot28(this, 0) : 0;
      if (gate == 0) {
        void* pField94 = *reinterpret_cast<void**>(self + 0x94);
        if (pField94 != 0) {
          void** pField94Vtable = *reinterpret_cast<void***>(pField94);
          reinterpret_cast<ObjNoArgFn>(pField94Vtable[0x18 / 4])(pField94, 0);
        }
        void* pField98 = *reinterpret_cast<void**>(self + 0x98);
        if (pField98 != 0) {
          void** pField98Vtable = *reinterpret_cast<void***>(pField98);
          reinterpret_cast<ObjNoArgFn>(pField98Vtable[0x18 / 4])(pField98, 0);
        }
        void* pField9c = *reinterpret_cast<void**>(self + 0x9C);
        if (pField9c != 0) {
          void** pField9cVtable = *reinterpret_cast<void***>(pField9c);
          reinterpret_cast<ObjNoArgFn>(pField9cVtable[0x18 / 4])(pField9c, 0);
        }
      }
      void* pField894 = *reinterpret_cast<void**>(self + 0x894);
      if (pField894 != 0) {
        void** pField894Vtable = *reinterpret_cast<void***>(pField894);
        reinterpret_cast<ObjNoArgFn>(pField894Vtable[0x18 / 4])(pField894, 0);
      }
    } else {
      void* pField94 = *reinterpret_cast<void**>(self + 0x94);
      if (pField94 != 0) {
        void** pField94Vtable = *reinterpret_cast<void***>(pField94);
        reinterpret_cast<ObjNoArgFn>(pField94Vtable[0x1C / 4])(pField94, 0);
      }
      *reinterpret_cast<void**>(self + 0x94) = 0;

      void* pField98 = *reinterpret_cast<void**>(self + 0x98);
      if (pField98 != 0) {
        void** pField98Vtable = *reinterpret_cast<void***>(pField98);
        reinterpret_cast<ObjNoArgFn>(pField98Vtable[0x1C / 4])(pField98, 0);
      }
      *reinterpret_cast<void**>(self + 0x98) = 0;

      void* pField9c = *reinterpret_cast<void**>(self + 0x9C);
      if (pField9c != 0) {
        void** pField9cVtable = *reinterpret_cast<void***>(pField9c);
        reinterpret_cast<ObjNoArgFn>(pField9cVtable[0x1C / 4])(pField9c, 0);
      }
      *reinterpret_cast<void**>(self + 0x9C) = 0;

      void* pField894 = *reinterpret_cast<void**>(self + 0x894);
      if (pField894 != 0) {
        void** pField894Vtable = *reinterpret_cast<void***>(pField894);
        reinterpret_cast<ObjNoArgFn>(pField894Vtable[0x1C / 4])(pField894, 0);
      }
      *reinterpret_cast<void**>(self + 0x894) = 0;
    }
  } else {
    int ministerMask = streamSlot40 != 0 ? streamSlot40(stream, 0) : 0;

    if ((ministerMask & 1) == 0) {
      void* pField94 = *reinterpret_cast<void**>(self + 0x94);
      if (pField94 != 0) {
        void** pField94Vtable = *reinterpret_cast<void***>(pField94);
        reinterpret_cast<ObjNoArgFn>(pField94Vtable[0x1C / 4])(pField94, 0);
      }
      *reinterpret_cast<void**>(self + 0x94) = 0;
    } else {
      void* pField94 = *reinterpret_cast<void**>(self + 0x94);
      if (pField94 == 0) {
        pField94 = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x20));
        if (pField94 != 0) {
          reinterpret_cast<ConstructNoArgFn>(thunk_ConstructTForeignMinister)(pField94, 0);
        }
        *reinterpret_cast<void**>(self + 0x94) = pField94;
        reinterpret_cast<void(__cdecl*)(void)>(thunk_InitializeTForeignMinisterStateAndCounters)();
      }
      if (pField94 != 0) {
        void** pField94Vtable = *reinterpret_cast<void***>(pField94);
        reinterpret_cast<ObjNoArgFn>(pField94Vtable[0x18 / 4])(pField94, 0);
      }
    }

    if ((ministerMask & 2) == 0) {
      void* pField98 = *reinterpret_cast<void**>(self + 0x98);
      if (pField98 != 0) {
        void** pField98Vtable = *reinterpret_cast<void***>(pField98);
        reinterpret_cast<ObjNoArgFn>(pField98Vtable[0x1C / 4])(pField98, 0);
      }
      *reinterpret_cast<void**>(self + 0x98) = 0;
    } else {
      void* pField98 = *reinterpret_cast<void**>(self + 0x98);
      if (pField98 == 0) {
        pField98 = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x20));
        if (pField98 != 0) {
          reinterpret_cast<ConstructNoArgFn>(thunk_WrapperFor_thunk_ConstructTMinister_At004be840)(
              pField98, 0);
        }
        reinterpret_cast<void(__cdecl*)(void)>(thunk_InitializeCityInteriorMinister)();
        *reinterpret_cast<void**>(self + 0x98) = pField98;
      }
      if (pField98 != 0) {
        void** pField98Vtable = *reinterpret_cast<void***>(pField98);
        reinterpret_cast<ObjNoArgFn>(pField98Vtable[0x18 / 4])(pField98, 0);
      }
    }

    if ((ministerMask & 4) == 0) {
      void* pField9c = *reinterpret_cast<void**>(self + 0x9C);
      if (pField9c != 0) {
        void** pField9cVtable = *reinterpret_cast<void***>(pField9c);
        reinterpret_cast<ObjNoArgFn>(pField9cVtable[0x1C / 4])(pField9c, 0);
      }
      *reinterpret_cast<void**>(self + 0x9C) = 0;
    } else {
      void* pField9c = *reinterpret_cast<void**>(self + 0x9C);
      if (pField9c == 0) {
        pField9c = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x20));
        if (pField9c != 0) {
          pField9c = reinterpret_cast<ConstructDefenseMinisterFn>(
              thunk_ConstructTDefenseMinisterBaseState)(pField9c, 0);
        }
        reinterpret_cast<void(__cdecl*)(void)>(thunk_InitializeTMinisterBaseOrderArrayMetrics)();
        *reinterpret_cast<void**>(self + 0x9C) = pField9c;
      }
      if (pField9c != 0) {
        void** pField9cVtable = *reinterpret_cast<void***>(pField9c);
        reinterpret_cast<ObjNoArgFn>(pField9cVtable[0x18 / 4])(pField9c, 0);
      }
    }

    void* pField894 = *reinterpret_cast<void**>(self + 0x894);
    if ((ministerMask & 8) == 0) {
      if (pField894 != 0) {
        void** pField894Vtable = *reinterpret_cast<void***>(pField894);
        reinterpret_cast<ObjNoArgFn>(pField894Vtable[0x1C / 4])(pField894, 0);
      }
      *reinterpret_cast<void**>(self + 0x894) = 0;
    } else if (pField894 != 0) {
      void** pField894Vtable = *reinterpret_cast<void***>(pField894);
      reinterpret_cast<ObjNoArgFn>(pField894Vtable[0x18 / 4])(pField894, 0);
    }
  }

  void* pField898 = *reinterpret_cast<void**>(self + 0x898);
  if (pField898 != 0) {
    void** pField898Vtable = *reinterpret_cast<void***>(pField898);
    int hasItems = reinterpret_cast<ObjQueryFn>(pField898Vtable[0x48 / 4])(pField898, 0);
    if (hasItems != 0) {
      reinterpret_cast<ObjNoArgFn>(pField898Vtable[0x54 / 4])(pField898, 0);
    }
    reinterpret_cast<ObjNoArgFn>(pField898Vtable[0x18 / 4])(pField898, 0);
  }

  if (streamSlot3C != 0) {
    streamSlot3C(stream, 0);
  }

  if (arg1 > 0 && pField898 != 0) {
    void** pField898Vtable = *reinterpret_cast<void***>(pField898);
    ObjPtrFn pField898Slot30 = reinterpret_cast<ObjPtrFn>(pField898Vtable[0x30 / 4]);
    int townOrdinal = 1;
    while (townOrdinal <= arg1) {
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

  void* pField894 = *reinterpret_cast<void**>(self + 0x894);
  if (arg1 > 0 && pField898 != 0 && pField894 != 0) {
    void** pField898Vtable = *reinterpret_cast<void***>(pField898);
    reinterpret_cast<ObjNoArgFn>(pField898Vtable[0x4C / 4])(pField898, 0);
    void** pField894Vtable = *reinterpret_cast<void***>(pField894);
    reinterpret_cast<ObjNoArgFn>(pField894Vtable[0x44 / 4])(pField894, 0);
  }

  void* pField89c = *reinterpret_cast<void**>(self + 0x89C);
  if (pField89c != 0) {
    void** pField89cVtable = *reinterpret_cast<void***>(pField89c);
    int hasItems = reinterpret_cast<ObjQueryFn>(pField89cVtable[0x48 / 4])(pField89c, 0);
    if (hasItems != 0) {
      reinterpret_cast<ObjNoArgFn>(pField89cVtable[0x54 / 4])(pField89c, 0);
    }
    reinterpret_cast<ObjNoArgFn>(pField89cVtable[0x18 / 4])(pField89c, 0);
  }

  if (streamSlot3C != 0) {
    streamSlot3C(stream, 0);
  }

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

  if (streamRead != 0) {
    streamRead(stream, 0, self + 0x8F0, 4);
    streamRead(stream, 0, self + 0x8F4, 1);
    streamRead(stream, 0, self + 0x8F8, 4);
    streamRead(stream, 0, self + 0x8FC, 1);
    streamRead(stream, 0, self + 0x900, 4);
    streamRead(stream, 0, self + 0x904, 1);
  }

  if (advanceTurnState > 0x0E) {
    void* pField90c = *reinterpret_cast<void**>(self + 0x90C);
    if (pField90c != 0) {
      void** pField90cVtable = *reinterpret_cast<void***>(pField90c);
      reinterpret_cast<ObjIntFn>(pField90cVtable[0x18 / 4])(pField90c, 0, arg1);
    }

    int nodeCount = 0;
    if (streamRead != 0) {
      streamRead(stream, 0, &nodeCount, 4);
    }
    if (nodeCount > 0 && streamSlotB0 != 0 && pField90c != 0) {
      void** pField90cVtable = *reinterpret_cast<void***>(pField90c);
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

  if (advanceTurnState > 0x25 && streamRead != 0) {
    streamRead(stream, 0, self + 0x910, 4);
    streamRead(stream, 0, self + 0x914, 4);
  }
  if (advanceTurnState > 0x2F && streamRead != 0) {
    streamRead(stream, 0, self + 0x918, 0x17);
  }
  if (advanceTurnState > 0x34 && streamRead != 0) {
    streamRead(stream, 0, self + 0x960, 4);
  }
}

// FUNCTION: IMPERIALISM 0x004DBD20
void TGreatPower::RebuildNationResourceYieldCountersAndDevelopmentTargets(void) {
  typedef char(__fastcall * GlobalMapMetricFn)(void*, int, int, int);
  typedef void(__fastcall * GreatPowerNeedUpdateFn)(TGreatPower*, int, int, int);

  unsigned char* self = reinterpret_cast<unsigned char*>(this);
  short* currentNeedByType = reinterpret_cast<short*>(self + 0x10E);
  short* developmentByType = reinterpret_cast<short*>(self + 0x11C);
  short* targetNeedByType = reinterpret_cast<short*>(self + 0x13C);
  char* influenceByRegion = thunk_BuildCityInfluenceLevelMap();
  int* globalMapState = reinterpret_cast<int*>(ReadGlobalPointer(kAddrGlobalMapStatePtr));
  int regionOffset = 0;
  int nationSlot = 0;

  for (int i = 0; i < 0x17; ++i) {
    currentNeedByType[i] = 0;
  }
  *reinterpret_cast<short*>(self + 0x134) = 0;

  if (influenceByRegion != 0 && globalMapState != 0) {
    int terrainStateTable = globalMapState[3];
    int cityStateTable = globalMapState[4];
    void** globalMapVtable = *reinterpret_cast<void***>(globalMapState);
    GlobalMapMetricFn mapMetric = reinterpret_cast<GlobalMapMetricFn>(globalMapVtable[0xC4 / 4]);

    while (static_cast<short>(nationSlot) < 0x1950) {
      char influence = *influenceByRegion;
      if (influence != 0) {
        if (*reinterpret_cast<char*>(terrainStateTable + 0x13 + regionOffset) == 0) {
          if (influence == 2) {
            ++(*reinterpret_cast<short*>(self + 0x134));
          }
        } else {
          for (int edgeIndex = 0; edgeIndex < 2; ++edgeIndex) {
            short resourceType = static_cast<short>(
                *reinterpret_cast<char*>(terrainStateTable + regionOffset + 0x11 + edgeIndex));
            if (resourceType != -1) {
              char contribution = mapMetric(globalMapState, 0, nationSlot, edgeIndex);
              currentNeedByType[resourceType] = static_cast<short>(
                  currentNeedByType[resourceType] + static_cast<short>(contribution));
            }
          }

          if (*reinterpret_cast<char*>(terrainStateTable + 2 + regionOffset) != 0 &&
              influence == 2) {
            ++(*reinterpret_cast<short*>(self + 0x134));
          }

          int cityRecordOffset =
              static_cast<int>(*reinterpret_cast<short*>(terrainStateTable + 0x14 + regionOffset)) *
              0xA8;
          if (*reinterpret_cast<short*>(cityStateTable + cityRecordOffset + 4) ==
              static_cast<short>(nationSlot)) {
            for (int devIdx = 0; devIdx < 10; ++devIdx) {
              developmentByType[devIdx] = static_cast<short>(
                  developmentByType[devIdx] +
                  *reinterpret_cast<short*>(cityStateTable + cityRecordOffset + 0x82 + devIdx * 2));
            }
          }
        }
      }

      ++nationSlot;
      ++influenceByRegion;
      regionOffset += 0x24;
    }
  }

  GreatPowerNeedUpdateFn updateNeed = reinterpret_cast<GreatPowerNeedUpdateFn>(this->field00[0x45]);
  for (int typeIndex = 0; typeIndex < 0x17; ++typeIndex) {
    if (currentNeedByType[typeIndex] < targetNeedByType[typeIndex]) {
      updateNeed(this, 0, typeIndex, currentNeedByType[typeIndex]);
    }
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
  typedef int(__fastcall * GreatPowerCanPayFn)(TGreatPower*, int, int);
  typedef void(__fastcall * GreatPowerIntFn)(TGreatPower*, int, int);
  typedef void(__fastcall * GreatPowerInt2Fn)(TGreatPower*, int, int, int);
  typedef void(__fastcall * GreatPowerInt3Fn)(TGreatPower*, int, int, int, int);

  unsigned char* self = reinterpret_cast<unsigned char*>(this);
  short targetClass = static_cast<short>(arg1);
  short policyCode = static_cast<short>(arg2);
  short* policyByNation = reinterpret_cast<short*>(self + 0xB2);
  short previousPolicy = policyByNation[targetClass];
  bool shouldApply = true;
  void** vtable = this->field00;

  if (policyCode == -1) {
    if (previousPolicy == 0x133) {
      reinterpret_cast<GreatPowerIntFn>(vtable[0x0E])(this, 0, 500);
    } else if (previousPolicy == 0x134) {
      reinterpret_cast<GreatPowerIntFn>(vtable[0x0E])(this, 0, 5000);
    }
  } else if (policyCode == 0x133) {
    int canPay = reinterpret_cast<GreatPowerCanPayFn>(vtable[0x7A])(this, 0, 500);
    if (canPay != 0) {
      reinterpret_cast<GreatPowerIntFn>(vtable[0x0E])(this, 0, 0xFFFFFE0C);
    } else {
      shouldApply = false;
    }
  } else if (policyCode == 0x134) {
    int canPay = reinterpret_cast<GreatPowerCanPayFn>(vtable[0x7A])(this, 0, 5000);
    if (canPay != 0) {
      reinterpret_cast<GreatPowerIntFn>(vtable[0x0E])(this, 0, 0xFFFFEC78);
    } else {
      shouldApply = false;
    }
  } else if (policyCode == 0x131) {
    reinterpret_cast<GreatPowerInt3Fn>(vtable[0xA1])(this, 0, targetClass, 4, -1);
    if (*reinterpret_cast<char*>(self + 0xA0) != 0) {
      reinterpret_cast<GreatPowerInt2Fn>(vtable[0x75])(this, 0, arg1, -1);
    }
  }

  if (shouldApply) {
    policyByNation[targetClass] = policyCode;
  }
  if (*reinterpret_cast<char*>(self + 0xA0) != 0) {
    thunk_NoOpDiplomacyPolicyStateChangedHook();
  }
}

// FUNCTION: IMPERIALISM 0x004DE860
void TGreatPower::ApplyJoinEmpireMode0GlobalDiplomacyReset(int arg1) {
  typedef void(__fastcall * QueueInterNationEventDedupFn)(void*, int, int, int, int, char);
  typedef void(__fastcall * TerrainSlot68Fn)(void*, int, int, int);
  typedef int(__fastcall * EligibilityFn)(void*, int, int);
  typedef void(__fastcall * ReleaseObjFn)(void*, int);
  typedef void(__fastcall * GreatPowerNoArgFn)(TGreatPower*, int);
  typedef void(__fastcall * GreatPowerSetValueFn)(TGreatPower*, int, int, int);
  typedef void(__fastcall * DipSlot74Fn)(void*, int, int, int, int);
  typedef void(__fastcall * DipSlot28Fn)(void*, int, int, int, int);
  typedef void(__fastcall * NationSlot94Fn)(void*, int, int, int);
  typedef void(__fastcall * SecondarySlot48Fn)(void*, int, int, int);
  typedef void(__fastcall * ApplyJoinEmpireResetImplFn)(void*, int, int);

  QueueInterNationEventDedupFn queueInterNationEventDedup =
      reinterpret_cast<QueueInterNationEventDedupFn>(thunk_QueueInterNationEventRecordDeduped);
  queueInterNationEventDedup(ReadGlobalPointer(kAddrInterNationEventQueueManagerPtr), 0, 0x1D,
                             this->field0c, 7, '\0');
  reinterpret_cast<void(__cdecl*)(void)>(thunk_RebuildMinorNationDispositionLookupTables)();

  unsigned char* self = reinterpret_cast<unsigned char*>(this);
  *reinterpret_cast<short*>(self + 0x0E) = static_cast<short>(arg1 + 100);

  EligibilityFn isNationEligible =
      reinterpret_cast<EligibilityFn>(thunk_IsNationSlotEligibleForEventProcessing);
  void** terrainTypeDescriptorCursor = reinterpret_cast<void**>(kAddrTerrainTypeDescriptorTable);
  int nationSlot = 0;
  while (reinterpret_cast<unsigned int>(terrainTypeDescriptorCursor) <
         kAddrTerrainTypeDescriptorTableEnd) {
    if (isNationEligible(ReadGlobalPointer(kAddrEligibilityManagerPtr), 0, nationSlot) != 0 &&
        nationSlot != this->field0c && nationSlot != arg1) {
      void* terrainTypeDescriptor = *terrainTypeDescriptorCursor;
      if (terrainTypeDescriptor != 0) {
        void** terrainVtable = *reinterpret_cast<void***>(terrainTypeDescriptor);
        TerrainSlot68Fn terrainSlot68 = reinterpret_cast<TerrainSlot68Fn>(terrainVtable[0x68 / 4]);
        terrainSlot68(terrainTypeDescriptor, 0, this->field0c, 100);
      }
    }
    ++terrainTypeDescriptorCursor;
    ++nationSlot;
  }

  reinterpret_cast<void(__cdecl*)(void)>(ResetTerrainAdjacencyMatrixRowAndSymmetricLink)();

  *reinterpret_cast<int*>(self + 0x10) = 0;

  int releaseOffsets[3];
  releaseOffsets[0] = 0x94;
  releaseOffsets[1] = 0x98;
  releaseOffsets[2] = 0x9C;
  int releaseIndex;
  for (releaseIndex = 0; releaseIndex < 3; ++releaseIndex) {
    void* obj = *reinterpret_cast<void**>(self + releaseOffsets[releaseIndex]);
    if (obj != 0) {
      void** objVtable = *reinterpret_cast<void***>(obj);
      reinterpret_cast<ReleaseObjFn>(objVtable[0x1C / 4])(obj, 0);
      *reinterpret_cast<void**>(self + releaseOffsets[releaseIndex]) = 0;
    }
  }

  *reinterpret_cast<short*>(self + 0xA2) = 0;
  *reinterpret_cast<short*>(self + 0xA4) = 0;
  *reinterpret_cast<short*>(self + 0xA6) = 0;
  *reinterpret_cast<short*>(self + 0xA8) = 0;
  *reinterpret_cast<int*>(self + 0xAC) = 0;
  *reinterpret_cast<short*>(self + 0xB0) = 0;

  int idx;
  for (idx = 0; idx < 0x17; ++idx) {
    *reinterpret_cast<short*>(self + 0xB2 + idx * 2) = static_cast<short>(-1);
    *reinterpret_cast<short*>(self + 0xE0 + idx * 2) = static_cast<short>(-1);
    *reinterpret_cast<unsigned char*>(self + 0x8A0 + idx) = 0;
    *reinterpret_cast<short*>(self + 0x14 + idx * 2) = 100;
  }

  for (idx = 0; idx < 0x17; ++idx) {
    *reinterpret_cast<short*>(self + 0x10E + idx * 2) = 0;
    *reinterpret_cast<short*>(self + 0x13C + idx * 2) = 0;
    *reinterpret_cast<short*>(self + 0x16A + idx * 2) = 0;
    *reinterpret_cast<short*>(self + 0x198 + idx * 2) = 0;
    *reinterpret_cast<short*>(self + 0x1C6 + idx * 2) = 0;
    *reinterpret_cast<short*>(self + 0x1F4 + idx * 2) = 0;
    *reinterpret_cast<short*>(self + 0x222 + idx * 2) = 0;
    *reinterpret_cast<short*>(self + 0x250 + idx * 2) = 0;
    int col;
    for (col = 0; col < 0x10; ++col) {
      int matrixIndex = col * 0x17 + idx;
      *reinterpret_cast<void**>(self + 0x280 + matrixIndex * 4) = 0;
    }
  }

  *reinterpret_cast<int*>(self + 0x840) = 0;
  *reinterpret_cast<int*>(self + 0x844) = 0;

  void* proposalQueue = *reinterpret_cast<void**>(self + 0x84C);
  if (proposalQueue != 0) {
    void** proposalQueueVtable = *reinterpret_cast<void***>(proposalQueue);
    reinterpret_cast<ReleaseObjFn>(proposalQueueVtable[0x1C / 4])(proposalQueue, 0);
  }
  void* turnEventQueue = *reinterpret_cast<void**>(self + 0x848);
  if (turnEventQueue != 0) {
    void** turnEventQueueVtable = *reinterpret_cast<void***>(turnEventQueue);
    reinterpret_cast<ReleaseObjFn>(turnEventQueueVtable[0x1C / 4])(turnEventQueue, 0);
  }

  GreatPowerNoArgFn slot5C = reinterpret_cast<GreatPowerNoArgFn>(this->field00[0x5C]);
  slot5C(this, 0);

  void* relationPanelManager = *reinterpret_cast<void**>(self + 0x894);
  if (relationPanelManager != 0) {
    void** relationPanelVtable = *reinterpret_cast<void***>(relationPanelManager);
    reinterpret_cast<ReleaseObjFn>(relationPanelVtable[0x1C / 4])(relationPanelManager, 0);
  }
  *reinterpret_cast<void**>(self + 0x894) = 0;

  GreatPowerNoArgFn slotA5 = reinterpret_cast<GreatPowerNoArgFn>(this->field00[0xA5]);
  slotA5(this, 0);

  void* diplomacyManager = ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr);
  void** diplomacyVtable =
      diplomacyManager != 0 ? *reinterpret_cast<void***>(diplomacyManager) : (void**)0;
  GreatPowerSetValueFn slot12 = reinterpret_cast<GreatPowerSetValueFn>(this->field00[0x12]);
  GreatPowerSetValueFn slot75 = reinterpret_cast<GreatPowerSetValueFn>(this->field00[0x75]);
  DipSlot74Fn dipSlot74 =
      diplomacyVtable != 0 ? reinterpret_cast<DipSlot74Fn>(diplomacyVtable[0x74 / 4]) : 0;
  DipSlot28Fn dipSlot28 =
      diplomacyVtable != 0 ? reinterpret_cast<DipSlot28Fn>(diplomacyVtable[0x28 / 4]) : 0;

  void** nationStateCursor = reinterpret_cast<void**>(kAddrNationStates);
  nationSlot = 0;
  while (reinterpret_cast<unsigned int>(nationStateCursor) < kAddrNationStatesEnd) {
    if (nationSlot != this->field0c &&
        isNationEligible(ReadGlobalPointer(kAddrEligibilityManagerPtr), 0, nationSlot) != 0) {
      if (dipSlot74 != 0) {
        dipSlot74(diplomacyManager, 0, this->field0c, nationSlot, 6);
      }
      if (dipSlot28 != 0) {
        dipSlot28(diplomacyManager, 0, this->field0c, nationSlot, 0x31);
      }
      void* nationState = *nationStateCursor;
      if (nationState != 0 &&
          *reinterpret_cast<char*>(reinterpret_cast<unsigned char*>(nationState) + 0xA0) == 0) {
        void** nationVtable = *reinterpret_cast<void***>(nationState);
        NationSlot94Fn nationSlot94 = reinterpret_cast<NationSlot94Fn>(nationVtable[0x94 / 4]);
        nationSlot94(nationState, 0, this->field0c, 0x131);
      }
      slot12(this, 0, nationSlot, 100);
      slot75(this, 0, nationSlot, -1);
    }
    ++nationStateCursor;
    ++nationSlot;
  }

  int secondarySlot;
  for (secondarySlot = 7; secondarySlot < 0x17; ++secondarySlot) {
    void** secondarySlots = reinterpret_cast<void**>(kAddrSecondaryNationStateSlots);
    void* secondaryState = secondarySlots[secondarySlot];
    bool directReset = true;
    if (secondaryState != 0) {
      short ownerNation =
          *reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(secondaryState) + 0x0E);
      if (ownerNation >= 200) {
        if (ownerNation < 100) {
          ownerNation =
              *reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(secondaryState) + 0x0C);
        } else if (ownerNation < 200) {
          ownerNation = static_cast<short>(ownerNation - 100);
        } else {
          ownerNation = static_cast<short>(ownerNation - 200);
        }
        directReset = ownerNation == this->field0c;
      }
    }

    if (!directReset) {
      if (dipSlot74 != 0) {
        dipSlot74(diplomacyManager, 0, this->field0c, secondarySlot, 6);
      }
      if (dipSlot28 != 0) {
        dipSlot28(diplomacyManager, 0, this->field0c, secondarySlot, 0x31);
      }
    }

    slot12(this, 0, secondarySlot, 100);
    slot75(this, 0, secondarySlot, -1);

    void** terrainTypeDescriptorTable = reinterpret_cast<void**>(kAddrTerrainTypeDescriptorTable);
    if (terrainTypeDescriptorTable[secondarySlot] != 0 && secondaryState != 0) {
      void** secondaryVtable = *reinterpret_cast<void***>(secondaryState);
      SecondarySlot48Fn secondarySlot48 =
          reinterpret_cast<SecondarySlot48Fn>(secondaryVtable[0x48 / 4]);
      secondarySlot48(secondaryState, 0, this->field0c, 100);
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
  typedef void(__fastcall * QueueSlot38Fn)(void*, int, int*);
  typedef char(__fastcall * GreatPowerSlot28Fn)(TGreatPower*, int);
  typedef void(__fastcall * QueueInterNationEventFn)(void*, int, int, int, char);
  typedef void(__fastcall * SendTurnEvent13Fn)(void*, int, int);
  typedef char(__fastcall * DipSlot84Fn)(void*, int, int);
  typedef short(__fastcall * DipSlot70Fn)(void*, int, int, int);
  typedef char(__fastcall * DipSlot44Fn)(void*, int, int, int);
  typedef void(__fastcall * DipSlot7CFn)(void*, int, int, int, int);
  typedef int(__fastcall * IsEligibleFn)(void*, int, int);
  typedef void(__fastcall * GreatPowerSlotA1ApplyFn)(TGreatPower*, int, int, int, int);

  struct Event13Payload {
    int marker0;
    int nationMask;
    int marker1;
    int targetMask;
  };

  unsigned char* selfBytes = reinterpret_cast<unsigned char*>(this);
  short policyCode = static_cast<short>(arg2);

  if (*reinterpret_cast<unsigned char*>(selfBytes + 0xA0) != 0) {
    int packedCode = (static_cast<int>(static_cast<unsigned short>(arg1)) << 16) |
                     static_cast<unsigned short>(arg2);
    void* diplomacyQueue = *reinterpret_cast<void**>(selfBytes + 0x848);
    if (diplomacyQueue != 0) {
      void** queueVtable = *reinterpret_cast<void***>(diplomacyQueue);
      reinterpret_cast<QueueSlot38Fn>(queueVtable[0x38 / 4])(diplomacyQueue, 0, &packedCode);
    }

    Event13Payload payload;
    payload.marker0 = 1;
    payload.nationMask = 1 << (static_cast<unsigned char>(this->field0c) & 0x1F);
    payload.marker1 = 1;
    payload.targetMask = 1 << (static_cast<unsigned char>(arg1) & 0x1F);

    char immediateDispatch = reinterpret_cast<GreatPowerSlot28Fn>(this->field00[0x28])(this, 0);
    if (immediateDispatch == 0) {
      void* queueManager = ReadGlobalPointer(kAddrInterNationEventQueueManagerPtr);
      reinterpret_cast<QueueInterNationEventFn>(QueueInterNationEventIntoNationBucket)(
          queueManager, 0, static_cast<int>(this->field0c), reinterpret_cast<int>(&payload), '\0');
    } else {
      reinterpret_cast<SendTurnEvent13Fn>(thunk_CreateAndSendTurnEvent13_NationAndNineDwords)(
          0, static_cast<int>(this->field0c), reinterpret_cast<int>(&payload));
    }
  }

  TDiplomacyTurnStateManager* diplomacyState = reinterpret_cast<TDiplomacyTurnStateManager*>(
      ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr));
  if (diplomacyState == 0) {
    return;
  }

  void** diplomacyVtable = reinterpret_cast<void**>(diplomacyState->vftable);
  int nationSlot = static_cast<int>(this->field0c);

  if (policyCode == 0x130 &&
      reinterpret_cast<DipSlot84Fn>(diplomacyVtable[0x84 / 4])(diplomacyState, 0, arg1) != 0) {
    for (int slot = 0; slot < 7; ++slot) {
      if (reinterpret_cast<IsEligibleFn>(thunk_IsNationSlotEligibleForEventProcessing)(0, 0,
                                                                                       slot) == 0) {
        continue;
      }

      short relationState = reinterpret_cast<DipSlot70Fn>(diplomacyVtable[0x70 / 4])(
          diplomacyState, nationSlot, slot, 0);
      if (relationState != 2) {
        continue;
      }

      if (reinterpret_cast<DipSlot44Fn>(diplomacyVtable[0x44 / 4])(diplomacyState, slot, arg1, 0) !=
          0) {
        reinterpret_cast<DipSlot7CFn>(diplomacyVtable[0x7C / 4])(diplomacyState, nationSlot, slot,
                                                                 1, 0);
      }
    }
  }

  if (policyCode != 0x12E) {
    return;
  }

  for (int slot = 0; slot < 7; ++slot) {
    if (reinterpret_cast<IsEligibleFn>(thunk_IsNationSlotEligibleForEventProcessing)(0, 0, slot) ==
        0) {
      continue;
    }

    if (reinterpret_cast<DipSlot44Fn>(diplomacyVtable[0x44 / 4])(diplomacyState, slot, arg1, 0) ==
        0) {
      continue;
    }

    if (reinterpret_cast<DipSlot44Fn>(diplomacyVtable[0x44 / 4])(diplomacyState, slot, nationSlot,
                                                                 0) == 0) {
      reinterpret_cast<GreatPowerSlotA1ApplyFn>(this->field00[0xA1])(this, 0, slot, 2,
                                                                     static_cast<short>(arg1));
    }
  }
}
#if defined(_MSC_VER)
#pragma optimize("", on)
#endif

// FUNCTION: IMPERIALISM 0x004DEFD0
void TGreatPower::QueueDiplomacyProposalCodeForTargetNation(void) {
  typedef void(__fastcall * QueueSlot38Fn)(void*, int, void*);

  void* proposalQueue = *reinterpret_cast<void**>(reinterpret_cast<unsigned char*>(this) + 0x84C);
  if (proposalQueue == 0) {
    return;
  }

  int payloadWords[2];
  payloadWords[0] = 0;
  payloadWords[1] = 0;

  void** queueVtable = *reinterpret_cast<void***>(proposalQueue);
  reinterpret_cast<QueueSlot38Fn>(queueVtable[0x38 / 4])(proposalQueue, 0, payloadWords);
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
  typedef short*(__fastcall * QueueSlot2CFn)(void*, int, int);
  typedef char(__cdecl * CooldownActiveFn)(void);
  typedef short(__fastcall * DipSlot70Fn)(void*, int, int, int);
  typedef char(__fastcall * DipSlot44Fn)(void*, int, int, int);
  typedef char(__fastcall * UiSlot90Fn)(void*, int, int, int, int);
  typedef void(__fastcall * GreatPowerSlot7BFn)(TGreatPower*, int, int);
  typedef void(__fastcall * GreatPowerSlot7CFn)(TGreatPower*, int, int);
  typedef void(__fastcall * GreatPowerSlotA1Fn)(TGreatPower*, int, int, int, int);
  typedef void(__fastcall * GreatPowerSlot73Fn)(TGreatPower*, int);

  void* proposalQueue = *reinterpret_cast<void**>(reinterpret_cast<unsigned char*>(this) + 0x84C);
  if (proposalQueue != 0) {
    int proposalCount =
        *reinterpret_cast<int*>(reinterpret_cast<unsigned char*>(proposalQueue) + 8);
    int queueOrdinal = 1;
    int proposalOrdinal = 1;

    if (proposalCount > 0) {
      void** queueVtable = *reinterpret_cast<void***>(proposalQueue);
      QueueSlot2CFn queueSlot2C = reinterpret_cast<QueueSlot2CFn>(queueVtable[0x2C / 4]);
      CooldownActiveFn isTurnCooldownActive =
          reinterpret_cast<CooldownActiveFn>(thunk_IsTurnCooldownCounterActiveOrResetFlag);
      GreatPowerSlot7BFn slot7B = reinterpret_cast<GreatPowerSlot7BFn>(this->field00[0x7B]);
      GreatPowerSlot7CFn slot7C = reinterpret_cast<GreatPowerSlot7CFn>(this->field00[0x7C]);
      GreatPowerSlotA1Fn slotA1 = reinterpret_cast<GreatPowerSlotA1Fn>(this->field00[0xA1]);
      void* diplomacyManager = ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr);
      void** diplomacyVtable =
          diplomacyManager != 0 ? *reinterpret_cast<void***>(diplomacyManager) : (void**)0;
      DipSlot70Fn dipSlot70 =
          diplomacyVtable != 0 ? reinterpret_cast<DipSlot70Fn>(diplomacyVtable[0x70 / 4]) : 0;
      DipSlot44Fn dipSlot44 =
          diplomacyVtable != 0 ? reinterpret_cast<DipSlot44Fn>(diplomacyVtable[0x44 / 4]) : 0;
      void* uiRuntimeContext = ReadGlobalPointer(kAddrUiRuntimeContextPtr);
      void** uiVtable =
          uiRuntimeContext != 0 ? *reinterpret_cast<void***>(uiRuntimeContext) : (void**)0;
      UiSlot90Fn uiSlot90 = uiVtable != 0 ? reinterpret_cast<UiSlot90Fn>(uiVtable[0x90 / 4]) : 0;

      while (proposalOrdinal <= proposalCount) {
        short* proposalEntry = queueSlot2C(proposalQueue, 0, queueOrdinal);
        if (proposalEntry == 0) {
          break;
        }

        short proposalCode = proposalEntry[0];
        short targetNation = proposalEntry[1];
        char shouldCommit = '\0';

        if (isTurnCooldownActive() == '\0') {
          short currentProposal = *reinterpret_cast<short*>(
              reinterpret_cast<unsigned char*>(this) + 0xB2 + static_cast<int>(targetNation) * 2);
          if (currentProposal == proposalCode) {
            shouldCommit = '\x01';
          } else {
            short uiProposalCode = proposalCode;
            if (proposalCode == 0x12E) {
              if (dipSlot70 == 0 ||
                  dipSlot70(diplomacyManager, this->field0c, targetNation, 0) != 4) {
                shouldCommit = '\0';
              } else if (uiSlot90 != 0) {
                shouldCommit =
                    uiSlot90(uiRuntimeContext, 0, this->field0c, targetNation, uiProposalCode);
              }
            } else if (uiSlot90 != 0) {
              shouldCommit =
                  uiSlot90(uiRuntimeContext, 0, this->field0c, targetNation, uiProposalCode);
            }
          }
        }

        if (shouldCommit == '\0') {
          slot7C(this, 0, proposalOrdinal);
        } else if (proposalCode == 0x132 && dipSlot44 != 0) {
          int checkNation = 0;
          while (checkNation < 7) {
            if (dipSlot44(diplomacyManager, targetNation, checkNation, 0) != '\0' &&
                dipSlot44(diplomacyManager, this->field0c, checkNation, 0) == '\0') {
              slotA1(this, 0, checkNation, 0x132, targetNation);
            }
            ++checkNation;
          }
        } else {
          slot7B(this, 0, proposalOrdinal);
        }

        ++proposalOrdinal;
        ++queueOrdinal;
      }
    }
  }

  GreatPowerSlot73Fn slot73 = reinterpret_cast<GreatPowerSlot73Fn>(this->field00[0x73]);
  slot73(this, 0);
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
    short value = *reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(this) + 0x964 + i * 2);
    appendWord(pMessage, 0, &value);
  }

  appendWord(pMessage, 0, reinterpret_cast<unsigned char*>(this) + 0x970);
  appendWord(pMessage, 0, reinterpret_cast<unsigned char*>(this) + 0xAF0);

  void* missionQueue = *reinterpret_cast<void**>(reinterpret_cast<unsigned char*>(this) + 0xB60);
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
  if (arg2 != -1 && *(reinterpret_cast<unsigned char*>(this) + 0x970 + arg2) != 1) {
    return;
  }

  if ((arg3 != 0) && (arg4 == -1)) {
    GetShortAtOffset14Fn getShortAtOffset14 =
        reinterpret_cast<GetShortAtOffset14Fn>(thunk_GetShortAtOffset14OrInvalid);
    short index = getShortAtOffset14();
    if (*(reinterpret_cast<unsigned char*>(this) + 0xAF0 + index) != 1) {
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

  void* missionQueue = *reinterpret_cast<void**>(reinterpret_cast<unsigned char*>(this) + 0xB60);
  void* queueVtable = *reinterpret_cast<void**>(missionQueue);
  reinterpret_cast<void(__fastcall*)(void*, int, void*)>(*reinterpret_cast<void**>(
      reinterpret_cast<unsigned char*>(queueVtable) + 0x30))(missionQueue, 0, missionObj);

  if (arg2 != -1) {
    *(reinterpret_cast<unsigned char*>(this) + 0x970 + arg2) = 2;
  }
  if (arg3 != 0) {
    if (arg3 == -1) {
      GetShortAtOffset14Fn getShortAtOffset14 =
          reinterpret_cast<GetShortAtOffset14Fn>(thunk_GetShortAtOffset14OrInvalid);
      short index = getShortAtOffset14();
      *(reinterpret_cast<unsigned char*>(this) + 0xAF0 + index) = 2;
    }
    if (arg3 != -1) {
      *(reinterpret_cast<unsigned char*>(this) + 0x970 + arg3) = 2;
    }
  }
}

static const double kMinusSix = -6.0;
static const double kMinusHundred = -100.0;
static const float kOne = 1.0f;
static const float kBonusMultiplier = 2.0f;

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
  int slot = 0;
  float selected = 0.0f;
  float sum = 0.0f;
  void** nationObjCursor = reinterpret_cast<void**>(0x006A4330);
  void** nationObjCursorEnd = reinterpret_cast<void**>(0x006A438C);

  for (; nationObjCursor < nationObjCursorEnd; ++nationObjCursor, ++slot) {
    if (!CallEligibilityThunkWithManager(slot)) {
      continue;
    }

    void* nationObj = *nationObjCursor;
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
float TGreatPower::ComputeAdvisoryMapNodeScoreFactorByCaseMetric(int metric, int arg2, int arg3,
                                                                 int arg4) {
  switch (metric - 1) {
  case 0: {
    return ComputeMetricRatioViaVirtualDispatch(arg4, false);
  }
  case 1: {
    return ComputeMetricRatioViaVirtualDispatch(arg4, true);
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
    int relationIndex = (int)this->field0c * 0x17 + arg3;
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
    int cityValue =
        *reinterpret_cast<int*>(reinterpret_cast<unsigned char*>(mapState10) + 0x9C + arg2 * 0xA8);
    return (float)cityValue / (float)total;
  }
  case 6:
  default:
    return kOne;
  }
}

// FUNCTION: IMPERIALISM 0x004E9060
float TGreatPower::ComputeMapActionContextCompositeScoreForNation(int arg1) {
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

    void** nationStates = reinterpret_cast<void**>(0x006A4330);
    for (i = 0; i < 7; ++i) {
      if (candidateFlags[i] != 0) {
        navyPriorities[i] =
            static_cast<short>(CallSumNavyOrderPriorityForNationAndNodeType(nationStates[i], arg1));
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
    float factor2 =
        thunk_ComputeAdvisoryMapNodeScoreFactorByCaseMetric(2, -1, arg1, selectedCandidateIndex);
    float factor4 =
        thunk_ComputeAdvisoryMapNodeScoreFactorByCaseMetric(4, -1, arg1, selectedCandidateIndex);
    float factor5 =
        thunk_ComputeAdvisoryMapNodeScoreFactorByCaseMetric(5, -1, arg1, selectedCandidateIndex);
    float factor7 =
        thunk_ComputeAdvisoryMapNodeScoreFactorByCaseMetric(7, -1, arg1, selectedCandidateIndex);
    compositeScore = factor2 * factor4 * factor5 * factor7;
  }

  return compositeScore;
}
