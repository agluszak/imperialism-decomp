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
void DispatchGreatPowerQuarterlyStatusMessageLevel1(void);
undefined4 ProcessPendingDiplomacyProposalQueue(void);
undefined4 CompileGreatPowerRelationshipDeltaLinesAndDispatchMessage(void);
void DispatchGreatPowerQuarterlyStatusMessageLevel2(void);
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
undefined4 thunk_AssignStringSharedRefAndReturnThis(void);
undefined4 thunk_DispatchLocalizedUiMessageWithTemplateA13A0(void);
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
undefined4 thunk_ConstructNationStateBase_Vtbl653938(void);
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
undefined4 thunk_RegisterUnitOrderWithOwnerManager(void);

// Legacy free-function symbol retained for old callsites that still reference
// the no-arg form; class-owned event queue methods are implemented below.
unsigned int QueueInterNationEventIntoNationBucket(void) {
  return 0;
}

// Legacy global helper still referenced by thunks/call-through wrappers.
unsigned int __cdecl GetTGreatPowerClassNamePointer(void) {
  return 0x00653688;
}

// Legacy global helper still referenced by constructor-style call-throughs.
unsigned int __cdecl CPtrList(void) {
  return 0;
}
undefined4 thunk_InitializeCivUnitOrderObject(void);
undefined4 thunk_GetCityBuildingProductionValueBySlot(void);
undefined4 thunk_SetGlobalRegionDevelopmentStageByte(void);
undefined4 thunk_DispatchCityRedrawInvalidateEvent(void);

struct TDiplomacyTurnStateManager {
  void* vftable;
};

struct TDiplomacyTurnStateManagerRelationView {
  unsigned char pad00[0x79C];
  short relationMatrix79C[0x17 * 0x17];
};

struct TTerrainDescriptorNationSlotView {
  unsigned char pad00[0x0C];
  short fallbackNationSlot;
  short encodedNationSlot;
};

struct TSecondaryNationStateOwnerView {
  unsigned char pad00[0x0C];
  short fallbackNationSlot;
  short encodedOwnerNationSlot;
};

struct TNationStateFlagsView {
  unsigned char pad00[0xA0];
  char busyFlagA0;
};

struct TLocalizationRuntimeView {
  void* vftable;
  unsigned char pad04[4];
  int mode;
  unsigned char pad0c[0x40 - 0x0C];
  int runtimeSubsystemIndex;
  int redrawEnabled;
};

struct TObArrayModeView {
  void* vftable;
  unsigned char pad04[0x14 - 0x04];
  short modeField14;
};

struct TProposalQueueCountView {
  unsigned char pad00[8];
  short count;
};

struct TShortNodeValueView {
  short value;
};

struct TTerrainStateRecordView {
  unsigned char pad00[2];
  unsigned char roadFlag;
  unsigned char pad03[0x11 - 0x03];
  signed char resourceTypeByEdge[2];
  unsigned char gateFlag;
  short cityRecordIndex;
  unsigned char pad16[0x24 - 0x16];
};

struct TGlobalMapCityScoreRecord;

struct TGlobalMapStateScoreView {
  void* vftable;
  unsigned char pad04[8];
  TTerrainStateRecordView* terrainStateTable;
  TGlobalMapCityScoreRecord* cityScoreTable;
  unsigned char pad14[4];
  int cityScoreTotal;
};

struct TGlobalMapCityScoreRecord {
  unsigned char pad00[2];
  unsigned char developmentStage;
  unsigned char pad03;
  short ownerNationSlot;
  short lastTurnTick;
  unsigned char pad08[0x3A - 0x08];
  signed char linkedRegionCount;
  unsigned char pad3B[0x42 - 0x3B];
  short linkedRegionIds[0x21];
  short stage1CounterA;
  short stage1CounterB;
  short pad88;
  short stage1CounterC;
  short stage1CounterD;
  short stage2CounterA;
  short stage2CounterB;
  short stage2CounterC;
  unsigned char pad94[0x9C - 0x94];
  int cityScoreValue;
  unsigned char padA0[0xA8 - 0xA0];
};

struct TTrackedObjectListEntryView {
  void* object;
  unsigned short pad04;
  short regionIndex;
};

struct TCityOrderCapabilityStateView {
  unsigned char pad00[0x193];
  unsigned char hasProductionOrder193;
};

struct TCivWorkOrderStateBaseView {
  void* vftable;
  unsigned char pad04[0x20];
  short remainingTurns24;
  short completionMarker26;
};

struct CPtrListSentinelView {
  void* vftable;
  int field04;
  int field08;
  int field0c;
  int field10;
  void* pField14;
  int field18;
};

static const unsigned int kAddrUiRuntimeContextPtr = 0x006A21BC;
static const unsigned int kAddrSecondaryNationStateSlots = 0x006A4280;
static const unsigned int kAddrDiplomacyTurnStateManagerPtr = 0x006A43D0;
static const unsigned int kAddrGlobalMapStatePtr = 0x006A43D4;
static const unsigned int kAddrInterNationEventQueueManagerPtr = 0x006A43E8;
static const unsigned int kAddrEligibilityManagerPtr = 0x006A43E0;
static const unsigned int kAddrCityOrderCapabilityStatePtr = 0x006A43D8;
static const unsigned int kAddrLocalizationTablePtr = 0x006A20F8;
static const unsigned int kAddrShGreatPowerPressureMessageRef = 0x006A2DF0;
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
static const unsigned int kAddrClassDescTGreatPower = 0x00653688;
static const unsigned int kAddrCPtrListRuntimeClassVtable = 0x00672EEC;
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
  short field14_needLevelByNation[0x17];
  short field42;
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
  unsigned char field8a0_candidateNationFlags[0x17];
  unsigned char pad_8b7;
  unsigned char pad_8b8[0x8c8 - 0x8b8];
  unsigned char field8c8_serializedFlags[0x0D];
  signed char field8d0;
  unsigned char pad_8d1[0x8d6 - 0x8d1];
  short field8d6[0x0d];
  int field8f0;
  signed char field8f4;
  unsigned char pad_8f5[3];
  int field8f8;
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
  int field960;
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
  void CompareMissionScoreVariantsByMode(int mode);
  void BuildGreatPowerMapContextTriggeredNationEventMessages(void);
  void BuildGreatPowerEligibleNationEventMessagesFromLinkedList(void);
  void ApplyNationResourceNeedTargetsToOrderState(void);
  void ApplyDiplomacyPolicyStateForTargetWithCostChecks(int arg1, int arg2);
  void AssignFallbackNationsToUnfilledDiplomacyNeedSlots(void);
  void SetDiplomacyGrantEntryForTargetAndUpdateTreasury(int arg1, int arg2);
  void RevokeDiplomacyGrantForTargetAndAdjustInfluence(int arg1);
  void SetNationResourceNeedCurrentByType(int needType, int currentValue);
  void TryIncrementNationResourceNeedTargetTowardCurrent(int needType);
  void AddAmountToAidAllocationMatrixCellAndTotal(int amount, short columnIndex, short rowIndex);
  int SumAidAllocationMatrixColumnForTarget(short targetNationId);
  int SumAidAllocationMatrixAllCells(void);
  int ComputeRemainingDiplomacyAidBudget(void);
  void GetDiplomacyExternalStateB6ByTarget(void);
  void DecrementDiplomacyCounterA2ByValue(int delta);
  void ResetDiplomacyPolicyAndGrantEntriesPreserveRecurringGrants(void);
  void ResetNationDiplomacyProposalQueue(void);
  void SetDiplomacyColonyBoycottFlagForTargetAndRefreshMinorNations(int targetNationSlot,
                                                                    int isBoycottEnabled);
  void ReleaseDiplomacyTrackedObjectSlots850(void);
  bool IsDiplomacyState1C6UnsetAndCounterPositiveForTarget(short targetNationSlot);
  void OrphanVtableAssignStub_004ddd20(void);
  void QueueInterNationEventForProposalCode12D_130(unsigned short proposalQueueIndex);
  void RebuildNationResourceYieldsAndRollField134Into136(void);
  bool CanAffordDiplomacyGrantEntryForTarget(short targetNationId,
                                             unsigned short proposedGrantEntry);
  bool CanAffordAdditionalDiplomacyCostAfterCommitments(short additionalCost);
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
  void QueueDiplomacyProposalCodeForTargetNation(void);
  void ApplyAcceptedDiplomacyProposalCode(short proposalIndex);
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
  void QueueWarTransitionFromAdvisoryAction(int arg1, int arg2);
  void ApplyJoinEmpireResetAndClearDiplomacyCaches(int arg1);
  void AddRegionToNationAndQueueMapActionMission(int arg1);
  void TryDispatchNationActionViaUiContextOrFallback(int arg1, int arg2);
  void QueueDiplomacyProposalCodeForTargetNationAndDispatchTurnEvent16(void);
  void TryDispatchNationActionViaUiThenTurnEvent(int arg1, int arg2);
  void ProcessPendingDiplomacyThenDispatchTurnEvent29A(void);
  void ApplyClientGreatPowerCommand69AndEmitTurnEvent1E(int arg1, int arg2);
  void QueueInterNationEventIntoNationBucket(int eventCode, int payloadOrNation,
                                             char isReplayBypass);
  void BuildGreatPowerTurnMessageSummaryAndDispatch(void);
  void QueueInterNationEventType0FWithBitmaskMerge(int eventCode, int nationA, int nationB,
                                                   char isReplayBypass);
  void QueueInterNationEventType0FForNationPairContext(short targetNationSlot,
                                                       short sourceNationSlot);
  void ConstructTurnOrderNavigationWindowEntryViewportAdaptive(void);
  void InitializeCivWorkOrderState(int nOrderType, int pOwnerContext, int nOrderOwnerNationId);
  void CPtrList(int ownerContext);
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

static __inline TGlobalMapStateScoreView* ReadGlobalMapStateScoreView(void) {
  return static_cast<TGlobalMapStateScoreView*>(ReadGlobalPointer(kAddrGlobalMapStatePtr));
}

static __inline TLocalizationRuntimeView* ReadLocalizationRuntimeView(void) {
  return static_cast<TLocalizationRuntimeView*>(ReadGlobalPointer(kAddrLocalizationTablePtr));
}

static __inline TTerrainStateRecordView*
GlobalMapState_GetTerrainRecord(const TGlobalMapStateScoreView* globalMapState, int regionIndex) {
  return globalMapState->terrainStateTable + regionIndex;
}

static __inline TGlobalMapCityScoreRecord*
GlobalMapState_GetCityRecord(const TGlobalMapStateScoreView* globalMapState, int cityIndex) {
  return globalMapState->cityScoreTable + cityIndex;
}

static __inline int
GlobalMapState_ReadCityScoreValue(const TGlobalMapStateScoreView* globalMapState, int cityIndex) {
  const TGlobalMapCityScoreRecord* cityRecord =
      GlobalMapState_GetCityRecord(globalMapState, cityIndex);
  return cityRecord->cityScoreValue;
}

static __inline short
CityRecord_ReadDevelopmentAccumulatorAt82(const TGlobalMapCityScoreRecord* cityRecord,
                                          int accumulatorIndex) {
  return cityRecord->linkedRegionIds[0x20 + accumulatorIndex];
}

static __inline signed char ReadLocaleByteStep(unsigned int baseAddress, int localeIndex) {
  return *reinterpret_cast<signed char*>(baseAddress + localeIndex * 4);
}

static __inline int ReadGlobalIntStep(unsigned int baseAddress, int index) {
  return *reinterpret_cast<int*>(baseAddress + index * 4);
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
  return static_cast<const TProposalQueueCountView*>(queue)->count;
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
  typedef void(__fastcall * QueueInterNationEventFn)(void*, int, int, void*, char);
  void* queueManager = ReadGlobalPointer(kAddrInterNationEventQueueManagerPtr);
  QueueInterNationEventFn queueInterNationEvent =
      reinterpret_cast<QueueInterNationEventFn>(QueueInterNationEventIntoNationBucket);
  queueInterNationEvent(queueManager, 0, sourceNation, payload, '\0');
}

static __inline void SendTurnEvent13WithPayload(int sourceNation, void* payload) {
  typedef void(__fastcall * SendTurnEvent13Fn)(void*, int, void*);
  SendTurnEvent13Fn sendTurnEvent13 =
      reinterpret_cast<SendTurnEvent13Fn>(thunk_CreateAndSendTurnEvent13_NationAndNineDwords);
  sendTurnEvent13(0, sourceNation, payload);
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
  const TNationStateFlagsView* nationStateView =
      static_cast<const TNationStateFlagsView*>(nationState);
  return nationStateView->busyFlagA0;
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
  const TDiplomacyTurnStateManagerRelationView* relationView =
      static_cast<const TDiplomacyTurnStateManagerRelationView*>(diplomacyManager);
  int matrixIndex = sourceNation * 0x17 + targetNation;
  return relationView->relationMatrix79C[matrixIndex];
}

static __inline short LookupOrderCompatibility(short sourceNationSlot, short targetNationSlot) {
  typedef short(__fastcall * LookupOrderCompatibilityFn)(void*, int, int, int);
  LookupOrderCompatibilityFn lookupOrderCompatibility =
      reinterpret_cast<LookupOrderCompatibilityFn>(thunk_LookupOrderCompatibilityMatrixValue);
  return lookupOrderCompatibility(ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr), 0,
                                  sourceNationSlot, targetNationSlot);
}

static __inline short TerrainDescriptor_GetEncodedNationSlot(void* terrainDescriptor) {
  const TTerrainDescriptorNationSlotView* terrainView =
      static_cast<const TTerrainDescriptorNationSlotView*>(terrainDescriptor);
  return terrainView->encodedNationSlot;
}

static __inline short TerrainDescriptor_GetFallbackNationSlot(void* terrainDescriptor) {
  const TTerrainDescriptorNationSlotView* terrainView =
      static_cast<const TTerrainDescriptorNationSlotView*>(terrainDescriptor);
  return terrainView->fallbackNationSlot;
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

static __inline short
DecodeSecondaryNationOwnerSlot(const TSecondaryNationStateOwnerView* secondaryNationStateView) {
  short ownerNationSlot = secondaryNationStateView->encodedOwnerNationSlot;
  if (ownerNationSlot < 200) {
    if (ownerNationSlot < 100) {
      ownerNationSlot = secondaryNationStateView->fallbackNationSlot;
    } else {
      ownerNationSlot = static_cast<short>(ownerNationSlot - 100);
    }
  } else {
    ownerNationSlot = static_cast<short>(ownerNationSlot - 200);
  }
  return ownerNationSlot;
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

static __inline void RegisterUnitOrderWithOwnerManager(TGreatPower* self, int nOrderType,
                                                       int pOwnerContext, int nOrderOwnerNationId) {
  typedef void(__fastcall * RegisterOrderFn)(TGreatPower*, int, int, int, int, int);
  RegisterOrderFn registerOrder =
      reinterpret_cast<RegisterOrderFn>(thunk_RegisterUnitOrderWithOwnerManager);
  registerOrder(self, 0, nOrderType, pOwnerContext, nOrderOwnerNationId, 0);
}

static __inline bool IsQuarterlyLocalizationGateOpen(void) {
  unsigned char* localizationTable =
      static_cast<unsigned char*>(ReadGlobalPointer(kAddrLocalizationTablePtr));
  if (localizationTable == 0) {
    return false;
  }

  int localizationTick = static_cast<int>(*reinterpret_cast<short*>(localizationTable + 0x2c));
  int quarterGate = (localizationTick + ((localizationTick >> 0x1f) & 3)) >> 2;
  return static_cast<short>(quarterGate) != 0;
}

static __inline void DispatchQuarterlyGreatPowerPressureMessage(int statusLevel) {
  unsigned char stackState[4];
  volatile unsigned char* localFrame = stackState;
  volatile int* sharedRef = reinterpret_cast<int*>(kAddrShGreatPowerPressureMessageRef);
  volatile int messageLevel = statusLevel;
  volatile int messageFlags = 0;
  (void)localFrame;
  (void)sharedRef;
  (void)messageLevel;
  (void)messageFlags;
  thunk_AssignStringSharedRefAndReturnThis();
  thunk_DispatchLocalizedUiMessageWithTemplateA13A0();
}

static const int kAidAllocationRowCount = 0x10;
static const int kAidAllocationColumnCount = 0x17;

// FUNCTION: IMPERIALISM 0x00401172
unsigned int TGreatPower::thunk_ComputeMapActionContextNodeValueAverage(void) {
  return ComputeMapActionContextNodeValueAverage();
}

// FUNCTION: IMPERIALISM 0x00401343
char* TGreatPower::thunk_BuildCityInfluenceLevelMap(void) {
  return reinterpret_cast<char*>(BuildCityInfluenceLevelMap());
}

// FUNCTION: IMPERIALISM 0x004014a6
void TGreatPower::thunk_QueueMapActionMissionFromCandidateAndMarkState(int arg1, int arg2, int arg3,
                                                                       int arg4) {
  QueueMapActionMissionFromCandidateAndMarkState(arg1, arg2, arg3, arg4);
}

// FUNCTION: IMPERIALISM 0x004016d1
void thunk_OrphanCallChain_C2_I10_004e03a0_At004016d1(void) {
  OrphanCallChain_C2_I10_004e03a0();
}

// FUNCTION: IMPERIALISM 0x00401983
void thunk_DispatchGreatPowerQuarterlyStatusMessageLevel1_At00401983(void) {
  DispatchGreatPowerQuarterlyStatusMessageLevel1();
}

// FUNCTION: IMPERIALISM 0x00401ad2
float TGreatPower::thunk_ComputeAdvisoryMapNodeScoreFactorByCaseMetric(int arg1, int arg2, int arg3,
                                                                       int arg4) {
  return ComputeAdvisoryMapNodeScoreFactorByCaseMetric(arg1, arg2, arg3, arg4);
}

// FUNCTION: IMPERIALISM 0x00401cbc
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

// FUNCTION: IMPERIALISM 0x00402bda
bool TGreatPower::thunk_ExecuteAdvisoryPromptAndApplyActionType2OrFallback_At00402bda(int arg1,
                                                                                      int arg2,
                                                                                      int arg3) {
  (void)arg1;
  (void)arg2;
  (void)arg3;
  return ExecuteAdvisoryPromptAndApplyActionType2OrFallback() != 0;
}

// FUNCTION: IMPERIALISM 0x00402e5f
void TGreatPower::thunk_PopulateCase16AdvisoryMapNodeCandidateState(void) {
  PopulateCase16AdvisoryMapNodeCandidateState();
}

// FUNCTION: IMPERIALISM 0x0040376a
void TGreatPower::thunk_InitializeGreatPowerMinisterRosterAndScenarioState(int arg1) {
  this->InitializeGreatPowerMinisterRosterAndScenarioState(arg1);
}

// FUNCTION: IMPERIALISM 0x0040389b
void thunk_DispatchTurnEvent11F8WithNoPayload_At0040389b(void) {
  DispatchTurnEvent11F8WithNoPayload();
}

// FUNCTION: IMPERIALISM 0x00403c15
bool TGreatPower::thunk_ExecuteAdvisoryPromptAndApplyActionType1_At00403c15(void) {
  return ExecuteAdvisoryPromptAndApplyActionType1(this, 0);
}

// FUNCTION: IMPERIALISM 0x00403e04
void TGreatPower::thunk_BuildGreatPowerTurnMessageSummaryAndDispatch_At00403e04(void) {
  BuildGreatPowerTurnMessageSummaryAndDispatch();
}

// FUNCTION: IMPERIALISM 0x00404007
void TGreatPower::thunk_QueueInterNationEventIntoNationBucket(int eventCode, int payloadOrNation,
                                                              char isReplayBypass) {
  QueueInterNationEventIntoNationBucket(eventCode, payloadOrNation, isReplayBypass);
}

// FUNCTION: IMPERIALISM 0x00404246
void TGreatPower::
    thunk_AddRegionIdToNationOwnedRegionListAndTriggerExpansionActionIfThresholdMet_At00404246(
        void) {
  AddRegionIdToNationOwnedRegionListAndTriggerExpansionActionIfThresholdMet();
}

// FUNCTION: IMPERIALISM 0x004048f4
void TGreatPower::thunk_ResetDiplomacyNeedScoresAndClearAidAllocationMatrix_At004048f4(void) {
  ResetDiplomacyNeedScoresAndClearAidAllocationMatrix();
}

// FUNCTION: IMPERIALISM 0x00404a9d
void* TGreatPower::ReplyToDiplomacyOffers(void) {
  return reinterpret_cast<void*>(GetTGreatPowerClassNamePointer());
}

// FUNCTION: IMPERIALISM 0x00404b33
void TGreatPower::thunk_InitializeCivWorkOrderState(int nOrderType, int pOwnerContext,
                                                    int nOrderOwnerNationId) {
  this->InitializeCivWorkOrderState(nOrderType, pOwnerContext, nOrderOwnerNationId);
}

// FUNCTION: IMPERIALISM 0x00404ce1
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

// FUNCTION: IMPERIALISM 0x00405a9c
void thunk_NoOpDiplomacyTargetTransitionCallback_At00405a9c(void) {
  NoOpDiplomacyTargetTransitionCallback();
}

// FUNCTION: IMPERIALISM 0x00405ac9
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

// FUNCTION: IMPERIALISM 0x00405de4
void TGreatPower::TGreatPower_VtblSlot07(void) {
  this->ReleaseOwnedGreatPowerObjectsAndDeleteSelf();
}

static __inline int CallSumNavyOrderPriorityForNationAndNodeType(void* nationObj, int arg);

// FUNCTION: IMPERIALISM 0x00406915
float TGreatPower::thunk_ComputeMapActionContextCompositeScoreForNation(int arg1) {
  return ComputeMapActionContextCompositeScoreForNation(arg1);
}

// FUNCTION: IMPERIALISM 0x00406a46
void TGreatPower::thunk_OrphanCallChain_C2_I21_004e2b00_At00406a46(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x00406b2c
void TGreatPower::thunk_RemoveRegionIdAndRunTrackedObjectCleanup_At00406b2c(void) {
  RemoveRegionIdAndRunTrackedObjectCleanup();
}

// FUNCTION: IMPERIALISM 0x00406c49
void TGreatPower::thunk_ClearFieldBlock1c6_At00406c49(void) {
  ClearFieldBlock1c6();
}

// FUNCTION: IMPERIALISM 0x00406c9e
void TGreatPower::thunk_ResetNationDiplomacySlotsAndMarkRelatedNations_At00406c9e(void) {
  ResetNationDiplomacySlotsAndMarkRelatedNations();
}

// FUNCTION: IMPERIALISM 0x00406ca3
void TGreatPower::BuildGreatPowerRelationshipDeltaSummaryAndDispatchMessage(void) {
  this->CompileGreatPowerRelationshipDeltaLinesAndDispatchMessage();
}

// FUNCTION: IMPERIALISM 0x00406fe1
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

  const TSecondaryNationStateOwnerView* secondaryNationStateView =
      static_cast<const TSecondaryNationStateOwnerView*>(secondaryNationState);
  short selectedSlot = DecodeSecondaryNationOwnerSlot(secondaryNationStateView);

  if (selectedSlot == this->field0c) {
    return;
  }

  void** secondaryVtable = *reinterpret_cast<void***>(secondaryNationState);
  SecondaryNationSlot4CFn slot4C =
      reinterpret_cast<SecondaryNationSlot4CFn>(secondaryVtable[0x4C / 4]);
  slot4C(secondaryNationState, 0, this->field0c, 1);
}

// FUNCTION: IMPERIALISM 0x004070e5
void TGreatPower::thunk_ApplyDiplomacyPolicyStateForTargetWithCostChecks_At004070e5(int arg1,
                                                                                    int arg2) {
  ApplyDiplomacyPolicyStateForTargetWithCostChecks(arg1, arg2);
}

// FUNCTION: IMPERIALISM 0x00407392
void TGreatPower::thunk_ApplyIndexedResourceDeltaAndAdjustNationTotals_At00407392(int arg1,
                                                                                  int arg2,
                                                                                  int arg3) {
  typedef void(__fastcall * GreatPowerVtableIntFn)(TGreatPower*, int, int);

  short* selectedResource = this->field198 + static_cast<short>(arg1);
  short delta = static_cast<short>(arg2);
  int scaledDelta = static_cast<int>(static_cast<short>(arg3)) * static_cast<int>(delta);
  void** vtable = this->field00;

  *selectedResource = static_cast<short>(*selectedResource + delta);
  reinterpret_cast<GreatPowerVtableIntFn>(vtable[0x0E])(this, 0, -scaledDelta);

  if (delta > 0) {
    reinterpret_cast<GreatPowerVtableIntFn>(vtable[0x66])(this, 0, arg2);
    this->field844 -= scaledDelta;
    return;
  }

  this->field840 -= scaledDelta;
  if (ApplyIndexedResourceDeltaAndAdjustNationTotals_Impl() != 0) {
    this->field910 -= arg1;
  }
}

// FUNCTION: IMPERIALISM 0x00407db0
void TGreatPower::thunk_RefreshGreatPowerRelationPanelsAndDispatchDeltaSummary_At00407db0(void) {
  RefreshGreatPowerRelationPanelsAndDispatchDeltaSummary();
}

// FUNCTION: IMPERIALISM 0x00407e8c
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

// FUNCTION: IMPERIALISM 0x004083f5
void TGreatPower::thunk_QueueDiplomacyProposalCodeForTargetNation_At004083f5(void) {
  QueueDiplomacyProposalCodeForTargetNation();
}

// FUNCTION: IMPERIALISM 0x004085ee
void TGreatPower::thunk_WrapperFor_FreeHeapBufferIfNotNull_At004d8c20_At004085ee(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x00408620
void TGreatPower::thunk_ConstructTurnOrderNavigationWindowEntryViewportAdaptive(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x0040862a
void TGreatPower::thunk_ApplyImmediateDiplomacyPolicySideEffects_At0040862a(int arg1, int arg2) {
  ApplyImmediateDiplomacyPolicySideEffects(arg1, arg2);
}

// FUNCTION: IMPERIALISM 0x004090b1
void TGreatPower::thunk_NoOpNationDiplomacyCallback_At004090b1(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x00409291
void TGreatPower::thunk_InitializeNationStateRuntimeSubsystems(int arg1, int arg2) {
  InitializeNationStateRuntimeSubsystems(arg1, arg2);
}

// FUNCTION: IMPERIALISM 0x004096c4
void TGreatPower::thunk_DispatchGreatPowerQuarterlyStatusMessageLevel0_At004096c4(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x004097fa
void TGreatPower::thunk_ApplyJoinEmpireMode0GlobalDiplomacyReset_At004097fa(int arg1) {
  ApplyJoinEmpireMode0GlobalDiplomacyReset(arg1);
}

// FUNCTION: IMPERIALISM 0x004097ff
void TGreatPower::thunk_RebuildNationResourceYieldCountersAndDevelopmentTargets_At004097ff(void) {
  RebuildNationResourceYieldCountersAndDevelopmentTargets();
}

// FUNCTION: IMPERIALISM 0x004D8950
void* __cdecl TGreatPower::CreateTGreatPowerInstance(void) {
  void* instance = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x964));
  if (instance == 0) {
    return 0;
  }

  typedef void(__fastcall * ConstructNationStateBaseFn)(void*, int);
  ConstructNationStateBaseFn constructNationStateBase =
      reinterpret_cast<ConstructNationStateBaseFn>(thunk_ConstructNationStateBase_Vtbl653938);
  constructNationStateBase(instance, 0);
  return instance;
}

// FUNCTION: IMPERIALISM 0x004D89D0
void* __cdecl TGreatPower::GetTGreatPowerClassNamePointer(void) {
  return reinterpret_cast<void*>(kAddrClassDescTGreatPower);
}

// FUNCTION: IMPERIALISM 0x004d8cc0
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

  ConstructPtrArrayFn constructPtrArray =
      reinterpret_cast<ConstructPtrArrayFn>(thunk_ConstructObArrayWithVtable654D38);
  InitializePtrArrayModeFn initializePtrArrayMode =
      reinterpret_cast<InitializePtrArrayModeFn>(thunk_InitializeObArrayVtable654D38ModeField);

  reinterpret_cast<InitializeNationIdentityFn>(
      thunk_InitializeNationStateIdentityAndOwnedRegionList)(reinterpret_cast<int>(this), arg1);

  TLocalizationRuntimeView* localizationRuntime = ReadLocalizationRuntimeView();
  if (localizationRuntime != 0) {
    int runtimeIndex = localizationRuntime->runtimeSubsystemIndex;
    this->field10 = ReadGlobalIntStep(kAddrNationRuntimeSubsystemCache, runtimeIndex);
  } else {
    this->field10 = 0;
  }

  this->fieldA0 = (static_cast<short>(arg2) == 1) ? 1 : 0;

  void* cityModel = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x20));
  if (cityModel != 0) {
    reinterpret_cast<InitializeCityModelFn>(thunk_InitializeCityModel)(cityModel, 0);
    reinterpret_cast<InitializeCityProductionFn>(thunk_InitializeCityProductionState)(
        reinterpret_cast<int>(cityModel), arg1);
  }
  this->pField894 = cityModel;

  void* trackedObjectList = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x20));
  if (trackedObjectList != 0) {
    reinterpret_cast<InitializeLinkedListSentinelFn>(
        WrapperFor_InitializeLinkedListSentinelNodeWithOwnerContext_At004a8640)(
        reinterpret_cast<unsigned char*>(trackedObjectList) + 4, 0);
    *reinterpret_cast<unsigned int*>(trackedObjectList) = kAddrVtblTArmyBattle;
  }
  this->pField898 = trackedObjectList;

  this->fieldAC = 0;
  this->fieldA6 = 0x0F;
  this->field900 = 0x0F;

  void* pField848 = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x18));
  if (pField848 != 0) {
    constructPtrArray(pField848, 0);
    initializePtrArrayMode(pField848, 0);
    TObArrayModeView* pField848Array = static_cast<TObArrayModeView*>(pField848);
    pField848Array->modeField14 = 4;
  }
  this->pField848 = pField848;

  void* pField84c = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x18));
  if (pField84c != 0) {
    constructPtrArray(pField84c, 0);
    initializePtrArrayMode(pField84c, 0);
    TObArrayModeView* pField84cArray = static_cast<TObArrayModeView*>(pField84c);
    pField84cArray->modeField14 = 4;
  }
  this->pField84c = pField84c;

  if (this->fieldA0 != 0) {
    void* foreignMinister = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x20));
    if (foreignMinister != 0) {
      reinterpret_cast<ConstructForeignMinisterFn>(thunk_ConstructTForeignMinister)(foreignMinister,
                                                                                    0);
    }
    reinterpret_cast<void(__cdecl*)(void)>(thunk_InitializeTForeignMinisterStateAndCounters)();
    this->pField94 = foreignMinister;

    void* interiorMinister = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x20));
    if (interiorMinister != 0) {
      reinterpret_cast<ConstructMinisterFn>(thunk_WrapperFor_thunk_ConstructTMinister_At004be840)(
          interiorMinister, 0);
    }
    reinterpret_cast<void(__cdecl*)(void)>(thunk_InitializeCityInteriorMinister)();
    this->pField98 = interiorMinister;

    void* defenseMinister = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x20));
    if (defenseMinister != 0) {
      defenseMinister = reinterpret_cast<ConstructDefenseMinisterFn>(
          thunk_ConstructTDefenseMinisterBaseState)(defenseMinister, 0);
    }
    reinterpret_cast<void(__cdecl*)(void)>(thunk_InitializeTMinisterBaseOrderArrayMetrics)();
    this->pField9c = defenseMinister;
  }

  int listIndex = 0;
  while (listIndex < 0x11) {
    void* relationList = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x18));
    if (relationList != 0) {
      constructPtrArray(relationList, 0);
      initializePtrArrayMode(relationList, 0);
      TObArrayModeView* relationListArray = static_cast<TObArrayModeView*>(relationList);
      relationListArray->modeField14 = 0x0C;
    }
    this->pField850[listIndex] = relationList;
    ++listIndex;
  }

  short* diplomacyNeedState = this->fieldB2;
  short* diplomacyGrantState = this->fieldE0;
  unsigned char* diplomacyFlags = this->field918;
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
    reinterpret_cast<ConstructPtrListFn>(::CPtrList)(
        reinterpret_cast<unsigned char*>(pField89c) + 4, 0);
    *reinterpret_cast<unsigned int*>(pField89c) = kAddrVtblTArmyBattle;
  }
  this->pField89c = pField89c;

  int candidateIndex = 0;
  while (candidateIndex < 0x17) {
    this->field8a0_candidateNationFlags[candidateIndex] = 0;
    ++candidateIndex;
  }
  this->pad_8b7 = 0;
  this->field904 = 1;

  void* pField908 = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x18));
  if (pField908 != 0) {
    constructPtrArray(pField908, 0);
    initializePtrArrayMode(pField908, 0);
    TObArrayModeView* pField908Array = static_cast<TObArrayModeView*>(pField908);
    pField908Array->modeField14 = 8;
  }
  this->pField908 = pField908;

  void* pField90c = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x20));
  if (pField90c != 0) {
    *reinterpret_cast<unsigned int*>(pField90c) = kAddrVtblRefCountedObjectBase;
    reinterpret_cast<ConstructPtrListFn>(::CPtrList)(
        reinterpret_cast<unsigned char*>(pField90c) + 4, 0);
    *reinterpret_cast<unsigned int*>(pField90c) = kAddrVtblTArmyBattle;
  }
  this->pField90c = pField90c;
  this->field960 = 0;
}

// FUNCTION: IMPERIALISM 0x004d9160
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

// FUNCTION: IMPERIALISM 0x004d92e0
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

  streamSlot3C(stream, 0, this->field8c8_serializedFlags, 0x0D);
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
  streamRead(stream, 0, &this->field8f8, 4);
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
    streamRead(stream, 0, &this->field960, 4);
  }
}

// Updates Great Power pressure/escalation state and propagates summary messages when thresholds
// cross.

// FUNCTION: IMPERIALISM 0x004DAF30
void TGreatPower::CompileGreatPowerRelationshipDeltaLinesAndDispatchMessage(void) {
  typedef char(__fastcall * GreatPowerSlot28Fn)(TGreatPower*, int);

  GreatPowerSlot28Fn slot28Gate = reinterpret_cast<GreatPowerSlot28Fn>(this->field00[0x28]);
  if (slot28Gate(this, 0) != 0) {
    return;
  }

  TLocalizationRuntimeView* localizationRuntime = ReadLocalizationRuntimeView();
  int localeIndex = 0;
  if (localizationRuntime != 0) {
    localeIndex = localizationRuntime->runtimeSubsystemIndex;
  }
  if (this->field8fc < ReadLocaleByteStep(kAddrCompileGreatPowerValue, localeIndex)) {
    return;
  }

  int strongestNation = -1;
  int strongestAbsDelta = 0;
  int signedDeltaTotal = 0;

  for (int nationSlot = 0; nationSlot < 0x17; ++nationSlot) {
    short previousDelta = this->field198[nationSlot];
    short currentDelta = this->field16a[nationSlot];
    short delta = static_cast<short>(currentDelta - previousDelta);
    if (delta == 0) {
      continue;
    }

    this->field198[nationSlot] = currentDelta;
    signedDeltaTotal += static_cast<int>(delta);

    int absDelta = (delta < 0) ? -static_cast<int>(delta) : static_cast<int>(delta);
    if (absDelta > strongestAbsDelta) {
      strongestAbsDelta = absDelta;
      strongestNation = nationSlot;
    }
  }

  if (strongestNation < 0) {
    return;
  }

  int payload = (strongestNation & 0xFFFF) | ((signedDeltaTotal & 0xFFFF) << 16);
  this->QueueInterNationEventIntoNationBucket(0x13A0, payload, '\0');
}

// FUNCTION: IMPERIALISM 0x004DB380
void TGreatPower::UpdateGreatPowerPressureStateAndDispatchEscalationMessage(void) {
  TLocalizationRuntimeView* localizationRuntime = ReadLocalizationRuntimeView();
  int localeIndex = 0;
  if (localizationRuntime != 0) {
    localeIndex = localizationRuntime->runtimeSubsystemIndex;
  }

  signed char& pressureCounter = this->field8fc;
  signed char& escalationCounter = this->field8f4;
  int relationScore = this->field10;

  if (relationScore < 0) {
    int nextPressure = static_cast<int>(pressureCounter) +
                       ReadLocaleByteStep(kAddrGreatPowerPressureRiseStep, localeIndex);
    int pressureRiseCap = ReadGlobalIntStep(kAddrGreatPowerPressureRiseCap, localeIndex);
    if (nextPressure > pressureRiseCap) {
      nextPressure = pressureRiseCap;
    }
    pressureCounter = static_cast<signed char>(nextPressure);

    if (pressureCounter > 0) {
      if (escalationCounter < 3) {
        escalationCounter = 3;
      } else {
        escalationCounter = static_cast<signed char>(escalationCounter + 1);
      }

      int escalationValue = static_cast<int>(escalationCounter);
      int hardThreshold = ReadGlobalIntStep(kAddrGreatPowerPressureHardAlertThreshold, localeIndex);
      int softThreshold = ReadGlobalIntStep(kAddrCompileGreatPowerValue, localeIndex);
      if (escalationValue >= hardThreshold || escalationValue >= softThreshold) {
        this->BuildGreatPowerRelationshipDeltaSummaryAndDispatchMessage();
      }
    }
  } else {
    if (escalationCounter != 0) {
      int nextPressure = static_cast<int>(pressureCounter) -
                         ReadLocaleByteStep(kAddrGreatPowerPressureDecayStep, localeIndex);
      int minFloor = ReadGlobalIntStep(kAddrGreatPowerPressureMinFloor, localeIndex);
      if (nextPressure < minFloor) {
        nextPressure = minFloor;
      }
      pressureCounter = static_cast<signed char>(nextPressure);
    }
    escalationCounter = 0;
  }

  relationScore = this->field10;
  if (relationScore >= 0) {
    this->field8f8 = 0;
    return;
  }

  int drainAmount = (199 - static_cast<int>(pressureCounter) * relationScore) / 200;
  this->field8f8 = drainAmount;
  this->field10 = relationScore - drainAmount;
}

// FUNCTION: IMPERIALISM 0x004dbd20
void TGreatPower::RebuildNationResourceYieldCountersAndDevelopmentTargets(void) {
  typedef char(__fastcall * GlobalMapMetricProc)(void*, int, int, int);
  typedef void(__fastcall * GreatPowerNeedUpdateProc)(TGreatPower*, int, int, int);

  const int kNeedTypeCount = 0x17;
  const int kMapRegionSlots = 0x1950;

  short* currentNeedByType = this->field10e;
  short* developmentByType = this->field10e + 7; // +0x11c overlays this runtime array.
  short* targetNeedByType = this->field13c;
  short& controlledRegionCount = this->field10e[0x13]; // +0x134
  char* influenceByRegion = thunk_BuildCityInfluenceLevelMap();
  TGlobalMapStateScoreView* globalMapState = ReadGlobalMapStateScoreView();
  int nationSlot = 0;

  for (int i = 0; i < kNeedTypeCount; ++i) {
    currentNeedByType[i] = 0;
  }
  controlledRegionCount = 0;

  if (influenceByRegion != 0 && globalMapState != 0 && globalMapState->terrainStateTable != 0 &&
      globalMapState->cityScoreTable != 0) {
    TTerrainStateRecordView* terrainTable =
        reinterpret_cast<TTerrainStateRecordView*>(globalMapState->terrainStateTable);
    TGlobalMapCityScoreRecord* cityTable =
        static_cast<TGlobalMapCityScoreRecord*>(globalMapState->cityScoreTable);
    void** globalMapVtable = *reinterpret_cast<void***>(globalMapState);
    GlobalMapMetricProc mapMetric =
        reinterpret_cast<GlobalMapMetricProc>(globalMapVtable[0xC4 / 4]);

    while (static_cast<short>(nationSlot) < kMapRegionSlots) {
      char influence = *influenceByRegion;
      if (influence != 0) {
        TTerrainStateRecordView* terrainRecord = &terrainTable[nationSlot];
        if (terrainRecord->gateFlag == 0) {
          if (influence == 2) {
            ++controlledRegionCount;
          }
        } else {
          for (int edgeIndex = 0; edgeIndex < 2; ++edgeIndex) {
            short resourceType = static_cast<short>(terrainRecord->resourceTypeByEdge[edgeIndex]);
            if (resourceType != -1) {
              char contribution = mapMetric(globalMapState, 0, nationSlot, edgeIndex);
              currentNeedByType[resourceType] = static_cast<short>(
                  currentNeedByType[resourceType] + static_cast<short>(contribution));
            }
          }

          if (terrainRecord->roadFlag != 0 && influence == 2) {
            ++controlledRegionCount;
          }

          int cityIndex = static_cast<int>(terrainRecord->cityRecordIndex);
          TGlobalMapCityScoreRecord* cityRecord = &cityTable[cityIndex];
          if (cityRecord->ownerNationSlot == static_cast<short>(nationSlot)) {
            for (int devIdx = 0; devIdx < 10; ++devIdx) {
              developmentByType[devIdx] =
                  static_cast<short>(developmentByType[devIdx] +
                                     CityRecord_ReadDevelopmentAccumulatorAt82(cityRecord, devIdx));
            }
          }
        }
      }

      ++nationSlot;
      ++influenceByRegion;
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

// FUNCTION: IMPERIALISM 0x004dbf00
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

    TGlobalMapStateScoreView* globalMapState = ReadGlobalMapStateScoreView();
    TLocalizationRuntimeView* localizationRuntime = ReadLocalizationRuntimeView();
    if (globalMapState != 0 && localizationRuntime != 0 && globalMapState->cityScoreTable != 0 &&
        globalMapState->terrainStateTable != 0) {
      TGlobalMapCityScoreRecord* cityTable =
          static_cast<TGlobalMapCityScoreRecord*>(globalMapState->cityScoreTable);
      TTerrainStateRecordView* terrainTable =
          reinterpret_cast<TTerrainStateRecordView*>(globalMapState->terrainStateTable);
      TGlobalMapCityScoreRecord* cityRecord = cityTable + regionId;
      short ownerSlot = this->field88;
      if (cityRecord->ownerNationSlot != ownerSlot) {
        LocalizationTickFn getTurnTick = reinterpret_cast<LocalizationTickFn>(
            (*reinterpret_cast<void***>(localizationRuntime))[0x3C / 4]);
        unsigned int turnDelta =
            static_cast<unsigned int>(static_cast<int>(getTurnTick(localizationRuntime, 0)) -
                                      static_cast<int>(cityRecord->lastTurnTick));

        if (turnDelta > 4) {
          int resourceSums[0x17];
          int i = 0;
          while (i < 0x17) {
            resourceSums[i] = 0;
            ++i;
          }

          int linkedCount = static_cast<int>(cityRecord->linkedRegionCount);
          int linkedIndex = 0;
          GlobalMapMetricFn mapMetric = reinterpret_cast<GlobalMapMetricFn>(
              (*reinterpret_cast<void***>(globalMapState))[0xC4 / 4]);
          while (linkedIndex < linkedCount) {
            short linkedRegion = cityRecord->linkedRegionIds[linkedIndex];
            int edge = 0;
            while (edge < 2) {
              signed char resourceType = terrainTable[linkedRegion].resourceTypeByEdge[edge];
              if (resourceType != -1) {
                resourceSums[resourceType] +=
                    static_cast<int>(mapMetric(globalMapState, 0, linkedRegion, edge));
              }
              ++edge;
            }
            ++linkedIndex;
          }

          short* stage1CounterA = &cityRecord->stage1CounterA;
          short* stage1CounterB = &cityRecord->stage1CounterB;
          short* stage1CounterC = &cityRecord->stage1CounterC;
          short* stage1CounterD = &cityRecord->stage1CounterD;
          short* stage2CounterA = &cityRecord->stage2CounterA;
          short* stage2CounterB = &cityRecord->stage2CounterB;
          short* stage2CounterC = &cityRecord->stage2CounterC;

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

            TCityOrderCapabilityStateView* orderCapabilityState =
                static_cast<TCityOrderCapabilityStateView*>(
                    ReadGlobalPointer(kAddrCityOrderCapabilityStatePtr));
            int capabilityScore = getProduction(cityRecord, 7);
            if (capabilityScore != 0 && orderCapabilityState != 0 &&
                orderCapabilityState->hasProductionOrder193 != 0) {
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

          if (cityRecord->developmentStage < pendingStage) {
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

        if (localizationRuntime->redrawEnabled != 0 && needsRedraw != 0) {
          dispatchRedraw(regionId);
        }
      }
    }

    ++regionOrdinal;
  }
}

// FUNCTION: IMPERIALISM 0x004DC540
void TGreatPower::CompareMissionScoreVariantsByMode(int mode) {
  // First-pass compile-safe variant: keep paired-score comparison shape by mode.
  int primaryMetric = (mode == 0) ? 4 : 5;
  int secondaryMetric = (mode == 0) ? 6 : 7;

  float primaryScore = this->ComputeMapActionContextCompositeScoreForNation(primaryMetric);
  float secondaryScore = this->ComputeMapActionContextCompositeScoreForNation(secondaryMetric);
  if (primaryScore < secondaryScore) {
    return;
  }
}

// FUNCTION: IMPERIALISM 0x004DC660
void TGreatPower::BuildGreatPowerMapContextTriggeredNationEventMessages(void) {
  void* diplomacyManager = ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr);
  if (diplomacyManager == 0) {
    return;
  }

  bool hasEligibleForeignNation = false;
  for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
    if (nationSlot == this->field0c) {
      continue;
    }
    if (Diplomacy_HasPolicyWithNation(diplomacyManager, nationSlot, this->field0c) != 0 &&
        IsNationSlotEligibleForEventProcessingFast(nationSlot) != 0) {
      hasEligibleForeignNation = true;
      break;
    }
  }
  if (!hasEligibleForeignNation) {
    return;
  }

  for (int nationSlotCandidate = 0; nationSlotCandidate < 7; ++nationSlotCandidate) {
    if (nationSlotCandidate == this->field0c) {
      continue;
    }
    unsigned int nationMask = 1u << (nationSlotCandidate & 0x1f);
    unsigned int selfMask = 1u << (this->field0c & 0x1f);
    if ((this->field914 & nationMask) != 0 && (this->field914 & selfMask) == 0) {
      int messageRef = 0;
      int scratchRef = 0;
      InitializeSharedStringRefFromEmpty(&messageRef);
      InitializeSharedStringRefFromEmpty(&scratchRef);
      ReleaseSharedStringRefIfNotEmpty(&scratchRef);
      ReleaseSharedStringRefIfNotEmpty(&messageRef);
      break;
    }
  }
}

// FUNCTION: IMPERIALISM 0x004DC840
void TGreatPower::BuildGreatPowerEligibleNationEventMessagesFromLinkedList(void) {
  typedef int(__fastcall * ListSlot48CountFn)(void*, int);
  typedef TTrackedObjectListEntryView*(__fastcall * ListSlot4CGetFn)(void*, int, int);

  void* diplomacyManager = ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr);
  if (diplomacyManager == 0) {
    return;
  }

  bool hasEligibleForeignNation = false;
  for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
    if (nationSlot == this->field0c) {
      continue;
    }
    if (Diplomacy_HasPolicyWithNation(diplomacyManager, nationSlot, this->field0c) != 0 &&
        IsNationSlotEligibleForEventProcessingFast(nationSlot) != 0) {
      hasEligibleForeignNation = true;
      break;
    }
  }
  if (!hasEligibleForeignNation) {
    return;
  }

  void* trackedList = this->pField89c;
  void** trackedListVtable = *reinterpret_cast<void***>(trackedList);
  ListSlot48CountFn getTrackedCount =
      reinterpret_cast<ListSlot48CountFn>(trackedListVtable[0x48 / 4]);
  ListSlot4CGetFn getTrackedEntry = reinterpret_cast<ListSlot4CGetFn>(trackedListVtable[0x4C / 4]);

  for (int entryIndex = getTrackedCount(trackedList, 0); entryIndex != 0; --entryIndex) {
    TTrackedObjectListEntryView* entry = getTrackedEntry(trackedList, 0, entryIndex);
    if (entry == 0) {
      continue;
    }
    if (entry->regionIndex >= 0 && this->field8a0_candidateNationFlags[entry->regionIndex] == 0) {
      int messageRef = 0;
      int scratchRef = 0;
      InitializeSharedStringRefFromEmpty(&messageRef);
      InitializeSharedStringRefFromEmpty(&scratchRef);
      ReleaseSharedStringRefIfNotEmpty(&scratchRef);
      ReleaseSharedStringRefIfNotEmpty(&messageRef);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004dc9f0
void TGreatPower::RefreshGreatPowerRelationPanelsAndDispatchDeltaSummary(void) {
  typedef void(__fastcall * GreatPowerNoArgFn)(TGreatPower*);
  typedef void(__fastcall * ManagerNoArgFn)(void*);

  if (this->pField894 == 0) {
    return;
  }

  void** vtable = this->field00;
  reinterpret_cast<GreatPowerNoArgFn>(vtable[0x4D])(this);
  reinterpret_cast<GreatPowerNoArgFn>(vtable[0x4E])(this);
  reinterpret_cast<GreatPowerNoArgFn>(vtable[0x43])(this);
  BuildGreatPowerRelationshipDeltaSummaryAndDispatchMessage();
  void* relationManager = this->pField894;
  void** managerVtable = *reinterpret_cast<void***>(relationManager);
  reinterpret_cast<ManagerNoArgFn>(managerVtable[0x28 / 4])(relationManager);
  reinterpret_cast<GreatPowerNoArgFn>(vtable[0x2A])(this);
}

// FUNCTION: IMPERIALISM 0x004DCD10
void TGreatPower::ApplyNationResourceNeedTargetsToOrderState(void) {
  typedef void(__fastcall * GreatPowerSlot0EFn)(TGreatPower*, int, int);
  typedef void(__fastcall * GreatPowerSlot64Fn)(TGreatPower*, int, int, int);
  typedef void(__fastcall * RelationMgrSlot80Fn)(void*, int);

  GreatPowerSlot0EFn applyTreasuryDelta = reinterpret_cast<GreatPowerSlot0EFn>(this->field00[0x0E]);
  RelationMgrSlot80Fn relationRefresh = 0;

  applyTreasuryDelta(this, 0, static_cast<int>(this->field13c[0x15]) * 500);

  void* relationManager = this->pField894;
  if (relationManager != 0) {
    void** relationManagerVtable = *reinterpret_cast<void***>(relationManager);
    relationRefresh = reinterpret_cast<RelationMgrSlot80Fn>(relationManagerVtable[0x80 / 4]);
    *reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(relationManager) + 0xE0) = 0;
    relationRefresh(relationManager, 0);
  }

  applyTreasuryDelta(this, 0, static_cast<int>(this->field13c[0x16]) * 200);

  if (relationManager != 0) {
    *reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(relationManager) + 0xE2) = 0;
    relationRefresh(relationManager, 0);
  }

  GreatPowerSlot64Fn applyNeedTarget = reinterpret_cast<GreatPowerSlot64Fn>(this->field00[0x64]);
  for (int needIndex = 0; static_cast<short>(needIndex) < 0x17; ++needIndex) {
    applyNeedTarget(this, 0, needIndex, this->field13c[needIndex]);
  }
}

// FUNCTION: IMPERIALISM 0x004dce10
void TGreatPower::SetNationResourceNeedCurrentByType(int needType, int currentValue) {
  short needIndex = static_cast<short>(needType);
  this->field10e[needIndex] = static_cast<short>(currentValue);
}

// FUNCTION: IMPERIALISM 0x004dce90
void TGreatPower::TryIncrementNationResourceNeedTargetTowardCurrent(int needType) {
  typedef void(__fastcall * GreatPowerNeedUpdateProc)(TGreatPower*, int, int, int);

  short needIndex = static_cast<short>(needType);
  short targetValue = this->field13c[needIndex];
  short currentValue = this->field10e[needIndex];
  if (targetValue < currentValue) {
    GreatPowerNeedUpdateProc updateNeed =
        reinterpret_cast<GreatPowerNeedUpdateProc>(this->field00[0x45]);
    updateNeed(this, 0, needType, static_cast<int>(targetValue) + 1);
  }
}

// FUNCTION: IMPERIALISM 0x004DCF10
void TGreatPower::IsNationResourceNeedCurrentSumExceedingCapA6(void) {
  int sumCurrentNeeds = 0;
  for (int needIndex = 0; needIndex < 0x17; ++needIndex) {
    sumCurrentNeeds += static_cast<int>(this->field10e[needIndex]);
  }

  this->fieldA8 = (sumCurrentNeeds > static_cast<int>(this->fieldA6)) ? 1 : 0;
}

// FUNCTION: IMPERIALISM 0x004dd0c0
void TGreatPower::SetDiplomacyColonyBoycottFlagForTargetAndRefreshMinorNations(
    int targetNationSlot, int isBoycottEnabled) {
  typedef char(__fastcall * SecondarySlot5CFn)(void*, int, int);
  typedef void(__fastcall * SecondarySlot48Fn)(void*, int, int, int);

  unsigned char boycottFlag = static_cast<unsigned char>(isBoycottEnabled);
  int policyValue = ((-(int)(boycottFlag != 0)) & 0xC8) + 0x64;
  this->field918[targetNationSlot] = boycottFlag;

  for (unsigned int secondaryStateCursor = 0x006A429C; secondaryStateCursor < 0x006A42DC;
       secondaryStateCursor += 4) {
    void* secondaryState = *reinterpret_cast<void**>(secondaryStateCursor);
    void** secondaryVtable = *reinterpret_cast<void***>(secondaryState);
    char hasNationFlag = reinterpret_cast<SecondarySlot5CFn>(secondaryVtable[0x5C / 4])(
        secondaryState, 0, this->field0c);
    if (hasNationFlag != 0) {
      reinterpret_cast<SecondarySlot48Fn>(secondaryVtable[0x48 / 4])(secondaryState, 0,
                                                                     targetNationSlot, policyValue);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004dd310
void TGreatPower::ReleaseDiplomacyTrackedObjectSlots850(void) {
  typedef void(__fastcall * ReleaseAt1CFn)(void*, int);

  for (int listIndex = 0; listIndex < 0x11; ++listIndex) {
    void* trackedObject = this->pField850[listIndex];
    void** trackedObjectVtable = *reinterpret_cast<void***>(trackedObject);
    reinterpret_cast<ReleaseAt1CFn>(trackedObjectVtable[0x1C / 4])(trackedObject, 0);
  }
}

// FUNCTION: IMPERIALISM 0x004dd340
void TGreatPower::AddAmountToAidAllocationMatrixCellAndTotal(int amount, short columnIndex,
                                                             short rowIndex) {
  int matrixIndex =
      static_cast<int>(rowIndex) * kAidAllocationColumnCount + static_cast<int>(columnIndex);

  GreatPower_AdjustTreasury(this, amount);
  this->field280[matrixIndex] += amount;
  this->field914 += amount;
}

// FUNCTION: IMPERIALISM 0x004dd3b0
int TGreatPower::SumAidAllocationMatrixColumnForTarget(short targetNationId) {
  int total = 0;
  int rowIndex = 0;
  while (rowIndex < kAidAllocationRowCount) {
    int matrixIndex = rowIndex * kAidAllocationColumnCount + static_cast<int>(targetNationId);
    total += this->field280[matrixIndex];
    ++rowIndex;
  }
  return total;
}

// FUNCTION: IMPERIALISM 0x004dd3f0
int TGreatPower::SumAidAllocationMatrixAllCells(void) {
  int total = 0;
  int rowIndex = 0;
  while (rowIndex < kAidAllocationRowCount) {
    int columnIndex = 0;
    while (columnIndex < kAidAllocationColumnCount) {
      int matrixIndex = rowIndex * kAidAllocationColumnCount + columnIndex;
      total += this->field280[matrixIndex];
      ++columnIndex;
    }
    ++rowIndex;
  }
  return total;
}

// FUNCTION: IMPERIALISM 0x004dd430
int TGreatPower::ComputeRemainingDiplomacyAidBudget(void) {
  typedef int(__fastcall * GreatPowerGetIntFn)(TGreatPower*, int);

  GreatPowerGetIntFn getBaseBudget = reinterpret_cast<GreatPowerGetIntFn>(this->field00[0x5F]);
  int outstandingCommitments = this->field8f8;
  int pendingAdjustments = this->field960;
  int baseBudget = getBaseBudget(this, 0);
  return baseBudget + this->field840 + this->field844 - pendingAdjustments - outstandingCommitments;
}

// FUNCTION: IMPERIALISM 0x004dd470
void TGreatPower::ResetDiplomacyNeedSlots7012AndRefreshIfModeGateMatches(void) {
  typedef void(__fastcall * GreatPowerSetNeedSlotFn)(TGreatPower*, int, int, int);
  typedef void(__fastcall * GreatPowerRefreshNeedPanelsFn)(TGreatPower*, int);

  TLocalizationRuntimeView* localizationTable = ReadLocalizationRuntimeView();
  if (localizationTable == 0) {
    return;
  }
  if (localizationTable->runtimeSubsystemIndex != 0 || localizationTable->mode != 2) {
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

// FUNCTION: IMPERIALISM 0x004dd4e0
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

// FUNCTION: IMPERIALISM 0x004dd740
void TGreatPower::GetDiplomacyExternalStateB6ByTarget(void) {
  if (this->pField894 == 0) {
    return;
  }
}

// FUNCTION: IMPERIALISM 0x004dda20
void TGreatPower::DecrementDiplomacyCounterA2ByValue(int delta) {
  this->fieldA2 = static_cast<short>(this->fieldA2 - static_cast<short>(delta));
}

// FUNCTION: IMPERIALISM 0x004dda90
void TGreatPower::QueueInterNationEventType0FForNationPairContext(short targetNationSlot,
                                                                  short sourceNationSlot) {
  QueueInterNationEventMergeFn mergeFn = reinterpret_cast<QueueInterNationEventMergeFn>(
      thunk_QueueInterNationEventType0FWithBitmaskMerge);
  mergeFn(ReadGlobalPointer(kAddrInterNationEventQueueManagerPtr), 0, this->field0c,
          sourceNationSlot, targetNationSlot, 0);
}

// FUNCTION: IMPERIALISM 0x004ddbb0
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
      void** uiVtable = *reinterpret_cast<void***>(uiRuntimeContext);
      UiRuntimeSlot98Fn uiSlot98 = reinterpret_cast<UiRuntimeSlot98Fn>(uiVtable[0x98 / 4]);
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

// FUNCTION: IMPERIALISM 0x004DDD20
void TGreatPower::OrphanVtableAssignStub_004ddd20(void) {
  this->field1c6[0] = 0;
}

// FUNCTION: IMPERIALISM 0x004ddd50
bool TGreatPower::IsDiplomacyState1C6UnsetAndCounterPositiveForTarget(short targetNationSlot) {
  typedef short(__fastcall * GreatPowerGetCounterFn)(TGreatPower*);

  GreatPowerGetCounterFn slot1D = reinterpret_cast<GreatPowerGetCounterFn>(this->field00[0x1D]);
  unsigned char result = 1;

  short activeCounter = slot1D(this);
  if (activeCounter <= 0 || this->field1c6[targetNationSlot] >= 0) {
    result = 0;
  }
  return result != 0;
}

// FUNCTION: IMPERIALISM 0x004ddfc0
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
    TLocalizationRuntimeView* localizationTable = ReadLocalizationRuntimeView();
    if (localizationTable != 0 && localizationTable->mode == 6) {
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

// FUNCTION: IMPERIALISM 0x004de2d0
void TGreatPower::ResetDiplomacyPolicyAndGrantEntriesPreserveRecurringGrants(void) {
  const unsigned short kResetValue = 0xFFFF;
  const unsigned short kRecurringGrantMask = 0x4000;

  int targetNation = 0;
  while (static_cast<short>(targetNation) < 0x17) {
    this->fieldB2[targetNation] = static_cast<short>(kResetValue);

    unsigned short grantEntry = static_cast<unsigned short>(this->fieldE0[targetNation]);
    this->fieldE0[targetNation] = static_cast<short>(kResetValue);
    if (grantEntry != kResetValue && (grantEntry & kRecurringGrantMask) != 0) {
      GreatPower_ResetPolicyForNation(this, targetNation, grantEntry);
    }

    ++targetNation;
  }
}

// FUNCTION: IMPERIALISM 0x004de340
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

// FUNCTION: IMPERIALISM 0x004de5e0
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

// FUNCTION: IMPERIALISM 0x004de700
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

// FUNCTION: IMPERIALISM 0x004de790
bool TGreatPower::CanAffordAdditionalDiplomacyCostAfterCommitments(short additionalCost) {
  int availableBudget = ComputeAvailableDiplomacyBudget(this);
  int remainingBudget = availableBudget - this->fieldAC - static_cast<int>(additionalCost);
  return remainingBudget >= 0;
}
#if defined(_MSC_VER)
#pragma optimize("", on)
#endif

// FUNCTION: IMPERIALISM 0x004de860
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

  this->field0e = static_cast<short>(arg1 + 100);

  EligibilityFn isNationEligible =
      reinterpret_cast<EligibilityFn>(thunk_IsNationSlotEligibleForEventProcessing);
  void* eligibilityManager = ReadGlobalPointer(kAddrEligibilityManagerPtr);
  void** terrainTypeDescriptors = ReadGlobalPointerArray(kAddrTerrainTypeDescriptorTable);
  int nationSlot;
  for (nationSlot = 0; nationSlot < kNationSlotCount; ++nationSlot) {
    if (isNationEligible(eligibilityManager, 0, nationSlot) != 0 && nationSlot != this->field0c &&
        nationSlot != arg1) {
      void* terrainTypeDescriptor = terrainTypeDescriptors[nationSlot];
      if (terrainTypeDescriptor != 0) {
        TerrainDescriptor_SetResetLevel(terrainTypeDescriptor, this->field0c, kResetDiplomacyLevel);
      }
    }
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

  unsigned char* candidateNationFlags = this->field8a0_candidateNationFlags;
  short* needLevelByNation = this->field14_needLevelByNation;

  int idx;
  for (idx = 0; idx < kNationSlotCount; ++idx) {
    this->fieldB2[idx] = static_cast<short>(-1);
    this->fieldE0[idx] = static_cast<short>(-1);
    candidateNationFlags[idx] = 0;
    needLevelByNation[idx] = 100;
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
      if (nationState != 0 && NationState_IsBusyA0(nationState) == 0) {
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
      const TSecondaryNationStateOwnerView* secondaryStateView =
          static_cast<const TSecondaryNationStateOwnerView*>(secondaryState);
      short encodedOwnerNation = secondaryStateView->encodedOwnerNationSlot;
      if (encodedOwnerNation >= 200) {
        short ownerNation = DecodeSecondaryNationOwnerSlot(secondaryStateView);
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

  TLocalizationRuntimeView* localizationTable = ReadLocalizationRuntimeView();
  if (localizationTable != 0 && localizationTable->redrawEnabled != 0) {
    reinterpret_cast<void(__cdecl*)(void)>(thunk_DispatchTaggedGameStateEvent1F20)();
  }
}

// FUNCTION: IMPERIALISM 0x004dedf0
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

// FUNCTION: IMPERIALISM 0x004defd0
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

// FUNCTION: IMPERIALISM 0x004df010
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

// FUNCTION: IMPERIALISM 0x004df370
void TGreatPower::QueueInterNationEventForProposalCode12D_130(unsigned short proposalQueueIndex) {
  const short kProposalCode12D = 0x12D;
  const short kProposalCode12E = 0x12E;
  const short kProposalCode12F = 0x12F;
  const short kProposalCode130 = 0x130;
  const int kEvent09 = 9;
  const int kEvent0B = 11;
  const int kEvent0D = 13;
  const int kEvent07 = 7;

  void* proposalQueue = this->pField84c;
  if (proposalQueue == 0) {
    return;
  }

  int queueOrdinal = static_cast<int>(static_cast<short>(proposalQueueIndex));
  if (queueOrdinal > static_cast<int>(ProposalQueue_GetCount(proposalQueue))) {
    return;
  }

  short* proposalEntry = ProposalQueue_GetEntryAt1Based(proposalQueue, queueOrdinal);
  short proposalCode = proposalEntry[0];
  short targetNation = proposalEntry[1];

  void* diplomacyManager = ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr);
  if (diplomacyManager != 0 && Diplomacy_HasFlag84ForNation(diplomacyManager, targetNation) != 0) {
    void* nationState = ReadGlobalPointerArraySlot(kAddrNationStates, targetNation);
    if (nationState != 0) {
      NationState_NotifyActionCode(nationState, this->field0c, -proposalCode);
    }
  }

  switch (proposalCode) {
  case kProposalCode12D:
    QueueInterNationEventRecordDedup(kEvent09, targetNation, this->field0c);
    return;
  case kProposalCode12E:
    QueueInterNationEventRecordDedup(kEvent0B, targetNation, this->field0c);
    return;
  case kProposalCode12F:
    QueueInterNationEventRecordDedup(kEvent0D, targetNation, this->field0c);
    return;
  case kProposalCode130:
    QueueInterNationEventRecordDedup(kEvent07, targetNation, this->field0c);
    return;
  default:
    return;
  }
}

// FUNCTION: IMPERIALISM 0x004df580
void TGreatPower::ResetNationDiplomacyProposalQueue(void) {
  void* proposalQueue = this->pField84c;
  if (proposalQueue != 0) {
    ReleaseObjectAtSlot1C(proposalQueue);
  }
}

// FUNCTION: IMPERIALISM 0x004df5c0
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

// FUNCTION: IMPERIALISM 0x004df5f0
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

// FUNCTION: IMPERIALISM 0x004E00D0
void DispatchGreatPowerQuarterlyStatusMessageLevel2(void) {
  if (!IsQuarterlyLocalizationGateOpen()) {
    return;
  }
  DispatchQuarterlyGreatPowerPressureMessage(2);
}

// FUNCTION: IMPERIALISM 0x004E0140
void DispatchGreatPowerQuarterlyStatusMessageLevel1(void) {
  if (!IsQuarterlyLocalizationGateOpen()) {
    return;
  }
  DispatchQuarterlyGreatPowerPressureMessage(1);
}

// FUNCTION: IMPERIALISM 0x004E01B0
void DispatchGreatPowerQuarterlyStatusMessageLevel0(void) {
  if (!IsQuarterlyLocalizationGateOpen()) {
    return;
  }
  DispatchQuarterlyGreatPowerPressureMessage(0);
}

// FUNCTION: IMPERIALISM 0x004e1d50
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
    void** diplomacyVtable = reinterpret_cast<void**>(diplomacyTurnStateManager->vftable);
    DiplomacyTurnStateSlot44Fn diplomacySlot44 =
        reinterpret_cast<DiplomacyTurnStateSlot44Fn>(diplomacyVtable[0x44 / 4]);
    if (diplomacySlot44 != 0) {
      result = diplomacySlot44(self->field0c);
    }
  }

  UiRuntimeSlot94Fn uiSlot94 = 0;
  if (uiRuntimeContext != 0) {
    void** uiVtable = *reinterpret_cast<void***>(uiRuntimeContext);
    uiSlot94 = reinterpret_cast<UiRuntimeSlot94Fn>(uiVtable[0x94 / 4]);
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
        const TSecondaryNationStateOwnerView* secondaryNationStateView =
            static_cast<const TSecondaryNationStateOwnerView*>(secondaryNationState);
        short stateValue = DecodeSecondaryNationOwnerSlot(secondaryNationStateView);
        if (stateValue != self->field0c) {
          void** secondaryVtable = *reinterpret_cast<void***>(secondaryNationState);
          SecondaryNationSlot4CFn slot4C =
              reinterpret_cast<SecondaryNationSlot4CFn>(secondaryVtable[0x4C / 4]);
          if (slot4C != 0) {
            slot4C(secondaryNationState, 0, self->field0c, 1);
          }
        }
      }
    }
  }
  return result != 0;
}

// FUNCTION: IMPERIALISM 0x004E22B0
void TGreatPower::AddRegionIdToNationOwnedRegionListAndTriggerExpansionActionIfThresholdMet(void) {
  typedef void(__fastcall * ListSlot14Fn)(void*, int);
  typedef int(__fastcall * ListSlot28Fn)(void*, int);
  typedef void(__fastcall * GreatPowerDispatchEventFn)(TGreatPower*, int, int, int);

  void* ownedRegionList = this->pField90;
  void** listVtable = *reinterpret_cast<void***>(ownedRegionList);
  reinterpret_cast<ListSlot14Fn>(listVtable[0x14 / 4])(ownedRegionList, 0);
  int ownedRegionCount = reinterpret_cast<ListSlot28Fn>(listVtable[0x28 / 4])(ownedRegionList, 0);

  unsigned char pressureGate = this->field8c8_serializedFlags[6];
  unsigned char nationGate = this->pad_8d1[3];
  if (ownedRegionCount > 8 && pressureGate > 0x32 && nationGate < 3) {
    GreatPowerDispatchEventFn dispatchEvent =
        reinterpret_cast<GreatPowerDispatchEventFn>(this->field00[0x2E]);
    dispatchEvent(this, 0, 0x0C, -1);
  }
}

// FUNCTION: IMPERIALISM 0x004E2330
void TGreatPower::ApplyDiplomacyTargetTransitionAndClearGrantEntry(int targetNationSlot,
                                                                   int policyCode) {
  typedef void(__fastcall * GreatPowerSlot84Fn)(TGreatPower*, int, int);
  typedef void(__fastcall * GreatPowerSlot85Fn)(TGreatPower*, int, int);

  short targetNation = static_cast<short>(targetNationSlot);
  if (policyCode == 500 || policyCode != 200) {
    this->field14_needLevelByNation[targetNation] = 100;
  } else {
    void* terrainDescriptor =
        ReadGlobalPointerArraySlot(kAddrTerrainTypeDescriptorTable, targetNation);
    short encodedNationSlot = TerrainDescriptor_GetEncodedNationSlot(terrainDescriptor);
    int resolvedNation = DecodeTerrainNationSlot(encodedNationSlot, terrainDescriptor);
    this->field14_needLevelByNation[targetNation] =
        this->field14_needLevelByNation[static_cast<short>(resolvedNation)];
  }

  this->fieldE0[targetNation] = -1;

  if (policyCode == 500) {
    void* diplomacyManager = ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr);
    this->fieldB2[targetNation] = -1;
    Diplomacy_SetRelationCode78(diplomacyManager, this->field0c, targetNation, 4);
    reinterpret_cast<GreatPowerSlot85Fn>(this->field00[0x85])(this, 0, targetNation);
    return;
  }

  if (policyCode != 200) {
    reinterpret_cast<GreatPowerSlot84Fn>(this->field00[0x84])(this, 0, targetNation);
    return;
  }

  if (this->field8a0_candidateNationFlags[targetNation] == 0) {
    void* terrainDescriptor =
        ReadGlobalPointerArraySlot(kAddrTerrainTypeDescriptorTable, targetNation);
    short encodedNationSlot = TerrainDescriptor_GetEncodedNationSlot(terrainDescriptor);
    int resolvedNation = DecodeTerrainNationSlot(encodedNationSlot, terrainDescriptor);
    if (this->field8a0_candidateNationFlags[static_cast<short>(resolvedNation)] == 0) {
      void* diplomacyManager = ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr);
      if (Diplomacy_HasPolicyWithNation(diplomacyManager, this->field0c, resolvedNation) == 0) {
        reinterpret_cast<GreatPowerSlot85Fn>(this->field00[0x85])(this, 0, targetNation);
        return;
      }
    }
  }

  reinterpret_cast<GreatPowerSlot84Fn>(this->field00[0x84])(this, 0, targetNation);
}

// FUNCTION: IMPERIALISM 0x004E2500
void TGreatPower::ReleaseTrackedObjectsByMapOwnerAndUnassignedEntries(int ownerClass) {
  typedef int(__fastcall * ListSlot48CountFn)(void*, int);
  typedef TTrackedObjectListEntryView*(__fastcall * ListSlot4CGetFn)(void*, int, int);
  typedef void(__fastcall * ObjSlot30Fn)(void*, int);
  typedef void(__fastcall * ObjSlot1CFn)(void*, int);

  TGlobalMapStateScoreView* globalMapState = ReadGlobalMapStateScoreView();
  void* filteredList = this->pField89c;
  void** filteredListVtable = *reinterpret_cast<void***>(filteredList);
  ListSlot48CountFn getFilteredCount =
      reinterpret_cast<ListSlot48CountFn>(filteredListVtable[0x48 / 4]);
  ListSlot4CGetFn getFilteredEntry =
      reinterpret_cast<ListSlot4CGetFn>(filteredListVtable[0x4C / 4]);

  for (int index = getFilteredCount(filteredList, 0); index != 0; --index) {
    TTrackedObjectListEntryView* entry = getFilteredEntry(filteredList, 0, index);
    if (entry == 0 || globalMapState == 0 || globalMapState->terrainStateTable == 0) {
      continue;
    }

    short mapOwnerClass = globalMapState->terrainStateTable[entry->regionIndex].cityRecordIndex;
    if (mapOwnerClass == ownerClass) {
      void* trackedObject = entry->object;
      void** trackedObjectVtable = *reinterpret_cast<void***>(trackedObject);
      reinterpret_cast<ObjSlot30Fn>(trackedObjectVtable[0x30 / 4])(trackedObject, 0);
      reinterpret_cast<ObjSlot1CFn>(trackedObjectVtable[0x1C / 4])(trackedObject, 0);
    }
  }

  void* unassignedList = this->pField44;
  void** unassignedListVtable = *reinterpret_cast<void***>(unassignedList);
  ListSlot48CountFn getUnassignedCount =
      reinterpret_cast<ListSlot48CountFn>(unassignedListVtable[0x48 / 4]);
  ListSlot4CGetFn getUnassignedEntry =
      reinterpret_cast<ListSlot4CGetFn>(unassignedListVtable[0x4C / 4]);

  for (int unassignedIndex = getUnassignedCount(unassignedList, 0); unassignedIndex != 0;
       --unassignedIndex) {
    TTrackedObjectListEntryView* entry = getUnassignedEntry(unassignedList, 0, unassignedIndex);
    if (entry != 0 && entry->regionIndex == -1) {
      void* trackedObject = entry->object;
      void** trackedObjectVtable = *reinterpret_cast<void***>(trackedObject);
      reinterpret_cast<ObjSlot1CFn>(trackedObjectVtable[0x1C / 4])(trackedObject, 0);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004E27B0
void TGreatPower::DispatchNationDiplomacySlotActionByMode(int targetNationSlot, int mode) {
  typedef void(__fastcall * GreatPowerSlotA8Fn)(TGreatPower*, int, int);
  typedef void(__fastcall * GreatPowerSlotA9Fn)(TGreatPower*, int);

  if (static_cast<short>(mode) == 6) {
    reinterpret_cast<GreatPowerSlotA8Fn>(this->field00[0xA8])(this, 0, targetNationSlot);
    return;
  }

  reinterpret_cast<GreatPowerSlotA9Fn>(this->field00[0xA9])(this, 0);
}

// FUNCTION: IMPERIALISM 0x004E2B70
void TGreatPower::BuildGreatPowerTurnMessageSummaryAndDispatch(void) {
  if (this->pField908 == 0) {
    return;
  }

  typedef int(__fastcall * QueueSlot48CountFn)(void*, int);
  typedef short*(__fastcall * QueueSlot2CGetFn)(void*, int, int);
  typedef short(__fastcall * LocalizationTickFn)(void*, int);

  void* summaryQueue = this->pField908;
  void** queueVtable = *reinterpret_cast<void***>(summaryQueue);
  QueueSlot48CountFn getQueueCount = reinterpret_cast<QueueSlot48CountFn>(queueVtable[0x48 / 4]);
  QueueSlot2CGetFn getQueueEntry = reinterpret_cast<QueueSlot2CGetFn>(queueVtable[0x2C / 4]);

  int queueCount = getQueueCount(summaryQueue, 0);
  if (queueCount <= 0) {
    return;
  }

  short activeTurn = 0;
  TLocalizationRuntimeView* localizationRuntime = ReadLocalizationRuntimeView();
  if (localizationRuntime != 0) {
    void** localizationVtable = *reinterpret_cast<void***>(localizationRuntime);
    LocalizationTickFn getTurnTick =
        reinterpret_cast<LocalizationTickFn>(localizationVtable[0x3C / 4]);
    activeTurn = static_cast<short>(getTurnTick(localizationRuntime, 0) - 1);
  }

  int mergedNationMask = 0;
  bool foundCurrentTurnEntry = false;

  for (int queueIndex = 1; queueIndex <= queueCount; ++queueIndex) {
    short* entry = getQueueEntry(summaryQueue, 0, queueIndex);
    if (entry == 0 || entry[0] != activeTurn) {
      continue;
    }

    foundCurrentTurnEntry = true;
    mergedNationMask |= 1 << (static_cast<int>(entry[1]) & 0x1F);
  }

  if (!foundCurrentTurnEntry) {
    return;
  }

  this->QueueInterNationEventIntoNationBucket(0x13A0, mergedNationMask, '\0');
}

// FUNCTION: IMPERIALISM 0x004E72C0
void TGreatPower::InitializeMapActionCandidateStateAndQueueMission(int arg1) {
  typedef short(__fastcall * StreamReadShortFn)(int, int, short*);
  typedef int(__fastcall * StreamReadBytesFn)(int, int, void*, int);
  typedef int(__fastcall * QueueCountFn)(void*, int);
  typedef void(__fastcall * QueueClearFn)(void*, int);
  typedef void(__fastcall * QueueLoadFromStreamFn)(void*, int, int);

  this->thunk_InitializeGreatPowerMinisterRosterAndScenarioState(arg1);

  StreamReadShortFn streamReadShort =
      reinterpret_cast<StreamReadShortFn>((*(void***)(arg1))[0x3C / 4]);
  for (int i = 0; i < 6; ++i) {
    streamReadShort(arg1, 0, &this->field964[i]);
  }
  SwapShortArrayBytes(this->field964, 6);

  StreamReadBytesFn streamReadBytes =
      reinterpret_cast<StreamReadBytesFn>((*(void***)(arg1))[0x3C / 4]);
  streamReadBytes(arg1, 0, this->field970, 0x180);
  streamReadBytes(arg1, 0, this->fieldAF0, 0x70);

  void* missionQueue = this->pFieldB60;
  if (missionQueue != 0) {
    void** queueVtable = *reinterpret_cast<void***>(missionQueue);
    QueueCountFn getCount = reinterpret_cast<QueueCountFn>(queueVtable[0x48 / 4]);
    QueueClearFn clearQueue = reinterpret_cast<QueueClearFn>(queueVtable[0x54 / 4]);
    QueueLoadFromStreamFn loadFromStream =
        reinterpret_cast<QueueLoadFromStreamFn>(queueVtable[0x18 / 4]);

    if (getCount(missionQueue, 0) != 0) {
      clearQueue(missionQueue, 0);
    }
    loadFromStream(missionQueue, 0, arg1);
  }

  if (*reinterpret_cast<int*>(kAddrAdvanceTurnMachineState) < 0x39) {
    this->thunk_QueueMapActionMissionFromCandidateAndMarkState(5, -1, 0, -1);
  }
}

// FUNCTION: IMPERIALISM 0x004e73f0
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

// FUNCTION: IMPERIALISM 0x004E7630
void TGreatPower::WrapperFor_TGreatPower_VtblSlot32_At004e7630(int arg1, int arg2, int arg3) {
  if (arg2 < 0 && arg1 > 6 && arg1 < 0x0D) {
    this->field10e[arg1] = static_cast<short>(this->field10e[arg1] + arg2);
  }

  this->thunk_ApplyIndexedResourceDeltaAndAdjustNationTotals_At00407392(arg1, arg2, arg3);
}

// FUNCTION: IMPERIALISM 0x004E7B20
void TGreatPower::ForwardApplyDiplomacyPolicyStateForTargetWithCostChecks(int arg1, int arg2) {
  this->thunk_ApplyDiplomacyPolicyStateForTargetWithCostChecks_At004070e5(arg1, arg2);
}

// FUNCTION: IMPERIALISM 0x004e7b50
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

// FUNCTION: IMPERIALISM 0x004e7c50
void TGreatPower::ApplyImmediateDiplomacyPolicySideEffectsWithSelectionHook(int arg1, int arg2) {
  typedef void(__fastcall * GreatPowerSlot84Fn)(TGreatPower*, int, int);

  if (static_cast<short>(arg2) == 0x131) {
    reinterpret_cast<GreatPowerSlot84Fn>(this->field00[0x84])(this, 0, static_cast<short>(arg1));
  }
  thunk_ApplyImmediateDiplomacyPolicySideEffects_At0040862a(arg1, arg2);
}

// FUNCTION: IMPERIALISM 0x004e8540
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
  void** queueVtable = *reinterpret_cast<void***>(missionQueue);
  QueuePushMissionFn pushMission = reinterpret_cast<QueuePushMissionFn>(queueVtable[0x30 / 4]);
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

// FUNCTION: IMPERIALISM 0x004e8750
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
    void* mgr = ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr);
    if (mgr == 0) {
      return kOne;
    }
    short relationValue = Diplomacy_ReadRelationMatrix79C(mgr, this->field0c, relationTargetNation);
    if (relationValue == 0) {
      return kOne;
    }
    return 100.0f / (float)relationValue;
  }
  case 5: {
    TGlobalMapStateScoreView* globalMapState = ReadGlobalMapStateScoreView();
    if (globalMapState == 0) {
      return kOne;
    }
    if (globalMapState->cityScoreTable == 0 || globalMapState->cityScoreTotal == 0) {
      return kOne;
    }
    int cityScore = GlobalMapState_ReadCityScoreValue(globalMapState, cityIndex);
    return (float)cityScore / (float)globalMapState->cityScoreTotal;
  }
  case 6:
  default:
    return kOne;
  }
}

// FUNCTION: IMPERIALISM 0x004e9060
float TGreatPower::ComputeMapActionContextCompositeScoreForNation(int nodeType) {
  typedef void(__fastcall * ConstructRelationshipListFn)(void*, int);
  typedef void(__fastcall * ManagerSlot88Fn)(void*, int, int, int, void*);
  typedef void*(__fastcall * ListSlot2CFn)(void*, int, int);
  typedef void(__fastcall * ListSlot24Fn)(void*);

  unsigned char* candidateFlags = this->field8a0_candidateNationFlags;
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
        selectedCandidateIndex =
            static_cast<int>(static_cast<TShortNodeValueView*>(firstNode)->value);
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

// FUNCTION: IMPERIALISM 0x004E9A50
void TGreatPower::SelectAndQueueAdvisoryMapMissionsCase16(void) {
  if (this->pField894 == 0) {
    return;
  }

  this->thunk_PopulateCase16AdvisoryMapNodeCandidateState();

  int bestNodeIndex = -1;
  float bestNodeScore = 0.0f;

  for (int nodeIndex = 0; nodeIndex < 0x180; ++nodeIndex) {
    if (this->field970[nodeIndex] != 1) {
      continue;
    }

    float nodeScore = this->thunk_ComputeMapActionContextCompositeScoreForNation(nodeIndex);
    if (bestNodeIndex < 0 || nodeScore > bestNodeScore) {
      bestNodeIndex = nodeIndex;
      bestNodeScore = nodeScore;
    }
  }

  if (bestNodeIndex < 0) {
    return;
  }

  this->thunk_QueueMapActionMissionFromCandidateAndMarkState(3, bestNodeIndex, 0, -1);

  int strongestNation = -1;
  int strongestNeed = 0;
  for (int nationSlot = 0; nationSlot < 0x17; ++nationSlot) {
    int needValue = static_cast<int>(this->field14_needLevelByNation[nationSlot]);
    if (needValue > strongestNeed) {
      strongestNeed = needValue;
      strongestNation = nationSlot;
    }
  }

  if (strongestNation >= 0 && strongestNation != this->field0c) {
    this->thunk_QueueInterNationEventType0FForNationPairContext_At00405ac9(
        static_cast<short>(strongestNation), this->field0c);
  }
}

// FUNCTION: IMPERIALISM 0x004E9ED0
void TGreatPower::QueueWarTransitionFromAdvisoryAction(int arg1, int arg2) {
  typedef void(__fastcall * GreatPowerSlot84Fn)(TGreatPower*, int, int);

  reinterpret_cast<GreatPowerSlot84Fn>(this->field00[0x84])(this, 0, arg1);
  this->thunk_QueueWarTransitionAndNotifyThirdPartyIfNeeded_At00406fe1(arg1, arg1, arg2, arg1);
}

// FUNCTION: IMPERIALISM 0x004EA150
void TGreatPower::ApplyJoinEmpireResetAndClearDiplomacyCaches(int arg1) {
  typedef void(__fastcall * GreatPowerSlotB3Fn)(TGreatPower*, int);

  this->thunk_ApplyJoinEmpireMode0GlobalDiplomacyReset_At004097fa(arg1);

  int i = 0;
  for (i = 0; i < 6; ++i) {
    this->field964[i] = 0;
  }
  for (i = 0; i < 0x180; ++i) {
    this->field970[i] = 0;
  }
  for (i = 0; i < 0x70; ++i) {
    this->fieldAF0[i] = 0;
  }

  reinterpret_cast<GreatPowerSlotB3Fn>(this->field00[0xB3])(this, 0);
}

// FUNCTION: IMPERIALISM 0x004EA290
void TGreatPower::AddRegionToNationAndQueueMapActionMission(int arg1) {
  this->thunk_AddRegionIdToNationOwnedRegionListAndTriggerExpansionActionIfThresholdMet_At00404246();

  if (arg1 >= 0 && arg1 < 0x180) {
    this->field970[arg1] = 1;
    this->thunk_QueueMapActionMissionFromCandidateAndMarkState(3, arg1, 0, -1);
  }
}

// FUNCTION: IMPERIALISM 0x004EA300
void TGreatPower::MarkNationPortZoneAndLinkedTilesForActionFlag(int arg1) {
  typedef int(__fastcall * ListCountFn)(void*, int);
  typedef int(__fastcall * ListGetByOrdinalFn)(void*, int, int);

  this->thunk_ResetNationDiplomacySlotsAndMarkRelatedNations_At00406c9e();

  void* terrainDescriptor = ReadGlobalPointerArraySlot(kAddrTerrainTypeDescriptorTable, arg1);
  if (terrainDescriptor != 0) {
    void* linkedNodeList =
        *reinterpret_cast<void**>(reinterpret_cast<unsigned char*>(terrainDescriptor) + 0x90);
    if (linkedNodeList != 0) {
      void** listVtable = *reinterpret_cast<void***>(linkedNodeList);
      ListCountFn getCount = reinterpret_cast<ListCountFn>(listVtable[0x28 / 4]);
      ListGetByOrdinalFn getByOrdinal = reinterpret_cast<ListGetByOrdinalFn>(listVtable[0x24 / 4]);

      int linkedCount = getCount(linkedNodeList, 0);
      for (int ordinal = 1; ordinal <= linkedCount; ++ordinal) {
        int nodeIndex = getByOrdinal(linkedNodeList, 0, ordinal);
        if (nodeIndex >= 0 && nodeIndex < 0x180) {
          this->field970[nodeIndex] = 1;
          this->thunk_QueueMapActionMissionFromCandidateAndMarkState(3, nodeIndex, 0, -1);
        }
      }
    }
  }

  GetShortAtOffset14Fn getPortNode =
      reinterpret_cast<GetShortAtOffset14Fn>(thunk_GetShortAtOffset14OrInvalid);
  short portNode = getPortNode();
  if (portNode >= 0 && portNode < 0x70) {
    this->fieldAF0[portNode] = 1;
    this->thunk_QueueMapActionMissionFromCandidateAndMarkState(3, -1, portNode, -1);
  }
}

// FUNCTION: IMPERIALISM 0x004ea470
void TGreatPower::RebuildNationResourceYieldsAndRollField134Into136(void) {
  this->thunk_RebuildNationResourceYieldCountersAndDevelopmentTargets_At004097ff();
  short carryValue = this->field10e[0x13];
  this->field10e[0x13] = 0;
  this->field10e[0x14] = static_cast<short>(this->field10e[0x14] + carryValue);
}

// FUNCTION: IMPERIALISM 0x004FFC10
void TGreatPower::ConstructTurnOrderNavigationWindowEntryViewportAdaptive(void) {
  this->fieldA0 = 0;
  this->fieldA2 = 0x14;
  this->fieldA4 = 0;
  this->fieldA6 = 0;
  this->fieldA8 = 0;
  this->fieldAC = 0;
}

// FUNCTION: IMPERIALISM 0x00540AC0
void TGreatPower::QueueDiplomacyProposalCodeForTargetNationAndDispatchTurnEvent16(void) {
  this->thunk_QueueDiplomacyProposalCodeForTargetNation_At004083f5();

  int payload = static_cast<int>(this->field0c) & 0xFF;
  payload |= (static_cast<int>(this->field0e) & 0xFF) << 8;
  SendTurnEvent13WithPayload(0x16, reinterpret_cast<void*>(payload));
}

// FUNCTION: IMPERIALISM 0x00541080
void TGreatPower::TryDispatchNationActionViaUiThenTurnEvent(int arg1, int arg2) {
  this->TryDispatchNationActionViaUiContextOrFallback(arg1, arg2);
  if (arg1 >= 0) {
    this->DispatchTurnEvent2103WithNationFromRecord();
  }
}

// FUNCTION: IMPERIALISM 0x005410F0
void TGreatPower::ProcessPendingDiplomacyThenDispatchTurnEvent29A(void) {
  this->ProcessPendingDiplomacyProposalQueue();

  for (int nationSlot = 0; nationSlot < 0x17; ++nationSlot) {
    void* nationState = ReadGlobalPointerArraySlot(kAddrNationStates, nationSlot);
    if (nationState == 0) {
      continue;
    }
    if (!NationState_IsBusyA0(nationState)) {
      // Pending-bit cleanup side effects are still unresolved; keep scan shape.
    }
  }

  void* uiRuntimeContext = ReadGlobalPointer(kAddrUiRuntimeContextPtr);
  if (uiRuntimeContext != 0) {
    UiRuntime_RequestDiplomacyDecision(uiRuntimeContext, this->field0c, this->field0c, 0x29A);
  }
}

// FUNCTION: IMPERIALISM 0x005416B0
void TGreatPower::ApplyClientGreatPowerCommand69AndEmitTurnEvent1E(int arg1, int arg2) {
  bool accepted = this->thunk_ExecuteAdvisoryPromptAndApplyActionType1_At00403c15();

  int payload = (0x69 << 16) | ((arg2 & 0xFF) << 8) | (arg1 & 0xFF);
  if (!accepted) {
    payload = -1;
  }

  this->QueueInterNationEventIntoNationBucket(0x1E, payload, '\0');
}

// FUNCTION: IMPERIALISM 0x0055C970
void TGreatPower::QueueInterNationEventIntoNationBucket(int eventCode, int payloadOrNation,
                                                        char isReplayBypass) {
  TLocalizationRuntimeView* localizationTable = ReadLocalizationRuntimeView();
  if (localizationTable != 0 && isReplayBypass == '\0' && localizationTable->redrawEnabled != 0) {
    SendTurnEvent13WithPayload(eventCode, reinterpret_cast<void*>(payloadOrNation));
    return;
  }

  QueueInterNationEventRecordDedup(eventCode, this->field0c, payloadOrNation);
}

struct TInterNationEventType0FMergePayload {
  int eventMarker;
  int eventCode;
  int nationMask;
  int nationB;
};

// FUNCTION: IMPERIALISM 0x0055CBD0
void TGreatPower::QueueInterNationEventType0FWithBitmaskMerge(int eventCode, int nationA,
                                                              int nationB, char isReplayBypass) {
  TLocalizationRuntimeView* localizationTable = ReadLocalizationRuntimeView();
  if (localizationTable != 0 && isReplayBypass == '\0' && localizationTable->redrawEnabled != 0) {
    SendTurnEvent13WithPayload(eventCode, reinterpret_cast<void*>(nationB));
    return;
  }

  TInterNationEventType0FMergePayload payload;
  payload.eventMarker = 0x0F;
  payload.eventCode = eventCode;
  payload.nationMask = 1 << (nationA & 0x1F);
  payload.nationB = nationB;
  QueueInterNationEventWithPayload(this->field0c, &payload);
}

// FUNCTION: IMPERIALISM 0x0055F140
unsigned int TGreatPower::ComputeMapActionContextNodeValueAverage(void) {
  TGlobalMapStateScoreView* globalMapState = ReadGlobalMapStateScoreView();
  if (globalMapState == 0 || globalMapState->cityScoreTable == 0) {
    return 0;
  }

  unsigned int totalValue = 0;
  unsigned int selectedCount = 0;

  for (int nodeIndex = 0; nodeIndex < 0x180; ++nodeIndex) {
    if (this->field970[nodeIndex] == 0) {
      continue;
    }
    totalValue +=
        static_cast<unsigned int>(GlobalMapState_ReadCityScoreValue(globalMapState, nodeIndex));
    ++selectedCount;
  }

  if (selectedCount == 0) {
    return static_cast<unsigned int>(
        GlobalMapState_ReadCityScoreValue(globalMapState, this->field0c));
  }

  return totalValue / selectedCount;
}

// FUNCTION: IMPERIALISM 0x005C2940
void TGreatPower::InitializeCivWorkOrderState(int nOrderType, int pOwnerContext,
                                              int nOrderOwnerNationId) {
  RegisterUnitOrderWithOwnerManager(this, nOrderType, pOwnerContext, nOrderOwnerNationId);
  TCivWorkOrderStateBaseView* orderState = reinterpret_cast<TCivWorkOrderStateBaseView*>(this);
  orderState->remainingTurns24 = 0;
  orderState->completionMarker26 = static_cast<short>(-1);
}

// FUNCTION: IMPERIALISM 0x00601F1D
void TGreatPower::CPtrList(int ownerContext) {
  CPtrListSentinelView* list = reinterpret_cast<CPtrListSentinelView*>(this);
  list->field0c = 0;
  list->field10 = 0;
  list->field08 = 0;
  list->field04 = 0;
  list->pField14 = 0;
  list->vftable = reinterpret_cast<void*>(kAddrCPtrListRuntimeClassVtable);
  list->field18 = ownerContext;
}
