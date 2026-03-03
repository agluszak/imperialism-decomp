// Manual decompilation file.
// Seeded from ghidra autogen and normalized into compile-safe wrappers.

#include "decomp_types.h"
#include "game/generated/vcall_facades.h"
#include <stddef.h>

class TGreatPower;
struct TListObject;
struct TQueueObject;
struct TMinisterObject;
struct TRelationManagerObject;
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
undefined4 thunk_ContainsPointerArrayEntryMatchingByteKey(void);
undefined4 thunk_TemporarilyClearAndRestoreUiInvalidationFlag(void);
undefined4 thunk_IsNationSlotEligibleForEventProcessing(void);
undefined4 thunk_GetInt32Field30(void);
undefined4 thunk_LookupOrderCompatibilityMatrixValue(void);
undefined4 thunk_ComputeWeightedNeighborLinkScoreForNode(void);
undefined4 thunk_SumWeightedNeighborLinkScoreForLinkedNodes(void);
undefined4 thunk_SumNavyOrderPriorityForNationAndNodeType(void);
undefined4 thunk_SumNavyOrderPriorityForNation(void);
undefined4 thunk_ComputeDefendProvinceMissionLocalSupportVectorScore(void);
undefined4 thunk_ComputeDefendProvinceMissionCrossNationSupportVectorScore(void);
undefined4 thunk_FindFirstPortZoneContextByNation(void);
undefined4 thunk_ComputeNavyOrderDistributionSimilarityScoreForExactSourceNation(void);
undefined4 thunk_ComputeNavyOrderDistributionSimilarityScoreWithDiplomacyFilter(void);
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
undefined4 thunk_DispatchTurnEvent1AWithNationActionPayload(void);
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
undefined4 thunk_ClearTurnResumeNationPendingBitAndMaybeFlushTelemetry(void);
undefined4 thunk_GetActiveNationId(void);
undefined4 thunk_SetEventPayloadNationIdFromSlotIndex(void);
undefined4 thunk_EnqueueOrSendTurnEventPacketToNation(void);
undefined4 thunk_SetTimeEmitPacketGameFlowTurnId(void);
undefined4 thunk_CreateAndSendTurnEvent21_ThreeBytes(void);

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
undefined4 GenerateThreadLocalRandom15(void);
undefined4 ReallocateHeapBlockWithAllocatorTracking(void);

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

struct TNationStateEventMessageFlagsView {
  unsigned char pad00[0x4C];
  unsigned char suppressEventMessage4C;
  unsigned char allowEventMessage4D;
};

struct TLocalizationRuntimeView {
  void* vftable;
  unsigned char pad04[4];
  int mode;
  unsigned char pad0c[0x2C - 0x0C];
  short quarterGateTick2c;
  unsigned char pad2e[0x40 - 0x2E];
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

struct TPortZoneContextVectorView {
  unsigned char pad00[0x28];
  int* entries;
  int entryCount;
  int activeEntryCount;
};

struct TMapActionContextListEntryView {
  void* vftable;
  unsigned char pad04[0x10 - 0x04];
  unsigned int nationMask;
  unsigned char pad14[0x18 - 0x14];
  TMapActionContextListEntryView* next;
};

struct TCityOrderCapabilityStateView {
  unsigned char pad00[0x193];
  unsigned char hasProductionOrder193;
};

struct TRelationManagerNeedRefreshView {
  unsigned char pad00[0xE0];
  short relationNeedSlotE0;
  short relationNeedSlotE2;
};

struct TGreatPowerDiplomacyExternalStateView {
  unsigned char pad00[0x894];
  void* diplomacyExternalState894;
};

struct TGreatPowerPressureUpdateView {
  unsigned char pad00[0x166];
  short pressureFactor166;
  short pressureFactor168;
  unsigned char pad16a[0x840 - 0x16A];
  int pressureOffset840;
  unsigned char pad844[0x8F0 - 0x844];
  int smoothedPressure8f0;
  signed char pressureValue8f4;
  unsigned char pad8f5[7];
  signed char pressureTier8fc;
  unsigned char pad8fd[3];
  int pendingDrain900;
};

struct TTerrainDescriptorLinkedNodesView {
  unsigned char pad00[0x90];
  void* linkedNodeList;
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
  short field0c;
  short field0e;
  int field10;
  void* pField14;
  int field18;
};

struct TRefCountedListOwnerView {
  void* vftable;
  CPtrListSentinelView listSentinel;
};

static const unsigned int kAddrUiRuntimeContextPtr = 0x006A21BC;
static const unsigned int kAddrNationInteractionStateManagerPtr = 0x006A43CC;
static const unsigned int kAddrSecondaryNationStateSlots = 0x006A4280;
static const unsigned int kAddrMapActionContextListHead = 0x006A3FC8;
static const unsigned int kAddrDiplomacyTurnStateManagerPtr = 0x006A43D0;
static const unsigned int kAddrGlobalMapStatePtr = 0x006A43D4;
static const unsigned int kAddrInterNationEventQueueManagerPtr = 0x006A43E8;
static const unsigned int kAddrEligibilityManagerPtr = 0x006A43E0;
static const unsigned int kAddrGameFlowStatePtr = 0x006A43C8;
static const unsigned int kAddrCityOrderCapabilityStatePtr = 0x006A43D8;
static const unsigned int kAddrLocalizationTablePtr = 0x006A20F8;
static const unsigned int kAddrShGreatPowerPressureMessageRef = 0x006A2DF0;
static const unsigned int kAddrTerrainTypeDescriptorTable = 0x006A4310;
static const unsigned int kAddrNationStates = 0x006A4370;
static const unsigned int kAddrCompileGreatPowerValue = 0x00653528;
static const unsigned int kAddrNationBasePressureByLocale = 0x00653498;
static const unsigned int kAddrGreatPowerPressureMinFloor = 0x006534B0;
static const unsigned int kAddrGreatPowerPressureRiseCap = 0x006534E0;
static const unsigned int kAddrGreatPowerPressureDecayStep = 0x006534F8;
static const unsigned int kAddrGreatPowerPressureRiseStep = 0x00653510;
static const unsigned int kAddrGreatPowerPressureHardAlertThreshold = 0x00653540;
static const unsigned int kAddrNationRuntimeSubsystemCache = 0x00653558;
static const unsigned int kAddrAdvanceTurnMachineState = 0x00695278;
static const unsigned int kAddrNationStatesMajorEnd = 0x006A438C;
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
  void** vftable;
  unsigned char pad_04[8];
  short nationSlot;
  short encodedNationSlot;
  int pressureScore;
  short needLevelByNation[0x17];
  short field42;
  void* pad_44_ptr;
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
  char thunk_TryDispatchNationActionViaUiContextOrFallback_At00404ce1(int arg1, int arg2, int arg3,
                                                                      int arg4);
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
  void CompareMissionScoreVariantsByMode(int mode);
  void BuildGreatPowerMapContextTriggeredNationEventMessages(void);
  void BuildGreatPowerEligibleNationEventMessagesFromLinkedList(void);
  void QueueWarTransitionAndNotifyThirdPartyIfNeeded(int arg1, int arg2, int arg3, int arg4);
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
  int GetDiplomacyExternalStateB6ByTarget(int targetNationSlot);
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
  void QueueDiplomacyProposalCodeForTargetNation(short proposalCode, short targetNationId);
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
  char TryDispatchNationActionViaUiContextOrFallback(int arg1, int arg2, int arg3, int arg4);
  void QueueDiplomacyProposalCodeForTargetNationAndDispatchTurnEvent16(int proposalCode,
                                                                       int targetNationId);
  void TryDispatchNationActionViaUiThenTurnEvent(int arg1, int arg2, int arg3, int arg4);
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

// C++98-compatible compile-time layout guards for the known TGreatPower core block.
// NOTE: class size/shape is still evolving. A failing guard is a useful drift signal,
// not automatically a correctness bug, unless it breaks a proven-stable core contract.
#define TG_LAYOUT_ASSERT(name, expr) typedef char name[(expr) ? 1 : -1]
TG_LAYOUT_ASSERT(TGreatPower_Offset_nationSlot_0x0C, offsetof(TGreatPower, nationSlot) == 0x0C);
TG_LAYOUT_ASSERT(TGreatPower_Offset_ownedRegionList_0x90,
                 offsetof(TGreatPower, ownedRegionList) == 0x90);
TG_LAYOUT_ASSERT(TGreatPower_Offset_diplomacyPolicyByNation_0xB2,
                 offsetof(TGreatPower, diplomacyPolicyByNation) == 0xB2);
TG_LAYOUT_ASSERT(TGreatPower_Offset_aidAllocationMatrix_0x280,
                 offsetof(TGreatPower, aidAllocationMatrix) == 0x280);
TG_LAYOUT_ASSERT(TGreatPower_Size_AtLeast_0x964, sizeof(TGreatPower) >= 0x964);
#undef TG_LAYOUT_ASSERT

// Tail offsets are still fluid while mixed-method promotions are being merged.
// Keep these as non-fatal probes until the class tail is stabilized.
// Drift here is expected during iterative extraction and is not treated as a hard failure.
enum {
  kTGreatPowerOffset_turnEventQueue = offsetof(TGreatPower, turnEventQueue),
  kTGreatPowerOffset_pendingAidTotal = offsetof(TGreatPower, pendingAidTotal),
  kTGreatPowerOffset_actionMetricByQuarter = offsetof(TGreatPower, actionMetricByQuarter),
};

static __inline void* ReadGlobalPointer(unsigned int address) {
  return *reinterpret_cast<void**>(address);
}

static __inline void** ReadGlobalPointerArray(unsigned int address) {
  return reinterpret_cast<void**>(address);
}

static __inline void* ReadGlobalPointerArraySlot(unsigned int address, int index) {
  return ReadGlobalPointerArray(address)[index];
}

static __inline void* ReadNationStateSlot(int nationSlot) {
  return ReadGlobalPointerArraySlot(kAddrNationStates, nationSlot);
}

static __inline void* ReadSecondaryNationStateSlot(int nationSlot) {
  return ReadGlobalPointerArraySlot(kAddrSecondaryNationStateSlots, nationSlot);
}

static __inline void* ReadTerrainDescriptorSlot(int nationSlot) {
  return ReadGlobalPointerArraySlot(kAddrTerrainTypeDescriptorTable, nationSlot);
}

static __inline TGlobalMapStateScoreView* ReadGlobalMapStateScoreView(void) {
  return static_cast<TGlobalMapStateScoreView*>(ReadGlobalPointer(kAddrGlobalMapStatePtr));
}

static __inline TLocalizationRuntimeView* ReadLocalizationRuntimeView(void) {
  return static_cast<TLocalizationRuntimeView*>(ReadGlobalPointer(kAddrLocalizationTablePtr));
}

static __inline unsigned char
LocalizationRuntime_ReadGateFlag7A(const TLocalizationRuntimeView* localizationRuntime) {
  return *reinterpret_cast<const unsigned char*>(
      reinterpret_cast<const unsigned char*>(localizationRuntime) + 0x7A);
}

static __inline void* GreatPower_GetInterNationQueueByEventCode(TGreatPower* self, int eventCode) {
  return self->diplomacyTrackedSlots[eventCode];
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

static __inline short
LocalizationRuntime_GetTurnTick(TLocalizationRuntimeView* localizationRuntime) {
  return VCall_LocalizationRuntime_GetTurnTick(localizationRuntime);
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

static __inline int Obj_QueryIntAtSlot(void* obj, int slotOffsetBytes) {
  return vcall_runtime::fastcall0<int>(obj, static_cast<unsigned int>(slotOffsetBytes / 4));
}

static __inline void Obj_CallNoArgAtSlot(void* obj, int slotOffsetBytes) {
  vcall_runtime::fastcall0v(obj, static_cast<unsigned int>(slotOffsetBytes / 4));
}

static __inline void Obj_CallIntArgAtSlot(void* obj, int slotOffsetBytes, int value) {
  vcall_runtime::fastcall1v(obj, static_cast<unsigned int>(slotOffsetBytes / 4), value);
}

static __inline void Obj_CallPtrArgAtSlot(void* obj, int slotOffsetBytes, void* value) {
  vcall_runtime::fastcall1v(obj, static_cast<unsigned int>(slotOffsetBytes / 4), value);
}

template <typename TObjectPtr>
static __inline void Obj_ReleaseAndClearSlot(TObjectPtr* objectSlot, int slotOffsetBytes) {
  void* object = static_cast<void*>(*objectSlot);
  if (object != 0) {
    Obj_CallNoArgAtSlot(object, slotOffsetBytes);
  }
  *objectSlot = 0;
}

static __inline void Stream_ReadAtSlot3C(void* stream, void* outBuf, int sizeBytes) {
  VCall_Stream_ReadAtSlot3C(stream, outBuf, sizeBytes);
}

static __inline int Stream_ReadIntAtSlot40(void* stream) {
  return VCall_Stream_ReadIntAtSlot40(stream);
}

static __inline void Stream_ReadRawAtSlot00(void* stream, void* outBuf, int sizeBytes) {
  VCall_Stream_ReadRawAtSlot00(stream, outBuf, sizeBytes);
}

static __inline char Stream_ReadByteAtSlotB0(void* stream, void* outByte) {
  return VCall_Stream_ReadByteAtSlotB0(stream, outByte);
}

static __inline short ProposalQueue_GetCount(void* queue) {
  return static_cast<const TProposalQueueCountView*>(queue)->count;
}

static __inline short* ProposalQueue_GetEntryAt1Based(void* queue, int queueIndex) {
  return static_cast<short*>(VCall_ProposalQueue_GetEntryAt1Based(queue, queueIndex));
}

static __inline void List_ResetSlot14(void* list) {
  VCall_List_ResetSlot14(list);
}

static __inline int List_GetCountSlot28(void* list) {
  return VCall_List_GetCountSlot28(list);
}

static __inline int List_GetIntByOrdinalSlot24(void* list, int ordinal) {
  return VCall_List_GetIntByOrdinalSlot24(list, ordinal);
}

static __inline int List_GetCountSlot48(void* list) {
  return VCall_List_GetCountSlot48(list);
}

static __inline TTrackedObjectListEntryView* List_GetTrackedEntrySlot4C(void* list, int ordinal) {
  return static_cast<TTrackedObjectListEntryView*>(VCall_List_GetTrackedEntrySlot4C(list, ordinal));
}

static __inline int ObArray_GetCountAtOffset8(void* list) {
  return *reinterpret_cast<int*>(reinterpret_cast<unsigned char*>(list) + 8);
}

static __inline short ObArray_GetShortValueByOrdinal1Based(void* list, int ordinal) {
  short* value = static_cast<short*>(VCall_ObArray_GetShortValueByOrdinalSlot2C(list, ordinal));
  return (value != 0) ? *value : static_cast<short>(-1);
}

static __inline void Diplomacy_BuildRelationshipListForNation(void* diplomacyManager,
                                                              int sourceNation, int mode,
                                                              void* outList) {
  VCall_Diplomacy_BuildRelationshipListSlot88(diplomacyManager, sourceNation, mode, outList);
}

static __inline short Diplomacy_GetRelationTier(void* diplomacyManager, int sourceNation,
                                                int targetNation) {
  return VCall_Diplomacy_GetRelationTierSlot70(diplomacyManager, sourceNation, targetNation);
}

static __inline char Diplomacy_HasPolicyWithNation(void* diplomacyManager, int sourceNation,
                                                   int targetNation) {
  return VCall_Diplomacy_HasPolicyWithNationSlot44(diplomacyManager, sourceNation, targetNation);
}

static __inline char UiRuntime_RequestDiplomacyDecision(void* uiRuntimeContext, int sourceNation,
                                                        int targetNation, int proposalCode) {
  return VCall_UiRuntime_RequestDiplomacyDecisionSlot90(uiRuntimeContext, sourceNation,
                                                        targetNation, proposalCode);
}

static __inline char IsTurnCooldownCounterActiveOrResetFlagAsChar(void) {
  char(__cdecl * isTurnCooldownActive)(void) =
      reinterpret_cast<char(__cdecl*)(void)>(thunk_IsTurnCooldownCounterActiveOrResetFlag);
  return isTurnCooldownActive();
}

static __inline void GreatPower_CommitProposalByIndex(TGreatPower* self, int proposalIndex) {
  VCall_GreatPower_CommitProposalByIndexSlot7B(self, proposalIndex);
}

static __inline void GreatPower_RemoveProposalByIndex(TGreatPower* self, int proposalIndex) {
  VCall_GreatPower_RemoveProposalByIndexSlot7C(self, proposalIndex);
}

static __inline void GreatPower_ApplyMutualDefenseWithNation(TGreatPower* self, int checkNation,
                                                             int sourceNation) {
  VCall_GreatPower_ApplyPolicyForNationSlotA1(self, checkNation, 0x132, sourceNation);
}

static __inline void GreatPower_FinalizeProposalQueue(TGreatPower* self) {
  VCall_GreatPower_FinalizeProposalQueueSlot73(self);
}

static __inline void QueueObject_WritePackedIntAtSlot38(void* queue, int* packedValue) {
  VCall_QueueObject_WritePackedIntAtSlot38(queue, packedValue);
}

static __inline char GreatPower_ShouldDispatchImmediately(TGreatPower* self) {
  return VCall_GreatPower_ShouldDispatchImmediatelySlot28(self);
}

static __inline void QueueInterNationEventWithPayload(int sourceNation, void* payload) {
  void* queueManager = ReadGlobalPointer(kAddrInterNationEventQueueManagerPtr);
  void(__fastcall * queueInterNationEvent)(void*, int, int, void*, char) =
      reinterpret_cast<void(__fastcall*)(void*, int, int, void*, char)>(
          QueueInterNationEventIntoNationBucket);
  queueInterNationEvent(queueManager, 0, sourceNation, payload, '\0');
}

static __inline void SendTurnEvent13WithPayload(int sourceNation, void* payload) {
  void(__fastcall * sendTurnEvent13)(void*, int, void*) =
      reinterpret_cast<void(__fastcall*)(void*, int, void*)>(
          thunk_CreateAndSendTurnEvent13_NationAndNineDwords);
  sendTurnEvent13(0, sourceNation, payload);
}

static __inline char IsNationSlotEligibleForEventProcessingFast(int nationSlot) {
  char(__fastcall * isNationEligible)(void*, int, int) =
      reinterpret_cast<char(__fastcall*)(void*, int, int)>(
          thunk_IsNationSlotEligibleForEventProcessing);
  void* eligibilityManager = ReadGlobalPointer(kAddrEligibilityManagerPtr);
  return isNationEligible(eligibilityManager, 0, nationSlot);
}

static __inline char Diplomacy_HasFlag84ForNation(void* diplomacyManager, int nationSlot) {
  return VCall_Diplomacy_HasFlag84ForNationSlot84(diplomacyManager, nationSlot);
}

static __inline void Diplomacy_SetRelationState(void* diplomacyManager, int sourceNation,
                                                int targetNation, int relationState) {
  vcall_runtime::fastcall3v_with_edx(diplomacyManager, static_cast<unsigned int>(0x7C / 4),
                                     sourceNation, targetNation, relationState, 0);
}

static __inline void GreatPower_ApplyPolicyForNation(TGreatPower* self, int targetNation,
                                                     int policyCode, int sourceNation) {
  VCall_GreatPower_ApplyPolicyForNationSlotA1(self, targetNation, policyCode, sourceNation);
}

static __inline void ReleaseObjectAtSlot1C(void* obj) {
  Obj_CallNoArgAtSlot(obj, 0x1C);
}

static __inline void Object_CallSlot30NoArgs(void* obj) {
  Obj_CallNoArgAtSlot(obj, 0x30);
}

static __inline void TerrainDescriptor_SetResetLevel(void* terrainDescriptor, int sourceNation,
                                                     int resetLevel) {
  VCall_TerrainDescriptor_SetResetLevelSlot68(terrainDescriptor, sourceNation, resetLevel);
}

static __inline void NationState_NotifyAction131(void* nationState, int sourceNation) {
  VCall_NationState_NotifyActionSlot94(nationState, sourceNation, 0x131);
}

static __inline void NationState_NotifyActionCode(void* nationState, int sourceNation,
                                                  int actionCode) {
  VCall_NationState_NotifyActionSlot94(nationState, sourceNation, actionCode);
}

static __inline void NationState_AssignNeedSlotFromSource(void* nationState, int needSlot,
                                                          int sourceNation) {
  VCall_NationState_AssignNeedSlotFromSourceSlot19C(nationState, needSlot, sourceNation);
}

static __inline char NationState_IsBusyA0(void* nationState) {
  const TNationStateFlagsView* nationStateView =
      static_cast<const TNationStateFlagsView*>(nationState);
  return nationStateView->busyFlagA0;
}

static __inline short GreatPower_GetNeedSlotValue(TGreatPower* self, int needSlot) {
  return VCall_GreatPower_GetNeedSlotValueSlot1F(self, needSlot);
}

static __inline void Object_CallSlot8CNoArgs(void* obj) {
  Obj_CallNoArgAtSlot(obj, 0x8C);
}

static __inline void SecondaryState_ResetDiplomacyLevel(void* secondaryState, int sourceNation,
                                                        int resetLevel) {
  VCall_SecondaryState_ResetDiplomacyLevelSlot48(secondaryState, sourceNation, resetLevel);
}

static __inline void GreatPower_ResetDiplomacyLevelForNation(TGreatPower* self, int nationSlot,
                                                             int resetLevel) {
  VCall_GreatPower_ResetDiplomacyLevelForNationSlot12(self, nationSlot, resetLevel);
}

static __inline void GreatPower_ResetPolicyForNation(TGreatPower* self, int nationSlot,
                                                     int resetPolicyCode) {
  VCall_GreatPower_ResetPolicyForNationSlot75(self, nationSlot, resetPolicyCode);
}

static __inline void GreatPower_CallSlot13(TGreatPower* self, int arg1, int arg2) {
  VCall_GreatPower_CallSlot13(self, arg1, arg2);
}

static __inline void GreatPower_SetPolicyForNation(TGreatPower* self, int nationSlot,
                                                   int policyCode) {
  VCall_GreatPower_SetPolicyForNationSlot74(self, nationSlot, policyCode);
}

static __inline int GreatPower_CanPayAmount(TGreatPower* self, int amount) {
  return VCall_GreatPower_CanPayAmountSlot7A(self, amount);
}

static __inline void GreatPower_AdjustTreasury(TGreatPower* self, int amount) {
  VCall_GreatPower_AdjustTreasurySlot0E(self, amount);
}

static __inline char GreatPower_CanSetGrantValue(TGreatPower* self, int grantValue) {
  return VCall_GreatPower_CanSetGrantValueSlot77(self, grantValue);
}

static __inline short Diplomacy_ReadRelationMatrix79C(void* diplomacyManager, int sourceNation,
                                                      int targetNation) {
  const TDiplomacyTurnStateManagerRelationView* relationView =
      static_cast<const TDiplomacyTurnStateManagerRelationView*>(diplomacyManager);
  int matrixIndex = sourceNation * 0x17 + targetNation;
  return relationView->relationMatrix79C[matrixIndex];
}

static __inline char GlobalMapState_CallMetricC4(void* globalMapState, int regionIndex,
                                                 int edgeIndex) {
  return VCall_GlobalMapState_CallMetricSlotC4(globalMapState, regionIndex, edgeIndex);
}

static __inline short LookupOrderCompatibility(short sourceNationSlot, short targetNationSlot) {
  short(__fastcall * lookupOrderCompatibility)(void*, int, int, int) =
      reinterpret_cast<short(__fastcall*)(void*, int, int, int)>(
          thunk_LookupOrderCompatibilityMatrixValue);
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

static __inline int ResolveTerrainNationSlotFromTarget(int targetNationSlot) {
  void* terrainDescriptor =
      ReadGlobalPointerArraySlot(kAddrTerrainTypeDescriptorTable, targetNationSlot);
  short encodedNationSlot = TerrainDescriptor_GetEncodedNationSlot(terrainDescriptor);
  return DecodeTerrainNationSlot(encodedNationSlot, terrainDescriptor);
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
  VCall_GreatPower_CallSlot5C(self);
}

static __inline void GreatPower_CallSlotA5(TGreatPower* self) {
  VCall_GreatPower_CallSlotA5(self);
}

static __inline void Diplomacy_SetFlag74(void* diplomacyManager, int sourceNation, int targetNation,
                                         int flagValue) {
  VCall_Diplomacy_SetFlag74(diplomacyManager, sourceNation, targetNation, flagValue);
}

static __inline void Diplomacy_SetFlag28(void* diplomacyManager, int sourceNation, int targetNation,
                                         int flagValue) {
  VCall_Diplomacy_SetFlag28(diplomacyManager, sourceNation, targetNation, flagValue);
}

static __inline void Diplomacy_SetRelationCode78(void* diplomacyManager, int sourceNation,
                                                 int targetNation, int relationCode) {
  vcall_runtime::fastcall2v_with_edx(diplomacyManager, static_cast<unsigned int>(0x78 / 4),
                                     sourceNation, targetNation, relationCode);
}

static __inline void QueueInterNationEventRecordDedup(int eventCode, int sourceNation,
                                                      int targetNation) {
  void(__fastcall * queueInterNationEventDedup)(void*, int, int, int, int, char) =
      reinterpret_cast<void(__fastcall*)(void*, int, int, int, int, char)>(
          thunk_QueueInterNationEventRecordDeduped);
  queueInterNationEventDedup(ReadGlobalPointer(kAddrInterNationEventQueueManagerPtr), 0, eventCode,
                             sourceNation, targetNation, '\0');
}

static __inline void ClearTurnResumeNationPendingBitAndMaybeFlushTelemetry(void* gameFlowState,
                                                                           int nationSlot) {
  void(__fastcall * clearPendingBit)(void*, int, int) =
      reinterpret_cast<void(__fastcall*)(void*, int, int)>(
          thunk_ClearTurnResumeNationPendingBitAndMaybeFlushTelemetry);
  clearPendingBit(gameFlowState, 0, nationSlot);
}

static __inline void TerrainDescriptor_CallSlot4C(void* terrainDescriptor, int sourceNation,
                                                  int modeValue) {
  VCall_TerrainDescriptor_CallSlot4C(terrainDescriptor, sourceNation, modeValue);
}

static __inline void TerrainDescriptor_CallSlot38(void* terrainDescriptor, int delta) {
  VCall_TerrainDescriptor_CallSlot38(terrainDescriptor, delta);
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
  return ClampNonNegative(self->pressureScore + self->diplomacyBudgetBase / 100);
}

static __inline void RegisterUnitOrderWithOwnerManager(TGreatPower* self, int nOrderType,
                                                       int pOwnerContext, int nOrderOwnerNationId) {
  void(__fastcall * registerOrder)(TGreatPower*, int, int, int, int, int) =
      reinterpret_cast<void(__fastcall*)(TGreatPower*, int, int, int, int, int)>(
          thunk_RegisterUnitOrderWithOwnerManager);
  registerOrder(self, 0, nOrderType, pOwnerContext, nOrderOwnerNationId, 0);
}

static __inline void GreatPower_CallSlotA1(TGreatPower* self) {
  VCall_GreatPower_CallSlotA1_NoArgs(self);
}

static __inline void GreatPower_DispatchEventSlot2E(TGreatPower* self, int eventCode, int arg) {
  VCall_GreatPower_DispatchEventSlot2E(self, eventCode, arg);
}

static __inline void GreatPower_CallSlot84(TGreatPower* self, int targetNation) {
  VCall_GreatPower_CallSlot84(self, targetNation);
}

static __inline void GreatPower_CallSlot85(TGreatPower* self, int targetNation) {
  VCall_GreatPower_CallSlot85(self, targetNation);
}

static __inline void GreatPower_CallSlotA8(TGreatPower* self, int targetNation) {
  VCall_GreatPower_CallSlotA8(self, targetNation);
}

static __inline void GreatPower_CallSlotA9(TGreatPower* self) {
  VCall_GreatPower_CallSlotA9(self);
}

static __inline void GreatPower_CallSlotB3(TGreatPower* self) {
  VCall_GreatPower_CallSlotB3(self);
}

static __inline void GreatPower_CallNoArgVirtual(TGreatPower* self, int slotIndex) {
  vcall_runtime::thiscall0v(self, static_cast<unsigned int>(slotIndex));
}

static __inline void RelationManager_RefreshSlot80(void* relationManager) {
  VCall_RelationManager_RefreshSlot80(relationManager);
}

static __inline void RelationManager_CallSlot28NoArgs(void* relationManager) {
  vcall_runtime::thiscall0v(relationManager, static_cast<unsigned int>(0x28 / 4));
}

static __inline void RelationManager_ClearNeedSlotE0AndRefresh(void* relationManager) {
  TRelationManagerNeedRefreshView* relationView =
      static_cast<TRelationManagerNeedRefreshView*>(relationManager);
  relationView->relationNeedSlotE0 = 0;
  RelationManager_RefreshSlot80(relationManager);
}

static __inline void RelationManager_ClearNeedSlotE2AndRefresh(void* relationManager) {
  TRelationManagerNeedRefreshView* relationView =
      static_cast<TRelationManagerNeedRefreshView*>(relationManager);
  relationView->relationNeedSlotE2 = 0;
  RelationManager_RefreshSlot80(relationManager);
}

static __inline void* AllocateObArrayWithMode(short mode) {
  void* array = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x18));
  if (array != 0) {
    void(__fastcall * constructPtrArray)(void*, int) =
        reinterpret_cast<void(__fastcall*)(void*, int)>(thunk_ConstructObArrayWithVtable654D38);
    void(__fastcall * initializePtrArrayMode)(void*, int) =
        reinterpret_cast<void(__fastcall*)(void*, int)>(
            thunk_InitializeObArrayVtable654D38ModeField);
    constructPtrArray(array, 0);
    initializePtrArrayMode(array, 0);
    static_cast<TObArrayModeView*>(array)->modeField14 = mode;
  }
  return array;
}

static __inline void* AllocateBattleListOwnerWithPtrListSentinel(void) {
  void* owner = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x20));
  if (owner != 0) {
    TRefCountedListOwnerView* ownerView = static_cast<TRefCountedListOwnerView*>(owner);
    ownerView->vftable = reinterpret_cast<void*>(kAddrVtblRefCountedObjectBase);
    reinterpret_cast<void(__fastcall*)(void*, int)>(::CPtrList)(
        static_cast<void*>(&ownerView->listSentinel), 0);
    ownerView->vftable = reinterpret_cast<void*>(kAddrVtblTArmyBattle);
  }
  return owner;
}

static __inline void* AllocateBattleListOwnerWithLinkedSentinel(void) {
  void* owner = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x20));
  if (owner != 0) {
    TRefCountedListOwnerView* ownerView = static_cast<TRefCountedListOwnerView*>(owner);
    reinterpret_cast<void(__fastcall*)(void*, int)>(
        WrapperFor_InitializeLinkedListSentinelNodeWithOwnerContext_At004a8640)(
        static_cast<void*>(&ownerView->listSentinel), 0);
    ownerView->vftable = reinterpret_cast<void*>(kAddrVtblTArmyBattle);
  }
  return owner;
}

static __inline bool IsQuarterlyLocalizationGateOpen(void) {
  TLocalizationRuntimeView* localizationTable = ReadLocalizationRuntimeView();
  if (localizationTable == 0) {
    return false;
  }

  int localizationTick = static_cast<int>(localizationTable->quarterGateTick2c);
  int quarterGate = (localizationTick + ((localizationTick >> 0x1f) & 3)) >> 2;
  return static_cast<short>(quarterGate) != 0;
}

static __inline void DispatchQuarterlyGreatPowerPressureMessage(int statusLevel) {
  // Keep this stack-local shape: the thunk pair expects transient locals
  // prepared in this frame before it captures/dispatches the localized ref.
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

static const int kNationSlotCount = 0x17;
static const int kMapNodeCount = 0x180;
static const int kPortZoneCount = 0x70;
static const int kAidAllocationRowCount = 0x10;
static const int kAidAllocationColumnCount = 0x17;
static const int kMajorNationCount = 7;
static const int kDiplomacyTrackedSlotCount = 0x11;

static __inline void InitializeAndReleaseSharedMessageRefs(void) {
  int messageRef = 0;
  int scratchRef = 0;
  InitializeSharedStringRefFromEmpty(&messageRef);
  InitializeSharedStringRefFromEmpty(&scratchRef);
  ReleaseSharedStringRefIfNotEmpty(&scratchRef);
  ReleaseSharedStringRefIfNotEmpty(&messageRef);
}

struct SharedRefPairScope {
  int first;
  int second;

  SharedRefPairScope() : first(0), second(0) {
    InitializeSharedStringRefFromEmpty(&first);
    InitializeSharedStringRefFromEmpty(&second);
  }

  ~SharedRefPairScope() {
    ReleaseSharedStringRefIfNotEmpty(&second);
    ReleaseSharedStringRefIfNotEmpty(&first);
  }
};

static __inline void InitializeThreeSharedRefs(int* firstRef, int* secondRef, int* thirdRef) {
  InitializeSharedStringRefFromEmpty(firstRef);
  InitializeSharedStringRefFromEmpty(secondRef);
  InitializeSharedStringRefFromEmpty(thirdRef);
}

static __inline void ReleaseThreeSharedRefs(int* firstRef, int* secondRef, int* thirdRef) {
  ReleaseSharedStringRefIfNotEmpty(thirdRef);
  ReleaseSharedStringRefIfNotEmpty(secondRef);
  ReleaseSharedStringRefIfNotEmpty(firstRef);
}

struct SharedRefTripleScope {
  int first;
  int second;
  int third;

  SharedRefTripleScope() : first(0), second(0), third(0) {
    InitializeSharedStringRefFromEmpty(&first);
    InitializeSharedStringRefFromEmpty(&second);
    InitializeSharedStringRefFromEmpty(&third);
  }

  ~SharedRefTripleScope() {
    ReleaseSharedStringRefIfNotEmpty(&third);
    ReleaseSharedStringRefIfNotEmpty(&second);
    ReleaseSharedStringRefIfNotEmpty(&first);
  }
};

static __inline void
MapActionContext_AssignDisplayRefFromSlot2C(TMapActionContextListEntryView* entry, int* outRef) {
  VCall_MapActionContext_AssignDisplayRefFromSlot2C(entry, outRef);
}

static __inline char SecondaryState_HasNationFlag5C(void* secondaryState, int nationSlot) {
  return VCall_SecondaryState_HasNationFlag5C(secondaryState, nationSlot);
}

static __inline void SecondaryState_SetPolicyValue48(void* secondaryState, int targetNationSlot,
                                                     int policyValue) {
  VCall_SecondaryState_SetPolicyValue48(secondaryState, targetNationSlot, policyValue);
}

static __inline void SecondaryState_CallSlot4C(void* secondaryState, int sourceNation,
                                               int modeValue) {
  VCall_SecondaryState_CallSlot4C(secondaryState, sourceNation, modeValue);
}

static __inline int GetCityBuildingProductionValueBySlot(void* cityRecord, int slot) {
  return reinterpret_cast<int(__cdecl*)(void*, int)>(thunk_GetCityBuildingProductionValueBySlot)(
      cityRecord, slot);
}

static __inline void SetGlobalRegionDevelopmentStageByte(short regionId, unsigned char stage) {
  reinterpret_cast<void(__cdecl*)(short, unsigned char)>(thunk_SetGlobalRegionDevelopmentStageByte)(
      regionId, stage);
}

static __inline void DispatchCityRedrawInvalidateEvent(short regionId) {
  reinterpret_cast<void(__cdecl*)(short)>(thunk_DispatchCityRedrawInvalidateEvent)(regionId);
}

static __inline float ComputeDefendProvinceMissionLocalSupportScore(int nodeContext) {
  return reinterpret_cast<float(__cdecl*)(int)>(
      thunk_ComputeDefendProvinceMissionLocalSupportVectorScore)(nodeContext);
}

static __inline float ComputeDefendProvinceMissionCrossNationSupportScore(int nodeContext) {
  return reinterpret_cast<float(__cdecl*)(int)>(
      thunk_ComputeDefendProvinceMissionCrossNationSupportVectorScore)(nodeContext);
}

static __inline TPortZoneContextVectorView* FindFirstPortZoneContextByNation(void) {
  return reinterpret_cast<TPortZoneContextVectorView*(__cdecl*)(void)>(
      thunk_FindFirstPortZoneContextByNation)();
}

static __inline void* ReallocateBufferWithAllocatorTracking(void* buffer, int sizeBytes) {
  return reinterpret_cast<void*(__cdecl*)(void*, int)>(ReallocateHeapBlockWithAllocatorTracking)(
      buffer, sizeBytes);
}

static __inline float ComputeNavyOrderScoreForExactSourceNation(int sourceNation, int nodeContext) {
  return reinterpret_cast<float(__cdecl*)(int, int)>(
      thunk_ComputeNavyOrderDistributionSimilarityScoreForExactSourceNation)(sourceNation,
                                                                             nodeContext);
}

static __inline float ComputeNavyOrderScoreWithDiplomacyFilter(int sourceNation, int nodeContext) {
  return reinterpret_cast<float(__cdecl*)(int, int)>(
      thunk_ComputeNavyOrderDistributionSimilarityScoreWithDiplomacyFilter)(sourceNation,
                                                                            nodeContext);
}

static __inline unsigned int GenerateThreadLocalRandom15Value(void) {
  return reinterpret_cast<unsigned int(__cdecl*)(void)>(GenerateThreadLocalRandom15)();
}

static __inline void ApplyJoinEmpireMode0GlobalDiplomacyResetImpl(void* globalMapState,
                                                                  int nationSlot) {
  reinterpret_cast<void(__fastcall*)(void*, int, int)>(
      ApplyJoinEmpireMode0GlobalDiplomacyReset_Impl)(globalMapState, 0, nationSlot);
}

static __inline void QueueNationPairWarTransition(void* queue, short sourceNation,
                                                  short targetNation) {
  reinterpret_cast<void(__cdecl*)(void*, short, short)>(thunk_QueueNationPairWarTransition)(
      queue, sourceNation, targetNation);
}

static __inline short GetShortAtOffset14OrInvalidValue(void) {
  return reinterpret_cast<short(__cdecl*)(void)>(thunk_GetShortAtOffset14OrInvalid)();
}

static __inline void* CreateMissionObjectByKindAndNodeContext(int sourceNation, int missionKind,
                                                              int arg2, int arg3, int arg4) {
  return reinterpret_cast<void*(__cdecl*)(int, int, int, int, int)>(
      thunk_CreateMissionObjectByKindAndNodeContext)(sourceNation, missionKind, arg2, arg3, arg4);
}

static __inline void TemporarilyClearAndRestoreUiInvalidationFlag(const char* path, int line) {
  reinterpret_cast<void(__cdecl*)(const char*, int)>(
      thunk_TemporarilyClearAndRestoreUiInvalidationFlag)(path, line);
}

static __inline void Message_AppendWordSlot78(void* message, const void* data) {
  VCall_Message_AppendWordSlot78(message, data);
}

static __inline void Message_AppendBytesSlot78(void* message, const void* data, int sizeBytes) {
  VCall_Message_AppendBytesSlot78(message, data, sizeBytes);
}

static __inline void Message_WriteEntrySlotB4(void* message, int value, int flags) {
  VCall_Message_WriteEntrySlotB4(message, value, flags);
}

static __inline void Queue_ApplyMessageSlot14(void* queue, void* message) {
  VCall_Queue_ApplyMessageSlot14(queue, message);
}

static __inline void Queue_RefreshSlot48(void* queue) {
  VCall_Queue_RefreshSlot48(queue);
}

static __inline int Queue_ReadIndexSlot4C(void* queue, int mode, int index) {
  return VCall_Queue_ReadIndexSlot4C(queue, mode, index);
}

static __inline void* List_GetNodeByOrdinalSlot2C(void* list, int mode, int ordinal) {
  return VCall_List_GetNodeByOrdinalSlot2C(list, mode, ordinal);
}

static __inline void List_ReleaseSlot24(void* list) {
  VCall_List_ReleaseSlot24(list);
}

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
char TGreatPower::thunk_TryDispatchNationActionViaUiContextOrFallback_At00404ce1(int arg1, int arg2,
                                                                                 int arg3,
                                                                                 int arg4) {
  return TryDispatchNationActionViaUiContextOrFallback(arg1, arg2, arg3, arg4);
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
#if defined(_MSC_VER)
#pragma optimize("agsy", on)
#endif
void TGreatPower::thunk_QueueWarTransitionAndNotifyThirdPartyIfNeeded_At00406fe1(int arg1, int arg2,
                                                                                 int arg3,
                                                                                 int arg4) {
  QueueWarTransitionAndNotifyThirdPartyIfNeeded(arg1, arg2, arg3, arg4);
}
#if defined(_MSC_VER)
#pragma optimize("", on)
#endif

// FUNCTION: IMPERIALISM 0x004070e5
void TGreatPower::thunk_ApplyDiplomacyPolicyStateForTargetWithCostChecks_At004070e5(int arg1,
                                                                                    int arg2) {
  ApplyDiplomacyPolicyStateForTargetWithCostChecks(arg1, arg2);
}

// FUNCTION: IMPERIALISM 0x00407392
void TGreatPower::thunk_ApplyIndexedResourceDeltaAndAdjustNationTotals_At00407392(int arg1,
                                                                                  int arg2,
                                                                                  int arg3) {
  short* selectedResource = this->relationDeltaSnapshot + static_cast<short>(arg1);
  short delta = static_cast<short>(arg2);
  int scaledDelta = static_cast<int>(static_cast<short>(arg3)) * static_cast<int>(delta);

  *selectedResource = static_cast<short>(*selectedResource + delta);
  VCall_GreatPower_AdjustTreasurySlot0E(this, -scaledDelta);

  if (delta > 0) {
    VCall_GreatPower_AdjustResourceDeltaSlot66(this, arg2);
    this->budgetPoolDelta -= scaledDelta;
    return;
  }

  this->budgetPoolBase -= scaledDelta;
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
void TGreatPower::thunk_QueueDiplomacyProposalCodeForTargetNation_At004083f5(int proposalCode,
                                                                             int targetNationId) {
  QueueDiplomacyProposalCodeForTargetNation(static_cast<short>(proposalCode),
                                            static_cast<short>(targetNationId));
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

TGreatPower::TGreatPower(int arg1, int arg2) {
  InitializeNationStateRuntimeSubsystems(arg1, arg2);
}

#define TGREATPOWER_RELEASE_OWNED_OBJECTS_BODY(SELF_PTR)                                           \
  Obj_ReleaseAndClearSlot(&(SELF_PTR)->relationManager, 0x1C);                                     \
  Obj_ReleaseAndClearSlot(&(SELF_PTR)->turnEventQueue, 0x24);                                      \
  Obj_ReleaseAndClearSlot(&(SELF_PTR)->proposalQueue, 0x24);                                       \
  Obj_ReleaseAndClearSlot(&(SELF_PTR)->foreignMinister, 0x1C);                                     \
  Obj_ReleaseAndClearSlot(&(SELF_PTR)->interiorMinister, 0x1C);                                    \
  Obj_ReleaseAndClearSlot(&(SELF_PTR)->defenseMinister, 0x1C);                                     \
  {                                                                                                \
    int listIndex = 0;                                                                             \
    while (listIndex < kDiplomacyTrackedSlotCount) {                                               \
      Obj_ReleaseAndClearSlot(&(SELF_PTR)->diplomacyTrackedSlots[listIndex], 0x24);                \
      ++listIndex;                                                                                 \
    }                                                                                              \
  }                                                                                                \
  Obj_ReleaseAndClearSlot(&(SELF_PTR)->townMarkerList, 0x58);                                      \
  Obj_ReleaseAndClearSlot(&(SELF_PTR)->trackedObjectList, 0x58);                                   \
  Obj_ReleaseAndClearSlot(&(SELF_PTR)->turnSummaryQueue, 0x24);                                    \
  Obj_ReleaseAndClearSlot(&(SELF_PTR)->missionNodeQueue, 0x58);                                    \
  Obj_ReleaseAndClearSlot(&(SELF_PTR)->pad_44_ptr, 0x58);                                          \
  if ((SELF_PTR)->ownedRegionList != 0) {                                                          \
    Obj_CallNoArgAtSlot((SELF_PTR)->ownedRegionList, 0x38);                                        \
    (SELF_PTR)->ownedRegionList = 0;                                                               \
  }

TGreatPower::~TGreatPower() {
  TGREATPOWER_RELEASE_OWNED_OBJECTS_BODY(this);
}

// FUNCTION: IMPERIALISM 0x004D8950
void* __cdecl TGreatPower::CreateTGreatPowerInstance(void) {
  void* instance = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x964));
  if (instance == 0) {
    return 0;
  }

  void(__fastcall * constructNationStateBase)(void*, int) =
      reinterpret_cast<void(__fastcall*)(void*, int)>(thunk_ConstructNationStateBase_Vtbl653938);
  constructNationStateBase(instance, 0);
  return instance;
}

// FUNCTION: IMPERIALISM 0x004D89D0
void* __cdecl TGreatPower::GetTGreatPowerClassNamePointer(void) {
  return reinterpret_cast<void*>(kAddrClassDescTGreatPower);
}

// FUNCTION: IMPERIALISM 0x004d8cc0
void TGreatPower::InitializeNationStateRuntimeSubsystems(int arg1, int arg2) {
  reinterpret_cast<void(__fastcall*)(int, int)>(
      thunk_InitializeNationStateIdentityAndOwnedRegionList)(reinterpret_cast<int>(this), arg1);

  TLocalizationRuntimeView* localizationRuntime = ReadLocalizationRuntimeView();
  if (localizationRuntime != 0) {
    int runtimeIndex = localizationRuntime->runtimeSubsystemIndex;
    this->pressureScore = ReadGlobalIntStep(kAddrNationRuntimeSubsystemCache, runtimeIndex);
  } else {
    this->pressureScore = 0;
  }

  this->scenarioLoadFlag = (static_cast<short>(arg2) == 1) ? 1 : 0;

  void* cityModel = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x20));
  if (cityModel != 0) {
    reinterpret_cast<void(__fastcall*)(void*, int)>(thunk_InitializeCityModel)(cityModel, 0);
    reinterpret_cast<void(__fastcall*)(int, int)>(thunk_InitializeCityProductionState)(
        reinterpret_cast<int>(cityModel), arg1);
  }
  this->relationManager = static_cast<TRelationManagerObject*>(cityModel);

  void* townMarkerListOwner = AllocateBattleListOwnerWithLinkedSentinel();
  this->townMarkerList = static_cast<TListObject*>(townMarkerListOwner);

  this->grantTotalCost = 0;
  this->needCapA6 = 0x0F;
  this->field900 = 0x0F;

  void* turnEventQueue = AllocateObArrayWithMode(4);
  this->turnEventQueue = static_cast<TQueueObject*>(turnEventQueue);

  void* proposalQueue = AllocateObArrayWithMode(4);
  this->proposalQueue = static_cast<TQueueObject*>(proposalQueue);

  if (this->scenarioLoadFlag != 0) {
    void* foreignMinister = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x20));
    if (foreignMinister != 0) {
      reinterpret_cast<void(__fastcall*)(void*, int)>(thunk_ConstructTForeignMinister)(
          foreignMinister, 0);
    }
    reinterpret_cast<void(__cdecl*)(void)>(thunk_InitializeTForeignMinisterStateAndCounters)();
    this->foreignMinister = static_cast<TMinisterObject*>(foreignMinister);

    void* interiorMinister = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x20));
    if (interiorMinister != 0) {
      reinterpret_cast<void(__fastcall*)(void*, int)>(
          thunk_WrapperFor_thunk_ConstructTMinister_At004be840)(interiorMinister, 0);
    }
    reinterpret_cast<void(__cdecl*)(void)>(thunk_InitializeCityInteriorMinister)();
    this->interiorMinister = static_cast<TMinisterObject*>(interiorMinister);

    void* defenseMinister = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x20));
    if (defenseMinister != 0) {
      defenseMinister = reinterpret_cast<void*(__fastcall*)(void*, int)>(
          thunk_ConstructTDefenseMinisterBaseState)(defenseMinister, 0);
    }
    reinterpret_cast<void(__cdecl*)(void)>(thunk_InitializeTMinisterBaseOrderArrayMetrics)();
    this->defenseMinister = static_cast<TMinisterObject*>(defenseMinister);
  }

  int listIndex = 0;
  while (listIndex < kDiplomacyTrackedSlotCount) {
    void* relationList = AllocateObArrayWithMode(0x0C);
    this->diplomacyTrackedSlots[listIndex] = static_cast<TQueueObject*>(relationList);
    ++listIndex;
  }

  short* diplomacyNeedState = this->diplomacyPolicyByNation;
  short* diplomacyGrantState = this->diplomacyGrantByNation;
  unsigned char* diplomacyFlags = this->colonyBoycottFlags;
  int nationSlot = 0;
  while (nationSlot < kNationSlotCount) {
    diplomacyNeedState[nationSlot] = -1;
    diplomacyGrantState[nationSlot] = -1;
    diplomacyFlags[nationSlot] = 0;
    ++nationSlot;
  }

  void* trackedObjectList = AllocateBattleListOwnerWithPtrListSentinel();
  this->trackedObjectList = static_cast<TListObject*>(trackedObjectList);

  int candidateIndex = 0;
  while (candidateIndex < kNationSlotCount) {
    this->candidateNationFlags[candidateIndex] = 0;
    ++candidateIndex;
  }
  this->scenarioInitFlag = 0;
  this->field904 = 1;

  void* turnSummaryQueue = AllocateObArrayWithMode(8);
  this->turnSummaryQueue = static_cast<TQueueObject*>(turnSummaryQueue);

  void* missionNodeQueue = AllocateBattleListOwnerWithPtrListSentinel();
  this->missionNodeQueue = static_cast<TListObject*>(missionNodeQueue);
  this->pendingAidTotal = 0;
}

// FUNCTION: IMPERIALISM 0x004d9160
void TGreatPower::ReleaseOwnedGreatPowerObjectsAndDeleteSelf(void) {
  TGREATPOWER_RELEASE_OWNED_OBJECTS_BODY(this);

  if (this != 0) {
    VCall_GreatPower_DeleteSelfSlot01(this, 1);
  }
}

#undef TGREATPOWER_RELEASE_OWNED_OBJECTS_BODY

// FUNCTION: IMPERIALISM 0x004d92e0
void TGreatPower::InitializeGreatPowerMinisterRosterAndScenarioState(int arg1) {
  reinterpret_cast<void(__fastcall*)(void*, int, int)>(
      thunk_DeserializeRecruitScenarioAndInstantiateOrders_At00409089)(this, 0, arg1);

  void* stream = reinterpret_cast<void*>(arg1);
  VCall_Stream_ReadAtSlot3C(stream, &this->scenarioLoadFlag, 1);
  VCall_Stream_ReadAtSlot3C(stream, &this->diplomacyCounterA2, 2);
  VCall_Stream_ReadAtSlot3C(stream, &this->diplomacyCounterA4, 2);
  VCall_Stream_ReadAtSlot3C(stream, &this->needCapA6, 2);
  VCall_Stream_ReadAtSlot3C(stream, &this->needsOverCapFlag, 2);
  if (*reinterpret_cast<int*>(kAddrAdvanceTurnMachineState) < 0x3E) {
    VCall_Stream_ReadAtSlot3C(stream, &this->grantTotalCost, 2);
  } else {
    VCall_Stream_ReadAtSlot3C(stream, &this->grantTotalCost, 4);
  }
  VCall_Stream_ReadAtSlot3C(stream, &this->diplomacyCounterB0, 2);
  VCall_Stream_ReadAtSlot3C(stream, this->diplomacyPolicyByNation, 0x2E);
  SwapShortArrayBytes(this->diplomacyPolicyByNation, kNationSlotCount);
  VCall_Stream_ReadAtSlot3C(stream, this->diplomacyGrantByNation, 0x2E);
  SwapShortArrayBytes(this->diplomacyGrantByNation, kNationSlotCount);
  VCall_Stream_ReadAtSlot3C(stream, this->needCurrentByType, 0x2E);
  SwapShortArrayBytes(this->needCurrentByType, kNationSlotCount);
  VCall_Stream_ReadAtSlot3C(stream, this->needTargetByType, 0x2E);
  SwapShortArrayBytes(this->needTargetByType, kNationSlotCount);
  VCall_Stream_ReadAtSlot3C(stream, this->relationDeltaCurrent, 0x2E);
  SwapShortArrayBytes(this->relationDeltaCurrent, kNationSlotCount);
  VCall_Stream_ReadAtSlot3C(stream, this->relationDeltaSnapshot, 0x2E);
  SwapShortArrayBytes(this->relationDeltaSnapshot, kNationSlotCount);
  VCall_Stream_ReadAtSlot3C(stream, this->diplomacyState1c6, 0x2E);
  SwapShortArrayBytes(this->diplomacyState1c6, kNationSlotCount);

  if (*reinterpret_cast<int*>(kAddrAdvanceTurnMachineState) > 0x16) {
    VCall_Stream_ReadAtSlot3C(stream, this->diplomacyState1f4, 0x2E);
    SwapShortArrayBytes(this->diplomacyState1f4, kNationSlotCount);
  }

  VCall_Stream_ReadAtSlot3C(stream, this->diplomacyState222, 0x2E);
  SwapShortArrayBytes(this->diplomacyState222, kNationSlotCount);
  VCall_Stream_ReadAtSlot3C(stream, this->diplomacyState250, 0x2E);
  SwapShortArrayBytes(this->diplomacyState250, kNationSlotCount);

  VCall_Stream_ReadAtSlot3C(stream, &this->budgetPoolBase, 4);
  VCall_Stream_ReadAtSlot3C(stream, &this->budgetPoolDelta, 4);
  VCall_Stream_ReadAtSlot3C(stream, this->aidAllocationMatrix, 0x5C0);
  ReverseDwordArrayBytes(this->aidAllocationMatrix, 0x170);

  VCall_Stream_ReadAtSlot3C(stream, this->serializedStatusFlags, 0x0D);
  VCall_Stream_ReadAtSlot3C(stream, this->field8d6, 0x1A);
  SwapShortArrayBytes(this->field8d6, 0x0D);

  Obj_CallNoArgAtSlot(this->turnEventQueue, 0x18);
  Obj_CallNoArgAtSlot(this->proposalQueue, 0x18);
  int listIndex = 0;
  while (listIndex < kDiplomacyTrackedSlotCount) {
    Obj_CallNoArgAtSlot(this->diplomacyTrackedSlots[listIndex], 0x18);
    ++listIndex;
  }

  if (*reinterpret_cast<int*>(kAddrAdvanceTurnMachineState) < 0x1D) {
    if (this->encodedNationSlot == -1) {
      char gate = VCall_GreatPower_ShouldDispatchImmediatelySlot28(this);
      if (gate == 0) {
        Obj_CallNoArgAtSlot(this->foreignMinister, 0x18);
        Obj_CallNoArgAtSlot(this->interiorMinister, 0x18);
        Obj_CallNoArgAtSlot(this->defenseMinister, 0x18);
      }
      Obj_CallNoArgAtSlot(this->relationManager, 0x18);
    } else {
      Obj_ReleaseAndClearSlot(&this->foreignMinister, 0x1C);
      Obj_ReleaseAndClearSlot(&this->interiorMinister, 0x1C);
      Obj_ReleaseAndClearSlot(&this->defenseMinister, 0x1C);
      Obj_ReleaseAndClearSlot(&this->relationManager, 0x1C);
    }
  } else {
    int ministerMask = VCall_Stream_ReadIntAtSlot40(stream);

    if ((ministerMask & 1) == 0) {
      Obj_ReleaseAndClearSlot(&this->foreignMinister, 0x1C);
    } else {
      void* foreignMinister = this->foreignMinister;
      if (foreignMinister == 0) {
        foreignMinister = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x20));
        if (foreignMinister != 0) {
          reinterpret_cast<void(__fastcall*)(void*, int)>(thunk_ConstructTForeignMinister)(
              foreignMinister, 0);
        }
        this->foreignMinister = static_cast<TMinisterObject*>(foreignMinister);
        reinterpret_cast<void(__cdecl*)(void)>(thunk_InitializeTForeignMinisterStateAndCounters)();
      }
      if (foreignMinister != 0) {
        Obj_CallNoArgAtSlot(foreignMinister, 0x18);
      }
    }

    if ((ministerMask & 2) == 0) {
      Obj_ReleaseAndClearSlot(&this->interiorMinister, 0x1C);
    } else {
      void* interiorMinister = this->interiorMinister;
      if (interiorMinister == 0) {
        interiorMinister = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x20));
        if (interiorMinister != 0) {
          reinterpret_cast<void(__fastcall*)(void*, int)>(
              thunk_WrapperFor_thunk_ConstructTMinister_At004be840)(interiorMinister, 0);
        }
        reinterpret_cast<void(__cdecl*)(void)>(thunk_InitializeCityInteriorMinister)();
        this->interiorMinister = static_cast<TMinisterObject*>(interiorMinister);
      }
      if (interiorMinister != 0) {
        Obj_CallNoArgAtSlot(interiorMinister, 0x18);
      }
    }

    if ((ministerMask & 4) == 0) {
      Obj_ReleaseAndClearSlot(&this->defenseMinister, 0x1C);
    } else {
      void* defenseMinister = this->defenseMinister;
      if (defenseMinister == 0) {
        defenseMinister = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x20));
        if (defenseMinister != 0) {
          defenseMinister = reinterpret_cast<void*(__fastcall*)(void*, int)>(
              thunk_ConstructTDefenseMinisterBaseState)(defenseMinister, 0);
        }
        reinterpret_cast<void(__cdecl*)(void)>(thunk_InitializeTMinisterBaseOrderArrayMetrics)();
        this->defenseMinister = static_cast<TMinisterObject*>(defenseMinister);
      }
      if (defenseMinister != 0) {
        Obj_CallNoArgAtSlot(defenseMinister, 0x18);
      }
    }

    if ((ministerMask & 8) == 0) {
      Obj_ReleaseAndClearSlot(&this->relationManager, 0x1C);
    } else {
      void* relationManager = this->relationManager;
      if (relationManager != 0) {
        Obj_CallNoArgAtSlot(relationManager, 0x18);
      }
    }
  }

  void* townMarkerList = this->townMarkerList;
  int hasItems = Obj_QueryIntAtSlot(townMarkerList, 0x48);
  if (hasItems != 0) {
    Obj_CallNoArgAtSlot(townMarkerList, 0x54);
  }
  Obj_CallNoArgAtSlot(townMarkerList, 0x18);

  int townCount = 0;
  VCall_Stream_ReadAtSlot3C(stream, &townCount, 4);

  if (townCount > 0) {
    int townOrdinal = 1;
    while (townOrdinal <= townCount) {
      void* townMarker = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x20));
      if (townMarker != 0) {
        reinterpret_cast<void(__fastcall*)(void*, int)>(thunk_ConstructFrogCityMarker)(townMarker,
                                                                                       0);
        Obj_CallNoArgAtSlot(townMarker, 0x18);
        Obj_CallPtrArgAtSlot(townMarkerList, 0x30, townMarker);
      }
      ++townOrdinal;
    }
  }

  if (townCount > 0) {
    Obj_CallNoArgAtSlot(townMarkerList, 0x4C);
    Obj_CallNoArgAtSlot(this->relationManager, 0x44);
  }

  void* trackedObjectList = this->trackedObjectList;
  hasItems = Obj_QueryIntAtSlot(trackedObjectList, 0x48);
  if (hasItems != 0) {
    Obj_CallNoArgAtSlot(trackedObjectList, 0x54);
  }
  Obj_CallNoArgAtSlot(trackedObjectList, 0x18);

  int unusedOrderCount = 0;
  VCall_Stream_ReadAtSlot3C(stream, &unusedOrderCount, 4);

  int orderOrdinal = 1;
  while (orderOrdinal < 5) {
    void* civOrderObj = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x20));
    if (civOrderObj != 0) {
      reinterpret_cast<void(__fastcall*)(void*, int)>(thunk_InitializeCivUnitOrderObject)(
          civOrderObj, 0);
      this->thunk_InitializeCivWorkOrderState(0, -1, this->nationSlot);
      Obj_CallNoArgAtSlot(civOrderObj, 0x18);
    }
    ++orderOrdinal;
  }

  VCall_Stream_ReadRawAtSlot00(stream, &this->diplomacyBudgetBase, 4);
  VCall_Stream_ReadRawAtSlot00(stream, &this->escalationCounter, 1);
  VCall_Stream_ReadRawAtSlot00(stream, &this->pendingCommitmentCost, 4);
  VCall_Stream_ReadRawAtSlot00(stream, &this->pressureCounter, 1);
  VCall_Stream_ReadRawAtSlot00(stream, &this->field900, 4);
  VCall_Stream_ReadRawAtSlot00(stream, &this->field904, 1);

  if (*reinterpret_cast<int*>(kAddrAdvanceTurnMachineState) > 0x0E) {
    void* missionNodeQueue = this->missionNodeQueue;
    Obj_CallIntArgAtSlot(missionNodeQueue, 0x18, arg1);

    int nodeCount = 0;
    VCall_Stream_ReadRawAtSlot00(stream, &nodeCount, 4);
    if (nodeCount > 0) {
      int nodeOrdinal = 1;
      while (nodeOrdinal <= nodeCount) {
        unsigned char hasNode = 0;
        char markerOk = VCall_Stream_ReadByteAtSlotB0(stream, &hasNode);
        if (markerOk != 0) {
          Obj_CallPtrArgAtSlot(missionNodeQueue, 0x30, 0);
        }
        ++nodeOrdinal;
      }
    }
  }

  if (*reinterpret_cast<int*>(kAddrAdvanceTurnMachineState) > 0x25) {
    VCall_Stream_ReadRawAtSlot00(stream, &this->field910, 4);
    VCall_Stream_ReadRawAtSlot00(stream, &this->aidAllocationTotal, 4);
  }
  if (*reinterpret_cast<int*>(kAddrAdvanceTurnMachineState) > 0x2F) {
    VCall_Stream_ReadRawAtSlot00(stream, this->colonyBoycottFlags, kNationSlotCount);
  }
  if (*reinterpret_cast<int*>(kAddrAdvanceTurnMachineState) > 0x34) {
    VCall_Stream_ReadRawAtSlot00(stream, &this->pendingAidTotal, 4);
  }
}

// Updates Great Power pressure/escalation state and propagates summary messages when thresholds
// cross.

// FUNCTION: IMPERIALISM 0x004DAF30
void TGreatPower::CompileGreatPowerRelationshipDeltaLinesAndDispatchMessage(void) {
  static const short kNationPriorityOrder[] = {0x0F, 0x0E, 0x0D, 0x10, 0x0C, 0x08, 0x0A, 0x09, 0x0B,
                                               0x06, 0x03, 0x04, 0x05, 0x00, 0x01, 0x02, 0x07, -1};

  if (GreatPower_ShouldDispatchImmediately(this) != 0) {
    return;
  }

  TLocalizationRuntimeView* localizationRuntime = ReadLocalizationRuntimeView();
  TGreatPowerPressureUpdateView* pressureView =
      reinterpret_cast<TGreatPowerPressureUpdateView*>(this);
  int localeIndex = 0;
  if (localizationRuntime != 0) {
    localeIndex = localizationRuntime->runtimeSubsystemIndex;
  }
  int compileThreshold = ReadGlobalIntStep(kAddrCompileGreatPowerValue, localeIndex);
  if (compileThreshold > static_cast<int>(pressureView->pressureTier8fc)) {
    return;
  }

  int relationDeltaByNation[0x17];
  for (int idx = 0; idx < 0x17; ++idx) {
    relationDeltaByNation[idx] = 0;
  }

  int summaryMessageRef = 0;
  InitializeSharedStringRefFromEmpty(&summaryMessageRef);

  TGreatPowerDiplomacyExternalStateView* diplomacyExternal =
      reinterpret_cast<TGreatPowerDiplomacyExternalStateView*>(this);
  int interactionScore = 0;

  const short* nationCursor = kNationPriorityOrder;
  while (*nationCursor != -1) {
    if (interactionScore + this->pressureScore >= 0) {
      break;
    }

    short nationSlot = *nationCursor;
    unsigned char* externalBytes =
        reinterpret_cast<unsigned char*>(diplomacyExternal->diplomacyExternalState894);
    if (externalBytes == 0) {
      ++nationCursor;
      continue;
    }

    short* relationDeltaPtr =
        reinterpret_cast<short*>(externalBytes + 0xB6 + static_cast<int>(nationSlot) * 2);
    short relationDelta = *relationDeltaPtr;
    if (relationDelta > 0) {
      *relationDeltaPtr = 0;
      relationDeltaByNation[nationSlot] = static_cast<int>(relationDelta);

      RelationManager_RefreshSlot80(diplomacyExternal->diplomacyExternalState894);

      void* nationInteractionState = ReadGlobalPointer(kAddrNationInteractionStateManagerPtr);
      if (nationInteractionState != 0) {
        interactionScore = Obj_QueryIntAtSlot(nationInteractionState, 0x4C);
      }
    }

    ++nationCursor;
  }

  VCall_GreatPower_AdjustTreasurySlot0E(this, 0);

  if (interactionScore > 0) {
    SharedRefPairScope localizedRefs;
    if (localizationRuntime != 0) {
      VCall_LocalizationRuntime_CallSlot84(localizationRuntime);
      VCall_LocalizationRuntime_CallSlot84WithId(localizationRuntime, interactionScore);
    }
    thunk_AssignStringSharedRefAndReturnThis();
    thunk_DispatchLocalizedUiMessageWithTemplateA13A0();
  }

  ReleaseSharedStringRefIfNotEmpty(&summaryMessageRef);
}

// FUNCTION: IMPERIALISM 0x004DB380
void TGreatPower::UpdateGreatPowerPressureStateAndDispatchEscalationMessage(void) {
  TGreatPowerPressureUpdateView* pressureView =
      reinterpret_cast<TGreatPowerPressureUpdateView*>(this);
  TLocalizationRuntimeView* localizationRuntime = ReadLocalizationRuntimeView();
  int localeIndex = 0;
  if (localizationRuntime != 0) {
    localeIndex = localizationRuntime->runtimeSubsystemIndex;
  }

  int pressureScore = this->pressureScore;
  int basePressure = VCall_GreatPower_GetBaseBudgetSlot5F(this);
  basePressure += static_cast<int>(pressureView->pressureFactor168) * 200;
  basePressure += static_cast<int>(pressureView->pressureFactor166) * 500;
  basePressure += pressureView->pressureOffset840;
  int pressureFloor = ReadGlobalIntStep(kAddrNationBasePressureByLocale, localeIndex);
  if (basePressure < pressureFloor) {
    basePressure = pressureFloor;
  }

  int smoothedPressure = (pressureView->smoothedPressure8f0 * 0x5A + basePressure * 1000) / 100;
  pressureView->smoothedPressure8f0 = smoothedPressure;
  int pressureBand = smoothedPressure / 100;

  if (pressureScore < 0) {
    int halfBand = pressureBand / 2;
    if ((-halfBand == pressureScore) || (-pressureScore < halfBand)) {
      pressureView->pressureTier8fc = 1;
    } else if ((-pressureBand == pressureScore) || (-pressureScore < pressureBand)) {
      if (pressureView->pressureTier8fc > 1) {
        int nextPressureValue =
            static_cast<int>(pressureView->pressureValue8f4) +
            static_cast<int>(ReadLocaleByteStep(kAddrGreatPowerPressureRiseStep, localeIndex));
        int pressureRiseCap = ReadGlobalIntStep(kAddrGreatPowerPressureRiseCap, localeIndex);
        if (nextPressureValue > pressureRiseCap) {
          nextPressureValue = pressureRiseCap;
        }
        pressureView->pressureValue8f4 = static_cast<signed char>(nextPressureValue);
      }
      pressureView->pressureTier8fc = 2;
    } else {
      int sharedMessageRef = 0;
      InitializeSharedStringRefFromEmpty(&sharedMessageRef);
      int nextPressureValue =
          static_cast<int>(pressureView->pressureValue8f4) +
          static_cast<int>(ReadLocaleByteStep(kAddrGreatPowerPressureRiseStep, localeIndex));
      int pressureRiseCap = ReadGlobalIntStep(kAddrGreatPowerPressureRiseCap, localeIndex);
      if (nextPressureValue > pressureRiseCap) {
        nextPressureValue = pressureRiseCap;
      }
      pressureView->pressureValue8f4 = static_cast<signed char>(nextPressureValue);

      if (pressureView->pressureTier8fc < 3) {
        pressureView->pressureTier8fc = 3;
      } else {
        pressureView->pressureTier8fc = static_cast<signed char>(pressureView->pressureTier8fc + 1);
      }

      int pressureTier = static_cast<int>(pressureView->pressureTier8fc);
      int hardThreshold = ReadGlobalIntStep(kAddrGreatPowerPressureHardAlertThreshold, localeIndex);
      int compileThreshold = ReadGlobalIntStep(kAddrCompileGreatPowerValue, localeIndex);

      if (hardThreshold <= pressureTier) {
        if (localizationRuntime != 0) {
          VCall_LocalizationRuntime_CallSlot84WithId(localizationRuntime, 4);
        }
        thunk_AssignStringSharedRefAndReturnThis();
        thunk_DispatchLocalizedUiMessageWithTemplateA13A0();
        ReleaseSharedStringRefIfNotEmpty(&sharedMessageRef);
        return;
      }

      if (pressureTier < compileThreshold) {
        if (localizationRuntime != 0) {
          int statusId = (pressureTier == (compileThreshold - 1)) ? 3 : 2;
          VCall_LocalizationRuntime_CallSlot84WithId(localizationRuntime, statusId);
        }
        DispatchQuarterlyGreatPowerPressureMessage(1);
      } else {
        if (localizationRuntime != 0) {
          VCall_LocalizationRuntime_CallSlot84WithId(localizationRuntime, 1);
        }
        DispatchQuarterlyGreatPowerPressureMessage(2);
      }
      ReleaseSharedStringRefIfNotEmpty(&sharedMessageRef);
    }
  } else {
    if (pressureView->pressureTier8fc != 0) {
      int nextPressureValue =
          static_cast<int>(pressureView->pressureValue8f4) -
          static_cast<int>(ReadLocaleByteStep(kAddrGreatPowerPressureDecayStep, localeIndex));
      int pressureMinFloor = ReadGlobalIntStep(kAddrGreatPowerPressureMinFloor, localeIndex);
      if (nextPressureValue < pressureMinFloor) {
        nextPressureValue = pressureMinFloor;
      }
      pressureView->pressureValue8f4 = static_cast<signed char>(nextPressureValue);
      pressureView->pressureTier8fc = 0;
    }
  }

  pressureScore = this->pressureScore;
  if (pressureScore >= 0) {
    pressureView->pendingDrain900 = 0;
    return;
  }

  int drainAmount = (0xC7 - static_cast<int>(pressureView->pressureValue8f4) * pressureScore) / 200;
  pressureView->pendingDrain900 = drainAmount;
  this->pressureScore = pressureScore - drainAmount;
}

// FUNCTION: IMPERIALISM 0x004dbd20
void TGreatPower::RebuildNationResourceYieldCountersAndDevelopmentTargets(void) {
  const int kMapRegionSlotCount = 0x1950;

  short* currentNeedByType = this->needCurrentByType;
  short* developmentByType = &this->needCurrentByType[7]; // +0x11c overlays this runtime array.
  short* targetNeedByType = this->needTargetByType;
  short& controlledRegionCount = this->needCurrentByType[0x13]; // +0x134
  char* influenceByRegion = thunk_BuildCityInfluenceLevelMap();
  TGlobalMapStateScoreView* globalMapState = ReadGlobalMapStateScoreView();
  int regionIndex = 0;

  for (int i = 0; i < kNationSlotCount; ++i) {
    currentNeedByType[i] = 0;
  }
  controlledRegionCount = 0;

  if (influenceByRegion != 0 && globalMapState != 0 && globalMapState->terrainStateTable != 0 &&
      globalMapState->cityScoreTable != 0) {
    TTerrainStateRecordView* terrainTable = globalMapState->terrainStateTable;
    TGlobalMapCityScoreRecord* cityTable = globalMapState->cityScoreTable;
    while (static_cast<short>(regionIndex) < kMapRegionSlotCount) {
      char influence = *influenceByRegion;
      if (influence != 0) {
        TTerrainStateRecordView* terrainRecord = &terrainTable[regionIndex];
        if (terrainRecord->gateFlag == 0) {
          if (influence == 2) {
            ++controlledRegionCount;
          }
        } else {
          for (int edgeIndex = 0; edgeIndex < 2; ++edgeIndex) {
            short resourceType = static_cast<short>(terrainRecord->resourceTypeByEdge[edgeIndex]);
            if (resourceType != -1) {
              char contribution =
                  GlobalMapState_CallMetricC4(globalMapState, regionIndex, edgeIndex);
              currentNeedByType[resourceType] = static_cast<short>(
                  currentNeedByType[resourceType] + static_cast<short>(contribution));
            }
          }

          if (terrainRecord->roadFlag != 0 && influence == 2) {
            ++controlledRegionCount;
          }

          int cityIndex = static_cast<int>(terrainRecord->cityRecordIndex);
          TGlobalMapCityScoreRecord* cityRecord = &cityTable[cityIndex];
          if (cityRecord->ownerNationSlot == static_cast<short>(regionIndex)) {
            for (int devIdx = 0; devIdx < 10; ++devIdx) {
              developmentByType[devIdx] =
                  static_cast<short>(developmentByType[devIdx] +
                                     CityRecord_ReadDevelopmentAccumulatorAt82(cityRecord, devIdx));
            }
          }
        }
      }

      ++regionIndex;
      ++influenceByRegion;
    }
  }

  for (int typeIndex = 0; typeIndex < kNationSlotCount; ++typeIndex) {
    if (currentNeedByType[typeIndex] < targetNeedByType[typeIndex]) {
      VCall_GreatPower_NeedUpdateSlot45(this, typeIndex, currentNeedByType[typeIndex]);
    }
  }
}

// Advances per-region development counters and emits diplomacy/map events when stage changes.

// FUNCTION: IMPERIALISM 0x004dbf00
void TGreatPower::AdvanceOwnedRegionDevelopmentCountersAndDispatchEvents(void) {
  void* regionList = this->ownedRegionList;
  if (regionList == 0) {
    return;
  }

  int totalRegions = List_GetCountSlot28(regionList);
  int regionOrdinal = 1;
  while (regionOrdinal <= totalRegions) {
    short regionId = static_cast<short>(List_GetIntByOrdinalSlot24(regionList, regionOrdinal));
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
      short ownerSlot = this->ownerNationSlot;
      if (cityRecord->ownerNationSlot != ownerSlot) {
        unsigned int turnDelta = static_cast<unsigned int>(
            static_cast<int>(LocalizationRuntime_GetTurnTick(localizationRuntime)) -
            static_cast<int>(cityRecord->lastTurnTick));

        if (turnDelta > 4) {
          int resourceSums[kNationSlotCount];
          int i = 0;
          while (i < kNationSlotCount) {
            resourceSums[i] = 0;
            ++i;
          }

          int linkedCount = static_cast<int>(cityRecord->linkedRegionCount);
          int linkedIndex = 0;
          while (linkedIndex < linkedCount) {
            short linkedRegion = cityRecord->linkedRegionIds[linkedIndex];
            int edge = 0;
            while (edge < 2) {
              signed char resourceType = terrainTable[linkedRegion].resourceTypeByEdge[edge];
              if (resourceType != -1) {
                resourceSums[resourceType] += static_cast<int>(
                    GlobalMapState_CallMetricC4(globalMapState, linkedRegion, edge));
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
              int prod = GetCityBuildingProductionValueBySlot(cityRecord, 1);
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
              int prod = GetCityBuildingProductionValueBySlot(cityRecord, 5);
              int prodLimit = (prod + ((prod >> 0x1f) & 3U)) >> 2;
              if (static_cast<int>(*stage1CounterB) < prodLimit &&
                  static_cast<int>(*stage1CounterB) < resourceSums[2] / 2) {
                pendingStage = 1;
                *stage1CounterB = static_cast<short>(*stage1CounterB + 1);
                needsRedraw = 1;
              }
            }

            if (resourceSums[3] != 0) {
              int prod = GetCityBuildingProductionValueBySlot(cityRecord, 3);
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
            int capabilityScore = GetCityBuildingProductionValueBySlot(cityRecord, 7);
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
            Obj_CallNoArgAtSlot(this, 0x74);

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
            SetGlobalRegionDevelopmentStageByte(regionId, pendingStage);
            if (pendingStage == 2) {
              GreatPower_DispatchEventSlot2E(this, 4, regionId);
            } else {
              GreatPower_DispatchEventSlot2E(this, 3, regionId);
              if (this->expansionAlertCounter < 0x33) {
                GreatPower_DispatchEventSlot2E(this, 8, -1);
              }
            }
          }
        }

        if (localizationRuntime->redrawEnabled != 0 && needsRedraw != 0) {
          DispatchCityRedrawInvalidateEvent(regionId);
        }
      }
    }

    ++regionOrdinal;
  }
}

// FUNCTION: IMPERIALISM 0x004DC540
void TGreatPower::CompareMissionScoreVariantsByMode(int mode) {
  if (mode == 0) {
    int nodeContext = VCall_GreatPower_GetNodeContextSlot40(this);
    float localScore = ComputeDefendProvinceMissionLocalSupportScore(nodeContext);
    float crossNationScore = ComputeDefendProvinceMissionCrossNationSupportScore(nodeContext);
    if (localScore < crossNationScore) {
      return;
    }
  } else {
    TPortZoneContextVectorView* portZoneContext = FindFirstPortZoneContextByNation();
    if (portZoneContext == 0) {
      return;
    }

    if (portZoneContext->entryCount == 0) {
      void* resizedEntries = ReallocateBufferWithAllocatorTracking(portZoneContext->entries, 8);
      if (resizedEntries == 0) {
        resizedEntries = ReallocateBufferWithAllocatorTracking(portZoneContext->entries, 4);
        portZoneContext->entries = static_cast<int*>(resizedEntries);
        portZoneContext->entryCount = 1;
      } else {
        portZoneContext->entries = static_cast<int*>(resizedEntries);
        portZoneContext->entryCount = 2;
      }
    }
    if (portZoneContext->activeEntryCount == 0) {
      portZoneContext->activeEntryCount = 1;
    }

    int firstEntry = 0;
    if (portZoneContext->entries != 0) {
      firstEntry = portZoneContext->entries[0];
    }

    float exactSourceScore =
        ComputeNavyOrderScoreForExactSourceNation(this->nationSlot, firstEntry);
    float diplomacyFilteredScore =
        ComputeNavyOrderScoreWithDiplomacyFilter(this->nationSlot, firstEntry);
    if (exactSourceScore < diplomacyFilteredScore) {
      return;
    }
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
    if (nationSlot == this->nationSlot) {
      continue;
    }
    if (Diplomacy_HasPolicyWithNation(diplomacyManager, nationSlot, this->nationSlot) != 0 &&
        IsNationSlotEligibleForEventProcessingFast(nationSlot) != 0) {
      hasEligibleForeignNation = true;
      break;
    }
  }
  if (!hasEligibleForeignNation) {
    return;
  }

  TMapActionContextListEntryView* contextEntry =
      *reinterpret_cast<TMapActionContextListEntryView**>(kAddrMapActionContextListHead);
  while (contextEntry != 0) {
    thunk_GetShortAtOffset14OrInvalid();
    if (thunk_ContainsPointerArrayEntryMatchingByteKey() != 0) {
      bool emittedMessage = false;
      for (int nationSlotCandidate = 0; nationSlotCandidate < kMajorNationCount;
           ++nationSlotCandidate) {
        if (nationSlotCandidate == this->nationSlot) {
          continue;
        }
        if (Diplomacy_HasPolicyWithNation(diplomacyManager, this->nationSlot,
                                          nationSlotCandidate) == 0) {
          continue;
        }

        unsigned int nationMask = 1u << (nationSlotCandidate & 0x1f);
        unsigned int selfMask = 1u << (this->nationSlot & 0x1f);
        unsigned int contextMask = contextEntry->nationMask;
        if ((contextMask & nationMask) != 0 && (contextMask & selfMask) == 0) {
          int contextRef = 0;
          int messageRef = 0;
          InitializeSharedStringRefFromEmpty(&contextRef);
          MapActionContext_AssignDisplayRefFromSlot2C(contextEntry, &contextRef);
          InitializeSharedStringRefFromEmpty(&messageRef);
          ReleaseSharedStringRefIfNotEmpty(&messageRef);
          ReleaseSharedStringRefIfNotEmpty(&contextRef);
          emittedMessage = true;
          break;
        }
      }
      if (emittedMessage) {
        contextEntry = contextEntry->next;
        continue;
      }
    }
    contextEntry = contextEntry->next;
  }
}

// FUNCTION: IMPERIALISM 0x004DC840
void TGreatPower::BuildGreatPowerEligibleNationEventMessagesFromLinkedList(void) {
  void* diplomacyManager = ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr);
  if (diplomacyManager == 0) {
    return;
  }

  bool hasEligibleForeignNation = false;
  for (int nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
    if (nationSlot == this->nationSlot) {
      continue;
    }
    if (Diplomacy_HasPolicyWithNation(diplomacyManager, nationSlot, this->nationSlot) != 0 &&
        IsNationSlotEligibleForEventProcessingFast(nationSlot) != 0) {
      hasEligibleForeignNation = true;
      break;
    }
  }
  if (!hasEligibleForeignNation) {
    return;
  }

  for (int scanSlot = 0; scanSlot < kMajorNationCount; ++scanSlot) {
    void* nationState = ReadNationStateSlot(scanSlot);
    if (nationState == 0) {
      continue;
    }

    TNationStateEventMessageFlagsView* messageFlags =
        static_cast<TNationStateEventMessageFlagsView*>(nationState);
    if (messageFlags->allowEventMessage4D != 0 && messageFlags->suppressEventMessage4C == 0) {
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
  if (this->relationManager == 0) {
    return;
  }

  GreatPower_CallNoArgVirtual(this, 0x4D);
  GreatPower_CallNoArgVirtual(this, 0x4E);
  GreatPower_CallNoArgVirtual(this, 0x43);
  BuildGreatPowerRelationshipDeltaSummaryAndDispatchMessage();
  RelationManager_CallSlot28NoArgs(this->relationManager);
  GreatPower_CallNoArgVirtual(this, 0x2A);
}

// FUNCTION: IMPERIALISM 0x004DCD10
void TGreatPower::ApplyNationResourceNeedTargetsToOrderState(void) {
  GreatPower_AdjustTreasury(this, static_cast<int>(this->needTargetByType[0x15]) * 500);

  void* relationManager = this->relationManager;
  if (relationManager != 0) {
    RelationManager_ClearNeedSlotE0AndRefresh(relationManager);
  }

  GreatPower_AdjustTreasury(this, static_cast<int>(this->needTargetByType[0x16]) * 200);

  if (relationManager != 0) {
    RelationManager_ClearNeedSlotE2AndRefresh(relationManager);
  }

  for (int needIndex = 0; static_cast<short>(needIndex) < kNationSlotCount; ++needIndex) {
    VCall_GreatPower_ApplyNeedTargetSlot64(this, needIndex, this->needTargetByType[needIndex]);
  }
}

// FUNCTION: IMPERIALISM 0x004dce10
void TGreatPower::SetNationResourceNeedCurrentByType(int needType, int currentValue) {
  short needIndex = static_cast<short>(needType);
  this->needCurrentByType[needIndex] = static_cast<short>(currentValue);
}

// FUNCTION: IMPERIALISM 0x004dce90
void TGreatPower::TryIncrementNationResourceNeedTargetTowardCurrent(int needType) {
  short needIndex = static_cast<short>(needType);
  short targetValue = this->needTargetByType[needIndex];
  short currentValue = this->needCurrentByType[needIndex];
  if (targetValue < currentValue) {
    VCall_GreatPower_NeedUpdateSlot45(this, needType, static_cast<int>(targetValue) + 1);
  }
}

// FUNCTION: IMPERIALISM 0x004DCF10
void TGreatPower::IsNationResourceNeedCurrentSumExceedingCapA6(void) {
  int sumCurrentNeeds = 0;
  for (int needIndex = 0; needIndex < kNationSlotCount; ++needIndex) {
    sumCurrentNeeds += static_cast<int>(this->needCurrentByType[needIndex]);
  }

  this->needsOverCapFlag = (sumCurrentNeeds > static_cast<int>(this->needCapA6)) ? 1 : 0;
}

// FUNCTION: IMPERIALISM 0x004dd0c0
void TGreatPower::SetDiplomacyColonyBoycottFlagForTargetAndRefreshMinorNations(
    int targetNationSlot, int isBoycottEnabled) {
  unsigned char boycottFlag = static_cast<unsigned char>(isBoycottEnabled);
  int policyValue = ((-(int)(boycottFlag != 0)) & 0xC8) + 0x64;
  this->colonyBoycottFlags[targetNationSlot] = boycottFlag;

  for (int secondarySlot = kMajorNationCount; secondarySlot < kNationSlotCount; ++secondarySlot) {
    void* secondaryState = ReadSecondaryNationStateSlot(secondarySlot);
    char hasNationFlag = SecondaryState_HasNationFlag5C(secondaryState, this->nationSlot);
    if (hasNationFlag != 0) {
      SecondaryState_SetPolicyValue48(secondaryState, targetNationSlot, policyValue);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004dd310
void TGreatPower::ReleaseDiplomacyTrackedObjectSlots850(void) {
  for (int listIndex = 0; listIndex < kDiplomacyTrackedSlotCount; ++listIndex) {
    void* trackedObject = this->diplomacyTrackedSlots[listIndex];
    ReleaseObjectAtSlot1C(trackedObject);
  }
}

// FUNCTION: IMPERIALISM 0x004dd340
void TGreatPower::AddAmountToAidAllocationMatrixCellAndTotal(int amount, short columnIndex,
                                                             short rowIndex) {
  int matrixIndex =
      static_cast<int>(rowIndex) * kAidAllocationColumnCount + static_cast<int>(columnIndex);

  GreatPower_AdjustTreasury(this, amount);
  this->aidAllocationMatrix[matrixIndex] += amount;
  this->aidAllocationTotal += amount;
}

// FUNCTION: IMPERIALISM 0x004dd3b0
int TGreatPower::SumAidAllocationMatrixColumnForTarget(short targetNationId) {
  int total = 0;
  int rowIndex = 0;
  while (rowIndex < kAidAllocationRowCount) {
    int matrixIndex = rowIndex * kAidAllocationColumnCount + static_cast<int>(targetNationId);
    total += this->aidAllocationMatrix[matrixIndex];
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
      total += this->aidAllocationMatrix[matrixIndex];
      ++columnIndex;
    }
    ++rowIndex;
  }
  return total;
}

// FUNCTION: IMPERIALISM 0x004dd430
int TGreatPower::ComputeRemainingDiplomacyAidBudget(void) {
  int outstandingCommitments = this->pendingCommitmentCost;
  int pendingAdjustments = this->pendingAidTotal;
  int baseBudget = VCall_GreatPower_GetBaseBudgetSlot5F(this);
  return baseBudget + this->budgetPoolBase + this->budgetPoolDelta - pendingAdjustments -
         outstandingCommitments;
}

// FUNCTION: IMPERIALISM 0x004dd470
void TGreatPower::ResetDiplomacyNeedSlots7012AndRefreshIfModeGateMatches(void) {
  TLocalizationRuntimeView* localizationTable = ReadLocalizationRuntimeView();
  if (localizationTable == 0) {
    return;
  }
  if (localizationTable->runtimeSubsystemIndex != 0 || localizationTable->mode != 2) {
    return;
  }

  VCall_GreatPower_SetNeedSlot69(this, 7, -1);
  VCall_GreatPower_SetNeedSlot69(this, 0, -1);
  VCall_GreatPower_SetNeedSlot69(this, 1, -1);
  VCall_GreatPower_SetNeedSlot69(this, 2, -1);
  VCall_GreatPower_RefreshNeedPanelsSlot6A(this);
}

// FUNCTION: IMPERIALISM 0x004dd4e0
void TGreatPower::AssignFallbackNationsToUnfilledDiplomacyNeedSlots(void) {
  const int kNeedSlotStart = 7;
  const int kNeedSlotEndExclusive = 12;
  const int kNeedSlotFallback = 5;

  if (this->scenarioLoadFlag == 0) {
    if (this->foreignMinister != 0) {
      Object_CallSlot8CNoArgs(this->foreignMinister);
    }
    return;
  }

  void* diplomacyManager = ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr);
  bool hasUnfilledNeedSlot = false;
  for (int needSlot = kNeedSlotStart; needSlot < kNeedSlotEndExclusive; ++needSlot) {
    if (GreatPower_GetNeedSlotValue(this, needSlot) < 0) {
      hasUnfilledNeedSlot = true;
    }
  }

  if (hasUnfilledNeedSlot) {
    short selectedNation = static_cast<short>(-1);
    void* relationshipList = AllocateObArrayWithMode(0);
    if (diplomacyManager != 0 && relationshipList != 0) {
      Diplomacy_BuildRelationshipListForNation(diplomacyManager, this->nationSlot, 1,
                                               relationshipList);
    }

    for (int needSlot = kNeedSlotStart; needSlot < kNeedSlotEndExclusive; ++needSlot) {
      if (GreatPower_GetNeedSlotValue(this, needSlot) < 0) {
        int listIndex = ObArray_GetCountAtOffset8(relationshipList);
        if (selectedNation < 0) {
          while (listIndex >= 1) {
            selectedNation = ObArray_GetShortValueByOrdinal1Based(relationshipList, listIndex);
            --listIndex;
            void* candidateState = ReadNationStateSlot(selectedNation);
            if (candidateState != 0 && NationState_IsBusyA0(candidateState) != 0) {
              selectedNation = static_cast<short>(-1);
            }
            if (selectedNation >= 0) {
              break;
            }
          }
        }

        if (selectedNation >= 0) {
          void* selectedNationState = ReadNationStateSlot(selectedNation);
          if (selectedNationState != 0) {
            NationState_AssignNeedSlotFromSource(selectedNationState, needSlot, this->nationSlot);
          }
        }
      }
    }

    if (relationshipList != 0) {
      Obj_CallNoArgAtSlot(relationshipList, 0x24);
    }
  }

  if (GreatPower_GetNeedSlotValue(this, kNeedSlotFallback) == -1) {
    bool foundFallbackNation = false;
    int fallbackNationSlot = -1;
    while (!foundFallbackNation) {
      fallbackNationSlot = static_cast<int>(GenerateThreadLocalRandom15Value() % 7);
      if (IsNationSlotEligibleForEventProcessingFast(fallbackNationSlot) != 0 &&
          Diplomacy_HasPolicyWithNation(diplomacyManager, fallbackNationSlot, this->nationSlot) ==
              0 &&
          fallbackNationSlot != this->nationSlot) {
        foundFallbackNation = true;
      }
    }

    void* fallbackNationState = ReadNationStateSlot(fallbackNationSlot);
    if (fallbackNationState != 0) {
      NationState_AssignNeedSlotFromSource(fallbackNationState, kNeedSlotFallback,
                                           this->nationSlot);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004dd740
int TGreatPower::GetDiplomacyExternalStateB6ByTarget(int targetNationSlot) {
  (void)targetNationSlot;
  const TGreatPowerDiplomacyExternalStateView* externalStateView =
      reinterpret_cast<const TGreatPowerDiplomacyExternalStateView*>(this);
  int externalState = reinterpret_cast<int>(externalStateView->diplomacyExternalState894);
  if (externalState == 0) {
    return 0;
  }
  return externalState;
}

// FUNCTION: IMPERIALISM 0x004dda20
void TGreatPower::DecrementDiplomacyCounterA2ByValue(int delta) {
  this->diplomacyCounterA2 =
      static_cast<short>(this->diplomacyCounterA2 - static_cast<short>(delta));
}

// FUNCTION: IMPERIALISM 0x004dda90
void TGreatPower::QueueInterNationEventType0FForNationPairContext(short targetNationSlot,
                                                                  short sourceNationSlot) {
  void(__fastcall * mergeFn)(void*, int, int, int, int, char) =
      reinterpret_cast<void(__fastcall*)(void*, int, int, int, int, char)>(
          thunk_QueueInterNationEventType0FWithBitmaskMerge);
  mergeFn(ReadGlobalPointer(kAddrInterNationEventQueueManagerPtr), 0, this->nationSlot,
          sourceNationSlot, targetNationSlot, 0);
}

// FUNCTION: IMPERIALISM 0x004ddbb0
char TGreatPower::TryDispatchNationActionViaUiContextOrFallback(int arg1, int arg2, int arg3,
                                                                int arg4) {
  void** selfVtable = *reinterpret_cast<void***>(this);
  char(__fastcall * canDispatchViaUi)(TGreatPower*, int, int) =
      reinterpret_cast<char(__fastcall*)(TGreatPower*, int, int)>(selfVtable[0x84 / 4]);

  if (canDispatchViaUi(this, 0, arg4) != 0) {
    void* uiRuntimeContext = ReadGlobalPointer(kAddrUiRuntimeContextPtr);
    void** uiVtable = *reinterpret_cast<void***>(uiRuntimeContext);
    void(__fastcall * uiSlot98)(void*, int, int, int, int, int) =
        reinterpret_cast<void(__fastcall*)(void*, int, int, int, int, int)>(uiVtable[0x98 / 4]);
    uiSlot98(uiRuntimeContext, 0, this->nationSlot, arg2, arg3, arg4);
    return 1;
  }

  void(__fastcall * fallbackDispatch)(TGreatPower*, int, int, int, int, int, int) =
      reinterpret_cast<void(__fastcall*)(TGreatPower*, int, int, int, int, int, int)>(
          selfVtable[0x1B0 / 4]);
  fallbackDispatch(this, 0, 1, arg1, 0, arg4, 0);
  return 0;
}

// FUNCTION: IMPERIALISM 0x004DDD20
void TGreatPower::OrphanVtableAssignStub_004ddd20(void) {
  this->diplomacyState1c6[0] = 0;
}

// FUNCTION: IMPERIALISM 0x004ddd50
bool TGreatPower::IsDiplomacyState1C6UnsetAndCounterPositiveForTarget(short targetNationSlot) {
  unsigned char result = 1;

  short activeCounter = VCall_GreatPower_GetCounterSlot1D(this);
  if (activeCounter <= 0 || this->diplomacyState1c6[targetNationSlot] >= 0) {
    result = 0;
  }
  return result != 0;
}

// FUNCTION: IMPERIALISM 0x004ddfc0
void TGreatPower::ApplyDiplomacyPolicyStateForTargetWithCostChecks(int arg1, int arg2) {
  const short kPolicyClear = -1;
  const short kPolicyRequiresCompatibilityStart = 0x12D;
  const short kPolicyTreasurySmall = 0x133;
  const short kPolicyTreasuryLarge = 0x134;

  short targetClass = static_cast<short>(arg1);
  short policyCode = static_cast<short>(arg2);
  char shouldApply = 1;

  if (policyCode < kPolicyRequiresCompatibilityStart + 1) {
    if (policyCode != kPolicyRequiresCompatibilityStart) {
      if (policyCode == kPolicyClear) {
        short previousPolicy = this->diplomacyPolicyByNation[targetClass];
        if (previousPolicy == kPolicyTreasurySmall) {
          GreatPower_AdjustTreasury(this, 500);
        } else if (previousPolicy == kPolicyTreasuryLarge) {
          GreatPower_AdjustTreasury(this, 5000);
        }
      }
      goto APPLY_POLICY_IF_ALLOWED;
    }
    if (LookupOrderCompatibility(this->nationSlot, targetClass) != 2) {
      shouldApply = 0;
    }
    goto APPLY_POLICY_IF_ALLOWED;
  }

  switch (policyCode - (kPolicyRequiresCompatibilityStart + 1)) {
  case 0:
  case 1:
    if (LookupOrderCompatibility(this->nationSlot, targetClass) != 2) {
      shouldApply = 0;
    }
    break;

  case 3: {
    TLocalizationRuntimeView* localizationTable = ReadLocalizationRuntimeView();
    if (localizationTable != 0 && localizationTable->mode == 6) {
      GreatPower_ApplyPolicyForNation(this, targetClass, 4, -1);
    }

    void* diplomacyManager = ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr);
    short relationTier = Diplomacy_GetRelationTier(diplomacyManager, targetClass, this->nationSlot);
    if (relationTier == 2) {
      Diplomacy_SetRelationState(diplomacyManager, this->nationSlot, targetClass, 1);
    }

    void* terrainDescriptor =
        ReadGlobalPointerArraySlot(kAddrTerrainTypeDescriptorTable, targetClass);
    if (terrainDescriptor != 0) {
      short encodedNationSlot = TerrainDescriptor_GetEncodedNationSlot(terrainDescriptor);
      if (encodedNationSlot > 199) {
        int resolvedNationSlot = DecodeTerrainNationSlot(encodedNationSlot, terrainDescriptor);
        if (Diplomacy_HasPolicyWithNation(diplomacyManager, this->nationSlot, resolvedNationSlot) ==
            0) {
          GreatPower_SetPolicyForNation(this, resolvedNationSlot, 0x131);
        }
      }
    }

    if (this->scenarioLoadFlag != 0) {
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
    this->diplomacyPolicyByNation[targetClass] = policyCode;
  }
  if (this->scenarioLoadFlag != 0) {
    thunk_NoOpDiplomacyPolicyStateChangedHook();
  }
}

// FUNCTION: IMPERIALISM 0x004de2d0
void TGreatPower::ResetDiplomacyPolicyAndGrantEntriesPreserveRecurringGrants(void) {
  const unsigned short kResetValue = 0xFFFF;
  const unsigned short kRecurringGrantMask = 0x4000;

  int targetNation = 0;
  while (static_cast<short>(targetNation) < 0x17) {
    this->diplomacyPolicyByNation[targetNation] = static_cast<short>(kResetValue);

    unsigned short grantEntry =
        static_cast<unsigned short>(this->diplomacyGrantByNation[targetNation]);
    this->diplomacyGrantByNation[targetNation] = static_cast<short>(kResetValue);
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
  const short kInfluenceAlertThreshold = 0x00FA;

  short targetNation = static_cast<short>(arg1);
  int targetIndex = static_cast<int>(targetNation);
  unsigned short oldGrantRaw =
      static_cast<unsigned short>(this->diplomacyGrantByNation[targetIndex]);
  unsigned short newGrantRaw = static_cast<unsigned short>(arg2);
  bool accepted = true;

  if (newGrantRaw != oldGrantRaw) {
    if (newGrantRaw != kGrantClear && GreatPower_CanSetGrantValue(this, newGrantRaw) == 0) {
      accepted = false;
    } else {
      if (oldGrantRaw != kGrantClear) {
        int oldGrantValue = static_cast<short>(oldGrantRaw & kGrantMask);
        this->grantTotalCost -= oldGrantValue;
        GreatPower_AdjustTreasury(this, oldGrantValue);
      }

      if (newGrantRaw != kGrantClear) {
        int newGrantValue = static_cast<short>(newGrantRaw & kGrantMask);
        this->grantTotalCost += newGrantValue;
        GreatPower_AdjustTreasury(this, -newGrantValue);
      }

      this->diplomacyGrantByNation[targetIndex] = static_cast<short>(newGrantRaw);
    }
  }

  if (this->scenarioLoadFlag != 0) {
    thunk_NoOpDiplomacyPolicyStateChangedHook();

    if (accepted && newGrantRaw != kGrantClear && targetNation > 6) {
      bool shouldDispatchAlert = false;
      void* diplomacyManager = ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr);
      if (diplomacyManager != 0) {
        int majorNation = 0;
        while (majorNation < 7) {
          if (majorNation != this->nationSlot) {
            short relationValue =
                Diplomacy_ReadRelationMatrix79C(diplomacyManager, majorNation, targetIndex);
            if (relationValue > kInfluenceAlertThreshold) {
              shouldDispatchAlert = true;
              break;
            }
          }
          ++majorNation;
        }
      }

      if (shouldDispatchAlert) {
        SharedRefPairScope sharedRefs;
        void* localizationRuntime = ReadLocalizationRuntimeView();
        if (localizationRuntime != 0) {
          VCall_LocalizationRuntime_CallSlot84(localizationRuntime);
          VCall_LocalizationRuntime_CallSlot84WithId(localizationRuntime, 0x2753);
        }
        thunk_AssignStringSharedRefAndReturnThis();
        thunk_AssignStringSharedRefAndReturnThis();
        thunk_DispatchLocalizedUiMessageWithTemplateA13A0();
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x004de5e0
#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif
void TGreatPower::RevokeDiplomacyGrantForTargetAndAdjustInfluence(int arg1) {
  short targetNation = static_cast<short>(arg1);
  int grantValue = DecodeActiveGrantValue(this->diplomacyGrantByNation[targetNation]);
  if (grantValue <= 0) {
    return;
  }

  void* terrainDescriptor =
      ReadGlobalPointerArraySlot(kAddrTerrainTypeDescriptorTable, targetNation);
  TerrainDescriptor_CallSlot38(terrainDescriptor, grantValue);

  this->grantTotalCost -= grantValue;

  void* diplomacyManager = ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr);
  if (LookupOrderCompatibility(targetNation, this->nationSlot) != 2) {
    return;
  }

  int sourceNation = this->nationSlot;
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

  int currentGrant = DecodeActiveGrantValue(this->diplomacyGrantByNation[targetNationId]);

  int availableBudget = ComputeAvailableDiplomacyBudget(this);
  int remainingBudget = currentGrant - proposedGrantValue + availableBudget;
  return remainingBudget >= 0;
}

// FUNCTION: IMPERIALISM 0x004de790
bool TGreatPower::CanAffordAdditionalDiplomacyCostAfterCommitments(short additionalCost) {
  int availableBudget = ComputeAvailableDiplomacyBudget(this);
  int remainingBudget = availableBudget - this->grantTotalCost - static_cast<int>(additionalCost);
  return remainingBudget >= 0;
}
#if defined(_MSC_VER)
#pragma optimize("", on)
#endif

// FUNCTION: IMPERIALISM 0x004de860
void TGreatPower::ApplyJoinEmpireMode0GlobalDiplomacyReset(int arg1) {
  const int kResetDiplomacyLevel = 100;
  const int kResetPolicyCode = -1;
  const int kDipFlagRelation = 6;
  const int kDipFlagPolicy = 0x31;

  QueueInterNationEventRecordDedup(0x1D, this->nationSlot, 7);
  reinterpret_cast<void(__cdecl*)(void)>(thunk_RebuildMinorNationDispositionLookupTables)();

  this->encodedNationSlot = static_cast<short>(arg1 + 100);

  int nationSlot;
  for (nationSlot = 0; nationSlot < kNationSlotCount; ++nationSlot) {
    if (IsNationSlotEligibleForEventProcessingFast(nationSlot) != 0 &&
        nationSlot != this->nationSlot && nationSlot != arg1) {
      TerrainDescriptor_SetResetLevel(ReadTerrainDescriptorSlot(nationSlot), this->nationSlot,
                                      kResetDiplomacyLevel);
    }
  }

  reinterpret_cast<void(__cdecl*)(void)>(ResetTerrainAdjacencyMatrixRowAndSymmetricLink)();

  this->pressureScore = 0;

  Obj_ReleaseAndClearSlot(&this->foreignMinister, 0x1C);
  Obj_ReleaseAndClearSlot(&this->interiorMinister, 0x1C);
  Obj_ReleaseAndClearSlot(&this->defenseMinister, 0x1C);

  this->diplomacyCounterA2 = 0;
  this->diplomacyCounterA4 = 0;
  this->needCapA6 = 0;
  this->needsOverCapFlag = 0;
  this->grantTotalCost = 0;
  this->diplomacyCounterB0 = 0;

  unsigned char* candidateNationFlags = this->candidateNationFlags;
  short* needLevelByNation = this->needLevelByNation;

  int idx;
  for (idx = 0; idx < kNationSlotCount; ++idx) {
    this->diplomacyPolicyByNation[idx] = static_cast<short>(-1);
    this->diplomacyGrantByNation[idx] = static_cast<short>(-1);
    candidateNationFlags[idx] = 0;
    needLevelByNation[idx] = 100;
  }

  for (idx = 0; idx < kNationSlotCount; ++idx) {
    this->needCurrentByType[idx] = 0;
    this->needTargetByType[idx] = 0;
    this->relationDeltaCurrent[idx] = 0;
    this->relationDeltaSnapshot[idx] = 0;
    this->diplomacyState1c6[idx] = 0;
    this->diplomacyState1f4[idx] = 0;
    this->diplomacyState222[idx] = 0;
    this->diplomacyState250[idx] = 0;
    int col;
    for (col = 0; col < kAidAllocationRowCount; ++col) {
      int matrixIndex = col * kAidAllocationColumnCount + idx;
      this->aidAllocationMatrix[matrixIndex] = 0;
    }
  }

  this->budgetPoolBase = 0;
  this->budgetPoolDelta = 0;

  ReleaseObjectAtSlot1C(this->proposalQueue);
  ReleaseObjectAtSlot1C(this->turnEventQueue);

  GreatPower_CallSlot5C(this);

  void* relationPanelManager = this->relationManager;
  if (relationPanelManager != 0) {
    ReleaseObjectAtSlot1C(relationPanelManager);
  }
  this->relationManager = 0;

  GreatPower_CallSlotA5(this);

  void* diplomacyManager = ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr);
  for (nationSlot = 0; nationSlot < kNationSlotCount; ++nationSlot) {
    if (nationSlot != this->nationSlot &&
        IsNationSlotEligibleForEventProcessingFast(nationSlot) != 0) {
      Diplomacy_SetFlag74(diplomacyManager, this->nationSlot, nationSlot, kDipFlagRelation);
      Diplomacy_SetFlag28(diplomacyManager, this->nationSlot, nationSlot, kDipFlagPolicy);
      void* nationState = ReadNationStateSlot(nationSlot);
      if (NationState_IsBusyA0(nationState) == 0) {
        NationState_NotifyAction131(nationState, this->nationSlot);
      }
      GreatPower_ResetDiplomacyLevelForNation(this, nationSlot, kResetDiplomacyLevel);
      GreatPower_ResetPolicyForNation(this, nationSlot, kResetPolicyCode);
    }
  }

  int secondarySlot;
  for (secondarySlot = kMajorNationCount; secondarySlot < kNationSlotCount; ++secondarySlot) {
    void* secondaryState = ReadSecondaryNationStateSlot(secondarySlot);
    bool directReset = true;
    const TSecondaryNationStateOwnerView* secondaryStateView =
        static_cast<const TSecondaryNationStateOwnerView*>(secondaryState);
    short encodedOwnerNation = secondaryStateView->encodedOwnerNationSlot;
    if (encodedOwnerNation >= 200) {
      short ownerNation = DecodeSecondaryNationOwnerSlot(secondaryStateView);
      directReset = ownerNation == this->nationSlot;
    }

    if (!directReset) {
      Diplomacy_SetFlag74(diplomacyManager, this->nationSlot, secondarySlot, kDipFlagRelation);
      Diplomacy_SetFlag28(diplomacyManager, this->nationSlot, secondarySlot, kDipFlagPolicy);
    }

    GreatPower_ResetDiplomacyLevelForNation(this, secondarySlot, kResetDiplomacyLevel);
    GreatPower_ResetPolicyForNation(this, secondarySlot, kResetPolicyCode);

    if (ReadTerrainDescriptorSlot(secondarySlot) != 0) {
      SecondaryState_ResetDiplomacyLevel(secondaryState, this->nationSlot, kResetDiplomacyLevel);
    }
  }

  reinterpret_cast<void(__cdecl*)(void)>(
      thunk_RemoveOrdersByNationFromPrimarySecondaryAndTaskForceLists)();
  ApplyJoinEmpireMode0GlobalDiplomacyResetImpl(ReadGlobalPointer(kAddrGlobalMapStatePtr),
                                               this->nationSlot);

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

  if (this->scenarioLoadFlag != 0) {
    int packedCode = (static_cast<int>(static_cast<unsigned short>(arg1)) << 16) |
                     static_cast<unsigned short>(arg2);
    void* diplomacyQueue = this->turnEventQueue;
    QueueObject_WritePackedIntAtSlot38(diplomacyQueue, &packedCode);

    Event13Payload payload;
    payload.marker0 = 1;
    payload.nationMask = 1 << (static_cast<unsigned char>(this->nationSlot) & 0x1F);
    payload.marker1 = 1;
    payload.targetMask = 1 << (static_cast<unsigned char>(arg1) & 0x1F);

    char immediateDispatch = GreatPower_ShouldDispatchImmediately(this);
    if (immediateDispatch == 0) {
      QueueInterNationEventWithPayload(static_cast<int>(this->nationSlot), &payload);
    } else {
      SendTurnEvent13WithPayload(static_cast<int>(this->nationSlot), &payload);
    }
  }

  void* diplomacyState = ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr);
  int nationSlot = static_cast<int>(this->nationSlot);

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
void TGreatPower::QueueDiplomacyProposalCodeForTargetNation(short proposalCode,
                                                            short targetNationId) {
  struct DiplomacyProposalRecord {
    short proposalCode;
    short targetNationId;
  };

  DiplomacyProposalRecord proposalRecord;
  proposalRecord.proposalCode = proposalCode;
  proposalRecord.targetNationId = targetNationId;

  QueueObject_WritePackedIntAtSlot38(this->proposalQueue, reinterpret_cast<int*>(&proposalRecord));
}

// FUNCTION: IMPERIALISM 0x004df010
void TGreatPower::ApplyAcceptedDiplomacyProposalCode(short proposalIndex) {
  const int kEvent03 = 3;
  const int kEvent04 = 4;
  const int kEvent05 = 5;
  const int kEvent02 = 2;

  SharedRefTripleScope sharedRefs;
  short* proposalEntry = ProposalQueue_GetEntryAt1Based(this->proposalQueue, proposalIndex);
  short proposalCode = proposalEntry[0];
  short targetNation = proposalEntry[1];
  int sourceNation = static_cast<int>(this->nationSlot);
  void* diplomacyManager = ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr);

  switch (static_cast<int>(proposalCode) - 0x12D) {
  case 0:
    GreatPower_CallSlot13(this, static_cast<int>(targetNation), 1);
    QueueInterNationEventRecordDedup(kEvent03, sourceNation, static_cast<int>(targetNation));
    break;

  case 1: {
    Diplomacy_SetRelationCode78(diplomacyManager, sourceNation, static_cast<int>(targetNation), 2);
    QueueInterNationEventRecordDedup(kEvent04, sourceNation, static_cast<int>(targetNation));
    int nationSlot = 0;
    for (nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
      if (Diplomacy_HasPolicyWithNation(diplomacyManager, nationSlot,
                                        static_cast<int>(targetNation)) != 0 &&
          Diplomacy_HasPolicyWithNation(diplomacyManager, sourceNation, nationSlot) == 0) {
        GreatPower_ApplyPolicyForNation(this, nationSlot, 2, static_cast<int>(targetNation));
      }
    }
    break;
  }

  case 2:
    Diplomacy_SetRelationCode78(diplomacyManager, sourceNation, static_cast<int>(targetNation), 3);
    QueueInterNationEventRecordDedup(kEvent05, sourceNation, static_cast<int>(targetNation));
    break;

  case 3: {
    Diplomacy_SetRelationCode78(diplomacyManager, sourceNation, static_cast<int>(targetNation), 4);
    QueueInterNationEventRecordDedup(kEvent02, sourceNation, static_cast<int>(targetNation));
    if (Diplomacy_HasFlag84ForNation(diplomacyManager, static_cast<int>(targetNation)) != 0) {
      int nationSlot = 0;
      for (nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
        if (IsNationSlotEligibleForEventProcessingFast(nationSlot) != 0 &&
            Diplomacy_GetRelationTier(diplomacyManager, sourceNation, nationSlot) == 2 &&
            Diplomacy_HasPolicyWithNation(diplomacyManager, nationSlot,
                                          static_cast<int>(targetNation)) != 0) {
          Diplomacy_SetRelationState(diplomacyManager, sourceNation, nationSlot, 1);
        }
      }
    }
    break;
  }

  case 5: {
    TerrainDescriptor_CallSlot4C(ReadTerrainDescriptorSlot(static_cast<int>(targetNation)),
                                 sourceNation, 1);
    QueueInterNationEventRecordDedup(kEvent03, static_cast<int>(targetNation), sourceNation);
    break;
  }

  default:
    break;
  }

  if (Diplomacy_HasFlag84ForNation(diplomacyManager, static_cast<int>(targetNation)) != 0 &&
      IsNationSlotEligibleForEventProcessingFast(static_cast<int>(targetNation)) != 0) {
    NationState_NotifyActionCode(ReadNationStateSlot(static_cast<int>(targetNation)), sourceNation,
                                 proposalCode);
  }
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

  void* proposalQueue = this->proposalQueue;
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
      NationState_NotifyActionCode(nationState, this->nationSlot, -proposalCode);
    }
  }

  switch (proposalCode) {
  case kProposalCode12D:
    QueueInterNationEventRecordDedup(kEvent09, targetNation, this->nationSlot);
    return;
  case kProposalCode12E:
    QueueInterNationEventRecordDedup(kEvent0B, targetNation, this->nationSlot);
    return;
  case kProposalCode12F:
    QueueInterNationEventRecordDedup(kEvent0D, targetNation, this->nationSlot);
    return;
  case kProposalCode130:
    QueueInterNationEventRecordDedup(kEvent07, targetNation, this->nationSlot);
    return;
  default:
    return;
  }
}

// FUNCTION: IMPERIALISM 0x004df580
void TGreatPower::ResetNationDiplomacyProposalQueue(void) {
  void* proposalQueue = this->proposalQueue;
  if (proposalQueue != 0) {
    ReleaseObjectAtSlot1C(proposalQueue);
  }
}

// FUNCTION: IMPERIALISM 0x004df5c0
void TGreatPower::DispatchTurnEvent2103WithNationFromRecord(void) {
  void* uiRuntimeContext = ReadGlobalPointer(kAddrUiRuntimeContextPtr);
  if (uiRuntimeContext == 0) {
    return;
  }

  VCall_UiRuntime_DispatchEventSlot4C(uiRuntimeContext, 0x2103, this->nationSlot);
}

// FUNCTION: IMPERIALISM 0x004df5f0
void TGreatPower::ProcessPendingDiplomacyProposalQueue(void) {
  const short kProposalTradeEmbargo = 0x12E;
  const short kProposalMutualDefense = 0x132;
  int proposalSummaryRef = 0;
  int proposalScratchRef = 0;
  int proposalIndex = 0;
  int queueIndex = 0;

  InitializeSharedStringRefFromEmpty(&proposalSummaryRef);
  InitializeSharedStringRefFromEmpty(&proposalScratchRef);

  void* proposalQueue = this->proposalQueue;
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
        if (this->diplomacyPolicyByNation[targetNation] == proposalCode) {
          shouldApplyProposal = 1;
        } else if (proposalCode == kProposalTradeEmbargo) {
          if (Diplomacy_GetRelationTier(diplomacyManager, this->nationSlot, targetNation) != 4) {
            shouldApplyProposal = 0;
          } else {
            shouldApplyProposal = UiRuntime_RequestDiplomacyDecision(
                uiRuntimeContext, this->nationSlot, targetNation, kProposalTradeEmbargo);
          }
        } else {
          shouldApplyProposal = UiRuntime_RequestDiplomacyDecision(
              uiRuntimeContext, this->nationSlot, targetNation, proposalCode);
        }

        if (shouldApplyProposal == 0) {
          GreatPower_RemoveProposalByIndex(this, proposalIndex);
        } else if (proposalCode == kProposalMutualDefense) {
          int checkNation = 0;
          do {
            if (Diplomacy_HasPolicyWithNation(diplomacyManager, targetNation, checkNation) != 0 &&
                Diplomacy_HasPolicyWithNation(diplomacyManager, this->nationSlot, checkNation) ==
                    0) {
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

  if (diplomacyTurnStateManager != 0 && diplomacyTurnStateManager->vftable != 0) {
    void** diplomacyVtable = reinterpret_cast<void**>(diplomacyTurnStateManager->vftable);
    char(__cdecl * diplomacySlot44)(short) =
        reinterpret_cast<char(__cdecl*)(short)>(diplomacyVtable[0x44 / 4]);
    if (diplomacySlot44 != 0) {
      result = diplomacySlot44(self->nationSlot);
    }
  }

  char(__fastcall * uiSlot94)(void*, int, int, int) = 0;
  if (uiRuntimeContext != 0) {
    void** uiVtable = *reinterpret_cast<void***>(uiRuntimeContext);
    uiSlot94 = reinterpret_cast<char(__fastcall*)(void*, int, int, int)>(uiVtable[0x94 / 4]);
  }

  if (result == 0) {
    result =
        (uiSlot94 != 0) ? uiSlot94(uiRuntimeContext, 0, self->nationSlot, targetNationSlot) : 0;
    if (result != 0) {
      GreatPower_CallSlotA1(self);
      return true;
    }
  } else {
    result =
        (uiSlot94 != 0) ? uiSlot94(uiRuntimeContext, 0, self->nationSlot, targetNationSlot) : 0;
    if (result != 0) {
      void* secondaryNationState = ReadSecondaryNationStateSlot(targetNationSlot);
      if (secondaryNationState != 0) {
        const TSecondaryNationStateOwnerView* secondaryNationStateView =
            static_cast<const TSecondaryNationStateOwnerView*>(secondaryNationState);
        short stateValue = DecodeSecondaryNationOwnerSlot(secondaryNationStateView);
        if (stateValue != self->nationSlot) {
          SecondaryState_CallSlot4C(secondaryNationState, self->nationSlot, 1);
        }
      }
    }
  }
  return result != 0;
}

// FUNCTION: IMPERIALISM 0x004E22B0
void TGreatPower::AddRegionIdToNationOwnedRegionListAndTriggerExpansionActionIfThresholdMet(void) {
  void* ownedRegionList = this->ownedRegionList;
  List_ResetSlot14(ownedRegionList);
  int ownedRegionCount = List_GetCountSlot28(ownedRegionList);

  unsigned char pressureGate = this->serializedStatusFlags[6];
  unsigned char nationGate = this->expansionEventGate;
  if (ownedRegionCount > 8 && pressureGate > 0x32 && nationGate < 3) {
    GreatPower_DispatchEventSlot2E(this, 0x0C, -1);
  }
}

// FUNCTION: IMPERIALISM 0x004E2330
void TGreatPower::ApplyDiplomacyTargetTransitionAndClearGrantEntry(int targetNationSlot,
                                                                   int policyCode) {
  const int kPolicyDefensivePact = 500;
  const int kPolicyTradeAgreement = 200;

  short targetNation = static_cast<short>(targetNationSlot);
  if (policyCode == kPolicyDefensivePact || policyCode != kPolicyTradeAgreement) {
    this->needLevelByNation[targetNation] = 100;
  } else {
    int resolvedNation = ResolveTerrainNationSlotFromTarget(targetNation);
    this->needLevelByNation[targetNation] =
        this->needLevelByNation[static_cast<short>(resolvedNation)];
  }

  this->diplomacyGrantByNation[targetNation] = -1;

  if (policyCode == kPolicyDefensivePact) {
    void* diplomacyManager = ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr);
    this->diplomacyPolicyByNation[targetNation] = -1;
    Diplomacy_SetRelationCode78(diplomacyManager, this->nationSlot, targetNation, 4);
    GreatPower_CallSlot85(this, targetNation);
    return;
  }

  if (policyCode != kPolicyTradeAgreement) {
    GreatPower_CallSlot84(this, targetNation);
    return;
  }

  if (this->candidateNationFlags[targetNation] == 0) {
    int resolvedNation = ResolveTerrainNationSlotFromTarget(targetNation);
    if (this->candidateNationFlags[static_cast<short>(resolvedNation)] == 0) {
      void* diplomacyManager = ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr);
      if (Diplomacy_HasPolicyWithNation(diplomacyManager, this->nationSlot, resolvedNation) == 0) {
        GreatPower_CallSlot85(this, targetNation);
        return;
      }
    }
  }

  GreatPower_CallSlot84(this, targetNation);
}

// FUNCTION: IMPERIALISM 0x004E2500
void TGreatPower::ReleaseTrackedObjectsByMapOwnerAndUnassignedEntries(int ownerClass) {
  TGlobalMapStateScoreView* globalMapState = ReadGlobalMapStateScoreView();
  void* filteredList = this->trackedObjectList;
  for (int index = List_GetCountSlot48(filteredList); index != 0; --index) {
    TTrackedObjectListEntryView* entry = List_GetTrackedEntrySlot4C(filteredList, index);
    if (entry == 0 || globalMapState == 0 || globalMapState->terrainStateTable == 0) {
      continue;
    }

    short mapOwnerClass = globalMapState->terrainStateTable[entry->regionIndex].cityRecordIndex;
    if (mapOwnerClass == ownerClass) {
      void* trackedObject = entry->object;
      Object_CallSlot30NoArgs(trackedObject);
      ReleaseObjectAtSlot1C(trackedObject);
    }
  }

  void* unassignedList = this->pad_44_ptr;
  for (int unassignedIndex = List_GetCountSlot48(unassignedList); unassignedIndex != 0;
       --unassignedIndex) {
    TTrackedObjectListEntryView* entry =
        List_GetTrackedEntrySlot4C(unassignedList, unassignedIndex);
    if (entry != 0 && entry->regionIndex == -1) {
      ReleaseObjectAtSlot1C(entry->object);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004E27B0
void TGreatPower::DispatchNationDiplomacySlotActionByMode(int targetNationSlot, int mode) {
  if (static_cast<short>(mode) == 6) {
    GreatPower_CallSlotA8(this, targetNationSlot);
    return;
  }

  GreatPower_CallSlotA9(this);
}

// FUNCTION: IMPERIALISM 0x004E27F0
void TGreatPower::QueueWarTransitionAndNotifyThirdPartyIfNeeded(int arg1, int arg2, int arg3,
                                                                int arg4) {
  QueueNationPairWarTransition(reinterpret_cast<void*>(arg1), this->nationSlot,
                               static_cast<short>(arg2));

  short proposalCode = static_cast<short>(arg3);
  if ((proposalCode != 1) && (proposalCode != 0x132)) {
    (void)arg4;
    return;
  }

  void* secondaryNationState = ReadSecondaryNationStateSlot(static_cast<unsigned char>(arg2));
  if (secondaryNationState == 0) {
    return;
  }

  const TSecondaryNationStateOwnerView* secondaryNationStateView =
      static_cast<const TSecondaryNationStateOwnerView*>(secondaryNationState);
  short selectedSlot = DecodeSecondaryNationOwnerSlot(secondaryNationStateView);

  if (selectedSlot == this->nationSlot) {
    return;
  }

  SecondaryState_CallSlot4C(secondaryNationState, this->nationSlot, 1);
}

// FUNCTION: IMPERIALISM 0x004E2B70
void TGreatPower::BuildGreatPowerTurnMessageSummaryAndDispatch(void) {
  if (this->turnSummaryQueue == 0) {
    return;
  }

  void* summaryQueue = this->turnSummaryQueue;
  int queueCount = List_GetCountSlot48(summaryQueue);
  if (queueCount <= 0) {
    return;
  }

  short activeTurn = 0;
  TLocalizationRuntimeView* localizationRuntime = ReadLocalizationRuntimeView();
  if (localizationRuntime != 0) {
    activeTurn = static_cast<short>(LocalizationRuntime_GetTurnTick(localizationRuntime) - 1);
  }

  int mergedNationMask = 0;
  bool foundCurrentTurnEntry = false;

  for (int queueIndex = 1; queueIndex <= queueCount; ++queueIndex) {
    short* entry = ProposalQueue_GetEntryAt1Based(summaryQueue, queueIndex);
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
  this->thunk_InitializeGreatPowerMinisterRosterAndScenarioState(arg1);

  void* stream = reinterpret_cast<void*>(arg1);
  Stream_ReadAtSlot3C(stream, this->actionMetricByQuarter, 0x0C);
  SwapShortArrayBytes(this->actionMetricByQuarter, 6);

  Stream_ReadAtSlot3C(stream, this->mapNodeStateFlags, 0x180);
  Stream_ReadAtSlot3C(stream, this->portZoneStateFlags, 0x70);

  void* missionQueue = this->missionQueue;
  if (Obj_QueryIntAtSlot(missionQueue, 0x48) != 0) {
    Obj_CallNoArgAtSlot(missionQueue, 0x54);
  }
  Obj_CallIntArgAtSlot(missionQueue, 0x18, arg1);

  int missionContext = 0;
  Stream_ReadAtSlot3C(stream, &missionContext, 4);
  for (int queueIndex = 1; queueIndex < 0x71; ++queueIndex) {
    missionContext = 0;
    char hasMission = Stream_ReadByteAtSlotB0(stream, &missionContext);
    if (hasMission != 0) {
      Obj_CallIntArgAtSlot(missionQueue, 0x30, missionContext);
    }
  }

  if (*reinterpret_cast<int*>(kAddrAdvanceTurnMachineState) < 0x39) {
    this->thunk_QueueMapActionMissionFromCandidateAndMarkState(5, -1, 0, -1);
  }
}

// FUNCTION: IMPERIALISM 0x004e73f0
void TGreatPower::WrapperFor_HandleCityDialogHintClusterUpdate_At004e73f0(void* pMessage) {
  thunk_HandleCityDialogHintClusterUpdate_At00408143(pMessage);

  for (int i = 0; i < 6; ++i) {
    short value = this->actionMetricByQuarter[i];
    Message_AppendBytesSlot78(pMessage, &value, 2);
  }

  Message_AppendBytesSlot78(pMessage, this->mapNodeStateFlags, 0x180);
  Message_AppendBytesSlot78(pMessage, this->portZoneStateFlags, 0x70);

  void* missionQueue = this->missionQueue;
  Queue_ApplyMessageSlot14(missionQueue, pMessage);
  Queue_RefreshSlot48(missionQueue);

  int zeroWord = 0;
  Message_AppendBytesSlot78(pMessage, &zeroWord, 4);
  for (int j = 1; j < 0x71; ++j) {
    int value = Queue_ReadIndexSlot4C(missionQueue, 0, j);
    Message_WriteEntrySlotB4(pMessage, value, 0);
  }
}

// FUNCTION: IMPERIALISM 0x004E7630
void TGreatPower::WrapperFor_TGreatPower_VtblSlot32_At004e7630(int arg1, int arg2, int arg3) {
  if (arg2 < 0 && arg1 > 6 && arg1 < 0x0D) {
    this->needCurrentByType[arg1] = static_cast<short>(this->needCurrentByType[arg1] + arg2);
  }

  this->thunk_ApplyIndexedResourceDeltaAndAdjustNationTotals_At00407392(arg1, arg2, arg3);
}

// FUNCTION: IMPERIALISM 0x004E7B20
void TGreatPower::ForwardApplyDiplomacyPolicyStateForTargetWithCostChecks(int arg1, int arg2) {
  this->thunk_ApplyDiplomacyPolicyStateForTargetWithCostChecks_At004070e5(arg1, arg2);
}

// FUNCTION: IMPERIALISM 0x004e7b50
void TGreatPower::QueueDiplomacyProposalCodeWithAllianceGuards(int arg1, int arg2) {
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
      char hasAllianceGuard =
          VCall_Diplomacy_HasAllianceGuardSlot60(diplomacyState, arg1, this->nationSlot);
      if (hasAllianceGuard == 0) {
        thunk_QueueDiplomacyProposalCodeForTargetNation_At004083f5(arg2, arg1);
      }
    }
    return;
  }
  default:
    thunk_QueueDiplomacyProposalCodeForTargetNation_At004083f5(arg2, arg1);
    return;
  }
}

// FUNCTION: IMPERIALISM 0x004e7c50
void TGreatPower::ApplyImmediateDiplomacyPolicySideEffectsWithSelectionHook(int arg1, int arg2) {
  if (static_cast<short>(arg2) == 0x131) {
    GreatPower_CallSlot84(this, static_cast<short>(arg1));
  }
  thunk_ApplyImmediateDiplomacyPolicySideEffects_At0040862a(arg1, arg2);
}

// FUNCTION: IMPERIALISM 0x004e8540
void TGreatPower::QueueMapActionMissionFromCandidateAndMarkState(int arg1, int arg2, int arg3,
                                                                 int arg4) {
  const unsigned char kNodeStateAvailable = 1;
  const unsigned char kNodeStateQueued = 2;

  if (arg2 != -1 && this->mapNodeStateFlags[arg2] != kNodeStateAvailable) {
    return;
  }

  if ((arg3 != 0) && (arg4 == -1)) {
    short index = GetShortAtOffset14OrInvalidValue();
    if (this->portZoneStateFlags[index] != kNodeStateAvailable) {
      return;
    }
  }

  int missionKind = arg1;
  if ((arg3 != 0) && (arg2 == -1) && (arg4 == -1) && (arg1 != 4)) {
    missionKind = 3;
    arg4 = -1;
  }

  void* missionObj =
      CreateMissionObjectByKindAndNodeContext(this->nationSlot, missionKind, arg2, arg3, arg4);
  if (missionObj == 0) {
    MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(kUCountryAutoCppPath, kAssertLineQueueMapAction);
  }

  void* missionQueue = this->missionQueue;
  Obj_CallPtrArgAtSlot(missionQueue, 0x30, missionObj);

  if (arg2 != -1) {
    this->mapNodeStateFlags[arg2] = kNodeStateQueued;
  }
  if (arg3 != 0) {
    if (arg3 == -1) {
      short index = GetShortAtOffset14OrInvalidValue();
      this->portZoneStateFlags[index] = kNodeStateQueued;
    }
    if (arg3 != -1) {
      this->mapNodeStateFlags[arg3] = kNodeStateQueued;
    }
  }
}

static const double kMinusSix = -6.0;
static const float kOne = 1.0f;

static __inline float CallVFunc23C(void* obj) {
  return vcall_runtime::thiscall0<float>(obj, static_cast<unsigned int>(0x23C / 4));
}

static __inline float CallVFunc240(void* obj) {
  return vcall_runtime::thiscall0<float>(obj, static_cast<unsigned int>(0x240 / 4));
}

static __inline bool CallEligibilityThunkWithManager(int nationSlot) {
  int(__cdecl * fn)(int) =
      reinterpret_cast<int(__cdecl*)(int)>(thunk_IsNationSlotEligibleForEventProcessing);
  return fn(nationSlot) != 0;
}

static __inline int CallGetField30ThunkWithManager(void) {
  int(__cdecl * fn)(void) = reinterpret_cast<int(__cdecl*)(void)>(thunk_GetInt32Field30);
  return fn();
}

static __inline int CallComputeWeightedNeighborLinkScoreForNode(void* nationObj, int arg) {
  int(__fastcall * fn)(void*, int, int) = reinterpret_cast<int(__fastcall*)(void*, int, int)>(
      thunk_ComputeWeightedNeighborLinkScoreForNode);
  return fn(nationObj, 0, arg);
}

static __inline int CallSumWeightedNeighborLinkScoreForLinkedNodes(void* nationObj) {
  int(__fastcall * fn)(void*) =
      reinterpret_cast<int(__fastcall*)(void*)>(thunk_SumWeightedNeighborLinkScoreForLinkedNodes);
  return fn(nationObj);
}

static __inline int CallSumNavyOrderPriorityForNationAndNodeType(void* nationObj, int arg) {
  int(__fastcall * fn)(void*, int, int) = reinterpret_cast<int(__fastcall*)(void*, int, int)>(
      thunk_SumNavyOrderPriorityForNationAndNodeType);
  return fn(nationObj, 0, arg);
}

static __inline int CallSumNavyOrderPriorityForNation(void* nationObj) {
  int(__fastcall * fn)(void*) =
      reinterpret_cast<int(__fastcall*)(void*)>(thunk_SumNavyOrderPriorityForNation);
  return fn(nationObj);
}

static __inline int CallVirtualIntAtOffset(void* obj, int offsetBytes) {
  return vcall_runtime::thiscall0<int>(obj, static_cast<unsigned int>(offsetBytes / 4));
}

static __inline int CallComputeGlobalMapActionContextNodeValueAverage(void) {
  int(__cdecl * fn)(void) =
      reinterpret_cast<int(__cdecl*)(void)>(thunk_ComputeGlobalMapActionContextNodeValueAverage);
  return fn();
}

#pragma optimize("y", on)  // omit frame pointer (helps match old prolog/epilog)
#pragma optimize("gt", on) // global optimizations (more likely to jump-table a dense switch)

// FUNCTION: IMPERIALISM 0x004e8750
float TGreatPower::ComputeAdvisoryMapNodeScoreFactorByCaseMetric(int metricCase, int cityIndex,
                                                                 int relationTargetNation,
                                                                 int selectedNationSlot) {
  switch (metricCase - 1) {
  case 0: {
    float sum = 0.0f;
    float selected = 0.0f;
    int slot = 0;
    void** nationObjects = ReadGlobalPointerArray(kAddrNationStates);

    for (; slot < 0x17; ++slot) {
      if (!CallEligibilityThunkWithManager(slot)) {
        continue;
      }
      void* nationObj = nationObjects[slot];
      float slotValue = CallVFunc23C(nationObj);
      sum += slotValue;
      if (slot == selectedNationSlot) {
        selected = CallVFunc23C(nationObj);
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
  case 1: {
    float sum = 0.0f;
    float selected = 0.0f;
    int slot = 0;
    void** nationObjects = ReadGlobalPointerArray(kAddrNationStates);

    for (; slot < 0x17; ++slot) {
      if (!CallEligibilityThunkWithManager(slot)) {
        continue;
      }
      void* nationObj = nationObjects[slot];
      float slotValue = CallVFunc240(nationObj);
      sum += slotValue;
      if (slot == selectedNationSlot) {
        selected = CallVFunc240(nationObj);
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
  case 2: {
    void* terrainDescriptor = ReadTerrainDescriptorSlot(selectedNationSlot);
    if (terrainDescriptor == 0) {
      return kOne;
    }

    TTerrainDescriptorLinkedNodesView* linkedNodesView =
        static_cast<TTerrainDescriptorLinkedNodesView*>(terrainDescriptor);
    if (linkedNodesView->linkedNodeList == 0) {
      return kOne;
    }

    int nodeWeight = CallVirtualIntAtOffset(linkedNodesView->linkedNodeList, 0x28);
    int weightedNeighbor =
        CallComputeWeightedNeighborLinkScoreForNode(terrainDescriptor, relationTargetNation);
    int linkedNodeTotal = CallSumWeightedNeighborLinkScoreForLinkedNodes(terrainDescriptor);

    float denominator = static_cast<float>(weightedNeighbor * nodeWeight) + 100.0f;
    if (denominator == 0.0f) {
      return kOne;
    }
    return (static_cast<float>(linkedNodeTotal) + 100.0f) / denominator;
  }
  case 3: {
    if (selectedNationSlot < 0 || selectedNationSlot >= 7) {
      return 0.0f;
    }

    void* nationObj = ReadNationStateSlot(selectedNationSlot);
    if (nationObj == 0) {
      return 0.0f;
    }

    int priorityForNode =
        CallSumNavyOrderPriorityForNationAndNodeType(nationObj, relationTargetNation);
    int nodeMultiplier = CallVirtualIntAtOffset(nationObj, 0x21C);
    int totalPriority = CallSumNavyOrderPriorityForNation(nationObj);

    float denominator =
        static_cast<float>(priorityForNode * nodeMultiplier) - static_cast<float>(kMinusSix);
    if (denominator == 0.0f) {
      return 0.0f;
    }
    return (static_cast<float>(totalPriority) - static_cast<float>(kMinusSix)) / denominator;
  }
  case 4: {
    void* mgr = ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr);
    if (mgr == 0) {
      return kOne;
    }
    short relationValue =
        Diplomacy_ReadRelationMatrix79C(mgr, this->nationSlot, relationTargetNation);
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
    float scoreRatio = (float)cityScore / (float)globalMapState->cityScoreTotal;

    const unsigned char* cityBytes = reinterpret_cast<const unsigned char*>(
        GlobalMapState_GetCityRecord(globalMapState, cityIndex));
    signed char primaryNation = static_cast<signed char>(cityBytes[0]);
    signed char controllingNation = static_cast<signed char>(cityBytes[1]);
    if (controllingNation == this->nationSlot && primaryNation != this->nationSlot) {
      void* diplomacyManager = ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr);
      if (diplomacyManager != 0 && VCall_Diplomacy_HasPolicyWithNationSlot44(
                                       diplomacyManager, this->nationSlot, primaryNation) != 0) {
        scoreRatio = scoreRatio * 2.0f;
      }
    }
    return scoreRatio;
  }
  case 6: {
    int globalAverage = CallComputeGlobalMapActionContextNodeValueAverage();
    if (globalAverage == 0) {
      return kOne;
    }
    unsigned int nodeValue = this->thunk_ComputeMapActionContextNodeValueAverage();
    return static_cast<float>(nodeValue) / static_cast<float>(globalAverage);
  }
  default:
    return kOne;
  }
}

// FUNCTION: IMPERIALISM 0x004e9060
float TGreatPower::ComputeMapActionContextCompositeScoreForNation(int nodeType) {
  unsigned char* candidateFlags = this->candidateNationFlags;
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
      reinterpret_cast<void(__fastcall*)(void*, int)>(thunk_ConstructObArrayWithVtable654D38)(
          relationshipList, 0);
      reinterpret_cast<void(__fastcall*)(void*, int)>(thunk_InitializeObArrayVtable654D38ModeField)(
          relationshipList, 0);
    }

    void* diplomacyManager = ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr);
    if (diplomacyManager != 0) {
      VCall_Diplomacy_BuildRelationshipListSlot88(diplomacyManager, this->nationSlot, 1,
                                                  relationshipList);
    }

    if (relationshipList != 0) {
      void* firstNode = List_GetNodeByOrdinalSlot2C(relationshipList, 0, 1);
      if (firstNode != 0) {
        selectedCandidateIndex =
            static_cast<int>(static_cast<TShortNodeValueView*>(firstNode)->value);
      }
      List_ReleaseSlot24(relationshipList);
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
  if (this->relationManager == 0) {
    return;
  }

  this->thunk_PopulateCase16AdvisoryMapNodeCandidateState();

  int bestNodeIndex = -1;
  float bestNodeScore = 0.0f;

  for (int nodeIndex = 0; nodeIndex < 0x180; ++nodeIndex) {
    if (this->mapNodeStateFlags[nodeIndex] != 1) {
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
    int needValue = static_cast<int>(this->needLevelByNation[nationSlot]);
    if (needValue > strongestNeed) {
      strongestNeed = needValue;
      strongestNation = nationSlot;
    }
  }

  if (strongestNation >= 0 && strongestNation != this->nationSlot) {
    this->thunk_QueueInterNationEventType0FForNationPairContext_At00405ac9(
        static_cast<short>(strongestNation), this->nationSlot);
  }
}

// FUNCTION: IMPERIALISM 0x004E9ED0
void TGreatPower::QueueWarTransitionFromAdvisoryAction(int arg1, int arg2) {
  GreatPower_CallSlot84(this, arg1);
  this->thunk_QueueWarTransitionAndNotifyThirdPartyIfNeeded_At00406fe1(arg1, arg1, arg2, arg1);
}

// FUNCTION: IMPERIALISM 0x004EA150
void TGreatPower::ApplyJoinEmpireResetAndClearDiplomacyCaches(int arg1) {
  this->thunk_ApplyJoinEmpireMode0GlobalDiplomacyReset_At004097fa(arg1);

  int i = 0;
  for (i = 0; i < 6; ++i) {
    this->actionMetricByQuarter[i] = 0;
  }
  for (i = 0; i < kMapNodeCount; ++i) {
    this->mapNodeStateFlags[i] = 0;
  }
  for (i = 0; i < kPortZoneCount; ++i) {
    this->portZoneStateFlags[i] = 0;
  }

  GreatPower_CallSlotB3(this);
}

// FUNCTION: IMPERIALISM 0x004EA290
void TGreatPower::AddRegionToNationAndQueueMapActionMission(int arg1) {
  this->thunk_AddRegionIdToNationOwnedRegionListAndTriggerExpansionActionIfThresholdMet_At00404246();

  if (arg1 >= 0 && arg1 < kMapNodeCount) {
    this->mapNodeStateFlags[arg1] = 1;
    this->thunk_QueueMapActionMissionFromCandidateAndMarkState(3, arg1, 0, -1);
  }
}

// FUNCTION: IMPERIALISM 0x004EA300
void TGreatPower::MarkNationPortZoneAndLinkedTilesForActionFlag(int arg1) {
  this->thunk_ResetNationDiplomacySlotsAndMarkRelatedNations_At00406c9e();

  void* terrainDescriptor = ReadTerrainDescriptorSlot(arg1);
  if (terrainDescriptor != 0) {
    TTerrainDescriptorLinkedNodesView* terrainView =
        static_cast<TTerrainDescriptorLinkedNodesView*>(terrainDescriptor);
    void* linkedNodeList = terrainView->linkedNodeList;
    if (linkedNodeList != 0) {
      int linkedCount = List_GetCountSlot28(linkedNodeList);
      for (int ordinal = 1; ordinal <= linkedCount; ++ordinal) {
        int nodeIndex = List_GetIntByOrdinalSlot24(linkedNodeList, ordinal);
        if (nodeIndex >= 0 && nodeIndex < kMapNodeCount) {
          this->mapNodeStateFlags[nodeIndex] = 1;
          this->thunk_QueueMapActionMissionFromCandidateAndMarkState(3, nodeIndex, 0, -1);
        }
      }
    }
  }

  short(__cdecl * getPortNode)(void) =
      reinterpret_cast<short(__cdecl*)(void)>(thunk_GetShortAtOffset14OrInvalid);
  short portNode = getPortNode();
  if (portNode >= 0 && portNode < kPortZoneCount) {
    this->portZoneStateFlags[portNode] = 1;
    this->thunk_QueueMapActionMissionFromCandidateAndMarkState(3, -1, portNode, -1);
  }
}

// FUNCTION: IMPERIALISM 0x004ea470
void TGreatPower::RebuildNationResourceYieldsAndRollField134Into136(void) {
  this->thunk_RebuildNationResourceYieldCountersAndDevelopmentTargets_At004097ff();
  short carryValue = this->needCurrentByType[0x13];
  this->needCurrentByType[0x13] = 0;
  this->needCurrentByType[0x14] = static_cast<short>(this->needCurrentByType[0x14] + carryValue);
}

// FUNCTION: IMPERIALISM 0x004FFC10
void TGreatPower::ConstructTurnOrderNavigationWindowEntryViewportAdaptive(void) {
  this->scenarioLoadFlag = 0;
  this->diplomacyCounterA2 = 0x14;
  this->diplomacyCounterA4 = 0;
  this->needCapA6 = 0;
  this->needsOverCapFlag = 0;
  this->grantTotalCost = 0;
}

// FUNCTION: IMPERIALISM 0x00540AC0
void TGreatPower::QueueDiplomacyProposalCodeForTargetNationAndDispatchTurnEvent16(
    int proposalCode, int targetNationId) {
  struct TurnEvent16PacketPayload {
    int eventCode;
    int eventParamA;
    int eventParamB;
    int payloadSize;
    int packetTag;
    short sourceNation;
  };

  this->thunk_QueueDiplomacyProposalCodeForTargetNation_At004083f5(proposalCode, targetNationId);

  TurnEvent16PacketPayload packetPayload;
  packetPayload.packetTag = 0x74696D65;
  reinterpret_cast<void(__cdecl*)(void)>(thunk_GetActiveNationId)();
  packetPayload.sourceNation = this->nationSlot;
  packetPayload.eventCode = 0x16;
  packetPayload.eventParamA = 0;
  packetPayload.eventParamB = 0;
  packetPayload.payloadSize = 0x20;

  reinterpret_cast<void(__cdecl*)(void)>(thunk_SetEventPayloadNationIdFromSlotIndex)();
  reinterpret_cast<void(__cdecl*)(int, int)>(thunk_EnqueueOrSendTurnEventPacketToNation)(
      reinterpret_cast<int>(&packetPayload.eventCode), 0);
}

// FUNCTION: IMPERIALISM 0x00541080
void TGreatPower::TryDispatchNationActionViaUiThenTurnEvent(int arg1, int arg2, int arg3,
                                                            int arg4) {
  char dispatchedViaUi =
      this->thunk_TryDispatchNationActionViaUiContextOrFallback_At00404ce1(arg1, arg2, arg3, arg4);
  if (dispatchedViaUi != 0) {
    reinterpret_cast<void(__stdcall*)(int, int, int, int, int)>(
        thunk_DispatchTurnEvent1AWithNationActionPayload)(this->nationSlot, arg1, arg2, arg3, arg4);
  }
}

// FUNCTION: IMPERIALISM 0x005410F0
void TGreatPower::ProcessPendingDiplomacyThenDispatchTurnEvent29A(void) {
  this->thunk_ProcessPendingDiplomacyProposalQueue_At00401cbc();
  void* gameFlowState = ReadGlobalPointer(kAddrGameFlowStatePtr);
  int nationSlot = 0;
  void** nationStateCursor = ReadGlobalPointerArray(kAddrNationStates);

  do {
    void* nationState = *nationStateCursor;
    if (nationState != 0 && NationState_IsBusyA0(nationState) == 0) {
      ClearTurnResumeNationPendingBitAndMaybeFlushTelemetry(gameFlowState, nationSlot);
    }
    ++nationStateCursor;
    ++nationSlot;
  } while (reinterpret_cast<unsigned int>(nationStateCursor) < kAddrNationStatesMajorEnd);

  void* uiRuntimeContext = ReadGlobalPointer(kAddrUiRuntimeContextPtr);
  VCall_UiRuntime_RequestDiplomacyDecisionSlot90(uiRuntimeContext, this->nationSlot,
                                                 this->nationSlot, 0x29A);
}

// FUNCTION: IMPERIALISM 0x005416B0
void TGreatPower::ApplyClientGreatPowerCommand69AndEmitTurnEvent1E(int arg1, int arg2) {
  struct TurnEvent1EPacketPayload {
    int eventCode;
    int eventParamA;
    int eventParamB;
    int payloadSize;
    int packetTag;
    unsigned char commandArgA;
    unsigned char commandArgB;
    unsigned char commandCode;
    unsigned char acceptedFlag;
  };

  bool accepted = this->thunk_ExecuteAdvisoryPromptAndApplyActionType1_At00403c15();
  TurnEvent1EPacketPayload packetPayload;
  packetPayload.packetTag = 0x74696D65;
  reinterpret_cast<void(__cdecl*)(void)>(thunk_GetActiveNationId)();
  packetPayload.eventCode = 0x1E;
  packetPayload.eventParamA = 0;
  packetPayload.eventParamB = 0;
  packetPayload.payloadSize = 0x24;
  reinterpret_cast<void(__cdecl*)(void)>(thunk_SetTimeEmitPacketGameFlowTurnId)();
  packetPayload.eventParamB = -1;
  reinterpret_cast<void(__cdecl*)(void)>(thunk_GetActiveNationId)();
  packetPayload.acceptedFlag = accepted ? 1 : 0;
  packetPayload.commandCode = 0x69;
  packetPayload.commandArgA = static_cast<unsigned char>(arg1);
  packetPayload.commandArgB = static_cast<unsigned char>(arg2);
  reinterpret_cast<void(__cdecl*)(int, int)>(thunk_EnqueueOrSendTurnEventPacketToNation)(
      reinterpret_cast<int>(&packetPayload.eventCode), 0);
}

// FUNCTION: IMPERIALISM 0x0055C970
void TGreatPower::QueueInterNationEventIntoNationBucket(int eventCode, int payloadOrNation,
                                                        char isReplayBypass) {
  TLocalizationRuntimeView* localizationTable = ReadLocalizationRuntimeView();
  if (localizationTable == 0) {
    return;
  }

  if (LocalizationRuntime_ReadGateFlag7A(localizationTable) == 0) {
    if (isReplayBypass == '\0' && localizationTable->redrawEnabled != 0) {
      SendTurnEvent13WithPayload(eventCode, reinterpret_cast<void*>(payloadOrNation));
      return;
    }

    void* interNationQueue = GreatPower_GetInterNationQueueByEventCode(this, eventCode);
    if (interNationQueue != 0) {
      QueueObject_WritePackedIntAtSlot38(interNationQueue, &payloadOrNation);
    }
  }
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
  if (localizationTable == 0) {
    return;
  }

  if (LocalizationRuntime_ReadGateFlag7A(localizationTable) == 0) {
    if (isReplayBypass == '\0' && localizationTable->redrawEnabled != 0) {
      reinterpret_cast<void(__cdecl*)(void)>(thunk_CreateAndSendTurnEvent21_ThreeBytes)();
      return;
    }

    void* mergeQueue = GreatPower_GetInterNationQueueByEventCode(this, 7);
    if (mergeQueue == 0) {
      return;
    }

    int queueCount = ObArray_GetCountAtOffset8(mergeQueue);
    for (int entryIndex = 1; entryIndex <= queueCount; ++entryIndex) {
      TInterNationEventType0FMergePayload* existingEntry =
          reinterpret_cast<TInterNationEventType0FMergePayload*>(
              VCall_ProposalQueue_GetEntryAt1Based(mergeQueue, entryIndex));
      if (existingEntry == 0) {
        continue;
      }
      if (existingEntry->eventMarker == 0x0F && existingEntry->nationB == nationB &&
          existingEntry->eventCode == eventCode) {
        existingEntry->nationMask |= 1 << (nationA & 0x1F);
        return;
      }
    }

    TInterNationEventType0FMergePayload payload;
    payload.eventMarker = 0x0F;
    payload.eventCode = eventCode;
    payload.nationMask = 1 << (nationA & 0x1F);
    payload.nationB = nationB;
    QueueObject_WritePackedIntAtSlot38(mergeQueue, reinterpret_cast<int*>(&payload));
  }
}

// FUNCTION: IMPERIALISM 0x0055F140
unsigned int TGreatPower::ComputeMapActionContextNodeValueAverage(void) {
  TGlobalMapStateScoreView* globalMapState = ReadGlobalMapStateScoreView();
  if (globalMapState == 0 || globalMapState->cityScoreTable == 0) {
    return 0;
  }

  unsigned int totalValue = 0;
  unsigned int selectedCount = 0;

  for (int nodeIndex = 0; nodeIndex < kMapNodeCount; ++nodeIndex) {
    if (this->mapNodeStateFlags[nodeIndex] == 0) {
      continue;
    }
    totalValue +=
        static_cast<unsigned int>(GlobalMapState_ReadCityScoreValue(globalMapState, nodeIndex));
    ++selectedCount;
  }

  if (selectedCount == 0) {
    return static_cast<unsigned int>(
        GlobalMapState_ReadCityScoreValue(globalMapState, this->nationSlot));
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
  list->field0e = 0;
  list->field10 = 0;
  list->field08 = 0;
  list->field04 = 0;
  list->pField14 = 0;
  list->vftable = reinterpret_cast<void*>(kAddrCPtrListRuntimeClassVtable);
  list->field18 = ownerContext;
}
