#include "game/TStreamView.h"
#include "game/TStream.h"
#include "game/TTerrainDescriptor.h"
#include "game/TMinor.h"
#include "game/TTrackedObject.h"
#include "game/TNationInteractionStateManager.h"
#include "game/TLocalizationRuntime.h"
#include "game/TNationState.h"
#include "game/TUiRuntimeContext.h"
#include "game/TRelationManager.h"
#include "game/TMinister.h"
#include "game/TGlobalMapState.h"
// Manual decompilation file.
// Seeded from ghidra autogen and normalized into compile-safe wrappers.

#include "decomp_types.h"
#include "game/GameAssert.h"
#include "game/generated/vcall_facades.h"
#include "game/CString.h"
#include "game/TGreatPower.h"
#include "game/TGlobalMapState.h"
#include "game/TDiplomacyTurnStateManager.h"
#include <stddef.h>
#include <new>

extern "C" void* g_pLocalizationTable;

// Minister-skill float coefficient tables (defined in global_data_tables.cpp).
extern "C" {
extern float g_DAT_Value_00653308[];
extern float g_DAT_Value_00653328[];
extern float g_DAT_Value_00653340[];
extern float g_DAT_Value_00653360[];
extern float g_DAT_Value_00653378[];
extern float g_DAT_Value_00653398[];
extern float g_DAT_006533b0_Value_006533B0[];
extern float g_DAT_006533d0_Value_006533D0[];
extern float g_DAT_006533e8_Value_006533E8[];
extern float g_DAT_Value_00653408[];
extern void* g_pMapActionContextListHead;
}

// Abstract View Classes for Native Virtual Method Dispatches (MSVC 5.0 compatible __thiscall
// dispatches)

// TQueueObject moved to include/game/TQueueObject.h

// Entry record returned by TQueueObject::GetEntryAt1BasedSlot2C for the
// diplomacy tracked-slot queues.
struct TDiplomacyTrackedEntry {
  short field0;
  short field2;
  short field4;
  short field6;
  int field8;
};

// Singly-linked global map-action-context node list (head at 0x006A3FC8).
struct MapActionContextNode {
  unsigned char pad00[0x10];
  unsigned char flags10; // +0x10
  unsigned char pad11[0x18 - 0x11];
  MapActionContextNode* next18; // +0x18
};

// Minister-skill-indexed float coefficient table lookup (DAT_0065xxxx tables).
static __inline double MinisterSkillFloat(const float* table, TMinister* minister) {
  return table[minister->skillIndexC];
}

typedef void* hwnd_t;

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
undefined4 ResetNationDiplomacySlotsAndMarkRelatedNations(void);
undefined4 thunk_QueueNationPairWarTransition(void);
void BuildGreatPowerRelationshipDeltaSummaryAndDispatchMessage(void);
void ApplyIndexedResourceDeltaAndAdjustNationTotals(void);
void RefreshGreatPowerRelationPanelsAndDispatchDeltaSummary(void);
void NoOpAdvisoryHandlerReturn(void);
void NoOpDiplomacyWarTransitionCallback(void);
void HandleCityDialogHintClusterUpdate(void);
void FreeHeapBufferIfNotNull(undefined4 ptr_value);
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
undefined4 thunk_DispatchTurnEvent1AWithNationActionPayload(void);
undefined4 ResetTerrainAdjacencyMatrixRowAndSymmetricLink(void);
undefined4 thunk_RemoveOrdersByNationFromPrimarySecondaryAndTaskForceLists(void);
undefined4 ApplyJoinEmpireMode0GlobalDiplomacyReset_Impl(void);
undefined4 thunk_DispatchTaggedGameStateEvent1F20(void);
undefined4 thunk_InitializeNationStateIdentityAndOwnedRegionList(void);
undefined4 thunk_InitializeCityModel(void);
undefined4 thunk_InitializeCityProductionState(void);
undefined4 WrapperFor_InitializeLinkedListSentinelNodeWithOwnerContext_At004a8640(void);

undefined4 thunk_DeserializeRecruitScenarioAndInstantiateOrders_At00409089(void);
undefined4 thunk_ConstructFrogCityMarker(void);
undefined4 thunk_ClearTurnResumeNationPendingBitAndMaybeFlushTelemetry(void);
undefined4 thunk_GetActiveNationId(void);
undefined4 thunk_SetEventPayloadNationIdFromSlotIndex(void);
undefined4 thunk_EnqueueOrSendTurnEventPacketToNation(void);
undefined4 thunk_SetTimeEmitPacketGameFlowTurnId(void);
undefined4 thunk_CreateAndSendTurnEvent21_ThreeBytes(void);
undefined4 thunk_AssignSharedStringFromIndexedA8EntryNameField(void);
undefined4 AssignStringSharedFromRef(undefined4 this_ptr, int* src_ref_ptr);
undefined4 thunk_GetResourceDescriptorWeightWord0ByType(void);

// Legacy free-function symbol retained for old callsites that still reference
// the no-arg form; class-owned event queue methods are implemented below.
unsigned int QueueInterNationEventIntoNationBucket(void) {
  return 0;
}

// Legacy global helper still referenced by thunks/call-through wrappers.
unsigned int __cdecl GetTGreatPowerClassNamePointer(void) {
  return 0x00653688;
}

undefined4 thunk_InitializeCivUnitOrderObject(void);
undefined4 thunk_GetCityBuildingProductionValueBySlot(void);
undefined4 thunk_SetGlobalRegionDevelopmentStageByte(void);
undefined4 thunk_DispatchCityRedrawInvalidateEvent(void);
undefined4 GenerateThreadLocalRandom15(void);
undefined4 ReallocateHeapBlockWithAllocatorTracking(void);

// Order-object construction thunks used by ExecuteNationPendingActionStateMachine
// (slot 0x32). Generic repo thunk form per Hard Rule 9; the order objects they
// construct are not yet recovered as real classes, so they are driven through the
// isolated __fastcall bridge helpers below (kept out of the method body).
undefined4 thunk_InitializeMilitaryUnitOrderObject(void);
undefined4 thunk_InitializeMilitaryRecruitOrderState(void);
undefined4 thunk_SetTaskForcePrimaryOrderLinkAndRefreshChildBacklinks(void);
undefined4 thunk_FindReachableRecruitSpawnTileWithVisitedReset(void);
undefined4 thunk_CreateNavyPrimaryOrderNodeAndAssignDisplayName(void);

// EH-body order/state globals (defined in global_data_tables.cpp). Direct absolute
// loads in the original; declaring them as real symbols lets reccmp pair the loads.
extern "C" {
extern void* g_pCityOrderCapabilityState;
extern void* g_pActiveMapOrderContext;

extern void* g_apMinorNationCapabilityObjects[];
}

struct TTerrainDescriptorNationSlotView {
  unsigned char pad00[0x0C];
  short fallbackNationSlot;
  short encodedNationSlot;
};

#include "game/TUnitOrderState.h"
#include "game/TCivWorkOrderState.h"
#include "game/TAdmiral.h"

struct TUnitOrderOwnerManagerView {
  virtual void s00() = 0;
  virtual void s01() = 0;
  virtual void s02() = 0;
  virtual void s03() = 0;
  virtual void s04() = 0;
  virtual void s05() = 0;
  virtual void s06() = 0;
  virtual void s07() = 0;
  virtual void s08() = 0;
  virtual void s09() = 0;
  virtual void s10() = 0;
  virtual void s11() = 0;
  virtual void VTableSlot12(TUnitOrderState* order) = 0; // slot 12 at 0x30
};

extern "C" void* g_apNationStates[];
extern "C" void* g_apTerrainTypeDescriptorTable[];

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

#include "game/TMessageObject.h"
#include "game/TObArray.h"
#include "game/TQueueObject.h"
#include "game/TStream.h"
#include "game/TIndexAndRankList.h"
#include "game/TPtrList.h"

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
static const char kUCountryAutoCppPath[] = "D:\\Ambit\\Cross\\UCountryAuto.cpp";
static const int kAssertLineQueueMapAction = 0x5ED;

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
TG_LAYOUT_ASSERT(TGreatPower_Offset_relationManager_0x894,
                 offsetof(TGreatPower, relationManager) == 0x894);
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

static __inline TGlobalMapState* ReadGlobalMapStateScoreView(void) {
  return static_cast<TGlobalMapState*>(ReadGlobalPointer(kAddrGlobalMapStatePtr));
}

static __inline TLocalizationRuntime* ReadLocalizationRuntimeView(void) {
  return static_cast<TLocalizationRuntime*>(ReadGlobalPointer(kAddrLocalizationTablePtr));
}

static __inline unsigned char
LocalizationRuntime_ReadGateFlag7A(const TLocalizationRuntime* localizationRuntime) {
  return *reinterpret_cast<const unsigned char*>(
      reinterpret_cast<const unsigned char*>(localizationRuntime) + 0x7A);
}

static __inline void* GreatPower_GetInterNationQueueByEventCode(TGreatPower* self, int eventCode) {
  return self->diplomacyTrackedSlots[eventCode];
}

static __inline TTerrainStateRecordView*
GlobalMapState_GetTerrainRecord(const TGlobalMapState* globalMapState, int regionIndex) {
  return globalMapState->terrainStateTable + regionIndex;
}

static __inline TGlobalMapCityScoreRecord*
GlobalMapState_GetCityRecord(const TGlobalMapState* globalMapState, int cityIndex) {
  return globalMapState->cityScoreTable + cityIndex;
}

static __inline int GlobalMapState_ReadCityScoreValue(const TGlobalMapState* globalMapState,
                                                      int cityIndex) {
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

static __inline short LocalizationRuntime_GetTurnTick(TLocalizationRuntime* localizationRuntime) {
  return localizationRuntime->GetTurnTickSlot3C();
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

template <typename T> static __inline void ReleaseAndClear1C(T** slot) {
  if (*slot != 0) {
    (*slot)->Call1C();
    *slot = 0;
  }
}

template <typename T> static __inline void ReleaseAndClear24(T** slot) {
  if (*slot != 0) {
    (*slot)->Call24();
    *slot = 0;
  }
}

template <typename T> static __inline void ReleaseAndClear58(T** slot) {
  if (*slot != 0) {
    (*slot)->Call58();
    *slot = 0;
  }
}

static __inline void Stream_ReadRawAtSlot00(void* stream, void* outBuf, int sizeBytes) {
  static_cast<TStreamView*>(stream)->ReadRaw00(outBuf, sizeBytes);
}

static __inline void Stream_ReadAtSlot3C(void* stream, void* outBuf, int sizeBytes) {
  static_cast<TStreamView*>(stream)->ReadAt3C(outBuf, sizeBytes);
}

static __inline int Stream_ReadIntAtSlot40(void* stream) {
  return static_cast<TStreamView*>(stream)->ReadInt40();
}

static __inline char Stream_ReadByteAtSlotB0(void* stream, void* outByte) {
  return static_cast<TStreamView*>(stream)->ReadByteB0(outByte);
}

static __inline short ProposalQueue_GetCount(void* queue) {
  return static_cast<const TProposalQueueCountView*>(queue)->count;
}

static __inline short* ProposalQueue_GetEntryAt1Based(void* queue, int queueIndex) {
  return static_cast<short*>(static_cast<TQueueObject*>(queue)->GetEntryAt1BasedSlot2C(queueIndex));
}

static __inline void List_ResetSlot14(void* list) {
  static_cast<TListObject*>(list)->ResetSlot14();
}

static __inline int List_GetCountSlot28(void* list) {
  return static_cast<TListObject*>(list)->GetCountSlot28();
}

static __inline int List_GetIntByOrdinalSlot24(void* list, int ordinal) {
  return static_cast<TListObject*>(list)->GetIntByOrdinalSlot24(ordinal);
}

static __inline int List_GetCountSlot48(void* list) {
  return static_cast<TListObject*>(list)->GetCountSlot48();
}

static __inline TTrackedObjectListEntryView* List_GetTrackedEntrySlot4C(void* list, int ordinal) {
  return static_cast<TTrackedObjectListEntryView*>(
      static_cast<TListObject*>(list)->GetTrackedEntrySlot4C(ordinal));
}

static __inline int ObArray_GetCountAtOffset8(void* list) {
  return *reinterpret_cast<int*>(reinterpret_cast<unsigned char*>(list) + 8);
}

static __inline short ObArray_GetShortValueByOrdinal1Based(void* list, int ordinal) {
  short* value =
      static_cast<short*>(reinterpret_cast<TObArray*>(list)->GetShortValueByOrdinalSlot2C(ordinal));
  return (value != 0) ? *value : static_cast<short>(-1);
}

static __inline char UiRuntime_RequestDiplomacyDecision(void* uiRuntimeContext, int sourceNation,
                                                        int targetNation, int proposalCode) {
  return static_cast<TUiRuntimeContext*>(uiRuntimeContext)
      ->RequestDiplomacyDecisionSlot90(sourceNation, targetNation, proposalCode);
}

static __inline char IsTurnCooldownCounterActiveOrResetFlagAsChar(void) {
  char(__cdecl * isTurnCooldownActive)(void) =
      reinterpret_cast<char(__cdecl*)(void)>(thunk_IsTurnCooldownCounterActiveOrResetFlag);
  return isTurnCooldownActive();
}

static __inline void QueueObject_WritePackedIntAtSlot38(void* queue, int* packedValue) {
  static_cast<TQueueObject*>(queue)->WritePackedIntSlot38(packedValue);
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

static __inline void ReleaseObjectAtSlot1C(void* obj) {
  if (obj != 0) {
    static_cast<TTrackedObject*>(obj)->Release1C();
  }
}

static __inline void Object_CallSlot30NoArgs(void* obj) {
  if (obj != 0) {
    static_cast<TTrackedObject*>(obj)->Call30();
  }
}

static __inline void TerrainDescriptor_SetResetLevel(void* terrainDescriptor, int sourceNation,
                                                     int resetLevel) {
  static_cast<TTerrainDescriptor*>(terrainDescriptor)
      ->SetResetLevelSlot68(sourceNation, resetLevel);
}

static __inline void NationState_NotifyAction131(void* nationState, int sourceNation) {
  static_cast<TGreatPower*>(nationState)->NotifyActionSlot94(sourceNation, 0x131);
}

static __inline void NationState_NotifyActionCode(void* nationState, int sourceNation,
                                                  int actionCode) {
  static_cast<TGreatPower*>(nationState)->NotifyActionSlot94(sourceNation, actionCode);
}

static __inline void NationState_AssignNeedSlotFromSource(void* nationState, int needSlot,
                                                          int sourceNation) {
  static_cast<TGreatPower*>(nationState)->AssignNeedSlotFromSourceSlot19C(needSlot, sourceNation);
}

static __inline char NationState_IsBusyA0(void* nationState) {
  const TNationStateFlags* nationStateView = static_cast<const TNationStateFlags*>(nationState);
  return nationStateView->busyFlagA0;
}

static __inline void Object_CallSlot8CNoArgs(void* obj) {
  if (obj != 0) {
    static_cast<TMinister*>(obj)->Call8C();
  }
}

static __inline void SecondaryState_ResetDiplomacyLevel(void* secondaryState, int sourceNation,
                                                        int resetLevel) {
  static_cast<TMinor*>(secondaryState)
      ->SetDiplomacyStandingSlot48(sourceNation, resetLevel);
}

static __inline char GlobalMapState_CallMetricC4(void* globalMapState, int regionIndex,
                                                 int edgeIndex) {
  return static_cast<TGlobalMapState*>(globalMapState)->CallMetricSlotC4(regionIndex, edgeIndex);
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
DecodeSecondaryNationOwnerSlot(const TSecondaryNationStateOwner* secondaryNationStateView) {
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
  static_cast<TTerrainDescriptor*>(terrainDescriptor)->CallSlot4C(sourceNation, modeValue);
}

static __inline void TerrainDescriptor_CallSlot38(void* terrainDescriptor, int delta) {
  static_cast<TTerrainDescriptor*>(terrainDescriptor)->CallSlot38(delta);
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
  return ClampNonNegative(self->treasuryValue10 + self->diplomacyBudgetBase / 100);
}

static __inline char IsSpecialNationInteractionResource(short resourceIndex) {
  return reinterpret_cast<char(__stdcall*)(short)>(
      ApplyIndexedResourceDeltaAndAdjustNationTotals_Impl)(resourceIndex);
}

static __inline void RelationManager_RefreshSlot80(void* relationManager) {
  static_cast<TRelationManager*>(relationManager)->Refresh80();
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
    TPtrList* ownerView = static_cast<TPtrList*>(owner);
    *reinterpret_cast<void**>(ownerView) = reinterpret_cast<void*>(kAddrVtblRefCountedObjectBase);
    new (&ownerView->listState) CPtrList(0);
    *reinterpret_cast<void**>(ownerView) = reinterpret_cast<void*>(kAddrVtblTArmyBattle);
  }
  return owner;
}

static __inline void* AllocateBattleListOwnerWithLinkedSentinel(void) {
  void* owner = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x20));
  if (owner != 0) {
    TPtrList* ownerView = static_cast<TPtrList*>(owner);
    reinterpret_cast<void(__fastcall*)(void*, int)>(
        WrapperFor_InitializeLinkedListSentinelNodeWithOwnerContext_At004a8640)(
        static_cast<void*>(&ownerView->listState), 0);
    *reinterpret_cast<void**>(ownerView) = reinterpret_cast<void*>(kAddrVtblTArmyBattle);
  }
  return owner;
}

static __inline bool IsQuarterlyLocalizationGateOpen(void) {
  TLocalizationRuntime* localizationTable = ReadLocalizationRuntimeView();
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

static const int kMapNodeCount = 0x180;
static const int kPortZoneCount = 0x70;
static const int kAidAllocationRowCount = 0x10;
static const int kAidAllocationColumnCount = 0x17;
static const int kMajorNationCount = 7;
static const int kDiplomacyTrackedSlotCount = 0x11;

static __inline void InitializeAndReleaseSharedMessageRefs(void) {
  CString messageRef;
  CString scratchRef;
}

struct SharedRefPairScope {
  CString first;
  CString second;

  SharedRefPairScope() {}

  ~SharedRefPairScope() {}
};

static __inline void InitializeThreeSharedRefs(CString* firstRef, CString* secondRef,
                                               CString* thirdRef) {}

static __inline void ReleaseThreeSharedRefs(CString* firstRef, CString* secondRef,
                                            CString* thirdRef) {
  thirdRef->~CString();
  secondRef->~CString();
  firstRef->~CString();
}

struct SharedRefTripleScope {
  CString first;
  CString second;
  CString third;

  SharedRefTripleScope() {}

  ~SharedRefTripleScope() {}
};

static __inline void
MapActionContext_AssignDisplayRefFromSlot2C(TMapActionContextListEntryView* entry, int* outRef) {
  VCall_MapActionContext_AssignDisplayRefFromSlot2C(entry, outRef);
}

static __inline char SecondaryState_HasNationFlag5C(void* secondaryState, int nationSlot) {
  return static_cast<TMinor*>(secondaryState)->HasMinorStandingLinkSlot5C(nationSlot);
}

static __inline void SecondaryState_SetPolicyValue48(void* secondaryState, int targetNationSlot,
                                                     int policyValue) {
  static_cast<TMinor*>(secondaryState)
      ->SetDiplomacyStandingSlot48(targetNationSlot, policyValue);
}

static __inline void SecondaryState_CallSlot4C(void* secondaryState, int sourceNation,
                                               int modeValue) {
  static_cast<TMinor*>(secondaryState)
      ->VTableSlot4C_Provisional(sourceNation, modeValue);
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

static __inline TPortZoneContextVectorView* FindFirstPortZoneContextByNation(short nationSlot) {
  return reinterpret_cast<TPortZoneContextVectorView*(__cdecl*)(short)>(
      thunk_FindFirstPortZoneContextByNation)(nationSlot);
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
  reinterpret_cast<TMessageObject*>(message)->AppendWordSlot78(data);
}

static __inline void Message_AppendBytesSlot78(void* message, const void* data, int sizeBytes) {
  reinterpret_cast<TMessageObject*>(message)->AppendBytesSlot7C(data, sizeBytes);
}

static __inline void Message_WriteEntrySlotB4(void* message, int value, int flags) {
  reinterpret_cast<TMessageObject*>(message)->WriteEntrySlotB4(value, flags);
}

static __inline void Queue_ApplyMessageSlot14(void* queue, void* message) {
  reinterpret_cast<TQueueObject*>(queue)->ApplyMessageSlot14(message);
}

static __inline void Queue_RefreshSlot48(void* queue) {
  reinterpret_cast<TQueueObject*>(queue)->RefreshSlot48();
}

static __inline int Queue_ReadIndexSlot4C(void* queue, int mode, int index) {
  return reinterpret_cast<TQueueObject*>(queue)->ReadIndexSlot4C(mode, index);
}

static __inline void* List_GetNodeByOrdinalSlot2C(void* list, int mode, int ordinal) {
  return reinterpret_cast<TListObject*>(list)->GetNodeByOrdinalSlot2C(mode, ordinal);
}

static __inline void List_ReleaseSlot24(void* list) {
  reinterpret_cast<TListObject*>(list)->ReleaseSlot24();
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
bool TGreatPower::thunk_ExecuteAdvisoryPromptAndApplyActionType1_At00403c15(int arg1, int arg2) {
  return this->ExecuteAdvisoryPromptAndApplyActionType1(arg1, arg2);
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
  this->TGreatPower::ClearDiplomacyState1c6Block();
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
void TGreatPower::ApplyDiplomacyRelationCodeAndNotifyThirdPartySlot284(int nationSlot,
                                                                      int policyCode,
                                                                      int targetNation) {
  QueueWarTransitionAndNotifyThirdPartyIfNeeded(nationSlot, policyCode, targetNation);
}
#if defined(_MSC_VER)
#pragma optimize("", on)
#endif

// FUNCTION: IMPERIALISM 0x004070e5
void TGreatPower::thunk_ApplyDiplomacyPolicyStateForTargetWithCostChecks_At004070e5(int arg1,
                                                                                    int arg2) {
  this->TGreatPower::ApplyDiplomacyPolicyStateForTargetWithCostChecks(arg1, arg2);
}

#pragma optimize("y", on)

// FUNCTION: IMPERIALISM 0x00407392
void TGreatPower::thunk_ApplyIndexedResourceDeltaAndAdjustNationTotals_At00407392(int arg1,
                                                                                  int arg2,
                                                                                  int arg3) {
  this->TGreatPower::ApplyIndexedResourceDeltaAndAdjustNationTotals(arg1, arg2, arg3);
}
#pragma optimize("", on)

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
void TGreatPower::DeleteSelfSlot01_Provisional(int freeSelfFlag) {
  this->identitySharedString0.~CString();
  this->identitySharedString1.~CString();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull(reinterpret_cast<undefined4>(this));
  }
}

// FUNCTION: IMPERIALISM 0x00408620
void TGreatPower::thunk_ConstructTurnOrderNavigationWindowEntryViewportAdaptive(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x0040862a
void TGreatPower::thunk_ApplyImmediateDiplomacyPolicySideEffects_At0040862a(int arg1, int arg2) {
  NotifyActionSlot94(arg1, arg2);
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

// FUNCTION: IMPERIALISM 0x004d89f0
TGreatPower::TGreatPower()
    : identitySharedString0(),
      identitySharedString1(),
      nationSlot(0),
      encodedNationSlot(0),
      treasuryValue10(0),
      field42(0),
      pad_44_ptr(0),
      ownerNationSlot(0),
      ownedRegionList(0),
      foreignMinister(0),
      interiorMinister(0),
      defenseMinister(0),
      diplomacyEligibilityA0(0),
      diplomacyCounterA2(0),
      tradeCapacity(0),
      needCapA6(0),
      needsOverCapFlag(0),
      grantTotalCost(0),
      diplomacyCounterB0(0),
      budgetPoolBase(0),
      budgetPoolDelta(0),
      turnEventQueue(0),
      proposalQueue(0),
      relationManager(0),
      townMarkerList(0),
      trackedObjectList(0),
      scenarioInitFlag(0),
      diplomacyBudgetBase(0),
      escalationCounter(0),
      pendingCommitmentCost(0),
      pressureCounter(0),
      field900(0),
      turnSummaryQueue(0),
      missionNodeQueue(0),
      field910(0),
      aidAllocationTotal(0),
      pendingAidTotal(0),
      missionQueue(0) {
  int localeIndex = 0;
  if (g_pLocalizationTable != 0) {
    localeIndex =
        *reinterpret_cast<int*>(reinterpret_cast<unsigned char*>(g_pLocalizationTable) + 0x40);
  }
  this->diplomacyBudgetBase =
      *reinterpret_cast<int*>(kAddrNationBasePressureByLocale + localeIndex * 4) * 100;
  this->escalationCounter =
      *reinterpret_cast<unsigned char*>(0x006534C8 + static_cast<unsigned int>(localeIndex) * 4);

  int nationIndex = 0;
  do {
    this->needLevelByNation[nationIndex] = 0;
    this->diplomacyPolicyByNation[nationIndex] = 0;
    this->diplomacyGrantByNation[nationIndex] = 0;
    this->needCurrentByType[nationIndex] = 0;
    this->needTargetByType[nationIndex] = 0;
    this->relationDeltaCurrent[nationIndex] = 0;
    this->relationDeltaSnapshot[nationIndex] = 0;
    this->diplomacyState1c6[nationIndex] = 0;
    this->diplomacyState1f4[nationIndex] = 0;
    this->diplomacyState222[nationIndex] = 0;
    this->diplomacyState250[nationIndex] = 0;
    this->colonyBoycottFlags[nationIndex] = 0;
    int matrixRow = 0;
    do {
      this->aidAllocationMatrix[nationIndex + matrixRow * 0x17] = 0;
      ++matrixRow;
    } while (matrixRow < 0x10);
    ++nationIndex;
  } while (nationIndex < 0x17);

  int pendingIndex = 0;
  do {
    this->serializedStatusFlags[pendingIndex] = 0;
    this->field8d6[pendingIndex] = -1;
    ++pendingIndex;
  } while (pendingIndex < 0x0D);

  int trackedIndex = 0;
  while (trackedIndex < kDiplomacyTrackedSlotCount) {
    this->diplomacyTrackedSlots[trackedIndex] = 0;
    ++trackedIndex;
  }
}

TGreatPower::TGreatPower(int arg1, int arg2) {
  InitializeNationStateRuntimeSubsystems(arg1, arg2);
}

static void ReleaseOwnedGreatPowerMemberPointers(TGreatPower* self) {
  ReleaseAndClear1C(&self->relationManager);
  ReleaseAndClear24(&self->turnEventQueue);
  ReleaseAndClear24(&self->proposalQueue);
  ReleaseAndClear1C(&self->foreignMinister);
  ReleaseAndClear1C(&self->interiorMinister);
  ReleaseAndClear1C(&self->defenseMinister);
  TQueueObject** trackedSlots = self->diplomacyTrackedSlots;
  int trackedSlotCount = 0x11;
  do {
    if (*trackedSlots != 0) {
      (*trackedSlots)->Call24();
    }
    *trackedSlots = 0;
    ++trackedSlots;
    trackedSlotCount = trackedSlotCount + -1;
  } while (trackedSlotCount != 0);
  ReleaseAndClear58(&self->townMarkerList);
  ReleaseAndClear58(&self->trackedObjectList);
  ReleaseAndClear24(&self->turnSummaryQueue);
  ReleaseAndClear58(&self->missionNodeQueue);
  ReleaseAndClear58(&self->pad_44_ptr);
  if (self->ownedRegionList != 0) {
    self->ownedRegionList->Call38();
    self->ownedRegionList = 0;
  }
}

TGreatPower::~TGreatPower() {
  ReleaseOwnedGreatPowerMemberPointers(this);
}

struct TRecruitmentDeltaContextView {
  unsigned char pad_00[0x04];
  short pendingDelta;
  unsigned char pad_06[0x08 - 0x06];
  void* cityContext;
  unsigned char pad_0c[0x48 - 0x0c];
  short entryId;
  unsigned char pad_4a[0x58 - 0x4a];
  unsigned char specialistMode;
};

// FUNCTION: IMPERIALISM 0x004b73b0
void TGreatPower::CommitCityRecruitmentOrderDelta(void) {
  /* Commits pending university/city recruitment delta into persistent city/nation state.
     Algorithm:
     1. Read pending delta count from context field +0x04; return if zero.
     2. Branch on specialist mode flag (+0x58): civilian branch vs specialist branch.
     3. Civilian branch: add pending count into city recruitment queue slot (city +0x4A[entryId])
     and spawn per-unit civilian order objects.
     4. Specialist branch: spawn military recruit order objects and apply nation progression gate
     updates for unlock tiers.
     5. Emit nation notification callback (+0x2C0) with mode 2 (civilian) or 3 (specialist).
     6. Clear pending delta (+0x04) after commit.
     7. For entryId==0, increment city counter at city+0x0A.
     Parameters:
     - this (IMPLICIT): City recruitment order context.
     Returns:
     - None.
     Persistence:
     - Pending delta: context +0x04.
     - Committed queue count: city +0x4A[entryId]. */
  TRecruitmentDeltaContextView* ctx = reinterpret_cast<TRecruitmentDeltaContextView*>(this);
  short pendingDelta = ctx->pendingDelta;
  if (pendingDelta <= 0 || ctx->cityContext == 0) {
    return;
  }

  CString sharedRefA;
  CString sharedRefB;

  TLocalizationRuntime* localization = ReadLocalizationRuntimeView();
  if (localization != 0) {
    localization->CallSlot84((ctx->specialistMode == 0) ? 0x2718 : 0x2717);
  }

  short* cityQueueBase =
      reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(ctx->cityContext) + 0x4A);
  cityQueueBase[ctx->entryId] = static_cast<short>(cityQueueBase[ctx->entryId] + pendingDelta);

  int ownerState =
      *reinterpret_cast<int*>(reinterpret_cast<unsigned char*>(ctx->cityContext) + 0xAC);
  short ownerNationSlot = 0;
  if (ownerState != 0) {
    ownerNationSlot =
        *reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(ownerState) + 0x0C);
  }

  for (short i = 0; i < pendingDelta; ++i) {
    void* orderObject = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x44));
    if (orderObject == 0) {
      continue;
    }
    reinterpret_cast<void(__fastcall*)(void*, int)>(thunk_InitializeCivUnitOrderObject)(orderObject,
                                                                                        0);

    short packedOrderType = static_cast<short>(ctx->entryId);
    reinterpret_cast<TCivWorkOrderState*>(orderObject)
        ->InitializeCivWorkOrderState(packedOrderType, i, ownerNationSlot);
  }

  ctx->pendingDelta = 0;
}

// FUNCTION: IMPERIALISM 0x004d7ae0
#pragma optimize("y", on)
void TGreatPower::AddToNationMetricAtField10(int amount) {
  this->treasuryValue10 += amount;
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004d8950
void* __cdecl TGreatPower::CreateTGreatPowerInstance(void) {
  void* instance = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x964));
  if (instance == 0) {
    return 0;
  }

  new (instance) TGreatPower();
  return instance;
}

// FUNCTION: IMPERIALISM 0x004d89d0
void* __cdecl TGreatPower::GetTGreatPowerClassNamePointer(void) {
  return reinterpret_cast<void*>(kAddrClassDescTGreatPower);
}

// FUNCTION: IMPERIALISM 0x004d8c00
short TGreatPower::GetDiplomacyCounterA2(void) {
  return this->diplomacyCounterA2;
}

// FUNCTION: IMPERIALISM 0x004d8cc0
void TGreatPower::InitializeNationStateRuntimeSubsystems(int arg1, int arg2) {
  reinterpret_cast<void(__fastcall*)(int, int)>(
      thunk_InitializeNationStateIdentityAndOwnedRegionList)(reinterpret_cast<int>(this), arg1);

  TLocalizationRuntime* localizationRuntime = ReadLocalizationRuntimeView();
  if (localizationRuntime != 0) {
    int runtimeIndex = localizationRuntime->runtimeSubsystemIndex;
    this->treasuryValue10 = ReadGlobalIntStep(kAddrNationRuntimeSubsystemCache, runtimeIndex);
  } else {
    this->treasuryValue10 = 0;
  }

  this->diplomacyEligibilityA0 = (static_cast<short>(arg2) == 1) ? 1 : 0;

  void* cityModel = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x20));
  if (cityModel != 0) {
    reinterpret_cast<void(__fastcall*)(void*, int)>(thunk_InitializeCityModel)(cityModel, 0);
    reinterpret_cast<void(__fastcall*)(int, int)>(thunk_InitializeCityProductionState)(
        reinterpret_cast<int>(cityModel), arg1);
  }
  this->relationManager = static_cast<TRelationManager*>(cityModel);

  void* townMarkerListOwner = AllocateBattleListOwnerWithLinkedSentinel();
  this->townMarkerList = static_cast<TListObject*>(townMarkerListOwner);

  this->grantTotalCost = 0;
  this->needCapA6 = 0x0F;
  this->field900 = 0x0F;

  void* turnEventQueue = AllocateObArrayWithMode(4);
  this->turnEventQueue = static_cast<TQueueObject*>(turnEventQueue);

  void* proposalQueue = AllocateObArrayWithMode(4);
  this->proposalQueue = static_cast<TQueueObject*>(proposalQueue);

  if (this->diplomacyEligibilityA0 != 0) {
    void* foreignMinister = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x20));
    if (foreignMinister != 0) {
      reinterpret_cast<void(__fastcall*)(void*, int)>(thunk_ConstructTForeignMinister)(
          foreignMinister, 0);
    }
    reinterpret_cast<void(__cdecl*)(void)>(thunk_InitializeTForeignMinisterStateAndCounters)();
    this->foreignMinister = static_cast<TMinister*>(foreignMinister);

    void* interiorMinister = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x20));
    if (interiorMinister != 0) {
      reinterpret_cast<void(__fastcall*)(void*, int)>(
          thunk_WrapperFor_thunk_ConstructTMinister_At004be840)(interiorMinister, 0);
    }
    reinterpret_cast<void(__cdecl*)(void)>(thunk_InitializeCityInteriorMinister)();
    this->interiorMinister = static_cast<TMinister*>(interiorMinister);

    void* defenseMinister = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x20));
    if (defenseMinister != 0) {
      defenseMinister = reinterpret_cast<void*(__fastcall*)(void*, int)>(
          thunk_ConstructTDefenseMinisterBaseState)(defenseMinister, 0);
    }
    reinterpret_cast<void(__cdecl*)(void)>(thunk_InitializeTMinisterBaseOrderArrayMetrics)();
    this->defenseMinister = static_cast<TMinister*>(defenseMinister);
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
  if (this->relationManager != 0) {
    this->relationManager->Call1C();
  }
  this->relationManager = 0;
  if (this->turnEventQueue != 0) {
    this->turnEventQueue->Call24();
  }
  this->turnEventQueue = 0;
  if (this->proposalQueue != 0) {
    this->proposalQueue->Call24();
  }
  this->proposalQueue = 0;
  if (this->foreignMinister != 0) {
    this->foreignMinister->Call1C();
  }
  this->foreignMinister = 0;
  if (this->interiorMinister != 0) {
    this->interiorMinister->Call1C();
  }
  this->interiorMinister = 0;
  if (this->defenseMinister != 0) {
    this->defenseMinister->Call1C();
  }
  this->defenseMinister = 0;
  TQueueObject** trackedSlots = this->diplomacyTrackedSlots;
  int trackedSlotCount = 0x11;
  do {
    if (*trackedSlots != 0) {
      (*trackedSlots)->Call24();
    }
    *trackedSlots = 0;
    ++trackedSlots;
    trackedSlotCount = trackedSlotCount + -1;
  } while (trackedSlotCount != 0);
  if (this->townMarkerList != 0) {
    this->townMarkerList->Call58();
  }
  this->townMarkerList = 0;
  if (this->trackedObjectList != 0) {
    this->trackedObjectList->Call58();
  }
  this->trackedObjectList = 0;
  {
    TQueueObject** turnSummarySlot =
        reinterpret_cast<TQueueObject**>(reinterpret_cast<unsigned char*>(this) + 0x908);
    if (*turnSummarySlot != 0) {
      (*turnSummarySlot)->Call24();
    }
    *turnSummarySlot = 0;
  }
  {
    TListObject** missionNodeSlot =
        reinterpret_cast<TListObject**>(reinterpret_cast<unsigned char*>(this) + 0x90c);
    if (*missionNodeSlot != 0) {
      (*missionNodeSlot)->Call58();
    }
    *missionNodeSlot = 0;
  }
  if (this->pad_44_ptr != 0) {
    this->pad_44_ptr->Call58();
  }
  this->pad_44_ptr = 0;
  if (this->ownedRegionList != 0) {
    this->ownedRegionList->Call38();
    this->ownedRegionList = 0;
  }
  if (this != 0) {
    this->DeleteSelfSlot01_Provisional(1);
  }
}

// FUNCTION: IMPERIALISM 0x004d92e0
void TGreatPower::InitializeGreatPowerMinisterRosterAndScenarioState(int arg1) {
  reinterpret_cast<void(__fastcall*)(void*, int, int)>(
      thunk_DeserializeRecruitScenarioAndInstantiateOrders_At00409089)(this, 0, arg1);

  void* stream = reinterpret_cast<void*>(arg1);
  Stream_ReadAtSlot3C(stream, &this->diplomacyEligibilityA0, 1);
  Stream_ReadAtSlot3C(stream, &this->diplomacyCounterA2, 2);
  Stream_ReadAtSlot3C(stream, &this->tradeCapacity, 2);
  Stream_ReadAtSlot3C(stream, &this->needCapA6, 2);
  Stream_ReadAtSlot3C(stream, &this->needsOverCapFlag, 2);
  if (*reinterpret_cast<int*>(kAddrAdvanceTurnMachineState) < 0x3E) {
    Stream_ReadAtSlot3C(stream, &this->grantTotalCost, 2);
  } else {
    Stream_ReadAtSlot3C(stream, &this->grantTotalCost, 4);
  }
  Stream_ReadAtSlot3C(stream, &this->diplomacyCounterB0, 2);
  Stream_ReadAtSlot3C(stream, this->diplomacyPolicyByNation, 0x2E);
  SwapShortArrayBytes(this->diplomacyPolicyByNation, kNationSlotCount);
  Stream_ReadAtSlot3C(stream, this->diplomacyGrantByNation, 0x2E);
  SwapShortArrayBytes(this->diplomacyGrantByNation, kNationSlotCount);
  Stream_ReadAtSlot3C(stream, this->needCurrentByType, 0x2E);
  SwapShortArrayBytes(this->needCurrentByType, kNationSlotCount);
  Stream_ReadAtSlot3C(stream, this->needTargetByType, 0x2E);
  SwapShortArrayBytes(this->needTargetByType, kNationSlotCount);
  Stream_ReadAtSlot3C(stream, this->relationDeltaCurrent, 0x2E);
  SwapShortArrayBytes(this->relationDeltaCurrent, kNationSlotCount);
  Stream_ReadAtSlot3C(stream, this->relationDeltaSnapshot, 0x2E);
  SwapShortArrayBytes(this->relationDeltaSnapshot, kNationSlotCount);
  Stream_ReadAtSlot3C(stream, this->diplomacyState1c6, 0x2E);
  SwapShortArrayBytes(this->diplomacyState1c6, kNationSlotCount);

  if (*reinterpret_cast<int*>(kAddrAdvanceTurnMachineState) > 0x16) {
    Stream_ReadAtSlot3C(stream, this->diplomacyState1f4, 0x2E);
    SwapShortArrayBytes(this->diplomacyState1f4, kNationSlotCount);
  }

  Stream_ReadAtSlot3C(stream, this->diplomacyState222, 0x2E);
  SwapShortArrayBytes(this->diplomacyState222, kNationSlotCount);
  Stream_ReadAtSlot3C(stream, this->diplomacyState250, 0x2E);
  SwapShortArrayBytes(this->diplomacyState250, kNationSlotCount);

  Stream_ReadAtSlot3C(stream, &this->budgetPoolBase, 4);
  Stream_ReadAtSlot3C(stream, &this->budgetPoolDelta, 4);
  Stream_ReadAtSlot3C(stream, this->aidAllocationMatrix, 0x5C0);
  ReverseDwordArrayBytes(this->aidAllocationMatrix, 0x170);

  Stream_ReadAtSlot3C(stream, this->serializedStatusFlags, 0x0D);
  Stream_ReadAtSlot3C(stream, this->field8d6, 0x1A);
  SwapShortArrayBytes(this->field8d6, 0x0D);

  this->turnEventQueue->Call18();
  this->proposalQueue->Call18();
  int listIndex = 0;
  while (listIndex < kDiplomacyTrackedSlotCount) {
    this->diplomacyTrackedSlots[listIndex]->Call18();
    ++listIndex;
  }

  if (*reinterpret_cast<int*>(kAddrAdvanceTurnMachineState) < 0x1D) {
    if (this->encodedNationSlot == -1) {
      char gate = this->ShouldDispatchImmediatelySlot28_Provisional();
      if (gate == 0) {
        this->foreignMinister->Call18();
        this->interiorMinister->Call18();
        this->defenseMinister->Call18();
      }
      this->relationManager->Call18();
    } else {
      ReleaseAndClear1C(&this->foreignMinister);
      ReleaseAndClear1C(&this->interiorMinister);
      ReleaseAndClear1C(&this->defenseMinister);
      ReleaseAndClear1C(&this->relationManager);
    }
  } else {
    int ministerMask = Stream_ReadIntAtSlot40(stream);

    if ((ministerMask & 1) == 0) {
      ReleaseAndClear1C(&this->foreignMinister);
    } else {
      void* foreignMinister = this->foreignMinister;
      if (foreignMinister == 0) {
        foreignMinister = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x20));
        if (foreignMinister != 0) {
          reinterpret_cast<void(__fastcall*)(void*, int)>(thunk_ConstructTForeignMinister)(
              foreignMinister, 0);
        }
        this->foreignMinister = static_cast<TMinister*>(foreignMinister);
        reinterpret_cast<void(__cdecl*)(void)>(thunk_InitializeTForeignMinisterStateAndCounters)();
      }
      if (foreignMinister != 0) {
        static_cast<TMinister*>(foreignMinister)->Call18();
      }
    }

    if ((ministerMask & 2) == 0) {
      ReleaseAndClear1C(&this->interiorMinister);
    } else {
      void* interiorMinister = this->interiorMinister;
      if (interiorMinister == 0) {
        interiorMinister = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x20));
        if (interiorMinister != 0) {
          reinterpret_cast<void(__fastcall*)(void*, int)>(
              thunk_WrapperFor_thunk_ConstructTMinister_At004be840)(interiorMinister, 0);
        }
        reinterpret_cast<void(__cdecl*)(void)>(thunk_InitializeCityInteriorMinister)();
        this->interiorMinister = static_cast<TMinister*>(interiorMinister);
      }
      if (interiorMinister != 0) {
        static_cast<TMinister*>(interiorMinister)->Call18();
      }
    }

    if ((ministerMask & 4) == 0) {
      ReleaseAndClear1C(&this->defenseMinister);
    } else {
      void* defenseMinister = this->defenseMinister;
      if (defenseMinister == 0) {
        defenseMinister = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x20));
        if (defenseMinister != 0) {
          defenseMinister = reinterpret_cast<void*(__fastcall*)(void*, int)>(
              thunk_ConstructTDefenseMinisterBaseState)(defenseMinister, 0);
        }
        reinterpret_cast<void(__cdecl*)(void)>(thunk_InitializeTMinisterBaseOrderArrayMetrics)();
        this->defenseMinister = static_cast<TMinister*>(defenseMinister);
      }
      if (defenseMinister != 0) {
        static_cast<TMinister*>(defenseMinister)->Call18();
      }
    }

    if ((ministerMask & 8) == 0) {
      ReleaseAndClear1C(&this->relationManager);
    } else {
      void* relationManager = this->relationManager;
      if (relationManager != 0) {
        static_cast<TRelationManager*>(relationManager)->Call18();
      }
    }
  }

  void* townMarkerList = this->townMarkerList;
  int hasItems = static_cast<TListObject*>(townMarkerList)->GetCountSlot48();
  if (hasItems != 0) {
    static_cast<TListObject*>(townMarkerList)->Call54();
  }
  static_cast<TListObject*>(townMarkerList)->Call18();

  int townCount = 0;
  Stream_ReadAtSlot3C(stream, &townCount, 4);

  if (townCount > 0) {
    int townOrdinal = 1;
    while (townOrdinal <= townCount) {
      void* townMarker = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x20));
      if (townMarker != 0) {
        reinterpret_cast<void(__fastcall*)(void*, int)>(thunk_ConstructFrogCityMarker)(townMarker,
                                                                                       0);
        static_cast<TListObject*>(townMarker)->Call18();
        static_cast<TListObject*>(townMarkerList)->AddTail30(townMarker);
      }
      ++townOrdinal;
    }
  }

  if (townCount > 0) {
    static_cast<TListObject*>(townMarkerList)->GetTrackedEntrySlot4C();
    this->relationManager->Call44();
  }

  void* trackedObjectList = this->trackedObjectList;
  hasItems = static_cast<TListObject*>(trackedObjectList)->GetCountSlot48();
  if (hasItems != 0) {
    static_cast<TListObject*>(trackedObjectList)->Call54();
  }
  static_cast<TListObject*>(trackedObjectList)->Call18();

  int unusedOrderCount = 0;
  Stream_ReadAtSlot3C(stream, &unusedOrderCount, 4);

  int orderOrdinal = 1;
  while (orderOrdinal < 5) {
    void* civOrderObj = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x20));
    if (civOrderObj != 0) {
      reinterpret_cast<void(__fastcall*)(void*, int)>(thunk_InitializeCivUnitOrderObject)(
          civOrderObj, 0);
      static_cast<TCivWorkOrderState*>(civOrderObj)
          ->thunk_InitializeCivWorkOrderState(0, -1, this->nationSlot);
      static_cast<TListObject*>(civOrderObj)->Call18();
    }
    ++orderOrdinal;
  }

  Stream_ReadRawAtSlot00(stream, &this->diplomacyBudgetBase, 4);
  Stream_ReadRawAtSlot00(stream, &this->escalationCounter, 1);
  Stream_ReadRawAtSlot00(stream, &this->pendingCommitmentCost, 4);
  Stream_ReadRawAtSlot00(stream, &this->pressureCounter, 1);
  Stream_ReadRawAtSlot00(stream, &this->field900, 4);
  Stream_ReadRawAtSlot00(stream, &this->field904, 1);

  if (*reinterpret_cast<int*>(kAddrAdvanceTurnMachineState) > 0x0E) {
    void* missionNodeQueue = this->missionNodeQueue;
    static_cast<TListObject*>(missionNodeQueue)->Call18(arg1);

    int nodeCount = 0;
    Stream_ReadRawAtSlot00(stream, &nodeCount, 4);
    if (nodeCount > 0) {
      int nodeOrdinal = 1;
      while (nodeOrdinal <= nodeCount) {
        unsigned char hasNode = 0;
        char markerOk = Stream_ReadByteAtSlotB0(stream, &hasNode);
        if (markerOk != 0) {
          static_cast<TListObject*>(missionNodeQueue)->AddTail30(0);
        }
        ++nodeOrdinal;
      }
    }
  }

  if (*reinterpret_cast<int*>(kAddrAdvanceTurnMachineState) > 0x25) {
    Stream_ReadRawAtSlot00(stream, &this->field910, 4);
    Stream_ReadRawAtSlot00(stream, &this->aidAllocationTotal, 4);
  }
  if (*reinterpret_cast<int*>(kAddrAdvanceTurnMachineState) > 0x2F) {
    Stream_ReadRawAtSlot00(stream, this->colonyBoycottFlags, kNationSlotCount);
  }
  if (*reinterpret_cast<int*>(kAddrAdvanceTurnMachineState) > 0x34) {
    Stream_ReadRawAtSlot00(stream, &this->pendingAidTotal, 4);
  }
}

// FUNCTION: IMPERIALISM 0x004daa10
#pragma optimize("y", on)
void TGreatPower::SetNationPendingActionStateAndPayload(int index, short payload) {
  if (*reinterpret_cast<int*>(kAddrAdvanceTurnMachineState) != -3) {
    this->serializedStatusFlags[index] = 0x32;
    this->field8d6[index] = payload;
  }
}
#pragma optimize("", on)

// Updates Great Power pressure/escalation state and propagates summary messages when thresholds
// cross.

// --- ExecuteNationPendingActionStateMachine (slot 0x32) order-object factories ---
//
// The civ order is now a real class (see new TCivWorkOrderState() below). The
// land/navy order objects stay on isolated __fastcall bridges (Hard Rule allowance)
// because their ctors embed a CString member whose non-trivial ~CString is what
// emits the EH frame + uStack_4 state markers — matching that requires CString to
// have a real C++ default ctor at 0x605797, but CString models its ctors as named
// methods (InitFromEmpty etc.) called explicitly at ~781 sites, so one address
// cannot be both. The military/navy EH ctors are therefore blocked behind a
// CString real-ctor refactor (heuristic 91); keep the bridges until then.

// new(0x44) + military land-unit recruit-order ctor (0x005c2df0). Embeds a CString
// member at +0x24 -> EH-framed ctor; blocked on the CString real-ctor lever.
static __inline void* AllocateMilitaryUnitOrderObject(void) {
  void* obj = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x44));
  if (obj != 0) {
    obj = reinterpret_cast<void*(__fastcall*)(void*)>(thunk_InitializeMilitaryUnitOrderObject)(obj);
  }
  return obj;
}

// Recruit-order initializer (0x005c2f50): thiscall(obj, capValue, nodeContext, nationSlot, 0).
static __inline void InitializeMilitaryRecruitOrder(void* obj, short capValue, int nodeContext,
                                                    short nationSlot) {
  reinterpret_cast<void(__fastcall*)(void*, int, int, int, int)>(
      thunk_InitializeMilitaryRecruitOrderState)(obj, capValue, nodeContext, nationSlot, 0);
}

// g_pCityOrderCapabilityState accessors (read-only data table, not a class region).
static __inline short CityOrderCapForNation(short nationSlot) {
  return *reinterpret_cast<short*>(reinterpret_cast<char*>(g_pCityOrderCapabilityState) +
                                   nationSlot * 0x14 + 0x1e8);
}
static __inline short CityOrderActiveZoneIndex(void) {
  return *reinterpret_cast<short*>(reinterpret_cast<char*>(g_pCityOrderCapabilityState) + 0x1d4);
}

// Per-zone recruit/secondary order counters on the relation-manager object (+0x894).
struct TRelationManagerOrderCountView {
  unsigned char pad00[0x5c];
  short recruitZoneCount5c[6]; // 0x5c..0x68, indexed by active zone
  short navySecondaryCount68;  // 0x68
};

// FUNCTION: IMPERIALISM 0x004dab20
#pragma optimize("y", on)
void TGreatPower::ExecuteNationPendingActionStateMachine(void) {
  void* relationManager =
      reinterpret_cast<TGreatPowerDiplomacyExternalStateView*>(this)->diplomacyExternalState894;
  static_cast<TRelationManager*>(relationManager)->RefreshOrderStateSlot0C();

  short nationSlot = this->nationSlot;

  // Land recruit order (serializedStatusFlags[1] == '2').
  if (this->serializedStatusFlags[1] == 0x32) {
    void* militaryOrder = AllocateMilitaryUnitOrderObject();
    int nodeContext = this->GetNodeContextSlot10_Provisional();
    InitializeMilitaryRecruitOrder(militaryOrder, CityOrderCapForNation(nationSlot), nodeContext,
                                   nationSlot);
    this->DispatchTurnOrderActionSlotB0(3, CityOrderCapForNation(nationSlot), 1);
  }

  // Navy primary/secondary order (serializedStatusFlags[0] == '2').
  if (this->serializedStatusFlags[0] == 0x32) {
    short zoneIndex = CityOrderActiveZoneIndex();
    void* portZone = reinterpret_cast<void*(__fastcall*)(void*, int, int, int)>(
        thunk_FindFirstPortZoneContextByNation)(g_pActiveMapOrderContext, nationSlot, nationSlot,
                                                0);
    reinterpret_cast<void*(__cdecl*)(int, void*, int, int)>(
        thunk_CreateNavyPrimaryOrderNodeAndAssignDisplayName)(zoneIndex, portZone, nationSlot, 0);

    TRelationManagerOrderCountView* orderCounts =
        static_cast<TRelationManagerOrderCountView*>(relationManager);
    ++orderCounts->recruitZoneCount5c[CityOrderActiveZoneIndex()];

    void* secondaryNode = new TAdmiral(nationSlot);
    reinterpret_cast<void(__fastcall*)(void*)>(
        thunk_SetTaskForcePrimaryOrderLinkAndRefreshChildBacklinks)(secondaryNode);

    this->DispatchTurnOrderActionSlotB0(3, 0x2508, 1);
    this->DispatchTurnOrderActionSlotB0(0, CityOrderActiveZoneIndex(), 1);
  }

  // Civil work order (serializedStatusFlags[2] < '3').
  if (this->serializedStatusFlags[2] < 0x33) {
    bool needsCivOrder = false;
    void** minorNationEntry = g_apMinorNationCapabilityObjects;
    short zoneCursor = 7;
    do {
      if (*reinterpret_cast<short*>(reinterpret_cast<char*>(g_pDiplomacyTurnStateManager) +
                                    (zoneCursor + nationSlot * 0x17) * 2 + 0x79c) > 0xa9) {
        void* entry = *minorNationEntry;
        short matchTag;
        if (entry != 0 &&
            (matchTag = *reinterpret_cast<short*>(reinterpret_cast<char*>(entry) + 0xe)) > 99 &&
            matchTag < 200) {
          if (matchTag < 200) {
            if (matchTag < 100) {
              matchTag = *reinterpret_cast<short*>(reinterpret_cast<char*>(entry) + 0xc);
            } else {
              matchTag = matchTag - 100;
            }
          } else {
            matchTag = matchTag - 200;
          }
          if (matchTag == nationSlot) {
            goto nextEntry;
          }
        }
        needsCivOrder = true;
      }
    nextEntry:
      ++minorNationEntry;
      ++zoneCursor;
    } while (minorNationEntry <= &g_apMinorNationCapabilityObjects[15]);

    if (needsCivOrder) {
      TCivWorkOrderState* civOrder = new TCivWorkOrderState();
      int spawnTile = reinterpret_cast<int(__fastcall*)(void*, int, int, int)>(
          thunk_FindReachableRecruitSpawnTileWithVisitedReset)(
          g_pGlobalMapState, this->ownerNationSlot, 0, nationSlot);
      civOrder->thunk_InitializeCivWorkOrderState(7, spawnTile, nationSlot);
      this->SetNationPendingActionStateAndPayload(2, -1);
    }
  }

  // Final pending-action flush (serializedStatusFlags[0x0a] == '2').
  if (this->serializedStatusFlags[0x0a] == 0x32) {
    static_cast<TRelationManagerOrderCountView*>(relationManager)->navySecondaryCount68 += 2;
    this->DispatchTurnOrderActionSlotB0(1, 6, 2);
  }
  this->VTableIndex15_Provisional();
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004daf30
void TGreatPower::CompileGreatPowerRelationshipDeltaLinesAndDispatchMessage(void) {
  static const short kNationPriorityOrder[] = {0x0F, 0x0E, 0x0D, 0x10, 0x0C, 0x08, 0x0A, 0x09, 0x0B,
                                               0x06, 0x03, 0x04, 0x05, 0x00, 0x01, 0x02, 0x07, -1};

  if (this->ShouldDispatchImmediatelySlot28_Provisional() != 0) {
    return;
  }

  TLocalizationRuntime* localizationRuntime = ReadLocalizationRuntimeView();
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

  CString summaryMessageRef;

  TGreatPowerDiplomacyExternalStateView* diplomacyExternal =
      reinterpret_cast<TGreatPowerDiplomacyExternalStateView*>(this);
  int interactionScore = 0;

  const short* nationCursor = kNationPriorityOrder;
  while (*nationCursor != -1) {
    if (interactionScore + this->treasuryValue10 >= 0) {
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
        interactionScore =
            static_cast<TNationInteractionStateManager*>(nationInteractionState)->QueryInt4C();
      }
    }

    ++nationCursor;
  }

  this->AddToNationMetricAtField10(0);

  if (interactionScore > 0) {
    SharedRefPairScope localizedRefs;
    if (localizationRuntime != 0) {
      localizationRuntime->CallSlot84();
      localizationRuntime->CallSlot84(interactionScore);
    }
    thunk_AssignStringSharedRefAndReturnThis();
    thunk_DispatchLocalizedUiMessageWithTemplateA13A0();
  }
}

// FUNCTION: IMPERIALISM 0x004db380
void TGreatPower::UpdateGreatPowerPressureStateAndDispatchEscalationMessage(void) {
  TGreatPowerPressureUpdateView* pressureView =
      reinterpret_cast<TGreatPowerPressureUpdateView*>(this);
  TLocalizationRuntime* localizationRuntime = ReadLocalizationRuntimeView();
  int localeIndex = 0;
  if (localizationRuntime != 0) {
    localeIndex = localizationRuntime->runtimeSubsystemIndex;
  }

  int treasuryValue10 = this->treasuryValue10;
  int basePressure = this->SumAidAllocationMatrixAllCells();
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

  if (treasuryValue10 < 0) {
    int halfBand = pressureBand / 2;
    if ((-halfBand == treasuryValue10) || (-treasuryValue10 < halfBand)) {
      pressureView->pressureTier8fc = 1;
    } else if ((-pressureBand == treasuryValue10) || (-treasuryValue10 < pressureBand)) {
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
      CString sharedMessageRef;
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
          localizationRuntime->CallSlot84(4);
        }
        thunk_AssignStringSharedRefAndReturnThis();
        thunk_DispatchLocalizedUiMessageWithTemplateA13A0();
        return;
      }

      if (pressureTier < compileThreshold) {
        if (localizationRuntime != 0) {
          int statusId = (pressureTier == (compileThreshold - 1)) ? 3 : 2;
          localizationRuntime->CallSlot84(statusId);
        }
        DispatchQuarterlyGreatPowerPressureMessage(1);
      } else {
        if (localizationRuntime != 0) {
          localizationRuntime->CallSlot84(1);
        }
        DispatchQuarterlyGreatPowerPressureMessage(2);
      }
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

  treasuryValue10 = this->treasuryValue10;
  if (treasuryValue10 >= 0) {
    pressureView->pendingDrain900 = 0;
    return;
  }

  int drainAmount = (0xC7 - static_cast<int>(pressureView->pressureValue8f4) * treasuryValue10) / 200;
  pressureView->pendingDrain900 = drainAmount;
  this->treasuryValue10 = treasuryValue10 - drainAmount;
}

// FUNCTION: IMPERIALISM 0x004dbd20
void TGreatPower::RebuildNationResourceYieldCountersAndDevelopmentTargets(void) {
  const int kMapRegionSlotCount = 0x1950;

  short* currentNeedByType = this->needCurrentByType;
  short* developmentByType = &this->needCurrentByType[7]; // +0x11c overlays this runtime array.
  short* targetNeedByType = this->needTargetByType;
  short& controlledRegionCount = this->needCurrentByType[0x13]; // +0x134
  char* influenceByRegion = thunk_BuildCityInfluenceLevelMap();
  TGlobalMapState* globalMapState = ReadGlobalMapStateScoreView();
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
      this->UpdateNeedTargetAndAccumulateOverCap(typeIndex, currentNeedByType[typeIndex]);
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

    TGlobalMapState* globalMapState = ReadGlobalMapStateScoreView();
    TLocalizationRuntime* localizationRuntime = ReadLocalizationRuntimeView();
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
            this->GetDiplomacyCounterA2();

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
              this->SetNationPendingActionStateAndPayload(4, regionId);
            } else {
              this->SetNationPendingActionStateAndPayload(3, regionId);
              if (this->expansionAlertCounter < 0x33) {
                this->SetNationPendingActionStateAndPayload(8, -1);
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

// FUNCTION: IMPERIALISM 0x004dc3f0
char TGreatPower::AnyNeedCurrentExceedsTargetWhenCapMismatch(void) {
  char result = 0;
  if (this->needCapA6 != this->needsOverCapFlag) {
    short needIndex = 0;
    while (this->needCurrentByType[needIndex] <= this->needTargetByType[needIndex]) {
      ++needIndex;
      if (needIndex > 0x16) {
        return result;
      }
    }
    result = 1;
  }
  return result;
}

// FUNCTION: IMPERIALISM 0x004dc540
char TGreatPower::CompareMissionScoreVariantsByMode(int mode) {
  if (mode == 0) {
    int nodeContext = this->GetNodeContextSlot10_Provisional();
    float localScore = ComputeDefendProvinceMissionLocalSupportScore(nodeContext);
    float crossNationScore = ComputeDefendProvinceMissionCrossNationSupportScore(nodeContext);
    if (localScore < crossNationScore) {
      return 0;
    }
    return 1;
  } else {
    TPortZoneContextVectorView* portZoneContext =
        FindFirstPortZoneContextByNation(this->nationSlot);

    if (portZoneContext->entryCount <= 0) {
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
    if (portZoneContext->activeEntryCount <= 0) {
      portZoneContext->activeEntryCount = 1;
    }

    int firstEntry = portZoneContext->entries[0];

    float exactSourceScore =
        ComputeNavyOrderScoreForExactSourceNation(this->nationSlot, firstEntry);
    float diplomacyFilteredScore =
        ComputeNavyOrderScoreWithDiplomacyFilter(this->nationSlot, firstEntry);
    if (exactSourceScore < diplomacyFilteredScore) {
      return 0;
    }
    return 1;
  }
}

// FUNCTION: IMPERIALISM 0x004dc660
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
    if (g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(nationSlot, this->nationSlot) !=
            0 &&
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
        if (g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(this->nationSlot,
                                                                    nationSlotCandidate) == 0) {
          continue;
        }

        unsigned int nationMask = 1u << (nationSlotCandidate & 0x1f);
        unsigned int selfMask = 1u << (this->nationSlot & 0x1f);
        unsigned int contextMask = contextEntry->nationMask;
        if ((contextMask & nationMask) != 0 && (contextMask & selfMask) == 0) {
          CString contextRef;
          CString messageRef;
          MapActionContext_AssignDisplayRefFromSlot2C(contextEntry,
                                                      reinterpret_cast<int*>(&contextRef));
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

// FUNCTION: IMPERIALISM 0x004dc840
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
    if (g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(nationSlot, this->nationSlot) !=
            0 &&
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

    TNationStateEventMessageFlags* messageFlags =
        static_cast<TNationStateEventMessageFlags*>(nationState);
    if (messageFlags->allowEventMessage4D != 0 && messageFlags->suppressEventMessage4C == 0) {
      CString messageRef;
      CString scratchRef;
      thunk_AssignSharedStringFromIndexedA8EntryNameField();
      scratchRef.AssignConcatCStrAndRef("\n", messageRef);
      AssignStringSharedFromRef(reinterpret_cast<undefined4>(&scratchRef),
                                reinterpret_cast<int*>(&messageRef));
    }
  }
}

// FUNCTION: IMPERIALISM 0x004dc9f0
void TGreatPower::RefreshGreatPowerRelationPanelsAndDispatchDeltaSummary(void) {
  if (this->relationManager == 0) {
    return;
  }

  this->VTableIndex77_Provisional();
  this->VTableIndex78_Provisional();
  this->VTableIndex67_Provisional();
  BuildGreatPowerRelationshipDeltaSummaryAndDispatchMessage();
  this->relationManager->Call28();
  this->VTableIndex42_Provisional();
}

// FUNCTION: IMPERIALISM 0x004dcc50
void TGreatPower::ApplyDiplomacyState222ToRelationManagerAndClear(void) {
  for (short nationSlot = 0; nationSlot < kNationSlotCount; ++nationSlot) {
    this->AddToRelationManagerFieldB6AndRefresh(nationSlot, this->diplomacyState222[nationSlot]);
    this->diplomacyState222[nationSlot] = 0;
  }
}

// FUNCTION: IMPERIALISM 0x004dcca0
void TGreatPower::ApplyRelationDeltaToRelationManagerAndUpdateState1f4(void) {
  for (short nationSlot = 0; nationSlot < kNationSlotCount; ++nationSlot) {
    this->AddToRelationManagerFieldB6AndRefresh(nationSlot, this->relationDeltaCurrent[nationSlot]);
    if (this->diplomacyState250[nationSlot] == -1 && this->relationDeltaCurrent[nationSlot] == 0) {
      this->diplomacyState1f4[nationSlot] =
          static_cast<short>(this->diplomacyState1f4[nationSlot] + 1);
    } else {
      this->diplomacyState1f4[nationSlot] = 0;
    }
    this->relationDeltaCurrent[nationSlot] = 0;
  }
}

// FUNCTION: IMPERIALISM 0x004dcd10
void TGreatPower::ApplyNationResourceNeedTargetsToOrderState(void) {
  this->AddToNationMetricAtField10(static_cast<int>(this->needTargetByType[0x15]) * 500);

  void* relationManager = this->relationManager;
  if (relationManager != 0) {
    RelationManager_ClearNeedSlotE0AndRefresh(relationManager);
  }

  this->AddToNationMetricAtField10(static_cast<int>(this->needTargetByType[0x16]) * 200);

  if (relationManager != 0) {
    RelationManager_ClearNeedSlotE2AndRefresh(relationManager);
  }

  for (int needIndex = 0; static_cast<short>(needIndex) < kNationSlotCount; ++needIndex) {
    this->AddToRelationManagerFieldB6AndRefresh(static_cast<short>(needIndex),
                                                this->needTargetByType[needIndex]);
  }
}

// FUNCTION: IMPERIALISM 0x004dcdd0
void TGreatPower::UpdateNeedTargetAndAccumulateOverCap(short needIndex, short value) {
  short* target = &this->needTargetByType[needIndex];
  this->needsOverCapFlag = static_cast<short>(this->needsOverCapFlag + (value - *target));
  *target = value;
}

// FUNCTION: IMPERIALISM 0x004dce10
void TGreatPower::SetNationResourceNeedCurrentByType(int needType, int currentValue) {
  short needIndex = static_cast<short>(needType);
  this->needCurrentByType[needIndex] = static_cast<short>(currentValue);
}

// FUNCTION: IMPERIALISM 0x004dce40
bool TGreatPower::IsNeedTargetEqualCurrent(short needIndex) {
  bool result = false;
  if (this->needTargetByType[needIndex] == this->needCurrentByType[needIndex]) {
    result = true;
  }
  return result;
}

// FUNCTION: IMPERIALISM 0x004dce70
short TGreatPower::GetNeedTargetByType(short needIndex) {
  return this->needTargetByType[needIndex];
}

// FUNCTION: IMPERIALISM 0x004dce90
void TGreatPower::TryIncrementNationResourceNeedTargetTowardCurrent(int needType) {
  short needIndex = static_cast<short>(needType);
  short targetValue = this->needTargetByType[needIndex];
  short currentValue = this->needCurrentByType[needIndex];
  if (targetValue < currentValue) {
    this->UpdateNeedTargetAndAccumulateOverCap(needType, static_cast<int>(targetValue) + 1);
  }
}

// FUNCTION: IMPERIALISM 0x004dcf10
void TGreatPower::IsNationResourceNeedCurrentSumExceedingCapA6(void) {
  int sumCurrentNeeds = 0;
  for (int needIndex = 0; needIndex < kNationSlotCount; ++needIndex) {
    sumCurrentNeeds += static_cast<int>(this->needCurrentByType[needIndex]);
  }

  this->needsOverCapFlag = (sumCurrentNeeds > static_cast<int>(this->needCapA6)) ? 1 : 0;
}

// FUNCTION: IMPERIALISM 0x004dcf60
short TGreatPower::TryDecayRelationNeedScores9AndB(void) {
  if (this->QueryNationMetricBySlot78(9) != 0) {
    if (this->QueryNationMetricBySlot78(0xb) != 0) {
      this->AddToRelationManagerFieldB6AndRefresh(9, -1);
      this->AddToRelationManagerFieldB6AndRefresh(0xb, -1);
      this->needCapA6 = static_cast<short>(this->needCapA6 + 1);
      return 1;
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004dcfd0
short TGreatPower::TryDecayRelationNeedScores9And8(void) {
  if (this->QueryNationMetricBySlot78(9) > 2) {
    if (this->QueryNationMetricBySlot78(8) != 0) {
      this->AddToRelationManagerFieldB6AndRefresh(9, -3);
      this->AddToRelationManagerFieldB6AndRefresh(8, -1);
      this->tradeCapacity = static_cast<short>(this->tradeCapacity + 1);
      return 1;
    }
  }
  return 0;
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

#pragma optimize("y", on)

// FUNCTION: IMPERIALISM 0x004dd140
void TGreatPower::RecomputeDiplomacyAidBudgetScoreFromResourceWeights(void) {
  int total = 0;
  for (int resourceType = 0; resourceType < 0x0E; ++resourceType) {
    short resourceWeight = reinterpret_cast<short(__cdecl*)(int)>(
        thunk_GetResourceDescriptorWeightWord0ByType)(resourceType);
    short relationWeight = *reinterpret_cast<short*>(
        reinterpret_cast<unsigned char*>(this->relationManager) + 0x5C + resourceType * 2);
    total += static_cast<short>(resourceWeight * relationWeight);
  }

  this->tradeCapacity = static_cast<short>(total);
  this->diplomacyCounterA2 = static_cast<short>(total);
}
#pragma optimize("", on)

#pragma optimize("y", on)

// FUNCTION: IMPERIALISM 0x004dd1b0
void TGreatPower::ResetDiplomacyNeedScoresAndClearAidAllocationMatrix(void) {
  this->RecomputeDiplomacyAidBudgetScoreFromResourceWeights();

  this->diplomacyCounterB0 = 0;
  this->budgetPoolDelta = 0;
  this->budgetPoolBase = 0;

  for (int nationIndex = 0; nationIndex < kNationSlotCount; ++nationIndex) {
    short snapshotValue = this->diplomacyState250[nationIndex];
    if (snapshotValue == -1) {
      ++this->diplomacyCounterB0;
    }
    this->diplomacyState1c6[nationIndex] = snapshotValue;

    short needScore = this->QueryNationMetricBySlot78(nationIndex);
    if (needScore < this->diplomacyState1c6[nationIndex]) {
      this->diplomacyState1c6[nationIndex] = this->QueryNationMetricBySlot78(nationIndex);
    }

    for (int rowIndex = 0; rowIndex < kAidAllocationRowCount; ++rowIndex) {
      this->aidAllocationMatrix[rowIndex * kAidAllocationColumnCount + nationIndex] = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x004dd270
void TGreatPower::RefreshDiplomacyNeedScoresAndClearAidAllocationMatrix(void) {
  for (int nationIndex = 0; nationIndex < kNationSlotCount; ++nationIndex) {
    short snapshotValue = this->diplomacyState250[nationIndex];
    if (snapshotValue == -1) {
      ++this->diplomacyCounterB0;
    }
    this->diplomacyState1c6[nationIndex] = snapshotValue;

    short needScore = this->QueryNationMetricBySlot78(nationIndex);
    if (needScore < this->diplomacyState1c6[nationIndex]) {
      this->diplomacyState1c6[nationIndex] = this->QueryNationMetricBySlot78(nationIndex);
    }

    for (int rowIndex = 0; rowIndex < kAidAllocationRowCount; ++rowIndex) {
      this->aidAllocationMatrix[rowIndex * kAidAllocationColumnCount + nationIndex] = 0;
    }
  }
}
#pragma optimize("", on)

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

  this->AddToNationMetricAtField10(amount);
  *reinterpret_cast<int*>(reinterpret_cast<unsigned char*>(this) + matrixIndex * 4 + 0x280) +=
      amount;
  *reinterpret_cast<int*>(reinterpret_cast<unsigned char*>(this) + 0x914) += amount;
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
  int baseBudget = this->SumAidAllocationMatrixAllCells();
  return baseBudget + this->budgetPoolBase + this->budgetPoolDelta - pendingAdjustments -
         outstandingCommitments;
}

// FUNCTION: IMPERIALISM 0x004dd470
void TGreatPower::ResetDiplomacyNeedSlots7012AndRefreshIfModeGateMatches(void) {
  TLocalizationRuntime* localizationTable =
      static_cast<TLocalizationRuntime*>(g_pLocalizationTable);
  if (localizationTable->runtimeSubsystemIndex != 0 || localizationTable->mode != 2) {
    return;
  }

  this->SetDiplomacyState1c6ClampedToCounterA4(7, -1);
  this->SetDiplomacyState1c6ClampedToCounterA4(0, -1);
  this->SetDiplomacyState1c6ClampedToCounterA4(1, -1);
  this->SetDiplomacyState1c6ClampedToCounterA4(2, -1);
  this->SnapshotDiplomacyState1c6Into250();
}

#pragma optimize("y", on)

// FUNCTION: IMPERIALISM 0x004dd4e0
void TGreatPower::AssignFallbackNationsToUnfilledDiplomacyNeedSlots(void) {
  const int kNeedSlotStart = 7;
  const int kNeedSlotEndExclusive = 12;
  const int kNeedSlotFallback = 5;

  if (this->diplomacyEligibilityA0 == 0) {
    if (this->foreignMinister != 0) {
      Object_CallSlot8CNoArgs(this->foreignMinister);
    }
    return;
  }

  void* diplomacyManager = ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr);
  bool hasUnfilledNeedSlot = false;
  for (int needSlot = kNeedSlotStart; needSlot < kNeedSlotEndExclusive; ++needSlot) {
    if (this->QueryNationMetricBySlot7C(needSlot) < 0) {
      hasUnfilledNeedSlot = true;
    }
  }

  if (hasUnfilledNeedSlot) {
    short selectedNation = static_cast<short>(-1);
    void* relationshipList = AllocateObArrayWithMode(0);
    if (diplomacyManager != 0 && relationshipList != 0) {
      g_pDiplomacyTurnStateManager->BuildRelationshipListSlot88(this->nationSlot, 1,
                                                                relationshipList);
    }

    for (int needSlot = kNeedSlotStart; needSlot < kNeedSlotEndExclusive; ++needSlot) {
      if (this->QueryNationMetricBySlot7C(needSlot) < 0) {
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
      static_cast<TIndexAndRankList*>(relationshipList)->ReleaseSlot24();
    }
  }

  if (this->QueryNationMetricBySlot7C(kNeedSlotFallback) == -1) {
    bool foundFallbackNation = false;
    int fallbackNationSlot = -1;
    while (!foundFallbackNation) {
      fallbackNationSlot = static_cast<int>(GenerateThreadLocalRandom15Value() % 7);
      if (IsNationSlotEligibleForEventProcessingFast(fallbackNationSlot) != 0 &&
          g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(fallbackNationSlot,
                                                                  this->nationSlot) == 0 &&
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

// FUNCTION: IMPERIALISM 0x004dd040
void TGreatPower::ResetDiplomacyLevelForNationSlot12_Provisional(int targetNationSlot,
                                                                 int resetLevel) {
  short nation = static_cast<short>(targetNationSlot);
  if (nation != this->nationSlot &&
      static_cast<short>(resetLevel) != this->needLevelByNation[nation]) {
    this->needLevelByNation[nation] = static_cast<short>(resetLevel);
  }
  if (this->diplomacyEligibilityA0 != 0) {
    thunk_NoOpDiplomacyPolicyStateChangedHook();
  }
  if (resetLevel == 300) {
    this->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(targetNationSlot, -1);
  }
}

// FUNCTION: IMPERIALISM 0x004dd740
short TGreatPower::GetDiplomacyExternalStateB6ByTarget(short targetNationSlot) {
  TRelationManager* relationManager = this->relationManager;
  if (relationManager == 0) {
    return 0;
  }
  return relationManager->fieldB6[targetNationSlot];
}

// FUNCTION: IMPERIALISM 0x004dd770
void TGreatPower::SetRelationManagerFieldB6AndRefresh(short targetSlot, short value) {
  TRelationManager* relationManager = this->relationManager;
  relationManager->fieldB6[targetSlot] = value;
  relationManager->Refresh80();
}

// FUNCTION: IMPERIALISM 0x004dd7b0
void TGreatPower::AddToRelationManagerFieldB6AndRefresh(short targetSlot, short value) {
  TRelationManager* relationManager = this->relationManager;
  relationManager->fieldB6[targetSlot] =
      static_cast<short>(relationManager->fieldB6[targetSlot] + value);
  relationManager->Refresh80();
}

// FUNCTION: IMPERIALISM 0x004dda20
void TGreatPower::DecrementDiplomacyCounterA2ByValue(int delta) {
  this->diplomacyCounterA2 =
      static_cast<short>(this->diplomacyCounterA2 - static_cast<short>(delta));
}

// FUNCTION: IMPERIALISM 0x004dda40
void TGreatPower::DecrementDiplomacyCounterA2Slot66(int delta) {
  this->diplomacyCounterA2 =
      static_cast<short>(this->diplomacyCounterA2 - static_cast<short>(delta));
}

// FUNCTION: IMPERIALISM 0x004dda60
int TGreatPower::SumDiplomacyState1c6AndRelationDeltaSnapshot(short nationSlot) {
  return this->diplomacyState1c6[nationSlot] + this->relationDeltaSnapshot[nationSlot];
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

// FUNCTION: IMPERIALISM 0x004ddad0
char TGreatPower::AreDiplomacyState1c6Slots13To16AllNonPositive(void) {
  char result = 1;
  short nationSlot = 0xd;
  do {
    if (nationSlot > 0x10) {
      return result;
    }
    short state = this->diplomacyState1c6[nationSlot];
    if (state > 0 && this->relationDeltaSnapshot[nationSlot] + state > 0) {
      result = 0;
    }
    ++nationSlot;
  } while (result != 0);
  return result;
}

short TGreatPower::QueryNationMetricBySlot78(short nationSlot) {
  return static_cast<short>(this->GetDiplomacyExternalStateB6ByTarget(nationSlot));
}

char TGreatPower::ShouldDispatchImmediatelySlot28_Provisional(void) {
  return this->diplomacyEligibilityA0;
}

// FUNCTION: IMPERIALISM 0x004ddb20
#pragma optimize("y", on)
short TGreatPower::QueryNationMetricBySlot7C(short targetNationSlot) {
  return this->diplomacyState1c6[targetNationSlot];
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004ddb40
void TGreatPower::SetDiplomacyState1c6ClampedToCounterA4(short targetSlot, short value) {
  if (targetSlot != -10) {
    short clamped = this->tradeCapacity;
    if (value <= this->tradeCapacity) {
      clamped = value;
    }
    this->diplomacyState1c6[targetSlot] = clamped;
  }
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004ddb80
void TGreatPower::SnapshotDiplomacyState1c6Into250(void) {
  for (int nationSlot = 0; nationSlot < kNationSlotCount; ++nationSlot) {
    this->diplomacyState250[nationSlot] = this->diplomacyState1c6[nationSlot];
  }
}

#pragma optimize("y", on)

// FUNCTION: IMPERIALISM 0x004ddbb0
char TGreatPower::TryDispatchNationActionViaUiContextOrFallback(int arg1, int arg2, int arg3,
                                                                int arg4) {
  if (this->IsDiplomacyState1C6UnsetAndCounterPositiveForTarget(static_cast<short>(arg4)) != 0) {
    TUiRuntimeContext* uiRuntimeContext =
        static_cast<TUiRuntimeContext*>(ReadGlobalPointer(kAddrUiRuntimeContextPtr));
    uiRuntimeContext->DispatchDecisionSlot98(this->nationSlot, arg2, arg3, arg4);
    return 1;
  }

  this->DispatchFallbackActionSlot6C_Provisional(1, arg1, 0, arg4, 0);
  return 0;
}

#pragma optimize("y", on)

// FUNCTION: IMPERIALISM 0x004ddc30
void TGreatPower::ApplyIndexedResourceDeltaAndAdjustNationTotals(int resourceIndex, int delta,
                                                                 int multiplier) {
  short index = static_cast<short>(resourceIndex);
  short deltaWord = static_cast<short>(delta);
  this->relationDeltaSnapshot[index] =
      static_cast<short>(this->relationDeltaSnapshot[index] + deltaWord);

  int deltaInt = static_cast<int>(deltaWord);
  short multiplierWord = static_cast<short>(multiplier);
  int scaledDelta = static_cast<int>(multiplierWord) * deltaInt;
  this->AddToNationMetricAtField10(-scaledDelta);

  if (deltaWord > 0) {
    this->DecrementDiplomacyCounterA2Slot66(delta);
    this->budgetPoolDelta -= scaledDelta;
    return;
  }

  this->budgetPoolBase -= scaledDelta;
  if (IsSpecialNationInteractionResource(index) != 0) {
    *reinterpret_cast<int*>(reinterpret_cast<unsigned char*>(this) + 0x910) -= deltaInt;
  }
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004ddd20
void TGreatPower::OrphanVtableAssignStub_004ddd20(void) {
  this->diplomacyState1c6[0] = 0;
}

// FUNCTION: IMPERIALISM 0x004ddd50
#pragma optimize("y", on)
bool TGreatPower::IsDiplomacyState1C6UnsetAndCounterPositiveForTarget(short targetNationSlot) {
  bool result = true;
  if (this->GetDiplomacyCounterA2() <= 0 || this->diplomacyState1c6[targetNationSlot] >= 0) {
    result = false;
  }
  return result;
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004dde30
char TGreatPower::AnyTrackedSlotEntryHasZeroField4(short targetSlot) {
  char found = 0;
  for (short entryIndex = 1; found == 0; ++entryIndex) {
    TQueueObject* trackedSlot = this->diplomacyTrackedSlots[targetSlot];
    if (entryIndex > trackedSlot->entryCount) {
      return found;
    }
    TDiplomacyTrackedEntry* entry =
        static_cast<TDiplomacyTrackedEntry*>(trackedSlot->GetEntryAt1BasedSlot2C(entryIndex));
    if (entry->field4 == 0) {
      found = 1;
    }
  }
  return found;
}

// FUNCTION: IMPERIALISM 0x004dde80
short TGreatPower::GetTrackedSlotEntryCountLow(short targetSlot) {
  return static_cast<short>(this->diplomacyTrackedSlots[targetSlot]->entryCount);
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004ddf20
void TGreatPower::AssignPayloadToTrackedSlotEntryMatchingField2(int targetSlot, int matchKey,
                                                                int payload) {
  bool matched = false;
  for (int entryIndex = 1; !matched; ++entryIndex) {
    TQueueObject* trackedSlot = this->diplomacyTrackedSlots[targetSlot];
    if (entryIndex > trackedSlot->entryCount) {
      return;
    }
    TDiplomacyTrackedEntry* entry =
        static_cast<TDiplomacyTrackedEntry*>(trackedSlot->GetEntryAt1BasedSlot2C(entryIndex));
    if (entry->field2 == matchKey) {
      matched = true;
      entry->field8 = payload;
      entry->field4 = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x004ddf90
void TGreatPower::ClearDiplomacyState1c6Block(void) {
  int* cursor = reinterpret_cast<int*>(this->diplomacyState1c6);
  for (int remaining = 0xb; remaining != 0; --remaining) {
    *cursor = 0;
    ++cursor;
  }
  *reinterpret_cast<short*>(cursor) = 0;
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
          this->AddToNationMetricAtField10(500);
        } else if (previousPolicy == kPolicyTreasuryLarge) {
          this->AddToNationMetricAtField10(5000);
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
    TLocalizationRuntime* localizationTable = ReadLocalizationRuntimeView();
    if (localizationTable != 0 && localizationTable->mode == 6) {
      this->ApplyDiplomacyRelationCodeAndNotifyThirdPartySlot284(targetClass, 4, -1);
    }

    void* diplomacyManager = ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr);
    short relationTier =
        g_pDiplomacyTurnStateManager->GetRelationTierSlot70(targetClass, this->nationSlot);
    if (relationTier == 2) {
      g_pDiplomacyTurnStateManager->ApplyRelationCode4Slot7c(this->nationSlot, targetClass, 1);
    }

    void* terrainDescriptor =
        ReadGlobalPointerArraySlot(kAddrTerrainTypeDescriptorTable, targetClass);
    if (terrainDescriptor != 0) {
      short encodedNationSlot = TerrainDescriptor_GetEncodedNationSlot(terrainDescriptor);
      if (encodedNationSlot > 199) {
        int resolvedNationSlot = DecodeTerrainNationSlot(encodedNationSlot, terrainDescriptor);
        if (g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(this->nationSlot,
                                                                    resolvedNationSlot) == 0) {
          this->ApplyDiplomacyPolicyStateForTargetWithCostChecks(resolvedNationSlot, 0x131);
        }
      }
    }

    if (this->diplomacyEligibilityA0 != 0) {
      this->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(targetClass, -1);
    }
    break;
  }

  case 5:
    if (this->CanAffordAdditionalDiplomacyCostAfterCommitments(500) != 0) {
      this->AddToNationMetricAtField10(0xFFFFFE0C);
    } else {
      shouldApply = 0;
    }
    break;

  case 6:
    if (this->CanAffordAdditionalDiplomacyCostAfterCommitments(5000) != 0) {
      this->AddToNationMetricAtField10(0xFFFFEC78);
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
  if (this->diplomacyEligibilityA0 != 0) {
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
      this->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(targetNation, grantEntry);
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
    if (newGrantRaw != kGrantClear &&
        this->CanAffordDiplomacyGrantEntryForTarget(targetNation, newGrantRaw) == 0) {
      accepted = false;
    } else {
      if (oldGrantRaw != kGrantClear) {
        int oldGrantValue = static_cast<short>(oldGrantRaw & kGrantMask);
        this->grantTotalCost -= oldGrantValue;
        this->AddToNationMetricAtField10(oldGrantValue);
      }

      if (newGrantRaw != kGrantClear) {
        int newGrantValue = static_cast<short>(newGrantRaw & kGrantMask);
        this->grantTotalCost += newGrantValue;
        this->AddToNationMetricAtField10(-newGrantValue);
      }

      this->diplomacyGrantByNation[targetIndex] = static_cast<short>(newGrantRaw);
    }
  }

  if (this->diplomacyEligibilityA0 != 0) {
    thunk_NoOpDiplomacyPolicyStateChangedHook();

    if (accepted && newGrantRaw != kGrantClear && targetNation > 6) {
      bool shouldDispatchAlert = false;
      void* diplomacyManager = ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr);
      if (diplomacyManager != 0) {
        int majorNation = 0;
        while (majorNation < 7) {
          if (majorNation != this->nationSlot) {
            short relationValue =
                g_pDiplomacyTurnStateManager
                    ->relationStandingScoreMatrix79c[(targetIndex) * 0x17 + (majorNation)];
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
        TLocalizationRuntime* localizationRuntime = ReadLocalizationRuntimeView();
        if (localizationRuntime != 0) {
          localizationRuntime->CallSlot84();
          localizationRuntime->CallSlot84(0x2753);
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
      g_pDiplomacyTurnStateManager
          ->relationStandingScoreMatrix79c[(targetNation) * 0x17 + (sourceNation)]);
  int relationDelta = ComputeGrantInfluenceDelta(grantValue);
  g_pDiplomacyTurnStateManager->SetStandingScoreSlot28(sourceNation, targetNation,
                                                       relationCode + relationDelta);
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

  this->treasuryValue10 = 0;

  ReleaseAndClear1C(&this->foreignMinister);
  ReleaseAndClear1C(&this->interiorMinister);
  ReleaseAndClear1C(&this->defenseMinister);

  this->diplomacyCounterA2 = 0;
  this->tradeCapacity = 0;
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

  this->ReleaseDiplomacyTrackedObjectSlots850();

  void* relationPanelManager = this->relationManager;
  if (relationPanelManager != 0) {
    ReleaseObjectAtSlot1C(relationPanelManager);
  }
  this->relationManager = 0;

  this->CallSlotA5_Provisional();

  void* diplomacyManager = ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr);
  for (nationSlot = 0; nationSlot < kNationSlotCount; ++nationSlot) {
    if (nationSlot != this->nationSlot &&
        IsNationSlotEligibleForEventProcessingFast(nationSlot) != 0) {
      g_pDiplomacyTurnStateManager->SetRelationCodeSlot74WithMode(this->nationSlot, nationSlot,
                                                                  kDipFlagRelation, 0);
      g_pDiplomacyTurnStateManager->SetStandingScoreSlot28(this->nationSlot, nationSlot,
                                                           kDipFlagPolicy);
      void* nationState = ReadNationStateSlot(nationSlot);
      if (NationState_IsBusyA0(nationState) == 0) {
        NationState_NotifyAction131(nationState, this->nationSlot);
      }
      this->ResetDiplomacyLevelForNationSlot12_Provisional(nationSlot, kResetDiplomacyLevel);
      this->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(nationSlot, kResetPolicyCode);
    }
  }

  int secondarySlot;
  for (secondarySlot = kMajorNationCount; secondarySlot < kNationSlotCount; ++secondarySlot) {
    void* secondaryState = ReadSecondaryNationStateSlot(secondarySlot);
    bool directReset = true;
    const TSecondaryNationStateOwner* secondaryStateView =
        static_cast<const TSecondaryNationStateOwner*>(secondaryState);
    short encodedOwnerNation = secondaryStateView->encodedOwnerNationSlot;
    if (encodedOwnerNation >= 200) {
      short ownerNation = DecodeSecondaryNationOwnerSlot(secondaryStateView);
      directReset = ownerNation == this->nationSlot;
    }

    if (!directReset) {
      g_pDiplomacyTurnStateManager->SetRelationCodeSlot74WithMode(this->nationSlot, secondarySlot,
                                                                  kDipFlagRelation, 0);
      g_pDiplomacyTurnStateManager->SetStandingScoreSlot28(this->nationSlot, secondarySlot,
                                                           kDipFlagPolicy);
    }

    this->ResetDiplomacyLevelForNationSlot12_Provisional(secondarySlot, kResetDiplomacyLevel);
    this->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(secondarySlot, kResetPolicyCode);

    if (ReadTerrainDescriptorSlot(secondarySlot) != 0) {
      SecondaryState_ResetDiplomacyLevel(secondaryState, this->nationSlot, kResetDiplomacyLevel);
    }
  }

  reinterpret_cast<void(__cdecl*)(void)>(
      thunk_RemoveOrdersByNationFromPrimarySecondaryAndTaskForceLists)();
  ApplyJoinEmpireMode0GlobalDiplomacyResetImpl(ReadGlobalPointer(kAddrGlobalMapStatePtr),
                                               this->nationSlot);

  TLocalizationRuntime* localizationTable = ReadLocalizationRuntimeView();
  if (localizationTable != 0 && localizationTable->redrawEnabled != 0) {
    reinterpret_cast<void(__cdecl*)(void)>(thunk_DispatchTaggedGameStateEvent1F20)();
  }
}

// FUNCTION: IMPERIALISM 0x004deca0
void TGreatPower::DecrementNeedLevelByNationStep(short nationSlot) {
  short* needLevel = &this->needLevelByNation[nationSlot];
  switch (*needLevel) {
  case 0x4b:
    if (this->treasuryValue10 > 10000) {
      *needLevel = 0x32;
    }
    break;
  case 0x5a:
    *needLevel = 0x4b;
    return;
  case 0x5f:
    *needLevel = 0x5a;
    return;
  case 100:
    *needLevel = 0x5f;
    return;
  }
}

// FUNCTION: IMPERIALISM 0x004dedf0
#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif
void TGreatPower::NotifyActionSlot94(int arg1, int arg2) {
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

  if (this->diplomacyEligibilityA0 != 0) {
    int packedCode = (static_cast<int>(static_cast<unsigned short>(arg1)) << 16) |
                     static_cast<unsigned short>(arg2);
    void* diplomacyQueue = this->turnEventQueue;
    QueueObject_WritePackedIntAtSlot38(diplomacyQueue, &packedCode);

    Event13Payload payload;
    payload.marker0 = 1;
    payload.nationMask = 1 << (static_cast<unsigned char>(this->nationSlot) & 0x1F);
    payload.marker1 = 1;
    payload.targetMask = 1 << (static_cast<unsigned char>(arg1) & 0x1F);

    char immediateDispatch = this->ShouldDispatchImmediatelySlot28_Provisional();
    if (immediateDispatch == 0) {
      QueueInterNationEventWithPayload(static_cast<int>(this->nationSlot), &payload);
    } else {
      SendTurnEvent13WithPayload(static_cast<int>(this->nationSlot), &payload);
    }
  }

  void* diplomacyState = ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr);
  int nationSlot = static_cast<int>(this->nationSlot);

  if (policyCode == kPolicyMutualDefense &&
      g_pDiplomacyTurnStateManager->HasFlag84ForNationSlot84(arg1) != 0) {
    for (int slot = 0; slot < kMajorNationCount; ++slot) {
      if (IsNationSlotEligibleForEventProcessingFast(slot) == 0) {
        continue;
      }

      short relationState = g_pDiplomacyTurnStateManager->GetRelationTierSlot70(nationSlot, slot);
      if (relationState != 2) {
        continue;
      }

      if (g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(slot, arg1) != 0) {
        g_pDiplomacyTurnStateManager->ApplyRelationCode4Slot7c(nationSlot, slot, 1);
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

    if (g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(slot, arg1) == 0) {
      continue;
    }

    if (g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(slot, nationSlot) == 0) {
      this->ApplyDiplomacyRelationCodeAndNotifyThirdPartySlot284(slot, 2, static_cast<short>(arg1));
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

// Typed vtable views for the diplomacy objects reached by opaque pointer in
// ApplyAcceptedDiplomacyProposalCode. Real (thiscall, no-edx) virtual dispatch
// matches the original `mov ecx,obj; call [vtbl+slot]` shape better than the
// generated VCall_* facades, which carry a spurious edx=0 argument.
struct DiplomacyManagerVtbl {
  virtual void s00() = 0;
  virtual void s01() = 0;
  virtual void s02() = 0;
  virtual void s03() = 0;
  virtual void s04() = 0;
  virtual void s05() = 0;
  virtual void s06() = 0;
  virtual void s07() = 0;
  virtual void s08() = 0;
  virtual void s09() = 0;
  virtual void s10() = 0;
  virtual void s11() = 0;
  virtual void s12() = 0;
  virtual void s13() = 0;
  virtual void s14() = 0;
  virtual void s15() = 0;
  virtual void s16() = 0;
  virtual char HasPolicyWithNationSlot44(int sourceNation, int targetNation) = 0; // 17 (0x44)
  virtual void s18() = 0;
  virtual void s19() = 0;
  virtual void s20() = 0;
  virtual void s21() = 0;
  virtual void s22() = 0;
  virtual void s23() = 0;
  virtual void s24() = 0;
  virtual void s25() = 0;
  virtual void s26() = 0;
  virtual void s27() = 0;
  virtual short GetRelationTierSlot70(int sourceNation, int targetNation) = 0; // 28 (0x70)
  virtual void s29() = 0;
  virtual void SetRelationCodeSlot78Final(int sourceNation, int targetNation,
                                          int relationCode) = 0; // 30 (0x78)
  virtual void ApplyRelationCode4Slot7c(int sourceNation, int targetNation,
                                        int updateMode) = 0; // 31 (0x7c)
  virtual void s32() = 0;
  virtual char HasFlag84ForNationSlot84(int nationSlot) = 0; // 33 (0x84)
};

struct TerrainDescriptorVtbl {
  virtual void s00() = 0;
  virtual void s01() = 0;
  virtual void s02() = 0;
  virtual void s03() = 0;
  virtual void s04() = 0;
  virtual void s05() = 0;
  virtual void s06() = 0;
  virtual void s07() = 0;
  virtual void s08() = 0;
  virtual void s09() = 0;
  virtual void s10() = 0;
  virtual void s11() = 0;
  virtual void s12() = 0;
  virtual void s13() = 0;
  virtual void s14() = 0;
  virtual void s15() = 0;
  virtual void s16() = 0;
  virtual void s17() = 0;
  virtual void s18() = 0;
  virtual void SetDiplomacyStandingSlot4c(int sourceNation, int mode) = 0; // 19 (0x4c)
};

struct NationStateVtbl {
  virtual void s00() = 0;
  virtual void s01() = 0;
  virtual void s02() = 0;
  virtual void s03() = 0;
  virtual void s04() = 0;
  virtual void s05() = 0;
  virtual void s06() = 0;
  virtual void s07() = 0;
  virtual void s08() = 0;
  virtual void s09() = 0;
  virtual void s10() = 0;
  virtual void s11() = 0;
  virtual void s12() = 0;
  virtual void s13() = 0;
  virtual void s14() = 0;
  virtual void s15() = 0;
  virtual void s16() = 0;
  virtual void s17() = 0;
  virtual void s18() = 0;
  virtual void s19() = 0;
  virtual void s20() = 0;
  virtual void s21() = 0;
  virtual void s22() = 0;
  virtual void s23() = 0;
  virtual void s24() = 0;
  virtual void s25() = 0;
  virtual void s26() = 0;
  virtual void s27() = 0;
  virtual void s28() = 0;
  virtual void s29() = 0;
  virtual void s30() = 0;
  virtual void s31() = 0;
  virtual void s32() = 0;
  virtual void s33() = 0;
  virtual void s34() = 0;
  virtual void s35() = 0;
  virtual void s36() = 0;
  virtual void NotifyActionSlot94(int sourceNation, int actionCode) = 0; // 37 (0x94)
};

// FUNCTION: IMPERIALISM 0x004df010
#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif
void TGreatPower::ApplyAcceptedDiplomacyProposalCode(short proposalIndex) {
  struct DiplomacyProposalRecord {
    short proposalCode;
    short targetNationSlot;
  };

  // Three independent destructible shared-string locals, constructed in order
  // and released in reverse. Modeling them as one aggregate scope object adds an
  // EH-state nesting level and reshapes the function; the original has three
  // separate locals (construct 0/1/2, advance ehstate after each).
  CString tmp0;
  CString tmp1;
  CString tmp2;

  DiplomacyProposalRecord* proposal = reinterpret_cast<DiplomacyProposalRecord*>(
      ProposalQueue_GetEntryAt1Based(this->proposalQueue, proposalIndex));

  switch (static_cast<int>(proposal->proposalCode) - 0x12D) {
  case 0:
    this->ApplyJoinEmpireAcceptanceSideEffectsForTargetNation(
        static_cast<int>(proposal->targetNationSlot), 1);
    QueueInterNationEventRecordDedup(3, this->nationSlot,
                                     static_cast<int>(proposal->targetNationSlot));
    break;

  case 1: {
    reinterpret_cast<DiplomacyManagerVtbl*>(ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr))
        ->SetRelationCodeSlot78Final(this->nationSlot, static_cast<int>(proposal->targetNationSlot),
                                     2);
    QueueInterNationEventRecordDedup(4, this->nationSlot,
                                     static_cast<int>(proposal->targetNationSlot));
    for (int nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
      if (reinterpret_cast<DiplomacyManagerVtbl*>(
              ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr))
                  ->HasPolicyWithNationSlot44(nationSlot,
                                              static_cast<int>(proposal->targetNationSlot)) != 0 &&
          reinterpret_cast<DiplomacyManagerVtbl*>(
              ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr))
                  ->HasPolicyWithNationSlot44(this->nationSlot, nationSlot) == 0) {
        this->ApplyDiplomacyRelationCodeAndNotifyThirdPartySlot284(nationSlot, 2, static_cast<int>(proposal->targetNationSlot));
      }
    }
    break;
  }

  case 2:
    reinterpret_cast<DiplomacyManagerVtbl*>(ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr))
        ->SetRelationCodeSlot78Final(this->nationSlot, static_cast<int>(proposal->targetNationSlot),
                                     3);
    QueueInterNationEventRecordDedup(5, this->nationSlot,
                                     static_cast<int>(proposal->targetNationSlot));
    break;

  case 3: {
    reinterpret_cast<DiplomacyManagerVtbl*>(ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr))
        ->SetRelationCodeSlot78Final(this->nationSlot, static_cast<int>(proposal->targetNationSlot),
                                     4);
    QueueInterNationEventRecordDedup(2, this->nationSlot,
                                     static_cast<int>(proposal->targetNationSlot));
    if (reinterpret_cast<DiplomacyManagerVtbl*>(
            ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr))
            ->HasFlag84ForNationSlot84(static_cast<int>(proposal->targetNationSlot)) != 0) {
      for (int nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
        if (IsNationSlotEligibleForEventProcessingFast(nationSlot) != 0 &&
            reinterpret_cast<DiplomacyManagerVtbl*>(
                ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr))
                    ->GetRelationTierSlot70(this->nationSlot, nationSlot) == 2 &&
            reinterpret_cast<DiplomacyManagerVtbl*>(
                ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr))
                    ->HasPolicyWithNationSlot44(
                        nationSlot, static_cast<int>(proposal->targetNationSlot)) != 0) {
          reinterpret_cast<DiplomacyManagerVtbl*>(
              ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr))
              ->ApplyRelationCode4Slot7c(this->nationSlot, nationSlot, 1);
        }
      }
    }
    break;
  }

  case 5: {
    reinterpret_cast<TerrainDescriptorVtbl*>(
        ReadTerrainDescriptorSlot(static_cast<int>(proposal->targetNationSlot)))
        ->SetDiplomacyStandingSlot4c(this->nationSlot, 1);
    QueueInterNationEventRecordDedup(3, static_cast<int>(proposal->targetNationSlot),
                                     this->nationSlot);
    break;
  }

  default:
    break;
  }

  if (reinterpret_cast<DiplomacyManagerVtbl*>(ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr))
              ->HasFlag84ForNationSlot84(static_cast<int>(proposal->targetNationSlot)) != 0 &&
      IsNationSlotEligibleForEventProcessingFast(static_cast<int>(proposal->targetNationSlot)) !=
          0) {
    reinterpret_cast<NationStateVtbl*>(
        ReadNationStateSlot(static_cast<int>(proposal->targetNationSlot)))
        ->NotifyActionSlot94(this->nationSlot, proposal->proposalCode);
  }
}
#if defined(_MSC_VER)
#pragma optimize("", on)
#endif

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
  if (diplomacyManager != 0 &&
      g_pDiplomacyTurnStateManager->HasFlag84ForNationSlot84(targetNation) != 0) {
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

  static_cast<TUiRuntimeContext*>(uiRuntimeContext)->DispatchEventSlot4C(0x2103, this->nationSlot);
}

// FUNCTION: IMPERIALISM 0x004df5f0
void TGreatPower::ProcessPendingDiplomacyProposalQueue(void) {
  const short kProposalTradeEmbargo = 0x12E;
  const short kProposalMutualDefense = 0x132;
  CString proposalSummaryRef;
  CString proposalScratchRef;
  int proposalIndex = 0;
  int queueIndex = 0;

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
          if (g_pDiplomacyTurnStateManager->GetRelationTierSlot70(this->nationSlot, targetNation) !=
              4) {
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
          this->QueueInterNationEventForProposalCode12D_130(proposalIndex);
        } else if (proposalCode == kProposalMutualDefense) {
          int checkNation = 0;
          do {
            if (g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(targetNation,
                                                                        checkNation) != 0 &&
                g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(this->nationSlot,
                                                                        checkNation) == 0) {
              this->ApplyDiplomacyRelationCodeAndNotifyThirdPartySlot284(checkNation, 0x132, targetNation);
            }
            ++checkNation;
          } while (checkNation < kMajorNationCount);
        } else {
          this->ApplyAcceptedDiplomacyProposalCode(proposalIndex);
        }
      } else {
        this->QueueInterNationEventForProposalCode12D_130(proposalIndex);
      }

      ++proposalIndex;
      ++queueIndex;
    } while (static_cast<short>(proposalIndex) <= proposalCount);
  }

  this->ResetDiplomacyPolicyAndGrantEntriesPreserveRecurringGrants();
}

// FUNCTION: IMPERIALISM 0x004e00d0
void DispatchGreatPowerQuarterlyStatusMessageLevel2(void) {
  if (!IsQuarterlyLocalizationGateOpen()) {
    return;
  }
  DispatchQuarterlyGreatPowerPressureMessage(2);
}

// FUNCTION: IMPERIALISM 0x004e0140
void DispatchGreatPowerQuarterlyStatusMessageLevel1(void) {
  if (!IsQuarterlyLocalizationGateOpen()) {
    return;
  }
  DispatchQuarterlyGreatPowerPressureMessage(1);
}

// FUNCTION: IMPERIALISM 0x004e01b0
void DispatchGreatPowerQuarterlyStatusMessageLevel0(void) {
  if (!IsQuarterlyLocalizationGateOpen()) {
    return;
  }
  DispatchQuarterlyGreatPowerPressureMessage(0);
}

struct TUiRuntimeDecisionPromptVtbl {
  virtual void s000() = 0;
  virtual void s001() = 0;
  virtual void s002() = 0;
  virtual void s003() = 0;
  virtual void s004() = 0;
  virtual void s005() = 0;
  virtual void s006() = 0;
  virtual void s007() = 0;
  virtual void s008() = 0;
  virtual void s009() = 0;
  virtual void s010() = 0;
  virtual void s011() = 0;
  virtual void s012() = 0;
  virtual void s013() = 0;
  virtual void s014() = 0;
  virtual void s015() = 0;
  virtual void s016() = 0;
  virtual void s017() = 0;
  virtual void s018() = 0;
  virtual void s019() = 0;
  virtual void s020() = 0;
  virtual void s021() = 0;
  virtual void s022() = 0;
  virtual void s023() = 0;
  virtual void s024() = 0;
  virtual void s025() = 0;
  virtual void s026() = 0;
  virtual void s027() = 0;
  virtual void s028() = 0;
  virtual void s029() = 0;
  virtual void s030() = 0;
  virtual void s031() = 0;
  virtual void s032() = 0;
  virtual void s033() = 0;
  virtual void s034() = 0;
  virtual void s035() = 0;
  virtual void s036() = 0;
  virtual char RequestDecisionSlot94(int sourceNation, int arg1, int arg2, int promptCode) = 0;
};

struct TDiplomacyManagerAdvisoryVtbl {
  virtual void s000() = 0;
  virtual void s001() = 0;
  virtual void s002() = 0;
  virtual void s003() = 0;
  virtual void s004() = 0;
  virtual void s005() = 0;
  virtual void s006() = 0;
  virtual void s007() = 0;
  virtual void s008() = 0;
  virtual void s009() = 0;
  virtual void s010() = 0;
  virtual void s011() = 0;
  virtual void s012() = 0;
  virtual void s013() = 0;
  virtual void s014() = 0;
  virtual void s015() = 0;
  virtual void s016() = 0;
  virtual char HasPolicySlot44(int sourceNation, int targetNation) = 0;
};

// FUNCTION: IMPERIALISM 0x004e0550
int TGreatPower::CountMapActionContextNodesWithNationBit(void) {
  int count = 0;
  MapActionContextNode* node = static_cast<MapActionContextNode*>(g_pMapActionContextListHead);
  if (node != 0) {
    do {
      if ((node->flags10 & (1 << (this->nationSlot & 0x1f))) != 0) {
        ++count;
      }
      node = node->next18;
    } while (node != 0);
  }
  return count;
}

// FUNCTION: IMPERIALISM 0x004e0590
double TGreatPower::ComputeMinisterSkillFloatSlot88(void) {
  return MinisterSkillFloat(g_DAT_Value_00653308, this->foreignMinister) +
         MinisterSkillFloat(g_DAT_Value_00653328, this->defenseMinister);
}

// FUNCTION: IMPERIALISM 0x004e05d0
double TGreatPower::ComputeMinisterSkillFloatSlot89(void) {
  return MinisterSkillFloat(g_DAT_Value_00653360, this->defenseMinister) +
         MinisterSkillFloat(g_DAT_Value_00653340, this->foreignMinister);
}

// FUNCTION: IMPERIALISM 0x004e0610
double TGreatPower::ComputeMinisterSkillFloatSlot8A(void) {
  return MinisterSkillFloat(g_DAT_Value_00653398, this->defenseMinister) +
         MinisterSkillFloat(g_DAT_Value_00653378, this->foreignMinister);
}

// FUNCTION: IMPERIALISM 0x004e0650
double TGreatPower::ComputeMinisterSkillFloatSlot8B(void) {
  return MinisterSkillFloat(g_DAT_006533b0_Value_006533B0, this->foreignMinister) +
         MinisterSkillFloat(g_DAT_006533d0_Value_006533D0, this->defenseMinister);
}

// FUNCTION: IMPERIALISM 0x004e0690
double TGreatPower::ComputeMinisterSkillFloatSlot8C(void) {
  return MinisterSkillFloat(g_DAT_Value_00653408, this->defenseMinister) +
         MinisterSkillFloat(g_DAT_006533e8_Value_006533E8, this->foreignMinister);
}

// FUNCTION: IMPERIALISM 0x004e0740
int TGreatPower::GetCityBuildingProductionViaRelationManagerSlot8D(short buildingSlot) {
  if (this->relationManager != 0) {
    return static_cast<short>(
        GetCityBuildingProductionValueBySlot(this->relationManager, buildingSlot));
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004e1d50
bool TGreatPower::ExecuteAdvisoryPromptAndApplyActionType1(int arg1, int arg2) {
  char result = 0;
  TDiplomacyManagerAdvisoryVtbl* diplomacyTurnStateManager =
      static_cast<TDiplomacyManagerAdvisoryVtbl*>(
          ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr));
  TUiRuntimeDecisionPromptVtbl* uiRuntimeContext =
      static_cast<TUiRuntimeDecisionPromptVtbl*>(ReadGlobalPointer(kAddrUiRuntimeContextPtr));

  result = diplomacyTurnStateManager->HasPolicySlot44(this->nationSlot, arg2);

  if (result == 0) {
    result = uiRuntimeContext->RequestDecisionSlot94(this->nationSlot, arg1, arg2, 0x0A);
    if (result != 0) {
      this->ApplyDiplomacyRelationCodeAndNotifyThirdPartySlot284(arg2, 1, arg1);
      return true;
    }
  } else {
    result = uiRuntimeContext->RequestDecisionSlot94(this->nationSlot, arg1, arg2, 0x0B);
    if (result != 0) {
      void* secondaryNationState = ReadSecondaryNationStateSlot(arg1);
      if (secondaryNationState != 0) {
        const TSecondaryNationStateOwner* secondaryNationStateView =
            static_cast<const TSecondaryNationStateOwner*>(secondaryNationState);
        short stateValue = DecodeSecondaryNationOwnerSlot(secondaryNationStateView);
        if (stateValue != this->nationSlot) {
          SecondaryState_CallSlot4C(secondaryNationState, this->nationSlot, 1);
        }
      }
    }
  }
  return result != 0;
}

// FUNCTION: IMPERIALISM 0x004e22b0
void TGreatPower::AddRegionIdToNationOwnedRegionListAndTriggerExpansionActionIfThresholdMet(void) {
  void* ownedRegionList = this->ownedRegionList;
  List_ResetSlot14(ownedRegionList);
  int ownedRegionCount = List_GetCountSlot28(ownedRegionList);

  unsigned char pressureGate = this->serializedStatusFlags[6];
  unsigned char nationGate = this->expansionEventGate;
  if (ownedRegionCount > 8 && pressureGate > 0x32 && nationGate < 3) {
    this->SetNationPendingActionStateAndPayload(0x0C, -1);
  }
}

// FUNCTION: IMPERIALISM 0x004e2330
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
    g_pDiplomacyTurnStateManager->SetRelationCodeSlot78Final(this->nationSlot, targetNation, 4);
    this->NotifyAllianceSlot214(targetNation);
    return;
  }

  if (policyCode != kPolicyTradeAgreement) {
    this->VTableSlot84_Provisional(targetNation);
    return;
  }

  if (this->candidateNationFlags[targetNation] == 0) {
    int resolvedNation = ResolveTerrainNationSlotFromTarget(targetNation);
    if (this->candidateNationFlags[static_cast<short>(resolvedNation)] == 0) {
      void* diplomacyManager = ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr);
      if (g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(this->nationSlot,
                                                                  resolvedNation) == 0) {
        this->NotifyAllianceSlot214(targetNation);
        return;
      }
    }
  }

  this->VTableSlot84_Provisional(targetNation);
}

// FUNCTION: IMPERIALISM 0x004e2500
void TGreatPower::ReleaseTrackedObjectsByMapOwnerAndUnassignedEntries(int ownerClass) {
  TGlobalMapState* globalMapState = ReadGlobalMapStateScoreView();
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

// FUNCTION: IMPERIALISM 0x004e27b0
void TGreatPower::DispatchNationDiplomacySlotActionByMode(int targetNationSlot, int mode) {
  if (static_cast<short>(mode) == 6) {
    this->CallSlotA8_Provisional(targetNationSlot);
    return;
  }

  this->CallSlotA9_Provisional(targetNationSlot);
}

// FUNCTION: IMPERIALISM 0x004d7b20
void TGreatPower::ApplyJoinEmpireModeForTargetNation(int targetNationSlot, int mode) {
  TLocalizationRuntime* localizationRuntime = ReadLocalizationRuntimeView();
  if (localizationRuntime != 0 && reinterpret_cast<int*>(localizationRuntime)[0x11] == 1) {
    reinterpret_cast<void(__cdecl*)(int, int, int)>(0x0054c5a0)(this->nationSlot, targetNationSlot,
                                                                 mode);
  }

  if (mode == 1) {
    g_pDiplomacyTurnStateManager->SetRelationCodeSlot78Final(this->nationSlot, targetNationSlot, 5);
    g_pDiplomacyTurnStateManager->SetRelationCodeSlot78Final(targetNationSlot, this->nationSlot, 5);
  }

  if (this->nationSlot < 7) {
    reinterpret_cast<void(__cdecl*)(void)>(0x00581200)();
  }

  if (mode == 0) {
    this->ApplyJoinEmpireMode0GlobalDiplomacyReset(targetNationSlot);
    return;
  }
  if (mode == 1) {
    this->ApplyJoinEmpireMode1TargetTransition(targetNationSlot);
    return;
  }
  this->GetIdentitySharedString1Slot58();
}

// FUNCTION: IMPERIALISM 0x004d7c90
void TGreatPower::ApplyJoinEmpireMode1TargetTransition(int targetNationSlot) {
  this->encodedNationSlot = static_cast<short>(targetNationSlot + 200);
  this->ResetDiplomacyLevelForNationSlot12_Provisional(targetNationSlot, 100);

  int nationSlot = 0;
  do {
    if (IsNationSlotEligibleForEventProcessingFast(nationSlot) != 0 &&
        nationSlot != this->nationSlot && nationSlot != targetNationSlot) {
      void* terrainDescriptor = g_apTerrainTypeDescriptorTable[nationSlot];
      if (terrainDescriptor != 0) {
        TerrainDescriptor_SetResetLevel(terrainDescriptor, this->nationSlot, 200);
      }
    }
    ++nationSlot;
  } while (nationSlot < kNationSlotCount);

  reinterpret_cast<void(__cdecl*)(short)>(0x004eef50)(this->nationSlot);
}

// FUNCTION: IMPERIALISM 0x004d7d50
CString* TGreatPower::GetIdentitySharedString1Slot58(void) {
  return &this->identitySharedString1;
}

// FUNCTION: IMPERIALISM 0x004e21b0
void TGreatPower::ApplyJoinEmpireAcceptanceSideEffectsForTargetNation(int targetNationSlot,
                                                                      int mode) {
  CString sharedStringScope;

  ApplyJoinEmpireModeForTargetNation(targetNationSlot, mode);

  if (targetNationSlot >= 0 && targetNationSlot < kNationSlotCount) {
    TGreatPower* targetNation =
        static_cast<TGreatPower*>(g_apNationStates[targetNationSlot]);
    if (targetNation != 0 && targetNation->field8d1 < 3) {
      targetNation->SetNationPendingActionStateAndPayload(9, this->nationSlot);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004e27f0
void TGreatPower::QueueWarTransitionAndNotifyThirdPartyIfNeeded(int targetNationSlot,
                                                                int policyCode,
                                                                int sourceNationSlot) {
  void* diplomacyManager = ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr);
  QueueNationPairWarTransition(diplomacyManager, this->nationSlot,
                               static_cast<short>(targetNationSlot));

  short proposalCode = static_cast<short>(policyCode);
  if ((proposalCode != 1) && (proposalCode != 0x132)) {
    return;
  }

  void* secondaryNationState = ReadSecondaryNationStateSlot(sourceNationSlot);
  if (secondaryNationState == 0) {
    return;
  }

  const TSecondaryNationStateOwner* secondaryNationStateView =
      static_cast<const TSecondaryNationStateOwner*>(secondaryNationState);
  short selectedSlot = DecodeSecondaryNationOwnerSlot(secondaryNationStateView);

  if (selectedSlot == this->nationSlot) {
    return;
  }

  SecondaryState_CallSlot4C(secondaryNationState, this->nationSlot, 1);
}

// FUNCTION: IMPERIALISM 0x004e2b70
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
  TLocalizationRuntime* localizationRuntime = ReadLocalizationRuntimeView();
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

// FUNCTION: IMPERIALISM 0x004e72c0
void TGreatPower::InitializeMapActionCandidateStateAndQueueMission(int arg1) {
  this->thunk_InitializeGreatPowerMinisterRosterAndScenarioState(arg1);

  void* stream = reinterpret_cast<void*>(arg1);
  Stream_ReadAtSlot3C(stream, this->actionMetricByQuarter, 0x0C);
  SwapShortArrayBytes(this->actionMetricByQuarter, 6);

  Stream_ReadAtSlot3C(stream, this->mapNodeStateFlags, 0x180);
  Stream_ReadAtSlot3C(stream, this->portZoneStateFlags, 0x70);

  TListObject* missionQueue = this->missionQueue;
  if (missionQueue->GetCountSlot48() != 0) {
    missionQueue->Call54();
  }
  missionQueue->Call18(arg1);

  int missionContext = 0;
  Stream_ReadAtSlot3C(stream, &missionContext, 4);
  for (int queueIndex = 1; queueIndex < 0x71; ++queueIndex) {
    missionContext = 0;
    char hasMission = Stream_ReadByteAtSlotB0(stream, &missionContext);
    if (hasMission != 0) {
      missionQueue->AddTail30(reinterpret_cast<void*>(missionContext));
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

// FUNCTION: IMPERIALISM 0x004e7630
void TGreatPower::WrapperFor_TGreatPower_VtblSlot32_At004e7630(int arg1, int arg2, int arg3) {
  if (arg2 < 0 && arg1 > 6 && arg1 < 0x0D) {
    this->needCurrentByType[arg1] = static_cast<short>(this->needCurrentByType[arg1] + arg2);
  }

  this->thunk_ApplyIndexedResourceDeltaAndAdjustNationTotals_At00407392(arg1, arg2, arg3);
}

// FUNCTION: IMPERIALISM 0x004e78d0
void TGreatPower::DispatchNationField98CallbackD4(void) {
  this->interiorMinister->CallD4();
}

// FUNCTION: IMPERIALISM 0x004e78f0
void TGreatPower::DispatchNationField9CCallback4C(void) {
  this->defenseMinister->Call4C();
}

// FUNCTION: IMPERIALISM 0x004e7990
void TGreatPower::DispatchNationField94Callbacks90And94(void) {
  this->foreignMinister->Call90();
  this->foreignMinister->Call94();
}

// FUNCTION: IMPERIALISM 0x004e7b20
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
    void* diplomacyState = ReadGlobalPointer(kAddrDiplomacyTurnStateManagerPtr);
    if (diplomacyState != 0) {
      char hasAllianceGuard =
          g_pDiplomacyTurnStateManager->HasAllianceGuardSlot60(arg1, this->nationSlot);
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
    this->VTableSlot84_Provisional(static_cast<short>(arg1));
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
    GAME_FAIL_NIL_POINTER();
    TemporarilyClearAndRestoreUiInvalidationFlag(kUCountryAutoCppPath, kAssertLineQueueMapAction);
  }

  TListObject* missionQueue = this->missionQueue;
  missionQueue->AddTail30(missionObj);

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
      TGreatPower* nationObj = static_cast<TGreatPower*>(nationObjects[slot]);
      float slotValue = nationObj->GetScoreFactorSlot23C();
      sum += slotValue;
      if (slot == selectedNationSlot) {
        selected = nationObj->GetScoreFactorSlot23C();
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
      TGreatPower* nationObj = static_cast<TGreatPower*>(nationObjects[slot]);
      float slotValue = nationObj->GetScoreFactorSlot240();
      sum += slotValue;
      if (slot == selectedNationSlot) {
        selected = nationObj->GetScoreFactorSlot240();
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

    int nodeWeight = static_cast<TListObject*>(linkedNodesView->linkedNodeList)->GetCountSlot28();
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

    TGreatPower* nationObj = static_cast<TGreatPower*>(ReadNationStateSlot(selectedNationSlot));
    if (nationObj == 0) {
      return 0.0f;
    }

    int priorityForNode =
        CallSumNavyOrderPriorityForNationAndNodeType(nationObj, relationTargetNation);
    int nodeMultiplier = nationObj->GetMultiplierSlot21C();
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
        g_pDiplomacyTurnStateManager
            ->relationStandingScoreMatrix79c[(relationTargetNation) * 0x17 + (this->nationSlot)];
    if (relationValue == 0) {
      return kOne;
    }
    return 100.0f / (float)relationValue;
  }
  case 5: {
    TGlobalMapState* globalMapState = ReadGlobalMapStateScoreView();
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
      if (diplomacyManager != 0 && g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(
                                       this->nationSlot, primaryNation) != 0) {
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
      g_pDiplomacyTurnStateManager->BuildRelationshipListSlot88(this->nationSlot, 1,
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

// FUNCTION: IMPERIALISM 0x004e9a50
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

// FUNCTION: IMPERIALISM 0x004e9ed0
void TGreatPower::QueueWarTransitionFromAdvisoryAction(int arg1, int arg2, int arg3) {
  this->VTableSlot84_Provisional(arg1);
  this->TGreatPower::ApplyDiplomacyRelationCodeAndNotifyThirdPartySlot284(arg1, arg2, arg3);
}

// FUNCTION: IMPERIALISM 0x004ea150
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

  this->CallSlotB3_Provisional();
}

// FUNCTION: IMPERIALISM 0x004ea290
void TGreatPower::AddRegionToNationAndQueueMapActionMission(int arg1) {
  this->thunk_AddRegionIdToNationOwnedRegionListAndTriggerExpansionActionIfThresholdMet_At00404246();

  if (arg1 >= 0 && arg1 < kMapNodeCount) {
    this->mapNodeStateFlags[arg1] = 1;
    this->thunk_QueueMapActionMissionFromCandidateAndMarkState(3, arg1, 0, -1);
  }
}

// FUNCTION: IMPERIALISM 0x004ea300
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

// FUNCTION: IMPERIALISM 0x004ffc10
void TGreatPower::ConstructTurnOrderNavigationWindowEntryViewportAdaptive(void) {
  this->diplomacyEligibilityA0 = 0;
  this->diplomacyCounterA2 = 0x14;
  this->tradeCapacity = 0;
  this->needCapA6 = 0;
  this->needsOverCapFlag = 0;
  this->grantTotalCost = 0;
}

// FUNCTION: IMPERIALISM 0x00540ac0
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

// FUNCTION: IMPERIALISM 0x005410f0
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
  static_cast<TUiRuntimeContext*>(uiRuntimeContext)
      ->RequestDiplomacyDecisionSlot90(this->nationSlot, this->nationSlot, 0x29A);
}

// FUNCTION: IMPERIALISM 0x005416b0
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

  bool accepted = this->thunk_ExecuteAdvisoryPromptAndApplyActionType1_At00403c15(arg1, arg2);
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

// FUNCTION: IMPERIALISM 0x0055c970
void TGreatPower::QueueInterNationEventIntoNationBucket(int eventCode, int payloadOrNation,
                                                        char isReplayBypass) {
  TLocalizationRuntime* localizationTable = ReadLocalizationRuntimeView();
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

// FUNCTION: IMPERIALISM 0x0055cbd0
void TGreatPower::QueueInterNationEventType0FWithBitmaskMerge(int eventCode, int nationA,
                                                              int nationB, char isReplayBypass) {
  TLocalizationRuntime* localizationTable = ReadLocalizationRuntimeView();
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
              static_cast<TQueueObject*>(mergeQueue)->GetEntryAt1BasedSlot2C(entryIndex));
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

// FUNCTION: IMPERIALISM 0x0055f140
unsigned int TGreatPower::ComputeMapActionContextNodeValueAverage(void) {
  TGlobalMapState* globalMapState = ReadGlobalMapStateScoreView();
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

struct STurnInstructionCiviCursorView {
  unsigned int* tokenCursor;
};

// FUNCTION: IMPERIALISM 0x00582630
void TGreatPower::HandleTurnInstruction_Civi_DeserializeAndCreateWorkOrder(void* pInstructionRaw) {
  STurnInstructionCiviCursorView* instruction =
      reinterpret_cast<STurnInstructionCiviCursorView*>(pInstructionRaw);
  if (instruction == 0 || instruction->tokenCursor == 0) {
    return;
  }

  unsigned int* cursor = instruction->tokenCursor;
  unsigned int token0 = *cursor++;
  unsigned int token1 = *cursor++;
  instruction->tokenCursor = cursor;

  short workOrderType = static_cast<short>((token0 >> 0x10) & 0xFFFF);
  short ownerNationSlot = static_cast<short>((token1 >> 0x10) & 0xFFFF);

  int mapState = reinterpret_cast<int>(ReadGlobalPointer(kAddrGlobalMapStatePtr));
  signed char cityOwnerTag = 0;
  if (mapState != 0) {
    int cityTable = *reinterpret_cast<int*>(mapState + 0x0C);
    if (cityTable != 0) {
      cityOwnerTag = *reinterpret_cast<signed char*>(cityTable + 4 + ownerNationSlot * 0x24);
    }
  }

  void* orderObject = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x44));
  if (orderObject == 0) {
    return;
  }

  reinterpret_cast<void(__fastcall*)(void*, int)>(thunk_InitializeCivUnitOrderObject)(orderObject,
                                                                                      0);
  reinterpret_cast<TCivWorkOrderState*>(orderObject)
      ->InitializeCivWorkOrderState(workOrderType, ownerNationSlot, static_cast<int>(cityOwnerTag));
}

float TGreatPower::GetScoreFactorSlot23C(void) {
  return 0.0f;
}

float TGreatPower::GetScoreFactorSlot240(void) {
  return 0.0f;
}

int TGreatPower::GetMultiplierSlot21C(void) {
  return 0;
}
