#include "game/TStream.h"
#include "game/TNavyMission.h"
#include "game/TStream.h"
#include "game/TTerrainDescriptor.h"
#include "game/TMinor.h"
#include "game/TTrackedObject.h"
#include "game/TNationInteractionStateManager.h"
#include "game/nation_slot_eligibility.h"
#include "game/TLocalizationRuntime.h"
#include "game/CIterator.h"
#include "game/TTownMarker.h"
#include "game/TUiRuntimeContext.h"
#include "game/UiRuntimeContext.h"
#include "game/TCity.h"
#include "game/TMinister.h"
#include "game/TForeignMinister.h"
#include "game/TDefenseMinister.h"
#include "game/TCityInteriorMinister.h"
#include "game/TMilitaryUnitOrderState.h"
#include "game/TIndexAndRankList.h"
#include "game/TGlobalMapState.h"
#include "game/TStationedUnitNode.h"
#include "game/TShip.h"
#include "game/TMilitaryUnit.h"
#include "game/TDefendProvinceMission.h"
#include "game/TMission.h"
#include "game/TZone.h"
#include "game/turn_event_packets.h"
#include "game/TTurnEventPacket.h"
#include "game/turn_flow_cooldown.h"
#include "game/ui_invalidation_guard.h"
#include "game/TTurnInstructionCiviCursor.h"
// Manual decompilation file.
// Seeded from ghidra autogen and normalized into compile-safe wrappers.

#include <math.h>
#include <string.h>

#include "decomp_types.h"
#include "game/GameAssert.h"
#include "game/generated/vcall_facades.h"
#include "game/CString.h"
#include "game/TGreatPower.h"

#include <string.h>

#include "game/mfc.h"
#include "game/TObject.h"
#include "game/TGreatPower_internal.h"
#include "game/TGlobalMapState.h"
#include "game/diplomacy_globals.h"
#include "game/TDiplomacyTurnStateManager.h"
#include "game/CIterator.h"
#include "game/TInterNationEventQueueManager.h"
#include "game/TShip.h"
#include "game/TTerrainDescriptor.h"
#include "game/TTurnEventQueue.h"
#include "game/TTownMarker.h"
#include "game/TradeCommodityMetricRecord.h"
#include "game/trade_quickdraw.h"
#include <stddef.h>
#include <new>

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
// Float constants for the relative-power-score family (slots 0x8e-0x9e).
extern float g_Compute_Advisory_Handler_LookupTable_00653700; // 0.0f
extern float g_Compute_Advisory_Handler_LookupTable_00653714; // -0.25f
extern float g_Iterate_Linked_List_Value_00653718;            // 0.25f
extern float g_Compute_City_Order_Value_0065371C;             // 0.5f
extern float g_Compute_Advisory_Handler_LookupTable_00653720; // -90.0f
extern float g_Compute_Advisory_Peer_LookupTable_00653724;    // -0.5f
extern float g_Compute_Advisory_Zero_00653FD0;
extern float g_Compute_Advisory_Map_Value_00653FD4;
extern double g_Compute_Advisory_MinusSix_00653FE8;
extern double g_Compute_Advisory_MinusHundred_00653FF0;
extern double g_Compute_Advisory_Hundred_00654000;
extern double g_Compute_Advisory_OnePointFive_00654008;
extern void* g_apNationStates_End;
// Per-unit-type military power weights (0xe-byte records, weight short at +0).
extern short g_Classify_Nation_Military_LookupTable_00695CD4[][7];
// Per-order-type sort priority table (slot 0x55 selection sort).
extern short g_DAT_006966d0_Value_006966D0[];
// Per-unit-type tactical category code (slot 0x11 garrison sweep).
extern short g_awTacticalUnitCategoryCodeBySlot[];
}
extern TZone* g_pMapActionContextListHead;

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

// TEMP: preamble bridge cluster — global/map accessors (retire into typed globals/views).

typedef void* hwnd_t;

undefined4 ComputeMapActionContextNodeValueAverage(void);
undefined4 BuildCityInfluenceLevelMap(void);
void DispatchGreatPowerQuarterlyStatusMessageLevel1(void);
undefined4 ProcessPendingDiplomacyProposalQueue(void);
undefined4 CompileGreatPowerRelationshipDeltaLinesAndDispatchMessage(void);
void DispatchGreatPowerQuarterlyStatusMessageLevel2(void);
undefined4 ExecuteAdvisoryPromptAndApplyActionType2OrFallback(void);
undefined4 PopulateCase16AdvisoryMapNodeCandidateState(void);
undefined4 DispatchTurnEvent11F8WithNoPayload(void);
undefined4 BuildGreatPowerTurnMessageSummaryAndDispatch(void);
undefined4 AddRegionIdToNationOwnedRegionListAndTriggerExpansionActionIfThresholdMet(void);
undefined4 ResetDiplomacyNeedScoresAndClearAidAllocationMatrix(void);
undefined4 InitializeCivWorkOrderState(void);
undefined4 thunk_GetShortAtOffset14OrInvalid(void);
undefined4 thunk_ContainsPointerArrayEntryMatchingByteKey(void);
undefined4 thunk_ComputeNavyOrderDistributionSimilarityScoreForExactSourceNation(void);
undefined4 thunk_ComputeNavyOrderDistributionSimilarityScoreWithDiplomacyFilter(void);
undefined4 thunk_AssignStringSharedRefAndReturnThis(void);
undefined4 thunk_DispatchLocalizedUiMessageWithTemplateA13A0(void);
undefined4 thunk_NoOpDiplomacyPolicyStateChangedHook(void);

static __inline void InvokeDiplomacyPolicyStateChangedHook(int policyOrGrant, int targetNation,
                                                           char acceptedFlag) {
  reinterpret_cast<void(__cdecl*)(int, int, int)>(thunk_NoOpDiplomacyPolicyStateChangedHook)(
      policyOrGrant, targetNation, static_cast<int>(acceptedFlag));
}
undefined4 thunk_CreateAndSendTurnEvent13_NationAndNineDwords(void);
float ComputeMapActionContextCompositeScoreForNation(void);
undefined4 thunk_QueueNationPairWarTransition(void);
void ApplyIndexedResourceDeltaAndAdjustNationTotals(void);
void RefreshGreatPowerRelationPanelsAndDispatchDeltaSummary(void);
void NoOpAdvisoryHandlerReturn(void);
void NoOpDiplomacyWarTransitionCallback(void);
void FreeHeapBufferIfNotNull(undefined4 ptr_value);
void ConstructTurnOrderNavigationWindowEntryViewportAdaptive(void);
void NoOpNationDiplomacyCallback(void);
void DispatchGreatPowerQuarterlyStatusMessageLevel0(void);
void ApplyJoinEmpireMode0GlobalDiplomacyReset(void);
void RebuildNationResourceYieldCountersAndDevelopmentTargets(void);
undefined4 ApplyIndexedResourceDeltaAndAdjustNationTotals_Impl(void);
int AllocateWithFallbackHandler(undefined4 size_bytes);
undefined4 thunk_QueueInterNationEventRecordDeduped(void);
undefined4 thunk_RebuildMinorNationDispositionLookupTables(void);
undefined4 thunk_DispatchTurnEvent1AWithNationActionPayload(void);
undefined4 thunk_RemoveOrdersByNationFromPrimarySecondaryAndTaskForceLists(void);
undefined4 ApplyJoinEmpireMode0GlobalDiplomacyReset_Impl(void);
undefined4 thunk_DispatchTaggedGameStateEvent1F20(void);
undefined4 thunk_InitializeNationStateIdentityAndOwnedRegionList(void);
undefined4 thunk_InitializeCityModel(void);
undefined4 thunk_InitializeCityProductionState(void);
undefined4 WrapperFor_InitializeLinkedListSentinelNodeWithOwnerContext_At004a8640(void);

undefined4 thunk_ConstructFrogCityMarker(void);
undefined4 thunk_ClearTurnResumeNationPendingBitAndMaybeFlushTelemetry(void);
undefined4 thunk_SetTimeEmitPacketGameFlowTurnId(void);
undefined4 thunk_CreateAndSendTurnEvent21_ThreeBytes(void);
undefined4 thunk_AssignSharedStringFromIndexedA8EntryNameField(void);

undefined4 thunk_InitializeCivUnitOrderObject(void);
undefined4 thunk_DispatchCityRedrawInvalidateEvent(void);
undefined4 GenerateThreadLocalRandom15(void);
undefined4 ReallocateHeapBlockWithAllocatorTracking(void);

undefined4 thunk_SetTaskForcePrimaryOrderLinkAndRefreshChildBacklinks(void);
undefined4 thunk_FindReachableRecruitSpawnTileWithVisitedReset(void);

// EH-body order/state globals (defined in global_data_tables.cpp). Direct absolute
// loads in the original; declaring them as real symbols lets reccmp pair the loads.
extern "C" {
extern void* g_pActiveMapOrderContext;

extern TMinor* g_apNationAuxRuntimeStateSlots[];
}

#include "game/TUnitOrderState.h"
#include "game/TZone.h"
#include "game/TCivWorkOrderState.h"
#include "game/TAdmiral.h"
#include "game/TMarkerReceiverView.h"
#include "game/TTrackedObjectListEntry.h"

#include "game/TMessageObject.h"
#include "game/TQueueObject.h"
#include "game/TStream.h"
#include "game/TIndexAndRankList.h"
#include "game/TSortedByRelationshipList.h"
#include "game/TPtrList.h"

static const unsigned int kAddrUiRuntimeContextPtr = 0x006A21BC;
static const unsigned int kAddrNationInteractionStateManagerPtr = 0x006A43CC;
static const unsigned int kAddrSecondaryNationStateSlots = 0x006A4280;
static const unsigned int kAddrInterNationEventQueueManagerPtr = 0x006A43E8;
static const unsigned int kAddrGameFlowStatePtr = 0x006A43C8;
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
TG_LAYOUT_ASSERT(TGreatPower_Offset_city_0x894,
                 offsetof(TGreatPower, city) == 0x894);
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

extern "C" UiRuntimeContext* g_pUiRuntimeContext;

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

static __inline int CPtrArray_GetCount(const CPtrArray* list) {
  return list->GetSize();
}

static __inline short IndexAndRankList_GetShortValueByOrdinal1Based(TIndexAndRankList* list,
                                                                    int ordinal) {
  short* value = static_cast<short*>(list->GetEntrySlot2C(ordinal));
  return (value != 0) ? *value : static_cast<short>(-1);
}

static __inline TSortedByRelationshipList* AllocateSortedByRelationshipListWithMode(short mode) {
  TSortedByRelationshipList* list =
      TSortedByRelationshipList::CreateTSortedByRelationshipListInstance();
  if (list != 0) {
    list->relationType = mode;
  }
  return list;
}

static __inline char UiRuntime_RequestDiplomacyDecision(void* uiRuntimeContext, int sourceNation,
                                                        int targetNation, int proposalCode) {
  return static_cast<TUiRuntimeContext*>(uiRuntimeContext)
      ->RequestDiplomacyDecisionSlot90(sourceNation, targetNation, proposalCode);
}

static __inline char IsTurnCooldownCounterActiveOrResetFlagAsChar(void) {
  return IsTurnCooldownCounterActiveOrResetFlag();
}

static __inline short DecodeSecondaryNationOwnerSlot(const TMinor* secondaryNationState) {
  short ownerNationSlot = secondaryNationState->ownerNationSlot0e;
  if (ownerNationSlot < 200) {
    if (ownerNationSlot < 100) {
      ownerNationSlot = secondaryNationState->fallbackNationSlot0c;
    } else {
      ownerNationSlot = static_cast<short>(ownerNationSlot - 100);
    }
  } else {
    ownerNationSlot = static_cast<short>(ownerNationSlot - 200);
  }
  return ownerNationSlot;
}

static __inline void ClearTurnResumeNationPendingBitAndMaybeFlushTelemetry(void* gameFlowState,
                                                                           int nationSlot) {
  void(__fastcall * clearPendingBit)(void*, int, int) =
      reinterpret_cast<void(__fastcall*)(void*, int, int)>(
          thunk_ClearTurnResumeNationPendingBitAndMaybeFlushTelemetry);
  clearPendingBit(gameFlowState, 0, nationSlot);
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
  TLocalizationRuntime* localizationTable = g_pLocalizationTable;
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

static __inline void DispatchCityRedrawInvalidateEvent(short regionId) {
  reinterpret_cast<void(__cdecl*)(short)>(thunk_DispatchCityRedrawInvalidateEvent)(regionId);
}

// TEMP: preamble bridge cluster — map-action score wrappers (retire to TGlobalMapState/TZone).
static __inline void* ReallocateBufferWithAllocatorTracking(void* buffer, int sizeBytes) {
  return reinterpret_cast<void*(__cdecl*)(void*, int)>(ReallocateHeapBlockWithAllocatorTracking)(
      buffer, sizeBytes);
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

static __inline void TemporarilyClearAndRestoreUiInvalidationFlag(const char* path, int line) {
  (void)path;
  (void)line;
  ::TemporarilyClearAndRestoreUiInvalidationFlag();
}

// --- File-scope helpers/types hoisted here so the IMPERIALISM markers below stay in
// ascending-address order (reccmp-decomplint function_out_of_order). ---

#include "game/TMapOrderContext.h"

static const char kUCountryCppPath[] = "D:\\Ambit\\Cross\\UCountry.cpp";

static const float kOne = 1.0f;

extern "C" {
extern float g_Classify_Nation_Military_Value_00653704; // -1.0f
extern float g_Classify_Nation_Military_Value_00653708; // 2.0f
extern float g_Classify_Nation_Military_Value_0065370C; // 1.0f
extern float g_Classify_Nation_Military_Value_00653710; // -2.0f
extern short g_Rebuild_Primary_Nation_Value_00653570[6][0x17];
}

undefined4 thunk_GenerateMappedFlavorTextByTableSlot(void);   // 0x00405312 -> 0x005d46b0
// 0x00401730 -> 0x005d5a70 (g_pUiRuntimeContext localized-message dispatch).
undefined4 thunk_RunControlStringProviderAndDispatchLocalizedMessage(void);

// Each dispatch reloads the UI-context global, as the original does.
static __inline void UiRuntime_QueueTurnStatusPrompt(int promptIndex, int payload) {
  reinterpret_cast<TUiRuntimeContext*>(g_pUiRuntimeContext)
      ->QueueTurnStatusPromptSlot3C(promptIndex, payload);
}

// View of the city commodity record's step-value virtual (slot 0x30 on the record's
// own vtable; the records are TAmtBar-shaped, see TradeCommodityMetricRecord).
struct TCommodityRecordStepView {
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
  virtual short GetStepValueSlot30() = 0;
protected:
  ~TCommodityRecordStepView() {}
};

// Packed entry layout shared by the diplomacyTrackedSlots queues (slots 0x6c/0x6f).
struct TrackedSlotEntryPacket {
  short kind;
  short targetNation;
  short value;
  short eligibility;
  int payload;
};

static __inline bool IsRecruitQuarterTickGate(short tickRaw) {
  int tick = static_cast<int>(tickRaw);
  int quarterIndex = (tick + ((tick >> 0x1f) & 3)) >> 2;
  if ((quarterIndex & 1) == 0) {
    return false;
  }
  int sign = tick >> 0x1f;
  int mod4 = tick;
  mod4 ^= sign;
  mod4 -= sign;
  mod4 &= 3;
  mod4 ^= sign;
  mod4 -= sign;
  return static_cast<short>(mod4) == 2;
}

static __inline TMapOrderContext* ActiveMapOrderContext(void) {
  return static_cast<TMapOrderContext*>(g_pActiveMapOrderContext);
}

// Slot 0x0c / 0x3b store the home region index as a 4-byte block over
// ownerNationSlot/pad_8a (the original field is an int).
static __inline int* GreatPower_HomeRegionIndex88(TGreatPower* self) {
  return reinterpret_cast<int*>(&self->ownerNationSlot);
}

// Slot 0x2ac base implementation. The original vtable slot holds the ILT thunk
// 0x0040389b -> 0x004daf00; the real body 0x004daf00 is still an autogen stub, so
// this virtual stays unannotated until that body is ported.
void TGreatPower::DispatchTurnEvent11F8NoPayloadSlot2AC(void) {
  DispatchTurnEvent11F8WithNoPayload();
}

// --- Scenario seeding / Frog City / influence-map family (slots 0x0c/0x0f/0x34/0x39/
// --- 0x3b/0x40/0x82) ---

// FUNCTION: IMPERIALISM 0x004d6770
char TGreatPower::ShouldDispatchImmediatelySlot28_Provisional(void) {
  return this->diplomacyEligibilityA0;
}

// FUNCTION: IMPERIALISM 0x004d71b0
#pragma optimize("y", on)
void TGreatPower::SeedInitialMilitaryAndNavyOrdersForOwnedRegions(void) {
  TLocalizationRuntime* localization = g_pLocalizationTable;
  if (localization->stateFlag114 > 0) {
    g_pGlobalMapState->NotifyCityRecordSlot12C(
        g_pGlobalMapState->terrainStateTable[this->ownerNationSlot].cityRecordIndex);
    return;
  }
  int ordinal = 1;
  if (this->ownedRegionList->GetCountOrReleaseSlot28() >= 1) {
    do {
      int regionId = this->ownedRegionList->GetIntByOrdinalSlot24(ordinal);
      short regionTerrainId = g_pGlobalMapState->cityScoreTable[regionId].ownerNationSlot;
      if ((g_pGlobalMapState->terrainStateTable[regionTerrainId].activeFlags1c & 1) != 0) {
        TMilitaryUnitOrderState* order = new TMilitaryUnitOrderState();
        order->InitializeRecruitOrderState(2, regionId, this->nationSlot);
        if (g_pLocalizationTable->runtimeSubsystemIndex < 2) {
          order->SetOrderModeSlot34(2, -1);
        }
        order = new TMilitaryUnitOrderState();
        order->InitializeRecruitOrderState(2, regionId, this->nationSlot);
        if (g_pLocalizationTable->runtimeSubsystemIndex < 2) {
          order->SetOrderModeSlot34(2, -1);
        }
        order = new TMilitaryUnitOrderState();
        order->InitializeRecruitOrderState(7, regionId, this->nationSlot);
        if (g_pLocalizationTable->runtimeSubsystemIndex < 2) {
          order->SetOrderModeSlot34(2, -1);
        }
        g_pGlobalMapState->NotifyCityRecordSlot12C(regionId);
        if (this->nationSlot < 7 &&
            g_apNationStates[this->nationSlot]->diplomacyEligibilityA0 ==
                0 &&
            g_pLocalizationTable->runtimeSubsystemIndex == 4) {
          order = new TMilitaryUnitOrderState();
          order->InitializeRecruitOrderState(6, regionId, this->nationSlot);
          if (g_pLocalizationTable->runtimeSubsystemIndex < 2) {
            order->SetOrderModeSlot34(2, -1);
          }
          order = new TMilitaryUnitOrderState();
          order->InitializeRecruitOrderState(5, regionId, this->nationSlot);
          if (g_pLocalizationTable->runtimeSubsystemIndex < 2) {
            order->SetOrderModeSlot34(2, -1);
          }
          TGreatPower* nation = g_apNationStates[this->nationSlot];
          TCity* cityForPort = (nation != 0) ? nation->city : 0;
          void* portZone = ActiveMapOrderContext()->FindPortZoneBySelectedTile(cityForPort);
          CreateNavyPrimaryOrderNodeAndAssignDisplayName(3, static_cast<TZone*>(portZone),
                                                         this->nationSlot, 0);
        }
        if (this->nationSlot < 7) {
          TGreatPower* nation = g_apNationStates[this->nationSlot];
          if (nation->diplomacyEligibilityA0 != 0 &&
              g_pLocalizationTable->runtimeSubsystemIndex == 0) {
            TCity* cityForPort = (nation != 0) ? nation->city : 0;
            TZone* portZone = static_cast<TZone*>(
                ActiveMapOrderContext()->FindPortZoneBySelectedTile(cityForPort));
            if (portZone->portZoneEntryCount2c == 0) {
              void* grownArray = reinterpret_cast<void*(__cdecl*)(void*, int)>(
                  ReallocateHeapBlockWithAllocatorTracking)(portZone->portZoneEntries28, 8);
              if (grownArray == 0) {
                portZone->portZoneEntries28 = static_cast<int*>(
                    reinterpret_cast<void*(__cdecl*)(void*, int)>(
                        ReallocateHeapBlockWithAllocatorTracking)(portZone->portZoneEntries28, 4));
                portZone->portZoneEntryCount2c = 1;
              } else {
                portZone->portZoneEntries28 = static_cast<int*>(grownArray);
                portZone->portZoneEntryCount2c = 2;
              }
            }
            if (portZone->portZoneActiveEntryCount30 == 0) {
              portZone->portZoneActiveEntryCount30 = 1;
            }
            CreateNavyPrimaryOrderNodeAndAssignDisplayName(
                3, reinterpret_cast<TZone*>(portZone->portZoneEntries28[0]), this->nationSlot, 0);
          }
        }
      }
      this->CreateMilitaryRecruitOrderForNode(regionId);
      this->CreateMilitaryRecruitOrderForNode(regionId);
      this->CreateMilitaryRecruitOrderForNode(regionId);
      if (g_pLocalizationTable->runtimeSubsystemIndex > 2) {
        this->CreateMilitaryRecruitOrderForNode(regionId);
        if (this->nationSlot >= 7) {
          TMilitaryUnitOrderState* lateOrder = new TMilitaryUnitOrderState();
          lateOrder->InitializeRecruitOrderState(7, regionId, this->nationSlot);
        }
      }
      if (*g_pGlobalMapState->scenarioTagText1c == '+') {
        TMilitaryUnitOrderState* bonusOrder = new TMilitaryUnitOrderState();
        bonusOrder->InitializeRecruitOrderState(2, regionId, this->nationSlot);
        bonusOrder->SetOrderModeSlot34(2, -1);
      }
      ++ordinal;
    } while (ordinal <= this->ownedRegionList->GetCountOrReleaseSlot28());
  }
  this->AssignDisplayNamesToUnnamedMilitaryUnits();
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004d7ae0
#pragma optimize("y", on)
void TGreatPower::AddToNationMetricAtField10(int amount) {
  this->treasuryValue10 += amount;
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004d7b20
void TGreatPower::ApplyJoinEmpireModeForTargetNation(int targetNationSlot, int mode) {
  if (g_pLocalizationTable != 0 && g_pLocalizationTable->redrawEnabled == 1) {
    DispatchJoinEmpireModeEventPacket24_27(this->nationSlot, targetNationSlot, mode);
  }

  if (mode == 1) {
    g_pDiplomacyTurnStateManager->SetRelationCodeSlot78Final(this->nationSlot, targetNationSlot, 5);
    g_pDiplomacyTurnStateManager->SetRelationCodeSlot78Final(targetNationSlot, this->nationSlot, 5);
  }

  if (this->nationSlot < 7) {
    g_pLocalizationTable->DecrementField30Value();
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
    if (IsNationSlotEligibleForEventProcessing(nationSlot) != 0 &&
        nationSlot != this->nationSlot && nationSlot != targetNationSlot) {
      void* terrainDescriptor = g_apTerrainTypeDescriptorTable[nationSlot];
      if (terrainDescriptor != 0) {
        reinterpret_cast<TTerrainDescriptor*>(terrainDescriptor)
            ->SetResetLevelSlot68(this->nationSlot, 200);
      }
    }
    ++nationSlot;
  } while (nationSlot < kNationSlotCount);

  g_pDiplomacyTurnStateManager->ResetTerrainAdjacencyMatrixRowAndSymmetricLink(this->nationSlot);
}

// FUNCTION: IMPERIALISM 0x004d7d20
#pragma optimize("y", on)
char TGreatPower::IsEncodedNationSlotMinus200Equal(int nationCode) {
  int adjusted = static_cast<int>(static_cast<short>(this->encodedNationSlot)) - 0xc8;
  if (adjusted == nationCode) {
    return 1;
  }
  return 0;
}
#pragma optimize("", on)

// --- Scenario seeding / Frog City / influence-map family (slots 0x0c/0x0f/0x34/0x39/
#pragma optimize("y", on)
void TGreatPower::CreateFrogCityTownMarkerAndAttach(void* receiver) {
  TTownMarker* marker = new TTownMarker();
  marker->InitializeTownMarker("Frog City", 0, 1, this->nationSlot);
  static_cast<TMarkerReceiverView*>(receiver)->AdoptMarkerSlot44(marker);
  marker->activeFlag4f = 1;
  this->townMarkerList->AddTail30(marker);
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004d7d50
CString* TGreatPower::GetIdentitySharedString1Slot58(void) {
  return &this->identitySharedString1;
}

// FUNCTION: IMPERIALISM 0x004d8000
#pragma optimize("y", on)
void TGreatPower::AssignDisplayNamesToUnnamedMilitaryUnits(void) {
  int ordinal = 1;
  if (this->militaryUnitList44->GetCountSlot48() < 1) {
    return;
  }
  do {
    TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(
        this->militaryUnitList44->GetTrackedEntrySlot4C(ordinal));
    if (unit->nameTag1a == 0) {
      if (unit->unitTypeId04 < 0x1b) {
        CString ordinalText;
        CString typeName;
        CString composedName;
        short unitType = unit->unitTypeId04;
        TLocalizationRuntime* localization = g_pLocalizationTable;
        short* nameOrdinalCounter = &this->unitNameOrdinalByType[unitType];
        localization->FormatOrdinalString(*nameOrdinalCounter, &ordinalText);
        localization->GetString(0x2717, unitType, &typeName);
        CString withSeparator = ordinalText + CString(" ");
        CString fullName = withSeparator + typeName;
        composedName = fullName;
        unit->displayName24 = composedName;
        unit->nameTag1a = this->unitNameCounter84;
        ++this->unitNameCounter84;
        ++*nameOrdinalCounter;
      } else {
        CString flavorBase;
        CString flavorName;
        g_pLocalizationTable->GetString(0x2744, 0, &flavorBase);
        do {
          reinterpret_cast<void(__cdecl*)(void*, int)>(thunk_GenerateMappedFlavorTextByTableSlot)(
              &flavorName, this->nationSlot);
        } while (flavorName.GetLength() > 0xf - flavorBase.GetLength());
        CString withSeparator = flavorBase + CString(" ");
        CString fullName = withSeparator + flavorName;
        flavorName = fullName;
        unit->displayName24 = flavorName;
        unit->nameTag1a = this->unitNameCounter84;
        ++this->unitNameCounter84;
      }
    }
    ++ordinal;
    ordinal = static_cast<short>(ordinal);
  } while (ordinal <= this->militaryUnitList44->GetCountSlot48());
}
#pragma optimize("", on)

// Updates Great Power pressure/escalation state and propagates summary messages when thresholds
// cross.

// --- Slots 0x0d/0x10/0x11/0x17/0x3a and the stationed-unit chain ---

// FUNCTION: IMPERIALISM 0x004d87b0
#pragma optimize("y", on)
int TGreatPower::GetHomeRegionCityRecordIndex(void) {
  return g_pGlobalMapState->terrainStateTable[this->ownerNationSlot].cityRecordIndex;
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004d87e0
#pragma optimize("y", on)
void TGreatPower::QueueRecruitOrdersForUndergarrisonedRegions(void) {
  short tickRaw = g_pLocalizationTable->quarterGateTick2c;
  if (!IsRecruitQuarterTickGate(tickRaw)) {
    return;
  }

  int garrisonThreshold = 3;
  if (static_cast<unsigned short>(this->nationSlot) < 7) {
    garrisonThreshold = 4;
  }

  int regionCount = this->ownedRegionList->GetCountOrReleaseSlot28();
  int ordinal = 1;
  if (ordinal > regionCount) {
    return;
  }
  do {
    short regionId = static_cast<short>(this->ownedRegionList->GetIntByOrdinalSlot24(ordinal));
    short garrisonCount = 0;
    TStationedUnitNode* unitChain;
    if ((regionId < 0) || (0x17f < regionId)) {
      unitChain = 0;
    } else {
      unitChain = *reinterpret_cast<TStationedUnitNode**>(
          reinterpret_cast<char*>(g_pGlobalMapState->cityScoreTable) + 0x98 +
          static_cast<int>(regionId) * 0xa8);
    }
    for (; unitChain != 0; unitChain = unitChain->next14) {
      if (unitChain->GetUnitMovementClassId() == 0) {
        garrisonCount = static_cast<short>(garrisonCount + 1);
      }
    }
    if (garrisonCount < static_cast<short>(garrisonThreshold)) {
      this->CreateMilitaryRecruitOrderForNode(static_cast<int>(regionId));
    }
    ordinal = ordinal + 1;
    regionCount = this->ownedRegionList->GetCountOrReleaseSlot28();
  } while (ordinal <= regionCount);
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
CRuntimeClass* TGreatPower::GetRuntimeClass() const {
  return reinterpret_cast<CRuntimeClass*>(kAddrClassDescTGreatPower);
}

char TGreatPower::ReturnFalseNationStateCapabilityFlag90(int arg) {
  (void)arg;
  return 0;
}

char TGreatPower::ReturnFalseNationStateCapabilityFlag98(void) {
  return 0;
}

char TGreatPower::ReturnFalseNationStateCapabilityFlag9C(void) {
  return 0;
}

void TGreatPower::NoOpNationSelectedRegionAndMapCellLabelHook(int arg1, int arg2) {
  (void)arg1;
  (void)arg2;
}

void TGreatPower::NoOpNationPendingActionHook(void) {}

void TGreatPower::NoOpNationQueuedOrderHook(void) {}

void TGreatPower::OrphanRetStub_004dcc30(void) {}

void TGreatPower::OrphanRetStub_004d8bc0(void) {}

void TGreatPower::OrphanRetStub_004d8be0(int arg) {
  (void)arg;
}

// FUNCTION: IMPERIALISM 0x004d89f0
TGreatPower::TGreatPower()
    : identitySharedString0(), identitySharedString1(), nationSlot(0), encodedNationSlot(0),
      treasuryValue10(0), field42(0), militaryUnitList44(0), ownerNationSlot(0), ownedRegionList(0),
      foreignMinister(0), interiorMinister(0), defenseMinister(0), diplomacyEligibilityA0(0),
      diplomacyCounterA2(0), tradeCapacity(0), needCapA6(0), needsOverCapFlag(0), grantTotalCost(0),
      diplomacyCounterB0(0), budgetPoolBase(0), budgetPoolDelta(0), turnEventQueue(0),
      proposalQueue(0), city(0), townMarkerList(0), trackedObjectList(0),
      scenarioInitFlag(0), diplomacyBudgetBase(0), escalationCounter(0), pendingCommitmentCost(0),
      pressureCounter(0), field900(0), turnSummaryQueue(0), missionNodeQueue(0), field910(0),
      aidAllocationTotal(0), pendingAidTotal(0), missionQueue(0) {
  int localeIndex = 0;
  if (g_pLocalizationTable != 0) {
    localeIndex = g_pLocalizationTable->runtimeSubsystemIndex;
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

// SYNTHETIC: IMPERIALISM 0x004d8c20
// TGreatPower::`scalar deleting destructor'

// Member release lives in Free() (0x004d9160); the real destructor only tears down
// the two identity CStrings (implicitly).
// FUNCTION: IMPERIALISM 0x004d8c50
TGreatPower::~TGreatPower() {}

// FUNCTION: IMPERIALISM 0x004d8cc0
void TGreatPower::InitializeNationStateRuntimeSubsystems(int arg1, int arg2) {
  reinterpret_cast<void(__fastcall*)(int, int)>(
      thunk_InitializeNationStateIdentityAndOwnedRegionList)(reinterpret_cast<int>(this), arg1);

  TLocalizationRuntime* localizationRuntime = g_pLocalizationTable;
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
  this->city = static_cast<TCity*>(cityModel);

  void* townMarkerListOwner = AllocateBattleListOwnerWithLinkedSentinel();
  this->townMarkerList = static_cast<TPtrList*>(townMarkerListOwner);

  this->grantTotalCost = 0;
  this->needCapA6 = 0x0F;
  this->field900 = 0x0F;

  this->turnEventQueue =
      reinterpret_cast<TQueueObject*>(AllocateSortedByRelationshipListWithMode(4));

  this->proposalQueue =
      reinterpret_cast<TQueueObject*>(AllocateSortedByRelationshipListWithMode(4));

  if (this->diplomacyEligibilityA0 != 0) {
    TForeignMinister* foreignMinister = new TForeignMinister();
    foreignMinister->InitializeStateAndCounters();
    this->foreignMinister = foreignMinister;

    TCityInteriorMinister* interiorMinister = new TCityInteriorMinister();
    interiorMinister->InitializeCityInteriorState();
    this->interiorMinister = interiorMinister;

    TDefenseMinister* defenseMinister = new TDefenseMinister();
    defenseMinister->InitializeBaseOrderArrayMetrics();
    this->defenseMinister = defenseMinister;
  }

  int listIndex = 0;
  while (listIndex < kDiplomacyTrackedSlotCount) {
    this->diplomacyTrackedSlots[listIndex] =
        reinterpret_cast<TQueueObject*>(AllocateSortedByRelationshipListWithMode(0x0C));
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
  this->trackedObjectList = static_cast<TPtrList*>(trackedObjectList);

  int candidateIndex = 0;
  while (candidateIndex < kNationSlotCount) {
    this->candidateNationFlags[candidateIndex] = 0;
    ++candidateIndex;
  }
  this->scenarioInitFlag = 0;
  this->field904 = 1;

  this->turnSummaryQueue =
      reinterpret_cast<TQueueObject*>(AllocateSortedByRelationshipListWithMode(8));

  void* missionNodeQueue = AllocateBattleListOwnerWithPtrListSentinel();
  this->missionNodeQueue = static_cast<TPtrList*>(missionNodeQueue);
  this->pendingAidTotal = 0;
}

// FUNCTION: IMPERIALISM 0x004d9160
void TGreatPower::Free(void) {
  if (this->city != 0) {
    this->city->Call1C();
  }
  this->city = 0;
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
  if (this->turnSummaryQueue != 0) {
    this->turnSummaryQueue->Call24();
  }
  this->turnSummaryQueue = 0;
  if (this->missionNodeQueue != 0) {
    this->missionNodeQueue->Call58();
  }
  this->missionNodeQueue = 0;
  if (this->militaryUnitList44 != 0) {
    this->militaryUnitList44->Call58();
  }
  this->militaryUnitList44 = 0;
  if (this->ownedRegionList != 0) {
    this->ownedRegionList->Call38();
    this->ownedRegionList = 0;
  }
  delete this;
}

// FUNCTION: IMPERIALISM 0x004d92e0
void TGreatPower::ReadFrom(TStream* stream) {
  this->DeserializeRecruitScenarioAndInstantiateOrders(reinterpret_cast<int>(stream));
  stream->ReadBytes(&this->diplomacyEligibilityA0, 1);
  stream->ReadBytes(&this->diplomacyCounterA2, 2);
  stream->ReadBytes(&this->tradeCapacity, 2);
  stream->ReadBytes(&this->needCapA6, 2);
  stream->ReadBytes(&this->needsOverCapFlag, 2);
  if (*reinterpret_cast<int*>(kAddrAdvanceTurnMachineState) < 0x3E) {
    stream->ReadBytes(&this->grantTotalCost, 2);
  } else {
    stream->ReadBytes(&this->grantTotalCost, 4);
  }
  stream->ReadBytes(&this->diplomacyCounterB0, 2);
  stream->ReadBytes(this->diplomacyPolicyByNation, 0x2E);
  SwapShortArrayBytes(this->diplomacyPolicyByNation, kNationSlotCount);
  stream->ReadBytes(this->diplomacyGrantByNation, 0x2E);
  SwapShortArrayBytes(this->diplomacyGrantByNation, kNationSlotCount);
  stream->ReadBytes(this->needCurrentByType, 0x2E);
  SwapShortArrayBytes(this->needCurrentByType, kNationSlotCount);
  stream->ReadBytes(this->needTargetByType, 0x2E);
  SwapShortArrayBytes(this->needTargetByType, kNationSlotCount);
  stream->ReadBytes(this->relationDeltaCurrent, 0x2E);
  SwapShortArrayBytes(this->relationDeltaCurrent, kNationSlotCount);
  stream->ReadBytes(this->relationDeltaSnapshot, 0x2E);
  SwapShortArrayBytes(this->relationDeltaSnapshot, kNationSlotCount);
  stream->ReadBytes(this->diplomacyState1c6, 0x2E);
  SwapShortArrayBytes(this->diplomacyState1c6, kNationSlotCount);

  if (*reinterpret_cast<int*>(kAddrAdvanceTurnMachineState) > 0x16) {
    stream->ReadBytes(this->diplomacyState1f4, 0x2E);
    SwapShortArrayBytes(this->diplomacyState1f4, kNationSlotCount);
  }

  stream->ReadBytes(this->diplomacyState222, 0x2E);
  SwapShortArrayBytes(this->diplomacyState222, kNationSlotCount);
  stream->ReadBytes(this->diplomacyState250, 0x2E);
  SwapShortArrayBytes(this->diplomacyState250, kNationSlotCount);

  stream->ReadBytes(&this->budgetPoolBase, 4);
  stream->ReadBytes(&this->budgetPoolDelta, 4);
  stream->ReadBytes(this->aidAllocationMatrix, 0x5C0);
  ReverseDwordArrayBytes(this->aidAllocationMatrix, 0x170);

  stream->ReadBytes(this->serializedStatusFlags, 0x0D);
  stream->ReadBytes(this->field8d6, 0x1A);
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
      this->city->Call18();
    } else {
      ReleaseAndClear1C(&this->foreignMinister);
      ReleaseAndClear1C(&this->interiorMinister);
      ReleaseAndClear1C(&this->defenseMinister);
      ReleaseAndClear1C(&this->city);
    }
  } else {
    int ministerMask = static_cast<TStream*>(stream)->ReadInteger();

    if ((ministerMask & 1) == 0) {
      ReleaseAndClear1C(&this->foreignMinister);
    } else {
      TMinister* foreignMinister = this->foreignMinister;
      if (foreignMinister == 0) {
        TForeignMinister* created = new TForeignMinister();
        created->InitializeStateAndCounters();
        this->foreignMinister = created;
        foreignMinister = created;
      }
      if (foreignMinister != 0) {
        foreignMinister->Call18();
      }
    }

    if ((ministerMask & 2) == 0) {
      ReleaseAndClear1C(&this->interiorMinister);
    } else {
      TMinister* interiorMinister = this->interiorMinister;
      if (interiorMinister == 0) {
        TCityInteriorMinister* created = new TCityInteriorMinister();
        created->InitializeCityInteriorState();
        this->interiorMinister = created;
        interiorMinister = created;
      }
      if (interiorMinister != 0) {
        interiorMinister->Call18();
      }
    }

    if ((ministerMask & 4) == 0) {
      ReleaseAndClear1C(&this->defenseMinister);
    } else {
      TMinister* defenseMinister = this->defenseMinister;
      if (defenseMinister == 0) {
        TDefenseMinister* created = new TDefenseMinister();
        created->InitializeBaseOrderArrayMetrics();
        this->defenseMinister = created;
        defenseMinister = created;
      }
      if (defenseMinister != 0) {
        defenseMinister->Call18();
      }
    }

    if ((ministerMask & 8) == 0) {
      ReleaseAndClear1C(&this->city);
    } else {
      void* cityObject = this->city;
      if (cityObject != 0) {
        static_cast<TCity*>(cityObject)->Call18();
      }
    }
  }

  void* townMarkerList = this->townMarkerList;
  int hasItems = static_cast<TPtrList*>(townMarkerList)->GetCountSlot48();
  if (hasItems != 0) {
    static_cast<TPtrList*>(townMarkerList)->Call54();
  }
  static_cast<TPtrList*>(townMarkerList)->Call18();

  int townCount = 0;
  static_cast<TStream*>(stream)->ReadBytes(&townCount, 4);

  if (townCount > 0) {
    int townOrdinal = 1;
    while (townOrdinal <= townCount) {
      void* townMarker = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x20));
      if (townMarker != 0) {
        reinterpret_cast<void(__fastcall*)(void*, int)>(thunk_ConstructFrogCityMarker)(townMarker,
                                                                                       0);
        static_cast<TPtrList*>(townMarker)->Call18();
        static_cast<TPtrList*>(townMarkerList)->AddTail30(townMarker);
      }
      ++townOrdinal;
    }
  }

  if (townCount > 0) {
    this->city->AdoptSelectedOrderSlot44(
        static_cast<TPtrList*>(townMarkerList)->GetTrackedEntrySlot4C());
  }

  void* trackedObjectList = this->trackedObjectList;
  hasItems = static_cast<TPtrList*>(trackedObjectList)->GetCountSlot48();
  if (hasItems != 0) {
    static_cast<TPtrList*>(trackedObjectList)->Call54();
  }
  static_cast<TPtrList*>(trackedObjectList)->Call18();

  int unusedOrderCount = 0;
  static_cast<TStream*>(stream)->ReadBytes(&unusedOrderCount, 4);

  int orderOrdinal = 1;
  while (orderOrdinal < 5) {
    void* civOrderObj = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x20));
    if (civOrderObj != 0) {
      reinterpret_cast<void(__fastcall*)(void*, int)>(thunk_InitializeCivUnitOrderObject)(
          civOrderObj, 0);
      static_cast<TCivWorkOrderState*>(civOrderObj)
          ->InitializeCivWorkOrderState(0, -1, this->nationSlot);
      static_cast<TPtrList*>(civOrderObj)->Call18();
    }
    ++orderOrdinal;
  }

  static_cast<TStream*>(stream)->ReadBytes(&this->diplomacyBudgetBase, 4);
  static_cast<TStream*>(stream)->ReadBytes(&this->escalationCounter, 1);
  static_cast<TStream*>(stream)->ReadBytes(&this->pendingCommitmentCost, 4);
  static_cast<TStream*>(stream)->ReadBytes(&this->pressureCounter, 1);
  static_cast<TStream*>(stream)->ReadBytes(&this->field900, 4);
  static_cast<TStream*>(stream)->ReadBytes(&this->field904, 1);

  if (*reinterpret_cast<int*>(kAddrAdvanceTurnMachineState) > 0x0E) {
    void* missionNodeQueue = this->missionNodeQueue;
    static_cast<TPtrList*>(missionNodeQueue)->Call18(reinterpret_cast<int>(stream));

    int nodeCount = 0;
    static_cast<TStream*>(stream)->ReadBytes(&nodeCount, 4);
    if (nodeCount > 0) {
      int nodeOrdinal = 1;
      while (nodeOrdinal <= nodeCount) {
        unsigned char hasNode = 0;
        char markerOk = static_cast<TStream*>(stream)->ReadByte(&hasNode);
        if (markerOk != 0) {
          static_cast<TPtrList*>(missionNodeQueue)->AddTail30(0);
        }
        ++nodeOrdinal;
      }
    }
  }

  if (*reinterpret_cast<int*>(kAddrAdvanceTurnMachineState) > 0x25) {
    static_cast<TStream*>(stream)->ReadBytes(&this->field910, 4);
    static_cast<TStream*>(stream)->ReadBytes(&this->aidAllocationTotal, 4);
  }
  if (*reinterpret_cast<int*>(kAddrAdvanceTurnMachineState) > 0x2F) {
    static_cast<TStream*>(stream)->ReadBytes(this->colonyBoycottFlags, kNationSlotCount);
  }
  if (*reinterpret_cast<int*>(kAddrAdvanceTurnMachineState) > 0x34) {
    static_cast<TStream*>(stream)->ReadBytes(&this->pendingAidTotal, 4);
  }
}

// FUNCTION: IMPERIALISM 0x004d9c70
void TGreatPower::WriteTo(TStream* stream) {
  (void)stream;
}

// FUNCTION: IMPERIALISM 0x004da3e0
#pragma optimize("y", on)
void TGreatPower::ReadCoreStateAndRecreateCivOrdersFromStream(void* streamState, int unusedArg) {
  (void)unusedArg;
  TStream* stream = static_cast<TStream*>(streamState);
  stream->ReadBytes(&this->encodedNationSlot, 2);
  stream->ReadBytes(&this->treasuryValue10, 4);
  stream->ReadBytes(&this->ownerNationSlot, 4);
  stream->ReadBytes(&this->serializedField8c, 4);

  if (this->trackedObjectList->GetCountSlot48() != 0) {
    this->trackedObjectList->Call54();
  }
  this->trackedObjectList->Call18(reinterpret_cast<int>(streamState));

  int orderCount = stream->ReadShort();
  for (; orderCount > 0; --orderCount) {
    TCivWorkOrderState* civOrder = new TCivWorkOrderState();
    civOrder->InitializeCivWorkOrderState(0, -1, this->nationSlot);
    civOrder->ReadFromStreamSlot18(stream);
  }
}
#pragma optimize("", on)

// --- Slot 0x0a/0x0b stream serialization pair and status-flag slots 0x2b-0x33 ---

// FUNCTION: IMPERIALISM 0x004da500
#pragma optimize("y", on)
void TGreatPower::WriteCoreStateAndTrackedOrdersToStream(void* streamState) {
  TStream* stream = static_cast<TStream*>(streamState);
  stream->WriteBytesSlot78(&this->encodedNationSlot, 2);
  stream->WriteBytesSlot78(&this->treasuryValue10, 4);
  stream->WriteBytesSlot78(&this->ownerNationSlot, 4);
  stream->WriteBytesSlot78(&this->serializedField8c, 4);

  this->trackedObjectList->ResetSlot14(streamState);
  int orderCount = this->trackedObjectList->GetCountSlot48();
  stream->WriteCountSlot88(orderCount);
  for (int ordinal = 1; ordinal <= orderCount; ++ordinal) {
    TUnitOrderState* order = reinterpret_cast<TUnitOrderState*>(
        this->trackedObjectList->GetTrackedEntrySlot4C(ordinal));
    order->WriteToStreamSlot14(stream);
  }
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004da5e0
#pragma optimize("y", on)
void TGreatPower::DispatchPendingStatusPrompts(void) {
  unsigned char* flags = this->serializedStatusFlags;
  char flag5Handled = static_cast<signed char>(flags[5]) >= 0x33;
  if (!flag5Handled &&
      CityOrderCapabilityState()->orderCapRows277[this->nationSlot].flag == 2) {
    UiRuntime_QueueTurnStatusPrompt(5, this->field8d6[5]);
  }
  if (flags[6] == 0x32) {
    UiRuntime_QueueTurnStatusPrompt(6, this->field8d6[6]);
  }
  if (flags[7] == 0x32) {
    if (this->field8d6[7] == 2) {
      TCity* cityPtr = this->city;
      cityPtr->fieldB6[10] = cityPtr->fieldB6[10] + 10;
      cityPtr->Refresh80();
      UiRuntime_QueueTurnStatusPrompt(7, this->field8d6[7]);
    } else if (this->field8d6[7] == 3) {
      TCity* cityPtr = this->city;
      cityPtr->fieldB6[10] = cityPtr->fieldB6[10] + 10;
      cityPtr->Refresh80();
      UiRuntime_QueueTurnStatusPrompt(7, -1);
    }
  }
  if (flags[8] == 0x32) {
    UiRuntime_QueueTurnStatusPrompt(8, this->field8d6[8]);
  }
  if (flags[9] == 0x32) {
    UiRuntime_QueueTurnStatusPrompt(9, this->field8d6[9]);
  }
  if (flags[10] == 0x32) {
    UiRuntime_QueueTurnStatusPrompt(10, this->field8d6[10]);
  }
  if (flags[11] == 0x32) {
    UiRuntime_QueueTurnStatusPrompt(11, this->field8d6[11]);
  }
  if (flags[12] == 0x32) {
    UiRuntime_QueueTurnStatusPrompt(12, this->field8d6[12]);
  }
  if (flags[0] == 0x32) {
    UiRuntime_QueueTurnStatusPrompt(0, CityOrderActiveZoneIndex());
  }
  if (flags[1] == 0x32) {
    UiRuntime_QueueTurnStatusPrompt(1, this->field8d6[1]);
  }
  if (flags[2] == 0x32) {
    UiRuntime_QueueTurnStatusPrompt(2, this->field8d6[2]);
  }
  if (flags[3] == 0x32) {
    UiRuntime_QueueTurnStatusPrompt(3, this->field8d6[3]);
  }
  if (flags[4] == 0x32) {
    UiRuntime_QueueTurnStatusPrompt(4, this->field8d6[4]);
  }
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004da860
#pragma optimize("y", on)
void TGreatPower::MarkStatusFlag5HandledIfCapabilityActive(void) {
  if (CityOrderCapabilityState()->orderCapRows277[this->nationSlot].flag == 2) {
    this->serializedStatusFlags[5] = 0x33;
  }
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004da8a0
#pragma optimize("y", on)
void TGreatPower::MarkAllPendingStatusFlagsHandled(void) {
  unsigned char* flags = this->serializedStatusFlags;
  char flag5Handled = static_cast<signed char>(flags[5]) >= 0x33;
  if (!flag5Handled &&
      CityOrderCapabilityState()->orderCapRows277[this->nationSlot].flag == 2) {
    flags[5] = 0x33;
  }
  if (flags[6] == 0x32) {
    flags[6] = 0x33;
  }
  if (flags[7] == 0x32) {
    if (this->field8d6[7] == 2) {
      flags[7] = 0x33;
    } else if (this->field8d6[7] == 3) {
      flags[7] = 0x34;
      this->field8d6[7] = -1;
    }
  }
  if (flags[8] == 0x32) {
    flags[8] = 0x33;
  }
  if (flags[9] == 0x32) {
    flags[9] = 0x33;
  }
  if (flags[10] == 0x32) {
    flags[10] = 0x33;
  }
  if (flags[11] == 0x32) {
    flags[11] = 0x33;
  }
  if (flags[12] == 0x32) {
    flags[12] = 0x33;
  }
  if (flags[0] == 0x32) {
    flags[0] =
        static_cast<unsigned char>(*reinterpret_cast<char*>(&this->field8d6[0]) + 0x33);
  }
  if (flags[1] == 0x32) {
    flags[1] =
        static_cast<unsigned char>(*reinterpret_cast<char*>(&this->field8d6[1]) + 0x33);
  }
  if (flags[2] == 0x32) {
    flags[2] = 0x33;
  }
  if (flags[3] == 0x32) {
    flags[3] = 0;
  }
  if (flags[4] == 0x32) {
    flags[4] = 0;
  }
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004daa10
#pragma optimize("y", on)
void TGreatPower::SetNationPendingActionStateAndPayload(int index, short payload) {
  if (*reinterpret_cast<int*>(kAddrAdvanceTurnMachineState) != -3) {
    this->serializedStatusFlags[index] = 0x32;
    this->field8d6[index] = payload;
  }
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004daa50
#pragma optimize("y", on)
void TGreatPower::AddNodeToMissionNodeQueue(void* node) {
  this->missionNodeQueue->AddTail30(node);
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004daa80
#pragma optimize("y", on)
void TGreatPower::DispatchMissionNodeCallbacksAndClearQueue(void) {
  CIterator nodeIter(this->missionNodeQueue);
  for (TMissionNodeCallback* node = static_cast<TMissionNodeCallback*>(nodeIter.Reset());
       nodeIter.More(); node = static_cast<TMissionNodeCallback*>(nodeIter.Advance())) {
    node->DispatchSlot28();
  }
  static_cast<TPtrList*>(this->missionNodeQueue)->Call54();
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004dae70
#pragma optimize("y", on)
char TGreatPower::HasTrackedOrderOfType7(void) {
  char found = 0;
  CIterator orderIter(this->trackedObjectList);
  TUnitOrderState* order = static_cast<TUnitOrderState*>(orderIter.Reset());
  if (orderIter.More()) {
    while (order->orderType != 7) {
      order = static_cast<TUnitOrderState*>(orderIter.Advance());
      if (!orderIter.More()) {
        return 0;
      }
    }
    found = 1;
  }
  return found;
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004daf30
void TGreatPower::CompileGreatPowerRelationshipDeltaLinesAndDispatchMessage(void) {
  static const short kNationPriorityOrder[] = {0x0F, 0x0E, 0x0D, 0x10, 0x0C, 0x08, 0x0A, 0x09, 0x0B,
                                               0x06, 0x03, 0x04, 0x05, 0x00, 0x01, 0x02, 0x07, -1};

  if (this->ShouldDispatchImmediatelySlot28_Provisional() != 0) {
    return;
  }

  TLocalizationRuntime* localizationRuntime = g_pLocalizationTable;
  int localeIndex = 0;
  if (localizationRuntime != 0) {
    localeIndex = localizationRuntime->runtimeSubsystemIndex;
  }
  int compileThreshold = ReadGlobalIntStep(kAddrCompileGreatPowerValue, localeIndex);
  if (compileThreshold > static_cast<int>(this->pressureCounter)) {
    return;
  }

  int relationDeltaByNation[0x17];
  for (int idx = 0; idx < 0x17; ++idx) {
    relationDeltaByNation[idx] = 0;
  }

  CString summaryMessageRef;

  int interactionScore = 0;

  const short* nationCursor = kNationPriorityOrder;
  while (*nationCursor != -1) {
    if (interactionScore + this->treasuryValue10 >= 0) {
      break;
    }

    short nationSlot = *nationCursor;
    TCity* cityPtr = this->city;
    if (cityPtr == 0) {
      ++nationCursor;
      continue;
    }

    short* relationDeltaPtr = &cityPtr->fieldB6[nationSlot];
    short relationDelta = *relationDeltaPtr;
    if (relationDelta > 0) {
      *relationDeltaPtr = 0;
      relationDeltaByNation[nationSlot] = static_cast<int>(relationDelta);

      cityPtr->Refresh80();

      void* nationInteractionState = g_pNationInteractionStateManager;
      if (nationInteractionState != 0) {
        interactionScore =
            g_pNationInteractionStateManager->QueryProposalWeightSlot4C(nationSlot);
      }
    }

    ++nationCursor;
  }

  this->AddToNationMetricAtField10(0);

  if (interactionScore > 0) {
    SharedRefPairScope localizedRefs;
    if (localizationRuntime != 0) {
      localizationRuntime->GetString(0x274b, 0, &localizedRefs.first);
      localizationRuntime->GetString(0x274b, static_cast<short>(interactionScore),
                                     &localizedRefs.second);
    }
    thunk_AssignStringSharedRefAndReturnThis();
    thunk_DispatchLocalizedUiMessageWithTemplateA13A0();
  }
}

// FUNCTION: IMPERIALISM 0x004db380
void TGreatPower::UpdateGreatPowerPressureStateAndDispatchEscalationMessage(void) {
  TLocalizationRuntime* localizationRuntime = g_pLocalizationTable;
  int localeIndex = 0;
  if (localizationRuntime != 0) {
    localeIndex = localizationRuntime->runtimeSubsystemIndex;
  }

  int treasuryValue10 = this->treasuryValue10;
  int basePressure = this->SumAidAllocationMatrixAllCells();
  basePressure += static_cast<int>(this->needTargetByType[0x16]) * 200;
  basePressure += static_cast<int>(this->needTargetByType[0x15]) * 500;
  basePressure += this->budgetPoolBase;
  int pressureFloor = ReadGlobalIntStep(kAddrNationBasePressureByLocale, localeIndex);
  if (basePressure < pressureFloor) {
    basePressure = pressureFloor;
  }

  int smoothedPressure = (this->diplomacyBudgetBase * 0x5A + basePressure * 1000) / 100;
  this->diplomacyBudgetBase = smoothedPressure;
  int pressureBand = smoothedPressure / 100;

  if (treasuryValue10 < 0) {
    int halfBand = pressureBand / 2;
    if ((-halfBand == treasuryValue10) || (-treasuryValue10 < halfBand)) {
      this->pressureCounter = 1;
    } else if ((-pressureBand == treasuryValue10) || (-treasuryValue10 < pressureBand)) {
      if (this->pressureCounter > 1) {
        int nextPressureValue =
            static_cast<int>(this->escalationCounter) +
            static_cast<int>(ReadLocaleByteStep(kAddrGreatPowerPressureRiseStep, localeIndex));
        int pressureRiseCap = ReadGlobalIntStep(kAddrGreatPowerPressureRiseCap, localeIndex);
        if (nextPressureValue > pressureRiseCap) {
          nextPressureValue = pressureRiseCap;
        }
        this->escalationCounter = static_cast<signed char>(nextPressureValue);
      }
      this->pressureCounter = 2;
    } else {
      CString sharedMessageRef;
      int nextPressureValue =
          static_cast<int>(this->escalationCounter) +
          static_cast<int>(ReadLocaleByteStep(kAddrGreatPowerPressureRiseStep, localeIndex));
      int pressureRiseCap = ReadGlobalIntStep(kAddrGreatPowerPressureRiseCap, localeIndex);
      if (nextPressureValue > pressureRiseCap) {
        nextPressureValue = pressureRiseCap;
      }
      this->escalationCounter = static_cast<signed char>(nextPressureValue);

      if (this->pressureCounter < 3) {
        this->pressureCounter = 3;
      } else {
        this->pressureCounter = static_cast<signed char>(this->pressureCounter + 1);
      }

      int pressureTier = static_cast<int>(this->pressureCounter);
      int hardThreshold = ReadGlobalIntStep(kAddrGreatPowerPressureHardAlertThreshold, localeIndex);
      int compileThreshold = ReadGlobalIntStep(kAddrCompileGreatPowerValue, localeIndex);

      if (hardThreshold <= pressureTier) {
        if (localizationRuntime != 0) {
          localizationRuntime->GetString(0x274b, 4, &sharedMessageRef);
        }
        thunk_AssignStringSharedRefAndReturnThis();
        thunk_DispatchLocalizedUiMessageWithTemplateA13A0();
        return;
      }

      if (pressureTier < compileThreshold) {
        if (localizationRuntime != 0) {
          int statusId = (pressureTier == (compileThreshold - 1)) ? 3 : 2;
          localizationRuntime->GetString(
              0x274b, static_cast<short>(statusId),
              reinterpret_cast<void*>(kAddrShGreatPowerPressureMessageRef));
        }
        DispatchQuarterlyGreatPowerPressureMessage(1);
      } else {
        if (localizationRuntime != 0) {
          localizationRuntime->GetString(
              0x274b, 1, reinterpret_cast<void*>(kAddrShGreatPowerPressureMessageRef));
        }
        DispatchQuarterlyGreatPowerPressureMessage(2);
      }
    }
  } else {
    if (this->pressureCounter != 0) {
      int nextPressureValue =
          static_cast<int>(this->escalationCounter) -
          static_cast<int>(ReadLocaleByteStep(kAddrGreatPowerPressureDecayStep, localeIndex));
      int pressureMinFloor = ReadGlobalIntStep(kAddrGreatPowerPressureMinFloor, localeIndex);
      if (nextPressureValue < pressureMinFloor) {
        nextPressureValue = pressureMinFloor;
      }
      this->escalationCounter = static_cast<signed char>(nextPressureValue);
      this->pressureCounter = 0;
    }
  }

  treasuryValue10 = this->treasuryValue10;
  if (treasuryValue10 >= 0) {
    this->field900 = 0;
    return;
  }

  int drainAmount = (0xC7 - static_cast<int>(this->escalationCounter) * treasuryValue10) / 200;
  this->field900 = drainAmount;
  this->treasuryValue10 = treasuryValue10 - drainAmount;
}

// FUNCTION: IMPERIALISM 0x004db7d0
#pragma optimize("y", on)
void TGreatPower::BuildTransportLinkedInfluenceMap(char** outInfluenceMap) {
  if (this->city == 0) {
    return;
  }
  char* influenceMap = reinterpret_cast<char*>(AllocateWithFallbackHandler(0x1950));
  if (influenceMap == 0) {
    GAME_FAIL_NIL_POINTER();
    TemporarilyClearAndRestoreUiInvalidationFlag(kUCountryCppPath, 0xa0e);
  }
  memset(influenceMap, 0, 0x1950);

  CIterator markerCursor(this->townMarkerList);
  TTownMarker* marker = static_cast<TTownMarker*>(markerCursor.Reset());
  while (markerCursor.More() != 0 &&
         static_cast<int>(marker->regionId14) != *GreatPower_HomeRegionIndex88(this)) {
    marker = static_cast<TTownMarker*>(markerCursor.Advance());
  }
  char homeLinked = static_cast<TTownMarker*>(marker)->IsTransportLinkedAndEnabled();
  if (homeLinked == 0) {
    this->MarkConnectedOwnedRegionsFrom(reinterpret_cast<unsigned char*>(influenceMap),
                                        marker->regionId14);
    marker = static_cast<TTownMarker*>(markerCursor.Reset());
    while (markerCursor.More() != 0 && homeLinked == 0) {
      if (influenceMap[marker->regionId14] != 0 &&
          static_cast<TTownMarker*>(marker)->IsTransportLinkedAndEnabled() != 0) {
        homeLinked = 1;
      }
      marker = static_cast<TTownMarker*>(markerCursor.Advance());
    }
  }
  marker = static_cast<TTownMarker*>(markerCursor.Reset());
  while (markerCursor.More() != 0) {
    if (static_cast<TTownMarker*>(marker)->IsTransportLinkedAndEnabled() != 0 && homeLinked != 0 &&
        marker->activeFlag4f != 0 && influenceMap[marker->regionId14] == 0) {
      this->MarkConnectedOwnedRegionsFrom(reinterpret_cast<unsigned char*>(influenceMap),
                                          marker->regionId14);
    }
    marker = static_cast<TTownMarker*>(markerCursor.Advance());
  }
  marker = static_cast<TTownMarker*>(markerCursor.Reset());
  while (markerCursor.More() != 0) {
    if ((influenceMap[marker->regionId14] == 0 || marker->activeFlag4f == 0) &&
        (static_cast<TTownMarker*>(marker)->IsTransportLinkedAndEnabled() == 0 || homeLinked == 0)) {
      marker->transportLinkedFlag4c = 0;
    } else {
      marker->transportLinkedFlag4c = 1;
    }
    marker = static_cast<TTownMarker*>(markerCursor.Advance());
  }
  if (outInfluenceMap != 0) {
    marker = static_cast<TTownMarker*>(markerCursor.Reset());
    while (markerCursor.More() != 0) {
      if (static_cast<TTownMarker*>(marker)->IsTransportLinkedAndEnabled() != 0 && homeLinked != 0) {
        influenceMap[marker->regionId14] = 1;
      }
      marker = static_cast<TTownMarker*>(markerCursor.Advance());
    }
    *outInfluenceMap = influenceMap;
    return;
  }
  FreeHeapBufferIfNotNull(reinterpret_cast<undefined4>(influenceMap));
}
#pragma optimize("", on)

// --- Slots 0x35/0x37/0x50/0x51/0x55-0x57 ---

// FUNCTION: IMPERIALISM 0x004dbac0
#pragma optimize("y", on)
void TGreatPower::MarkConnectedOwnedRegionsFrom(unsigned char* regionMap, short regionId) {
  short nextRegion;
  do {
    regionMap[regionId] = 1;
    nextRegion = 0;
    char adjacencyBits = g_pGlobalMapState->terrainStateTable[regionId].adjacencyBits06;
    for (short direction = 0; direction < 6; ++direction) {
      if ((adjacencyBits & (1 << direction)) != 0) {
        short neighbor =
            TGlobalMapState::GetWrappedHexNeighborTileIndexByDirection(regionId, direction);
        if (static_cast<short>(g_pGlobalMapState->terrainStateTable[neighbor].ownerNationTag04) ==
                this->nationSlot &&
            regionMap[neighbor] == 0) {
          if (nextRegion != 0) {
            this->MarkConnectedOwnedRegionsFrom(regionMap, neighbor);
          } else {
            nextRegion = neighbor;
          }
        }
      }
    }
    regionId = nextRegion;
  } while (nextRegion != 0 && regionMap[nextRegion] == 0);
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004dbd20
void TGreatPower::RebuildNationResourceYieldCountersAndDevelopmentTargets(void) {
  const int kMapRegionSlotCount = 0x1950;

  short* currentNeedByType = this->needCurrentByType;
  short* developmentByType = &this->needCurrentByType[7]; // +0x11c overlays this runtime array.
  short* targetNeedByType = this->needTargetByType;
  short& controlledRegionCount = this->needCurrentByType[0x13]; // +0x134
  // TEMP: 0x004dbbb0 (BuildCityInfluenceLevelMap) is still an autogen stub; call it
  // through the generic thunk declaration until it is ported as a real member.
  char* influenceByRegion = reinterpret_cast<char*>(BuildCityInfluenceLevelMap());
  TGlobalMapState* globalMapState = g_pGlobalMapState;
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
                  globalMapState->CallMetricSlotC4(regionIndex, edgeIndex);
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
  TPtrList* regionList = this->ownedRegionList;
  if (regionList == 0) {
    return;
  }

  int totalRegions = regionList->GetCountOrReleaseSlot28();
  int regionOrdinal = 1;
  while (regionOrdinal <= totalRegions) {
    short regionId = static_cast<short>(regionList->GetIntByOrdinalSlot24(regionOrdinal));
    unsigned char pendingStage = 0;
    unsigned char needsRedraw = 0;

    TGlobalMapState* globalMapState = g_pGlobalMapState;
    TLocalizationRuntime* localizationRuntime = g_pLocalizationTable;
    if (globalMapState != 0 && localizationRuntime != 0 && globalMapState->cityScoreTable != 0 &&
        globalMapState->terrainStateTable != 0) {
      TGlobalMapCityScoreRecord* cityTable =
          globalMapState->cityScoreTable;
      TTerrainStateRecordView* terrainTable =
          globalMapState->terrainStateTable;
      TGlobalMapCityScoreRecord* cityRecord = cityTable + regionId;
      short ownerSlot = this->ownerNationSlot;
      if (cityRecord->ownerNationSlot != ownerSlot) {
        unsigned int turnDelta = static_cast<unsigned int>(
            static_cast<int>(localizationRuntime->GetTurnTickSlot3C()) -
            static_cast<int>(cityRecord->lastTurnTick));

        if (turnDelta > 4) {
          int resourceSums[kNationSlotCount];
          int i = 0;
          while (i < kNationSlotCount) {
            resourceSums[i] = 0;
            ++i;
          }

          int linkedCount = cityRecord->linkedRegionCount;
          int linkedIndex = 0;
          while (linkedIndex < linkedCount) {
            short linkedRegion = cityRecord->linkedRegionIds[linkedIndex];
            int edge = 0;
            while (edge < 2) {
              signed char resourceType = terrainTable[linkedRegion].resourceTypeByEdge[edge];
              if (resourceType != -1) {
                resourceSums[resourceType] += static_cast<int>(
                    globalMapState->CallMetricSlotC4(linkedRegion, edge));
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
              int prod = this->city->GetBuildingProductionValueBySlot( 1);
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
              int prod = this->city->GetBuildingProductionValueBySlot( 5);
              int prodLimit = (prod + ((prod >> 0x1f) & 3U)) >> 2;
              if (static_cast<int>(*stage1CounterB) < prodLimit &&
                  static_cast<int>(*stage1CounterB) < resourceSums[2] / 2) {
                pendingStage = 1;
                *stage1CounterB = static_cast<short>(*stage1CounterB + 1);
                needsRedraw = 1;
              }
            }

            if (resourceSums[3] != 0) {
              int prod = this->city->GetBuildingProductionValueBySlot( 3);
              int prodLimit = (prod + ((prod >> 0x1f) & 3U)) >> 2;
              if (static_cast<int>(*stage1CounterC) < prodLimit &&
                  static_cast<int>(*stage1CounterC) < resourceSums[3] / 2) {
                pendingStage = 1;
                *stage1CounterC = static_cast<short>(*stage1CounterC + 1);
                needsRedraw = 1;
              }
            }

            TCityOrderCapabilityState* orderCapabilityState = CityOrderCapabilityState();
            int capabilityScore = this->city->GetBuildingProductionValueBySlot( 7);
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
            g_pGlobalMapState->SetRegionDevelopmentStageByte(regionId, pendingStage);
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

// FUNCTION: IMPERIALISM 0x004dc440
#pragma optimize("y", on)
char TGreatPower::HasAnyCommodityRecordBelowStepValue(void) {
  NationCityTradeState* tradeCity = GetNationTradeCityState(this);
  if (tradeCity->scenarioTradeDescriptor->valueAt1C <= 1) {
    return 0;
  }
  for (int recordIndex = 8; recordIndex < 0xd; ++recordIndex) {
    TradeCommodityMetricRecord* record =
        tradeCity->tradeCommodityRecordPtrs[static_cast<short>(recordIndex)];
    short controlValue = record->controlValue;
    if (reinterpret_cast<TCommodityRecordStepView*>(record)->GetStepValueSlot30() > controlValue) {
      return 1;
    }
  }
  return 0;
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004dc4c0
#pragma optimize("y", on)
short TGreatPower::ComputeTreasuryStatusPromptCode(void) {
  int dispatchCounter = g_pDiplomacyTurnStateManager->proposalDispatchCounter790;
  short promptCode = 0;
  int turnTick = g_pLocalizationTable->GetTurnTickSlot3C();
  if (dispatchCounter == 0 && turnTick == 3) {
    promptCode = 0x25;
    return promptCode;
  }
  if (dispatchCounter - turnTick > 4 && this->treasuryValue10 >= 10000) {
    promptCode = 0x27;
  }
  return promptCode;
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004dc540
char TGreatPower::CompareMissionScoreVariantsByMode(int mode) {
  if (mode == 0) {
    int nodeContext = this->GetHomeRegionCityRecordIndex();
    float localScore = TDefendProvinceMission::ComputeLocalSupportVectorScore(nodeContext);
    float crossNationScore = TDefendProvinceMission::ComputeCrossNationSupportVectorScore(nodeContext);
    if (localScore < crossNationScore) {
      return 0;
    }
    return 1;
  } else {
    TZone* portZoneContext = TZone::FindFirstPortZoneContextByNation(this->nationSlot);

    if (portZoneContext->portZoneEntryCount2c <= 0) {
      void* resizedEntries =
          ReallocateBufferWithAllocatorTracking(portZoneContext->portZoneEntries28, 8);
      if (resizedEntries == 0) {
        resizedEntries =
            ReallocateBufferWithAllocatorTracking(portZoneContext->portZoneEntries28, 4);
        portZoneContext->portZoneEntries28 = static_cast<int*>(resizedEntries);
        portZoneContext->portZoneEntryCount2c = 1;
      } else {
        portZoneContext->portZoneEntries28 = static_cast<int*>(resizedEntries);
        portZoneContext->portZoneEntryCount2c = 2;
      }
    }
    if (portZoneContext->portZoneActiveEntryCount30 <= 0) {
      portZoneContext->portZoneActiveEntryCount30 = 1;
    }

    int firstEntry = portZoneContext->portZoneEntries28[0];

    float exactSourceScore =
        TNavyMission::ComputeOrderDistributionSimilarityScoreForExactSourceNation(this->nationSlot,
                                                                                  firstEntry);
    float diplomacyFilteredScore =
        TNavyMission::ComputeOrderDistributionSimilarityScoreWithDiplomacyFilter(this->nationSlot,
                                                                                 firstEntry);
    if (exactSourceScore < diplomacyFilteredScore) {
      return 0;
    }
    return 1;
  }
}

// FUNCTION: IMPERIALISM 0x004dc660
void TGreatPower::BuildGreatPowerMapContextTriggeredNationEventMessages(void) {
  void* diplomacyManager = g_pDiplomacyTurnStateManager;
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
        IsNationSlotEligibleForEventProcessing(nationSlot) != 0) {
      hasEligibleForeignNation = true;
      break;
    }
  }
  if (!hasEligibleForeignNation) {
    return;
  }

  TZone* contextEntry = static_cast<TZone*>(g_pMapActionContextListHead);
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
        unsigned int contextMask = contextEntry->field10;
        if ((contextMask & nationMask) != 0 && (contextMask & selfMask) == 0) {
          CString contextRef;
          CString messageRef;
          contextEntry->AssignZoneDisplayNameToOutputRef(&contextRef);
          emittedMessage = true;
          break;
        }
      }
      if (emittedMessage) {
        contextEntry = contextEntry->prev18;
        continue;
      }
    }
    contextEntry = contextEntry->prev18;
  }
}

// FUNCTION: IMPERIALISM 0x004dc840
void TGreatPower::BuildGreatPowerEligibleNationEventMessagesFromLinkedList(void) {
  void* diplomacyManager = g_pDiplomacyTurnStateManager;
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
        IsNationSlotEligibleForEventProcessing(nationSlot) != 0) {
      hasEligibleForeignNation = true;
      break;
    }
  }
  if (!hasEligibleForeignNation) {
    return;
  }

  TPtrList* townMarkerList = this->townMarkerList;
  if (townMarkerList == 0) {
    return;
  }

  CIterator cursor(townMarkerList);
  cursor.Reset();
  while (cursor.More()) {
    TTownMarker* marker = static_cast<TTownMarker*>(cursor.current);
    if (marker != 0 && marker->enabledFlag4d != 0 && marker->transportLinkedFlag4c == 0) {
      CString messageRef;
      CString scratchRef;
      thunk_AssignSharedStringFromIndexedA8EntryNameField();
      scratchRef = CString("\n") + messageRef;
      scratchRef += messageRef;
    }
    cursor.Advance();
  }
}

// FUNCTION: IMPERIALISM 0x004dc9f0
void TGreatPower::RefreshGreatPowerRelationPanelsAndDispatchDeltaSummary(void) {
  if (this->city == 0) {
    return;
  }

  this->RebuildNationResourceYieldCountersAndDevelopmentTargets();
  this->AdvanceOwnedRegionDevelopmentCountersAndDispatchEvents();
  this->ApplyNationResourceNeedTargetsToOrderState();
  this->CompileGreatPowerRelationshipDeltaLinesAndDispatchMessage();
  this->city->Call28();
  this->NoOpNationPendingActionHook();
}

// FUNCTION: IMPERIALISM 0x004dca60
#pragma optimize("y", on)
void TGreatPower::NotifyCitySlot2C(void) {
  TCity* cityPtr = this->city;
  if (cityPtr != 0) {
    cityPtr->Call2C();
  }
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004dcaa0
#pragma optimize("y", on)
unsigned int TGreatPower::GetEffectiveDiplomacyCounterA2ForCode(int proposalCode) {
  if (this->foreignMinister->capabilityFlag26 != 0) {
    if (g_pNationInteractionStateManager->IsCapabilityCategoryActiveSlot3C(4) != 0) {
      if (static_cast<short>(proposalCode) == 4) {
        return static_cast<unsigned short>(this->diplomacyCounterA2);
      }
      short resolvedCode =
          g_pNationInteractionStateManager->ResolveProposalCodeForCategorySlot84(proposalCode, 4);
      if (resolvedCode == static_cast<short>(proposalCode)) {
        int reducedCounter = static_cast<int>(this->diplomacyCounterA2) - 2;
        return reducedCounter & (static_cast<int>(reducedCounter < 1) - 1);
      }
      return static_cast<unsigned short>(this->diplomacyCounterA2);
    }
  }
  if (this->foreignMinister->capabilityFlag28 != 0) {
    if (g_pNationInteractionStateManager->IsCapabilityCategoryActiveSlot3C(5) != 0) {
      if (static_cast<short>(proposalCode) == 5) {
        return static_cast<unsigned short>(this->diplomacyCounterA2);
      }
      short resolvedCode =
          g_pNationInteractionStateManager->ResolveProposalCodeForCategorySlot84(proposalCode, 5);
      if (resolvedCode == static_cast<short>(proposalCode)) {
        int reducedCounter = static_cast<int>(this->diplomacyCounterA2) - 2;
        return reducedCounter & (static_cast<int>(reducedCounter < 1) - 1);
      }
      return static_cast<unsigned short>(this->diplomacyCounterA2);
    }
  }
  if (this->foreignMinister->capabilityFlag24 != 0 &&
      g_pNationInteractionStateManager->IsCapabilityCategoryActiveSlot3C(3) != 0) {
    if (static_cast<short>(proposalCode) != 3) {
      short resolvedCode =
          g_pNationInteractionStateManager->ResolveProposalCodeForCategorySlot84(proposalCode, 3);
      if (resolvedCode == static_cast<short>(proposalCode)) {
        int reducedCounter = static_cast<int>(this->diplomacyCounterA2) - 2;
        return reducedCounter & (static_cast<int>(reducedCounter < 1) - 1);
      }
      if (static_cast<short>(proposalCode) != 3) {
        return static_cast<unsigned short>(this->diplomacyCounterA2);
      }
    }
    if (this->foreignMinister->capabilityFlag26 != 0) {
      int reducedCounter = static_cast<int>(this->diplomacyCounterA2) - 1;
      return reducedCounter & (static_cast<int>(reducedCounter < 1) - 1);
    }
  }
  return static_cast<unsigned short>(this->diplomacyCounterA2);
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004dcc50
void TGreatPower::ApplyDiplomacyState222ToCityFieldB6AndClear(void) {
  for (short nationSlot = 0; nationSlot < kNationSlotCount; ++nationSlot) {
    this->AddToCityFieldB6AndRefresh(nationSlot, this->diplomacyState222[nationSlot]);
    this->diplomacyState222[nationSlot] = 0;
  }
}

// FUNCTION: IMPERIALISM 0x004dcca0
void TGreatPower::ApplyRelationDeltaToCityFieldB6AndUpdateState1f4(void) {
  for (short nationSlot = 0; nationSlot < kNationSlotCount; ++nationSlot) {
    this->AddToCityFieldB6AndRefresh(nationSlot, this->relationDeltaCurrent[nationSlot]);
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

  TCity* cityPtr = this->city;
  if (cityPtr != 0) {
    cityPtr->fieldB6[0x15] = 0;
    cityPtr->Refresh80();
  }

  this->AddToNationMetricAtField10(static_cast<int>(this->needTargetByType[0x16]) * 200);

  if (cityPtr != 0) {
    cityPtr->fieldB6[0x16] = 0;
    cityPtr->Refresh80();
  }

  for (int needIndex = 0; static_cast<short>(needIndex) < kNationSlotCount; ++needIndex) {
    this->AddToCityFieldB6AndRefresh(static_cast<short>(needIndex),
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
  if (this->GetDiplomacyExternalStateB6ByTarget(9) != 0) {
    if (this->GetDiplomacyExternalStateB6ByTarget(0xb) != 0) {
      this->AddToCityFieldB6AndRefresh(9, -1);
      this->AddToCityFieldB6AndRefresh(0xb, -1);
      this->needCapA6 = static_cast<short>(this->needCapA6 + 1);
      return 1;
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004dcfd0
short TGreatPower::TryDecayRelationNeedScores9And8(void) {
  if (this->GetDiplomacyExternalStateB6ByTarget(9) > 2) {
    if (this->GetDiplomacyExternalStateB6ByTarget(8) != 0) {
      this->AddToCityFieldB6AndRefresh(9, -3);
      this->AddToCityFieldB6AndRefresh(8, -1);
      this->tradeCapacity = static_cast<short>(this->tradeCapacity + 1);
      return 1;
    }
  }
  return 0;
}
#pragma optimize("y", on)

// FUNCTION: IMPERIALISM 0x004dd040
void TGreatPower::ResetDiplomacyLevelForNationSlot12_Provisional(int targetNationSlot,
                                                                 int resetLevel) {
  short nation = static_cast<short>(targetNationSlot);
  if (nation != this->nationSlot &&
      static_cast<short>(resetLevel) != this->needLevelByNation[nation]) {
    this->needLevelByNation[nation] = static_cast<short>(resetLevel);
  }
  if (this->diplomacyEligibilityA0 != 0) {
    InvokeDiplomacyPolicyStateChangedHook(-1, targetNationSlot, 1);
  }
  if (resetLevel == 300) {
    this->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(targetNationSlot, -1);
  }
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004dd0c0
void TGreatPower::SetDiplomacyColonyBoycottFlagForTargetAndRefreshMinorNations(
    int targetNationSlot, int isBoycottEnabled) {
  unsigned char boycottFlag = static_cast<unsigned char>(isBoycottEnabled);
  int policyValue = ((-(int)(boycottFlag != 0)) & 0xC8) + 0x64;
  this->colonyBoycottFlags[targetNationSlot] = boycottFlag;

  for (int secondarySlot = kMajorNationCount; secondarySlot < kNationSlotCount; ++secondarySlot) {
    TMinor* secondaryState = g_apSecondaryNationStateSlots[secondarySlot];
    char hasNationFlag = secondaryState->HasMinorStandingLinkSlot5C(this->nationSlot);
    if (hasNationFlag != 0) {
      secondaryState->SetDiplomacyStandingSlot48(targetNationSlot, policyValue);
    }
  }
}

#pragma optimize("y", on)

// FUNCTION: IMPERIALISM 0x004dd140
void TGreatPower::RecomputeDiplomacyAidBudgetScoreFromResourceWeights(void) {
  int total = 0;
  for (int resourceType = 0; resourceType < 0x0E; ++resourceType) {
    short resourceWeight = GetResourceDescriptorWeightWord0ByType(static_cast<short>(resourceType));
    short relationWeight = *reinterpret_cast<short*>(
        reinterpret_cast<unsigned char*>(this->city) + 0x5C + resourceType * 2);
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

    short needScore = this->GetDiplomacyExternalStateB6ByTarget(nationIndex);
    if (needScore < this->diplomacyState1c6[nationIndex]) {
      this->diplomacyState1c6[nationIndex] = this->GetDiplomacyExternalStateB6ByTarget(nationIndex);
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

    short needScore = this->GetDiplomacyExternalStateB6ByTarget(nationIndex);
    if (needScore < this->diplomacyState1c6[nationIndex]) {
      this->diplomacyState1c6[nationIndex] = this->GetDiplomacyExternalStateB6ByTarget(nationIndex);
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
    if (trackedObject != 0) {
      static_cast<TTrackedObject*>(trackedObject)->Release1C();
    }
  }
}

// FUNCTION: IMPERIALISM 0x004dd340
void TGreatPower::AddAmountToAidAllocationMatrixCellAndTotal(int amount, short columnIndex,
                                                             short rowIndex) {
  this->AddToNationMetricAtField10(amount);
  int index =
      static_cast<int>(rowIndex) * kAidAllocationColumnCount + static_cast<int>(columnIndex);
  this->aidAllocationMatrix[index] += amount;
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
  int baseBudget = this->SumAidAllocationMatrixAllCells();
  return baseBudget + this->budgetPoolBase + this->budgetPoolDelta - pendingAdjustments -
         outstandingCommitments;
}

// FUNCTION: IMPERIALISM 0x004dd470
void TGreatPower::ResetDiplomacyNeedSlots7012AndRefreshIfModeGateMatches(void) {
  TLocalizationRuntime* localizationTable =
      g_pLocalizationTable;
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
      this->foreignMinister->Call8C();
    }
    return;
  }

  void* diplomacyManager = g_pDiplomacyTurnStateManager;
  bool hasUnfilledNeedSlot = false;
  for (int needSlot = kNeedSlotStart; needSlot < kNeedSlotEndExclusive; ++needSlot) {
    if (this->QueryNationMetricBySlot7C(needSlot) < 0) {
      hasUnfilledNeedSlot = true;
    }
  }

  if (hasUnfilledNeedSlot) {
    short selectedNation = static_cast<short>(-1);
    TSortedByRelationshipList* relationshipList = AllocateSortedByRelationshipListWithMode(0);
    if (diplomacyManager != 0 && relationshipList != 0) {
      g_pDiplomacyTurnStateManager->BuildRelationshipListSlot88(this->nationSlot, 1,
                                                                relationshipList);
    }

    for (int needSlot = kNeedSlotStart; needSlot < kNeedSlotEndExclusive; ++needSlot) {
      if (this->QueryNationMetricBySlot7C(needSlot) < 0) {
        int listIndex = CPtrArray_GetCount(relationshipList);
        if (selectedNation < 0) {
          while (listIndex >= 1) {
            selectedNation =
                IndexAndRankList_GetShortValueByOrdinal1Based(relationshipList, listIndex);
            --listIndex;
            TGreatPower* candidateState = g_apNationStates[selectedNation];
            if (candidateState != 0 && candidateState->diplomacyEligibilityA0 != 0) {
              selectedNation = static_cast<short>(-1);
            }
            if (selectedNation >= 0) {
              break;
            }
          }
        }

        if (selectedNation >= 0) {
          TGreatPower* selectedNationState = g_apNationStates[selectedNation];
          if (selectedNationState != 0) {
            selectedNationState->AssignNeedSlotFromSourceSlot19C(needSlot, this->nationSlot);
          }
        }
      }
    }

    if (relationshipList != 0) {
      relationshipList->ReleaseSlot24();
    }
  }

  if (this->QueryNationMetricBySlot7C(kNeedSlotFallback) == -1) {
    bool foundFallbackNation = false;
    int fallbackNationSlot = -1;
    while (!foundFallbackNation) {
      fallbackNationSlot = static_cast<int>(GenerateThreadLocalRandom15Value() % 7);
      if (IsNationSlotEligibleForEventProcessing(fallbackNationSlot) != 0 &&
          g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(fallbackNationSlot,
                                                                  this->nationSlot) == 0 &&
          fallbackNationSlot != this->nationSlot) {
        foundFallbackNation = true;
      }
    }

    TGreatPower* fallbackNationState = g_apNationStates[fallbackNationSlot];
    if (fallbackNationState != 0) {
      fallbackNationState->AssignNeedSlotFromSourceSlot19C(kNeedSlotFallback, this->nationSlot);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004dd740
short TGreatPower::GetDiplomacyExternalStateB6ByTarget(short targetNationSlot) {
  TCity* cityPtr = this->city;
  if (cityPtr == 0) {
    return 0;
  }
  return cityPtr->fieldB6[targetNationSlot];
}

// FUNCTION: IMPERIALISM 0x004dd770
void TGreatPower::SetCityFieldB6AndRefresh(short targetSlot, short value) {
  TCity* cityPtr = this->city;
  cityPtr->fieldB6[targetSlot] = value;
  cityPtr->Refresh80();
}

// FUNCTION: IMPERIALISM 0x004dd7b0
void TGreatPower::AddToCityFieldB6AndRefresh(short targetSlot, short value) {
  TCity* cityPtr = this->city;
  cityPtr->fieldB6[targetSlot] =
      static_cast<short>(cityPtr->fieldB6[targetSlot] + value);
  cityPtr->Refresh80();
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004dd7f0
#pragma optimize("y", on)
unsigned int TGreatPower::ComputeProductionMetricForOrderKind(short orderKind) {
  switch (orderKind) {
  case 0:
  case 1: {
    int production = this->city->GetBuildingProductionValueBySlot( 0);
    return production + production;
  }
  case 2: {
    int production = this->city->GetBuildingProductionValueBySlot( 4);
    return production + production;
  }
  case 3:
  case 4:
    return this->city->GetBuildingProductionValueBySlot( 2);
  case 6: {
    int production = this->city->GetBuildingProductionValueBySlot( 6);
    return production + production;
  }
  case 8: {
    int production = this->city->GetBuildingProductionValueBySlot( 1);
    return production + production;
  }
  case 9:
  case 10: {
    int production = this->city->GetBuildingProductionValueBySlot( 5);
    return production + production;
  }
  case 0xb: {
    int production = this->city->GetBuildingProductionValueBySlot( 3);
    return production + production;
  }
  case 0xc: {
    int production = this->city->GetBuildingProductionValueBySlot( 0xb);
    return production + production;
  }
  case 7: {
    short* summary = this->city->GetCitySummaryRecordSlot74();
    TCity* city = this->city;
    short available =
        static_cast<short>(((((summary[0x14] + summary[0x12] + summary[0x11]) - city->fieldB6[7]) -
                             city->fieldB6[0x14]) -
                            city->fieldB6[0x11]) -
                           city->fieldB6[0x12]);
    if (available >= 0) {
      return static_cast<unsigned short>(available);
    }
    return 0;
  }
  case 5:
  case 0xd:
  case 0xe:
  case 0xf:
  case 0x10:
    return 0;
  default:
    return orderKind;
  }
}
#pragma optimize("", on)
#pragma optimize("y", on)

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
  TInterNationEventQueueManager* queueManager =
      g_pInterNationEventQueueManager;
  if (queueManager != 0) {
    queueManager->QueueInterNationEventType0FWithBitmaskMerge(
        this->nationSlot, sourceNationSlot, targetNationSlot, '\0');
  }
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
        reinterpret_cast<TUiRuntimeContext*>(g_pUiRuntimeContext);
    uiRuntimeContext->DispatchDecisionSlot98(this->nationSlot, arg2, arg3, arg4);
    return 1;
  }

  this->AppendTrackedSlotEntry(1, arg1, 0, static_cast<short>(arg4), 0);
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
void TGreatPower::ClearDiplomacyState1c6ForTarget(short targetSlot) {
  this->diplomacyState1c6[targetSlot] = 0;
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

// FUNCTION: IMPERIALISM 0x004ddd90
#pragma optimize("y", on)
void TGreatPower::AppendTrackedSlotEntry(short kind, int targetNation, short value, short slotIndex,
                                         int payload) {
  TrackedSlotEntryPacket packet;
  packet.payload = payload;
  packet.kind = kind;
  packet.targetNation = static_cast<short>(targetNation);
  packet.value = value;
  if (kind == 1 ||
      (kind == 0 && g_pDiplomacyTurnStateManager->HasFlag84ForNationSlot84(targetNation) == 0)) {
    packet.eligibility = 1;
  } else {
    packet.eligibility = 0;
  }
  this->diplomacyTrackedSlots[slotIndex]->WritePackedIntSlot38(reinterpret_cast<int*>(&packet));
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004dde30
char TGreatPower::AnyTrackedSlotEntryHasZeroField4(short targetSlot) {
  char found = 0;
  for (short entryIndex = 1; found == 0; ++entryIndex) {
    TQueueObject* trackedSlot = this->diplomacyTrackedSlots[targetSlot];
    if (entryIndex > trackedSlot->GetEntryCount()) {
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
  return static_cast<short>(this->diplomacyTrackedSlots[targetSlot]->GetEntryCount());
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004ddeb0
#pragma optimize("y", on)
void TGreatPower::ReadTrackedSlotEntryFields(short slotIndex, short ordinal, short* outKind,
                                             short* outValue, short* outTargetNation,
                                             int* outPayload) {
  TrackedSlotEntryPacket* entry = static_cast<TrackedSlotEntryPacket*>(
      this->diplomacyTrackedSlots[slotIndex]->GetEntryAt1BasedSlot2C(ordinal));
  *outKind = entry->kind;
  *outTargetNation = entry->targetNation;
  *outValue = entry->value;
  *outPayload = entry->payload;
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004ddf20
void TGreatPower::AssignPayloadToTrackedSlotEntryMatchingField2(int targetSlot, int matchKey,
                                                                int payload) {
  bool matched = false;
  for (int entryIndex = 1; !matched; ++entryIndex) {
    TQueueObject* trackedSlot = this->diplomacyTrackedSlots[targetSlot];
    if (entryIndex > trackedSlot->GetEntryCount()) {
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
bool TGreatPower::ApplyDiplomacyPolicyStateForTargetWithCostChecks(int arg1, int arg2) {
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
    if (g_pDiplomacyTurnStateManager->LookupOrderCompatibilityMatrixValue(this->nationSlot,
                                                                       targetClass) != 2) {
      shouldApply = 0;
    }
    goto APPLY_POLICY_IF_ALLOWED;
  }

  switch (policyCode - (kPolicyRequiresCompatibilityStart + 1)) {
  case 0:
  case 1:
    if (g_pDiplomacyTurnStateManager->LookupOrderCompatibilityMatrixValue(this->nationSlot,
                                                                          targetClass) != 2) {
      shouldApply = 0;
    }
    break;

  case 3: {
    TLocalizationRuntime* localizationTable = g_pLocalizationTable;
    if (localizationTable != 0 && localizationTable->mode == 6) {
      this->ApplyDiplomacyRelationCodeAndNotifyThirdPartySlot284(targetClass, 4, -1);
    }

    void* diplomacyManager = g_pDiplomacyTurnStateManager;
    short relationTier =
        g_pDiplomacyTurnStateManager->GetRelationTierSlot70(targetClass, this->nationSlot);
    if (relationTier == 2) {
      g_pDiplomacyTurnStateManager->ApplyRelationCode4Slot7c(this->nationSlot, targetClass, 1);
    }

    void* terrainDescriptor =
        g_apTerrainTypeDescriptorTable[targetClass];
    if (terrainDescriptor != 0) {
      const TTerrainDescriptor* terrain = static_cast<const TTerrainDescriptor*>(terrainDescriptor);
      short encodedNationSlot = terrain->encodedNationSlot0e;
      if (encodedNationSlot > 199) {
        int resolvedNationSlot = DecodeTerrainNationSlotFromDescriptor(terrain, encodedNationSlot);
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
    InvokeDiplomacyPolicyStateChangedHook(static_cast<int>(policyCode),
                                          static_cast<int>(targetClass), shouldApply);
  }
  return shouldApply != 0;
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
bool TGreatPower::SetDiplomacyGrantEntryForTargetAndUpdateTreasury(int arg1, int arg2) {
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
    InvokeDiplomacyPolicyStateChangedHook(static_cast<int>(static_cast<short>(newGrantRaw)),
                                          static_cast<int>(targetNation), accepted ? 1 : 0);

    if (accepted && newGrantRaw != kGrantClear && targetNation > 6) {
      bool shouldDispatchAlert = false;
      void* diplomacyManager = g_pDiplomacyTurnStateManager;
      if (diplomacyManager != 0) {
        int majorNation = 0;
        while (majorNation < 7) {
          if (majorNation != this->nationSlot) {
            short relationValue =
                g_pDiplomacyTurnStateManager
                    ->relationStandingScoreMatrix79c[majorNation * 0x17 + targetIndex];
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
        TLocalizationRuntime* localizationRuntime = g_pLocalizationTable;
        if (localizationRuntime != 0) {
          localizationRuntime->GetString(0x2753, 0, &sharedRefs.first);
          localizationRuntime->GetString(0x2753, 0, &sharedRefs.second);
        }
        thunk_AssignStringSharedRefAndReturnThis();
        thunk_AssignStringSharedRefAndReturnThis();
        thunk_DispatchLocalizedUiMessageWithTemplateA13A0();
      }
    }
  }
  return accepted;
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
      g_apTerrainTypeDescriptorTable[targetNation];
  static_cast<TTerrainDescriptor*>(terrainDescriptor)->CallSlot38(grantValue);

  this->grantTotalCost -= grantValue;

  if (g_pDiplomacyTurnStateManager->LookupOrderCompatibilityMatrixValue(targetNation,
                                                                     this->nationSlot) != 2) {
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

// FUNCTION: IMPERIALISM 0x004de7e0
#pragma optimize("y", on)
void TGreatPower::ApplyTurnDiplomacyStateSlot1e0(void) {
  if (this->city != 0 && this->foreignMinister != 0) {
    this->foreignMinister->Call80();
  }
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004de810
void TGreatPower::CallSlotA5_Provisional(void) {
  TPtrList* trackedList = this->trackedObjectList;
  if (trackedList == 0) {
    return;
  }

  int remaining = trackedList->GetCountSlot48();
  while (remaining > 0) {
    TTrackedObjectListEntry* entry = static_cast<TTrackedObjectListEntry*>(
        trackedList->GetTrackedEntrySlot4C(remaining));
    if (entry != 0) {
      reinterpret_cast<TTrackedObject*>(entry)->Call30();
    }
    if (entry != 0) {
      reinterpret_cast<TTrackedObject*>(entry)->Release1C();
    }
    --remaining;
  }
}

// FUNCTION: IMPERIALISM 0x004de860
void TGreatPower::ApplyJoinEmpireMode0GlobalDiplomacyReset(int arg1) {
  const int kResetDiplomacyLevel = 100;
  const int kResetPolicyCode = -1;
  const int kDipFlagRelation = 6;
  const int kDipFlagPolicy = 0x31;

  if (g_pInterNationEventQueueManager != 0) {
    g_pInterNationEventQueueManager
        ->QueueInterNationEventRecordDeduped(0x1D, this->nationSlot, 7, '\0');
  }
  reinterpret_cast<void(__cdecl*)(void)>(thunk_RebuildMinorNationDispositionLookupTables)();

  this->encodedNationSlot = static_cast<short>(arg1 + 100);

  int nationSlot;
  for (nationSlot = 0; nationSlot < kNationSlotCount; ++nationSlot) {
    if (IsNationSlotEligibleForEventProcessing(nationSlot) != 0 &&
        nationSlot != this->nationSlot && nationSlot != arg1) {
      reinterpret_cast<TTerrainDescriptor*>(g_apTerrainTypeDescriptorTable[nationSlot])
          ->SetResetLevelSlot68(this->nationSlot, kResetDiplomacyLevel);
    }
  }

  g_pDiplomacyTurnStateManager->ResetTerrainAdjacencyMatrixRowAndSymmetricLink(this->nationSlot);

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

  if (this->proposalQueue != 0) {
    this->proposalQueue->Release1C();
  }
  if (this->turnEventQueue != 0) {
    this->turnEventQueue->Release1C();
  }

  this->ReleaseDiplomacyTrackedObjectSlots850();

  void* relationPanelManager = this->city;
  if (relationPanelManager != 0) {
    static_cast<TTrackedObject*>(relationPanelManager)->Release1C();
  }
  this->city = 0;

  this->CallSlotA5_Provisional();

  for (nationSlot = 0; nationSlot < kNationSlotCount; ++nationSlot) {
    if (nationSlot != this->nationSlot &&
        IsNationSlotEligibleForEventProcessing(nationSlot) != 0) {
      g_pDiplomacyTurnStateManager->SetRelationCodeSlot74WithMode(this->nationSlot, nationSlot,
                                                                  kDipFlagRelation, 0);
      g_pDiplomacyTurnStateManager->SetStandingScoreSlot28(this->nationSlot, nationSlot,
                                                           kDipFlagPolicy);
      TGreatPower* nationState = g_apNationStates[nationSlot];
      if (nationState->diplomacyEligibilityA0 == 0) {
        nationState->NotifyActionSlot94(this->nationSlot, 0x131);
      }
      this->ResetDiplomacyLevelForNationSlot12_Provisional(nationSlot, kResetDiplomacyLevel);
      this->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(nationSlot, kResetPolicyCode);
    }
  }

  int secondarySlot;
  for (secondarySlot = kMajorNationCount; secondarySlot < kNationSlotCount; ++secondarySlot) {
    TMinor* secondaryState = g_apSecondaryNationStateSlots[secondarySlot];
    bool directReset = true;
    short encodedOwnerNation = secondaryState->ownerNationSlot0e;
    if (encodedOwnerNation >= 200) {
      short ownerNation = DecodeSecondaryNationOwnerSlot(secondaryState);
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

    if (reinterpret_cast<TTerrainDescriptor*>(g_apTerrainTypeDescriptorTable[secondarySlot]) != 0) {
      secondaryState->SetDiplomacyStandingSlot48(this->nationSlot, kResetDiplomacyLevel);
    }
  }

  reinterpret_cast<void(__cdecl*)(void)>(
      thunk_RemoveOrdersByNationFromPrimarySecondaryAndTaskForceLists)();
  ApplyJoinEmpireMode0GlobalDiplomacyResetImpl(g_pGlobalMapState, this->nationSlot);

  TLocalizationRuntime* localizationTable = g_pLocalizationTable;
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
    this->turnEventQueue->AddEntrySlot38(&packedCode);

    Event13Payload payload;
    payload.marker0 = 1;
    payload.nationMask = 1 << (static_cast<unsigned char>(this->nationSlot) & 0x1F);
    payload.marker1 = 1;
    payload.targetMask = 1 << (static_cast<unsigned char>(arg1) & 0x1F);

    char immediateDispatch = this->ShouldDispatchImmediatelySlot28_Provisional();
    if (immediateDispatch == 0) {
      if (g_pInterNationEventQueueManager != 0) {
        g_pInterNationEventQueueManager
            ->QueueInterNationEventIntoNationBucket(static_cast<int>(this->nationSlot),
                                                    reinterpret_cast<int>(&payload), '\0');
      }
    } else {
      reinterpret_cast<void(__cdecl*)(int, void*)>(
          thunk_CreateAndSendTurnEvent13_NationAndNineDwords)(static_cast<int>(this->nationSlot),
                                                              &payload);
    }
  }

  void* diplomacyState = g_pDiplomacyTurnStateManager;
  int nationSlot = static_cast<int>(this->nationSlot);

  if (policyCode == kPolicyMutualDefense &&
      g_pDiplomacyTurnStateManager->HasFlag84ForNationSlot84(arg1) != 0) {
    for (int slot = 0; slot < kMajorNationCount; ++slot) {
      if (IsNationSlotEligibleForEventProcessing(slot) == 0) {
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
    if (IsNationSlotEligibleForEventProcessing(slot) == 0) {
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

  this->proposalQueue->AddEntrySlot38(reinterpret_cast<int*>(&proposalRecord));
}

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
      this->proposalQueue->GetEntryAt1BasedSlot2C(proposalIndex));

  switch (static_cast<int>(proposal->proposalCode) - 0x12D) {
  case 0:
    this->ApplyJoinEmpireAcceptanceSideEffectsForTargetNation(
        static_cast<int>(proposal->targetNationSlot), 1);
    if (g_pInterNationEventQueueManager != 0) {
      g_pInterNationEventQueueManager
          ->QueueInterNationEventRecordDeduped(3, this->nationSlot,
                                               static_cast<int>(proposal->targetNationSlot), '\0');
    }
    break;

  case 1: {
    g_pDiplomacyTurnStateManager->SetRelationCodeSlot78Final(
        this->nationSlot, static_cast<int>(proposal->targetNationSlot), 2);
    if (g_pInterNationEventQueueManager != 0) {
      g_pInterNationEventQueueManager
          ->QueueInterNationEventRecordDeduped(4, this->nationSlot,
                                               static_cast<int>(proposal->targetNationSlot), '\0');
    }
    for (int nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
      if (g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(
              nationSlot, static_cast<int>(proposal->targetNationSlot)) != 0 &&
          g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(this->nationSlot, nationSlot) ==
              0) {
        this->ApplyDiplomacyRelationCodeAndNotifyThirdPartySlot284(
            nationSlot, 2, static_cast<int>(proposal->targetNationSlot));
      }
    }
    break;
  }

  case 2:
    g_pDiplomacyTurnStateManager->SetRelationCodeSlot78Final(
        this->nationSlot, static_cast<int>(proposal->targetNationSlot), 3);
    if (g_pInterNationEventQueueManager != 0) {
      g_pInterNationEventQueueManager
          ->QueueInterNationEventRecordDeduped(5, this->nationSlot,
                                               static_cast<int>(proposal->targetNationSlot), '\0');
    }
    break;

  case 3: {
    g_pDiplomacyTurnStateManager->SetRelationCodeSlot78Final(
        this->nationSlot, static_cast<int>(proposal->targetNationSlot), 4);
    if (g_pInterNationEventQueueManager != 0) {
      g_pInterNationEventQueueManager
          ->QueueInterNationEventRecordDeduped(2, this->nationSlot,
                                               static_cast<int>(proposal->targetNationSlot), '\0');
    }
    if (g_pDiplomacyTurnStateManager->HasFlag84ForNationSlot84(
            static_cast<int>(proposal->targetNationSlot)) != 0) {
      for (int nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
        if (IsNationSlotEligibleForEventProcessing(
                nationSlot) != 0 &&
            g_pDiplomacyTurnStateManager->GetRelationTierSlot70(this->nationSlot, nationSlot) ==
                2 &&
            g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(
                nationSlot, static_cast<int>(proposal->targetNationSlot)) != 0) {
          g_pDiplomacyTurnStateManager->ApplyRelationCode4Slot7c(this->nationSlot, nationSlot, 1);
        }
      }
    }
    break;
  }

  case 5: {
    reinterpret_cast<TTerrainDescriptor*>(g_apTerrainTypeDescriptorTable[static_cast<int>(
        proposal->targetNationSlot)])
        ->CallSlot4C(this->nationSlot, 1);
    if (g_pInterNationEventQueueManager != 0) {
      g_pInterNationEventQueueManager
          ->QueueInterNationEventRecordDeduped(3, static_cast<int>(proposal->targetNationSlot),
                                               this->nationSlot, '\0');
    }
    break;
  }

  default:
    break;
  }

  if (g_pDiplomacyTurnStateManager->HasFlag84ForNationSlot84(
          static_cast<int>(proposal->targetNationSlot)) != 0 &&
      IsNationSlotEligibleForEventProcessing(
          static_cast<int>(proposal->targetNationSlot)) != 0) {
    g_apNationStates[static_cast<int>(proposal->targetNationSlot)]->NotifyActionSlot94(
        this->nationSlot, proposal->proposalCode);
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

  TQueueObject* queue = static_cast<TQueueObject*>(proposalQueue);
  int queueOrdinal = static_cast<int>(static_cast<short>(proposalQueueIndex));
  if (queueOrdinal > static_cast<int>(queue->GetEntryCount())) {
    return;
  }

  short* proposalEntry =
      static_cast<short*>(queue->GetEntryAt1BasedSlot2C(queueOrdinal));
  short proposalCode = proposalEntry[0];
  short targetNation = proposalEntry[1];

  void* diplomacyManager = g_pDiplomacyTurnStateManager;
  if (diplomacyManager != 0 &&
      g_pDiplomacyTurnStateManager->HasFlag84ForNationSlot84(targetNation) != 0) {
    TGreatPower* nationState = g_apNationStates[targetNation];
    if (nationState != 0) {
      nationState->NotifyActionSlot94(this->nationSlot, -proposalCode);
    }
  }

  switch (proposalCode) {
  case kProposalCode12D:
    if (g_pInterNationEventQueueManager != 0) {
      g_pInterNationEventQueueManager
          ->QueueInterNationEventRecordDeduped(kEvent09, targetNation, this->nationSlot, '\0');
    }
    return;
  case kProposalCode12E:
    if (g_pInterNationEventQueueManager != 0) {
      g_pInterNationEventQueueManager
          ->QueueInterNationEventRecordDeduped(kEvent0B, targetNation, this->nationSlot, '\0');
    }
    return;
  case kProposalCode12F:
    if (g_pInterNationEventQueueManager != 0) {
      g_pInterNationEventQueueManager
          ->QueueInterNationEventRecordDeduped(kEvent0D, targetNation, this->nationSlot, '\0');
    }
    return;
  case kProposalCode130:
    if (g_pInterNationEventQueueManager != 0) {
      g_pInterNationEventQueueManager
          ->QueueInterNationEventRecordDeduped(kEvent07, targetNation, this->nationSlot, '\0');
    }
    return;
  default:
    return;
  }
}

// FUNCTION: IMPERIALISM 0x004df4b0
#pragma optimize("y", on)
char TGreatPower::IsEventCodeAllowedForRelationTier(short eventCode, int targetNation) {
  char allowed = 0;
  short relationTier =
      g_pDiplomacyTurnStateManager->GetRelationTierSlot70(this->nationSlot, targetNation);
  switch (relationTier) {
  case 2:
    if (eventCode != 0x130 && eventCode != 0x12f && eventCode != 0x12e) {
      return 1;
    }
    break;
  case 3:
    if (eventCode != 0x130 && eventCode != 0x12f) {
      return 1;
    }
    break;
  case 4:
    if (eventCode != 0x130) {
      return 1;
    }
    break;
  case 6:
    if (eventCode == 0x130) {
      allowed = 1;
    }
    break;
  }
  return allowed;
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004df580
void TGreatPower::ResetNationDiplomacyProposalQueue(void) {
  void* proposalQueue = this->proposalQueue;
  if (proposalQueue != 0) {
    static_cast<TTrackedObject*>(proposalQueue)->Release1C();
  }
}

// FUNCTION: IMPERIALISM 0x004df5c0
void TGreatPower::DispatchTurnEvent2103WithNationFromRecord(void) {
  void* uiRuntimeContext = g_pUiRuntimeContext;
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
  TQueueObject* queue = static_cast<TQueueObject*>(proposalQueue);
  short proposalCount = static_cast<short>(queue->GetEntryCount());
  if (proposalCount != 0 && proposalCount > 0) {
    proposalIndex = 1;
    queueIndex = 1;
    void* diplomacyManager = g_pDiplomacyTurnStateManager;
    void* uiRuntimeContext = g_pUiRuntimeContext;

    do {
      short* proposalEntry =
          static_cast<short*>(queue->GetEntryAt1BasedSlot2C(queueIndex));
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
              this->ApplyDiplomacyRelationCodeAndNotifyThirdPartySlot284(checkNation, 0x132,
                                                                         targetNation);
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

// FUNCTION: IMPERIALISM 0x004df810
#pragma optimize("y", on)
void TGreatPower::ApplyScenarioRelationPresetAndSpawnFrogCity(TCity* mgr) {
  TCitySummaryObject* notifySink = mgr->productionSummary1d8;
  int presetLevel;
  if (this->diplomacyEligibilityA0 == 0) {
    presetLevel = 2;
  } else {
    presetLevel = g_pLocalizationTable->runtimeSubsystemIndex;
  }
  const short* presetRow = g_Rebuild_Primary_Nation_Value_00653570[presetLevel];
  for (int needIndex = 0; needIndex < 0x17; ++needIndex) {
    mgr->fieldB6[static_cast<short>(needIndex)] = presetRow[needIndex];
    mgr->Refresh80();
  }
  mgr->productionAccum1fc[8] += 999 - mgr->productionOrderTable1dc[8];
  mgr->productionOrderTable1dc[8] = 999;
  mgr->productionAccum1fc[10] += 999 - mgr->productionOrderTable1dc[10];
  mgr->productionOrderTable1dc[10] = 999;
  mgr->productionAccum1fc[9] += 999 - mgr->productionOrderTable1dc[9];
  mgr->productionOrderTable1dc[9] = 999;
  mgr->productionAccum1fc[7] += 999 - mgr->productionOrderTable1dc[7];
  mgr->productionOrderTable1dc[7] = 999;
  mgr->productionAccum1fc[14] += 999 - mgr->productionOrderTable1dc[14];
  mgr->productionOrderTable1dc[14] = 999;
  mgr->productionAccum1fc[13] += 999 - mgr->productionOrderTable1dc[13];
  mgr->productionOrderTable1dc[13] = 999;
  if (presetLevel == 0) {
    notifySink->NotifyProductionPresetSlot2C(2, 3, 2);
  } else {
    notifySink->NotifyProductionPresetSlot2C(4, 2, 1);
  }
  TLocalizationRuntime* localization = g_pLocalizationTable;
  if (this->diplomacyEligibilityA0 == 0 || localization->runtimeSubsystemIndex < 2 ||
      localization->stateFlag114 != 0) {
    if (this->ShouldDispatchImmediatelySlot28_Provisional() == 0 ||
        localization->stateFlag114 != 0) {
      this->CreateFrogCityAtHomeRegionAndAttach(mgr);
      return;
    }
  }
  this->CreateFrogCityTownMarkerAndAttach(mgr);
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004dfae0
#pragma optimize("y", on)
void TGreatPower::CreateFrogCityAtHomeRegionAndAttach(void* receiver) {
  TLocalizationRuntime* localization = g_pLocalizationTable;
  int homeRegionIndex = -1;
  if (localization->stateFlag114 == 0) {
    homeRegionIndex =
        static_cast<TCityInteriorMinister*>(this->interiorMinister)->GetHomeCityRecordIndexSlotC0();
  } else {
    TTerrainStateRecordView* terrainTable = g_pGlobalMapState->terrainStateTable;
    for (int regionId = 0; regionId < 0x1950; ++regionId) {
      if (static_cast<short>(terrainTable[static_cast<short>(regionId)].ownerNationTag04) ==
              this->nationSlot &&
          (terrainTable[static_cast<short>(regionId)].activeFlags1c & 1) != 0) {
        homeRegionIndex = regionId;
      }
    }
    if (static_cast<short>(homeRegionIndex) == -1) {
      CString message;
      {
        CString prefix("GP#");
        message = prefix;
      }
      message += static_cast<char>('0' + static_cast<char>(this->nationSlot));
      message += " is missing capitol site";
      thunk_AssignStringSharedRefAndReturnThis();
      thunk_RunControlStringProviderAndDispatchLocalizedMessage();
    }
  }
  *GreatPower_HomeRegionIndex88(this) = static_cast<short>(homeRegionIndex);
  TTownMarker* marker = new TTownMarker();
  marker->InitializeTownMarker("FrogCity", homeRegionIndex, 1, this->nationSlot);
  static_cast<TMarkerReceiverView*>(receiver)->AdoptMarkerSlot44(marker);
  marker->activeFlag4f = 1;
  this->townMarkerList->AddTail30(marker);
  g_pGlobalMapState->LinkRegionToNationSlot134(marker->regionId14, this->nationSlot);
  if (this->diplomacyEligibilityA0 == 0 && this->interiorMinister != 0) {
    this->interiorMinister->NotifySlot44(receiver);
  }
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004e00d0
void TGreatPower::DispatchGreatPowerQuarterlyStatusMessageLevel2(void) {
  if (!IsQuarterlyLocalizationGateOpen()) {
    return;
  }
  DispatchQuarterlyGreatPowerPressureMessage(2);
}

// FUNCTION: IMPERIALISM 0x004e0140
void TGreatPower::DispatchGreatPowerQuarterlyStatusMessageLevel1(void) {
  if (!IsQuarterlyLocalizationGateOpen()) {
    return;
  }
  DispatchQuarterlyGreatPowerPressureMessage(1);
}

// FUNCTION: IMPERIALISM 0x004e01b0
void TGreatPower::DispatchGreatPowerQuarterlyStatusMessageLevel0(void) {
  if (!IsQuarterlyLocalizationGateOpen()) {
    return;
  }
  DispatchQuarterlyGreatPowerPressureMessage(0);
}

// --- Slots 0x4c/0x65/0x6c/0x6f/0x78/0x7d/0x7f/0xac and trivial tail slots ---

// FUNCTION: IMPERIALISM 0x004e0220
#pragma optimize("y", on)
void TGreatPower::DispatchTrackedOrderSlot2CCallbacks(void) {
  CIterator orderIter(this->trackedObjectList);
  for (TUnitOrderState* order = static_cast<TUnitOrderState*>(orderIter.Reset()); orderIter.More();
       order = static_cast<TUnitOrderState*>(orderIter.Advance())) {
    order->DispatchSlot2C();
  }
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004e0290
#pragma optimize("y", on)
void TGreatPower::SortTrackedOrdersByTypePriority(void) {
  short orderCount = static_cast<short>(this->trackedObjectList->GetCountSlot48());
  int total = orderCount;
  for (int outer = 1; outer < total; ++outer) {
    void* entryOuter = this->trackedObjectList->GetTrackedEntrySlot4C(outer);
    short outerPriority =
        g_DAT_006966d0_Value_006966D0[static_cast<TUnitOrderState*>(entryOuter)->orderType];
    for (int inner = outer + 1; inner <= total; ++inner) {
      void* entryInner = this->trackedObjectList->GetTrackedEntrySlot4C(inner);
      short innerPriority =
          g_DAT_006966d0_Value_006966D0[static_cast<TUnitOrderState*>(entryInner)->orderType];
      if (innerPriority < outerPriority) {
        static_cast<TPtrList*>(this->trackedObjectList)
            ->SetEntryDataAtSlot60(outer, &entryInner, 1);
        static_cast<TPtrList*>(this->trackedObjectList)
            ->SetEntryDataAtSlot60(inner, &entryOuter, 1);
        entryOuter = entryInner;
        outerPriority = innerPriority;
      }
    }
  }
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004e03a0
#pragma optimize("y", on)
void TGreatPower::RunSlot4CThenSortTrackedOrders(void) {
  this->DispatchTrackedOrderSlot2CCallbacks();
  this->SortTrackedOrdersByTypePriority();
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004e03d0
#pragma optimize("y", on)
void TGreatPower::ResetField900FromNeedCapA6(void) {
  this->field900 = this->needCapA6 / 5;
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004e0420
void TGreatPower::VTableSlot84_Provisional(int targetNation) {
  (void)targetNation;
}

// FUNCTION: IMPERIALISM 0x004e0440
#pragma optimize("y", on)
void TGreatPower::NotifyAllianceSlot214(int targetNation) {
  (void)targetNation;
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004e0500
#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif
int TGreatPower::SumNavyOrderPriorityForNationSlot86(void) {
  int prioritySum = 0;
  for (TShip* node = static_cast<TShip*>(GetNavyPrimaryOrderListHead()); node != 0;
       node = node->nextOlder24) {
    if (node->ownerNationSlot14 == this->nationSlot) {
      prioritySum += GetIndustryActionCostWeightByResourceType(node->resourceType04);
    }
  }
  return prioritySum;
}
#if defined(_MSC_VER)
#pragma optimize("", on)
#endif

// FUNCTION: IMPERIALISM 0x004e0550
int TGreatPower::CountMapActionContextNodesWithNationBit(void) {
  int count = 0;
  TZone* node = static_cast<TZone*>(g_pMapActionContextListHead);
  if (node != 0) {
    do {
      if ((node->field10 & (1 << (this->nationSlot & 0x1f))) != 0) {
        ++count;
      }
      node = node->prev18;
    } while (node != 0);
  }
  return count;
}

// FUNCTION: IMPERIALISM 0x004e0590
double TGreatPower::ComputeMinisterSkillFloatSlot88(void) {
  return g_DAT_Value_00653308[this->foreignMinister->skillIndexC] +
         g_DAT_Value_00653328[this->defenseMinister->skillIndexC];
}

// FUNCTION: IMPERIALISM 0x004e05d0
double TGreatPower::ComputeMinisterSkillFloatSlot89(void) {
  return g_DAT_Value_00653360[this->defenseMinister->skillIndexC] +
         g_DAT_Value_00653340[this->foreignMinister->skillIndexC];
}

// FUNCTION: IMPERIALISM 0x004e0610
double TGreatPower::ComputeMinisterSkillFloatSlot8A(void) {
  return g_DAT_Value_00653398[this->defenseMinister->skillIndexC] +
         g_DAT_Value_00653378[this->foreignMinister->skillIndexC];
}

// FUNCTION: IMPERIALISM 0x004e0650
double TGreatPower::ComputeMinisterSkillFloatSlot8B(void) {
  return g_DAT_006533b0_Value_006533B0[this->foreignMinister->skillIndexC] +
         g_DAT_006533d0_Value_006533D0[this->defenseMinister->skillIndexC];
}

// FUNCTION: IMPERIALISM 0x004e0690
double TGreatPower::ComputeMinisterSkillFloatSlot8C(void) {
  return g_DAT_Value_00653408[this->defenseMinister->skillIndexC] +
         g_DAT_006533e8_Value_006533E8[this->foreignMinister->skillIndexC];
}

// FUNCTION: IMPERIALISM 0x004e06d0
#pragma optimize("y", on)
int TGreatPower::SumCommodityRecordAccumulatedValues(void) {
  NationCityTradeState* cityState = GetNationTradeCityState(this);
  int total = 0;
  if (cityState != 0) {
    total = cityState->tradeCommodityRecordPtrs[11]->accumulatedValue44 +
            cityState->tradeCommodityRecordPtrs[12]->accumulatedValue44 +
            cityState->tradeCommodityRecordPtrs[9]->accumulatedValue44 +
            cityState->tradeCommodityRecordPtrs[10]->accumulatedValue44 +
            cityState->tradeCommodityRecordPtrs[8]->accumulatedValue44;
  }
  return total;
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004e0740
int TGreatPower::GetCityBuildingProductionSlot8D(short buildingSlot) {
  if (this->city != 0) {
    return static_cast<short>(
        this->city->GetBuildingProductionValueBySlot( buildingSlot));
  }
  return 0;
}

#pragma optimize("y", on) // omit frame pointer, as in the original bodies
#pragma optimize("y", on)

// FUNCTION: IMPERIALISM 0x004e07b0
int TGreatPower::ComputeArmyCommitBudgetSlot8E(void) {
  if (this->city == 0) {
    return 0;
  }
  CityTradeScenarioDescriptor* scenario = GetNationTradeCityState(this)->scenarioTradeDescriptor;
  short scenarioCap = scenario->valueAt1C;
  short productionCap = scenario->productionSlots->valueAt4;
  if (scenarioCap < productionCap) {
    productionCap = scenarioCap;
  }
  int budget = productionCap;
  short metricCap = this->GetDiplomacyExternalStateB6ByTarget(0x10);
  if (static_cast<int>(metricCap) <= budget) {
    budget = metricCap;
  }
  int armyPower = SumMilitaryUnitPowerWeights(this->militaryUnitList44);
  if (armyPower / 2 <= budget) {
    budget = armyPower / 2;
  }
  return budget;
}

#pragma optimize("y", on)
// FUNCTION: IMPERIALISM 0x004e0890
float TGreatPower::GetScoreFactorSlot23C(void) {
  int armyPower = SumMilitaryUnitPowerWeights(this->militaryUnitList44);
  float armyPowerF = static_cast<float>(armyPower);
  float commitBudgetF = static_cast<float>(this->ComputeArmyCommitBudgetSlot8E());
  int production = this->GetCityBuildingProductionSlot8D(3);
  int poweredCap = static_cast<int>(armyPowerF * g_Iterate_Linked_List_Value_00653718);
  int productionTerm = static_cast<int>(static_cast<float>(production));
  if (productionTerm >= poweredCap) {
    productionTerm = poweredCap;
  }
  return armyPowerF + commitBudgetF + static_cast<float>(productionTerm);
}

// FUNCTION: IMPERIALISM 0x004e09a0
float TGreatPower::GetScoreFactorSlot240(void) {
  TCityOrderCapabilityState* capabilityState = CityOrderCapabilityState();
  int shipProduction;
  if (capabilityState->shipCapabilityFlag1a8 != 0) {
    shipProduction = this->GetCityBuildingProductionSlot8D(2);
  } else if (capabilityState->shipCapabilityFlag1a5 != 0) {
    shipProduction = (this->GetCityBuildingProductionSlot8D(4) +
                      this->GetCityBuildingProductionSlot8D(2)) /
                     2;
  } else {
    shipProduction = this->GetCityBuildingProductionSlot8D(4);
  }
  float shipProductionF = static_cast<float>(shipProduction);
  float navyPriorityF = static_cast<float>(this->SumNavyOrderPriorityForNationSlot86());
  int navyPriorityInt = static_cast<int>(navyPriorityF);
  int productionTerm = static_cast<int>(shipProductionF);
  if (productionTerm >= navyPriorityInt) {
    productionTerm = navyPriorityInt;
  }
  float productionTermF = static_cast<float>(productionTerm);
  int fleetPower = SumMilitaryUnitPowerWeights(this->militaryUnitList44);
  int priorityCap = static_cast<int>(navyPriorityF * g_Compute_City_Order_Value_0065371C);
  if (priorityCap >= fleetPower) {
    priorityCap = fleetPower;
  }
  return static_cast<float>(priorityCap) + navyPriorityF + productionTermF;
}

// FUNCTION: IMPERIALISM 0x004e0b20
float TGreatPower::ComputeArmyScoreRatioVsNation(int targetNation) {
  float selfScore = this->GetScoreFactorSlot23C();
  float targetScore =
      g_apNationStates[targetNation]->GetScoreFactorSlot23C();
  float allySum = SumAlliedArmyScoreFactors(targetNation);
  float denominator = targetScore - allySum * g_Compute_Advisory_Handler_LookupTable_00653714;
  if (denominator == g_Compute_Advisory_Handler_LookupTable_00653700) {
    return selfScore;
  }
  return selfScore / denominator;
}

// FUNCTION: IMPERIALISM 0x004e0c10
float TGreatPower::ComputeArmyScoreStandingRatioVsNation(int targetNation) {
  float selfScore = this->GetScoreFactorSlot23C();
  float targetScore =
      g_apNationStates[targetNation]->GetScoreFactorSlot23C();
  float allySum = SumAlliedArmyScoreFactors(targetNation);
  int yearTerm = GetClampedQuarterYearTerm();
  short* standingRow = GetRelationStandingRowForNation(this->nationSlot);
  float denominator = (static_cast<float>(standingRow[static_cast<short>(targetNation)]) -
                       allySum * g_Compute_Advisory_Handler_LookupTable_00653714) +
                      targetScore;
  float numerator =
      (static_cast<float>(yearTerm) + selfScore) - g_Compute_Advisory_Handler_LookupTable_00653720;
  if (denominator == g_Compute_Advisory_Handler_LookupTable_00653700) {
    return numerator;
  }
  return numerator / denominator;
}

// FUNCTION: IMPERIALISM 0x004e0d80
float TGreatPower::ComputeNavyScoreRatioVsNation(int targetNation) {
  float selfScore = this->GetScoreFactorSlot240();
  float targetScore =
      g_apNationStates[targetNation]->GetScoreFactorSlot240();
  float allySum = SumAlliedNavyScoreFactors(targetNation);
  float denominator = targetScore - allySum * g_Compute_Advisory_Handler_LookupTable_00653714;
  if (denominator == g_Compute_Advisory_Handler_LookupTable_00653700) {
    return selfScore;
  }
  return selfScore / denominator;
}

// FUNCTION: IMPERIALISM 0x004e0e70
float TGreatPower::ComputeNavyScoreStandingRatioVsNation(int targetNation) {
  float selfScore = this->GetScoreFactorSlot240();
  float targetScore =
      g_apNationStates[targetNation]->GetScoreFactorSlot240();
  float allySum = SumAlliedNavyScoreFactors(targetNation);
  int yearTerm = GetClampedQuarterYearTerm();
  short* standingRow = GetRelationStandingRowForNation(this->nationSlot);
  float denominator = (static_cast<float>(standingRow[static_cast<short>(targetNation)]) -
                       allySum * g_Compute_Advisory_Handler_LookupTable_00653714) +
                      targetScore;
  float numerator =
      (static_cast<float>(yearTerm) + selfScore) - g_Compute_Advisory_Handler_LookupTable_00653720;
  if (denominator == g_Compute_Advisory_Handler_LookupTable_00653700) {
    return numerator;
  }
  return numerator / denominator;
}

// FUNCTION: IMPERIALISM 0x004e0fe0
float TGreatPower::ComputeArmyScoreRatioVsNationWithSecondary(int targetNation, int secondarySlot) {
  float selfScore = this->GetScoreFactorSlot23C();
  int secondaryPower = SumMilitaryUnitPowerWeights(
      g_apSecondaryNationStateSlots[secondarySlot]->militaryUnitList44);
  float combinedScore = static_cast<float>(secondaryPower) + selfScore;
  char borderLinked = g_pGlobalMapState->AreNationsBorderLinked(targetNation, secondarySlot);
  float targetScore;
  if (borderLinked != 0) {
    targetScore =
        g_apNationStates[targetNation]->GetScoreFactorSlot23C();
  } else {
    targetScore =
        g_apNationStates[targetNation]->GetScoreFactorSlot240();
  }
  float allySum = SumAlliedArmyScoreFactors(targetNation);
  float denominator = targetScore - allySum * g_Compute_Advisory_Handler_LookupTable_00653714;
  if (denominator == g_Compute_Advisory_Handler_LookupTable_00653700) {
    return combinedScore;
  }
  return combinedScore / denominator;
}

#pragma optimize("y", on)
// FUNCTION: IMPERIALISM 0x004e1170
float TGreatPower::ComputeArmyScoreStandingRatioVsNationPair(int targetNation, int partnerNation) {
  float selfScore = this->GetScoreFactorSlot23C();
  char borderLinked = g_pGlobalMapState->AreNationsBorderLinked(targetNation, partnerNation);
  float targetScore;
  if (borderLinked != 0) {
    targetScore =
        g_apNationStates[targetNation]->GetScoreFactorSlot23C();
  } else {
    targetScore =
        g_apNationStates[targetNation]->GetScoreFactorSlot240();
  }
  float allySum = SumAlliedArmyScoreFactors(targetNation);
  short* standingRow = GetRelationStandingRowForNation(this->nationSlot);
  float denominator = (static_cast<float>(standingRow[static_cast<short>(targetNation)]) -
                       allySum * g_Compute_Advisory_Handler_LookupTable_00653714) +
                      targetScore;
  if (denominator == g_Compute_Advisory_Handler_LookupTable_00653700) {
    return static_cast<float>(standingRow[static_cast<short>(partnerNation)]) + selfScore;
  }
  return (static_cast<float>(standingRow[static_cast<short>(partnerNation)]) + selfScore) /
         denominator;
}
#pragma optimize("", on)

#pragma optimize("y", on)
// FUNCTION: IMPERIALISM 0x004e1300
float TGreatPower::ComputeNavyScoreRatioVsNationWithSecondary(int targetNation, int secondarySlot) {
  float selfScore = this->GetScoreFactorSlot240();
  int secondaryPower = SumMilitaryUnitPowerWeights(
      g_apSecondaryNationStateSlots[secondarySlot]->militaryUnitList44);
  float combinedScore = static_cast<float>(secondaryPower) + selfScore;
  char borderLinked = g_pGlobalMapState->AreNationsBorderLinked(targetNation, secondarySlot);
  float targetScore;
  if (borderLinked != 0) {
    targetScore =
        g_apNationStates[targetNation]->GetScoreFactorSlot23C();
  } else {
    targetScore =
        g_apNationStates[targetNation]->GetScoreFactorSlot240();
  }
  float allySum = SumAlliedNavyScoreFactors(targetNation);
  float denominator = targetScore - allySum * g_Compute_Advisory_Handler_LookupTable_00653714;
  if (denominator == g_Compute_Advisory_Handler_LookupTable_00653700) {
    return combinedScore;
  }
  return combinedScore / denominator;
}

#pragma optimize("y", on)
// FUNCTION: IMPERIALISM 0x004e1490
float TGreatPower::ComputeNavyScoreStandingRatioVsNationPair(int targetNation, int partnerNation) {
  float selfScore = this->GetScoreFactorSlot240();
  char borderLinked = g_pGlobalMapState->AreNationsBorderLinked(targetNation, partnerNation);
  float targetScore;
  if (borderLinked != 0) {
    targetScore =
        g_apNationStates[targetNation]->GetScoreFactorSlot23C();
  } else {
    targetScore =
        g_apNationStates[targetNation]->GetScoreFactorSlot240();
  }
  float allySum = SumAlliedNavyScoreFactors(targetNation);
  short* standingRow = GetRelationStandingRowForNation(this->nationSlot);
  float denominator = (static_cast<float>(standingRow[static_cast<short>(targetNation)]) -
                       allySum * g_Compute_Advisory_Handler_LookupTable_00653714) +
                      targetScore;
  if (denominator == g_Compute_Advisory_Handler_LookupTable_00653700) {
    return static_cast<float>(standingRow[static_cast<short>(partnerNation)]) + selfScore;
  }
  return (static_cast<float>(standingRow[static_cast<short>(partnerNation)]) + selfScore) /
         denominator;
}
#pragma optimize("", on)

#pragma optimize("y", on)
// FUNCTION: IMPERIALISM 0x004e1620
float TGreatPower::ComputeArmyScoreRatioForNationPair(int nationA, int nationB, char swapRoles) {
  int opponentNation = nationA;
  int partnerNation = nationB;
  if (swapRoles != 0) {
    opponentNation = nationB;
    partnerNation = nationA;
  }
  float selfScore = this->GetScoreFactorSlot23C();
  float opponentScore =
      g_apNationStates[opponentNation]->GetScoreFactorSlot23C();
  float partnerScore =
      g_apNationStates[partnerNation]->GetScoreFactorSlot23C();
  float allySum = SumAlliedArmyScoreFactors(opponentNation);
  float denominator = opponentScore - allySum * g_Compute_Advisory_Handler_LookupTable_00653714;
  float numerator;
  if (swapRoles == 0) {
    numerator = selfScore - partnerScore * g_Compute_Advisory_Peer_LookupTable_00653724;
  } else {
    numerator = selfScore - partnerScore * g_Compute_Advisory_Handler_LookupTable_00653714;
  }
  if (denominator != g_Compute_Advisory_Handler_LookupTable_00653700) {
    numerator = numerator / denominator;
  }
  return numerator;
}

// FUNCTION: IMPERIALISM 0x004e1750
float TGreatPower::ComputeArmyScoreStandingRatioForNationPair(int nationA, int nationB,
                                                              char swapRoles) {
  int opponentNation = nationA;
  int partnerNation = nationB;
  if (swapRoles != 0) {
    opponentNation = nationB;
    partnerNation = nationA;
  }
  float selfScore = this->GetScoreFactorSlot23C();
  float opponentScore =
      g_apNationStates[opponentNation]->GetScoreFactorSlot23C();
  float partnerScore =
      g_apNationStates[partnerNation]->GetScoreFactorSlot23C();
  float allySum = SumAlliedArmyScoreFactors(opponentNation);
  short* standingRow = GetRelationStandingRowForNation(this->nationSlot);
  float denominator = (static_cast<float>(standingRow[static_cast<short>(opponentNation)]) -
                       allySum * g_Compute_Advisory_Handler_LookupTable_00653714) +
                      opponentScore;
  float numerator;
  if (swapRoles == 0) {
    numerator = (static_cast<float>(standingRow[static_cast<short>(partnerNation)]) -
                 partnerScore * g_Compute_Advisory_Peer_LookupTable_00653724) +
                selfScore;
  } else {
    numerator = (static_cast<float>(standingRow[static_cast<short>(partnerNation)]) -
                 partnerScore * g_Compute_Advisory_Handler_LookupTable_00653714) +
                selfScore;
  }
  if (denominator != g_Compute_Advisory_Handler_LookupTable_00653700) {
    numerator = numerator / denominator;
  }
  return numerator;
}

// FUNCTION: IMPERIALISM 0x004e1910
float TGreatPower::ComputeNavyScoreRatioForNationPair(int nationA, int nationB, char swapRoles) {
  int opponentNation = nationA;
  int partnerNation = nationB;
  if (swapRoles != 0) {
    opponentNation = nationB;
    partnerNation = nationA;
  }
  float selfScore = this->GetScoreFactorSlot240();
  float opponentScore =
      g_apNationStates[opponentNation]->GetScoreFactorSlot240();
  float partnerScore =
      g_apNationStates[partnerNation]->GetScoreFactorSlot240();
  float allySum = SumAlliedNavyScoreFactors(opponentNation);
  float denominator = opponentScore - allySum * g_Compute_Advisory_Handler_LookupTable_00653714;
  float numerator;
  if (swapRoles == 0) {
    numerator = selfScore - partnerScore * g_Compute_Advisory_Peer_LookupTable_00653724;
  } else {
    numerator = selfScore - partnerScore * g_Compute_Advisory_Handler_LookupTable_00653714;
  }
  if (denominator != g_Compute_Advisory_Handler_LookupTable_00653700) {
    numerator = numerator / denominator;
  }
  return numerator;
}

// FUNCTION: IMPERIALISM 0x004e1a40
float TGreatPower::ComputeNavyScoreStandingRatioForNationPair(int nationA, int nationB,
                                                              char swapRoles) {
  int opponentNation = nationA;
  int partnerNation = nationB;
  if (swapRoles != 0) {
    opponentNation = nationB;
    partnerNation = nationA;
  }
  float selfScore = this->GetScoreFactorSlot240();
  float opponentScore =
      g_apNationStates[opponentNation]->GetScoreFactorSlot240();
  float partnerScore =
      g_apNationStates[partnerNation]->GetScoreFactorSlot240();
  float allySum = SumAlliedNavyScoreFactors(opponentNation);
  short* standingRow = GetRelationStandingRowForNation(this->nationSlot);
  float denominator = (static_cast<float>(standingRow[static_cast<short>(opponentNation)]) -
                       allySum * g_Compute_Advisory_Handler_LookupTable_00653714) +
                      opponentScore;
  float numerator;
  if (swapRoles == 0) {
    numerator = (static_cast<float>(standingRow[static_cast<short>(partnerNation)]) -
                 partnerScore * g_Compute_Advisory_Peer_LookupTable_00653724) +
                selfScore;
  } else {
    numerator = (static_cast<float>(standingRow[static_cast<short>(partnerNation)]) -
                 partnerScore * g_Compute_Advisory_Handler_LookupTable_00653714) +
                selfScore;
  }
  if (denominator != g_Compute_Advisory_Handler_LookupTable_00653700) {
    numerator = numerator / denominator;
  }
  return numerator;
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004e1c00
#pragma optimize("y", on)
char TGreatPower::ReturnZeroSlot9D(int targetNation) {
  (void)targetNation;
  return 0;
}
#pragma optimize("", on)
#pragma optimize("y", on)

// FUNCTION: IMPERIALISM 0x004e1c20
char TGreatPower::EvaluateJoinWarAgainstNationAndQueueEvent(int targetNation) {
  // Result intentionally ignored in the original; keep the call for its side effects.
  g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(this->nationSlot, targetNation);
  char joinsWar = 0;
  TGreatPower* targetState = g_apNationStates[targetNation];
  if (targetState->CompareMissionScoreVariantsByMode(0) == 0 &&
      targetState->CompareMissionScoreVariantsByMode(1) == 0) {
    float warThreshold = this->ComputeWarThresholdSlotA3_Provisional(targetNation);
    if (this->ComputeMinisterSkillFloatSlot8C() < warThreshold) {
      joinsWar = 1;
      for (int otherNation = 0; otherNation < 7; ++otherNation) {
        if (IsNationSlotEligibleForEventProcessing(otherNation) != 0 &&
            g_pDiplomacyTurnStateManager->GetRelationTierSlot70(this->nationSlot, otherNation) ==
                2 &&
            g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(otherNation, targetNation) !=
                0) {
          g_pDiplomacyTurnStateManager->ApplyRelationCode4Slot7c(this->nationSlot, otherNation, 1);
        }
      }
    }
  }
  if (joinsWar != 0) {
    g_pInterNationEventQueueManager
        ->QueueInterNationEventRecordDeduped(0x1c, targetNation, this->nationSlot, 0);
  }
  return joinsWar;
}

#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004e1d50
bool TGreatPower::ExecuteAdvisoryPromptAndApplyActionType1(int arg1, int arg2) {
  char result = 0;
  TUiRuntimeContext* uiRuntimeContext =
      reinterpret_cast<TUiRuntimeContext*>(g_pUiRuntimeContext);

  result = g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(this->nationSlot, arg2);

  if (result == 0) {
    result = uiRuntimeContext->RequestDecisionSlot94(this->nationSlot, arg1, arg2, 0x0A);
    if (result != 0) {
      this->ApplyDiplomacyRelationCodeAndNotifyThirdPartySlot284(arg2, 1, arg1);
      return true;
    }
  } else {
    result = uiRuntimeContext->RequestDecisionSlot94(this->nationSlot, arg1, arg2, 0x0B);
    if (result != 0) {
      TMinor* secondaryNationState = g_apSecondaryNationStateSlots[arg1];
      if (secondaryNationState != 0) {
        short stateValue = DecodeSecondaryNationOwnerSlot(secondaryNationState);
        if (stateValue != this->nationSlot) {
          secondaryNationState->VTableSlot4C_Provisional(this->nationSlot, 1);
        }
      }
    }
  }
  return result != 0;
}

// FUNCTION: IMPERIALISM 0x004e1f20
#pragma optimize("y", on)
void TGreatPower::NoOpSlotA2(void) {}
#pragma optimize("", on)

// --- Relative military/naval power score family (vtable slots 0x8e-0x9e) ---
// Helpers live in TGreatPower_power_score.cpp (TGreatPower_internal.h).

// FUNCTION: IMPERIALISM 0x004e1f40
#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif
float TGreatPower::ComputeWarThresholdSlotA3_Provisional(int targetNation) {
  float selfArmyScore = TruncatedScoreFactorToFloat(this->GetScoreFactorSlot23C());
  float selfNavyScore = TruncatedScoreFactorToFloat(this->GetScoreFactorSlot240());
  float alliedArmyForSelf = 0.0f;
  float alliedNavyForSelf = 0.0f;
  float alliedArmyForTarget = 0.0f;
  float alliedNavyForTarget = 0.0f;

  int nationIndex = 0;
  while (nationIndex < kMajorNationCount) {
    if (g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(nationIndex, this->nationSlot) !=
            0 &&
        IsNationSlotEligibleForEventProcessing(nationIndex) != 0 &&
        nationIndex != targetNation) {
      TGreatPower* allyState = g_apNationStates[nationIndex];
      alliedArmyForSelf += TruncatedScoreFactorToFloat(allyState->GetScoreFactorSlot23C());
      alliedNavyForSelf += TruncatedScoreFactorToFloat(allyState->GetScoreFactorSlot240());
    }
    ++nationIndex;
  }

  nationIndex = 0;
  while (nationIndex < kMajorNationCount) {
    if (g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(nationIndex, targetNation) != 0 &&
        IsNationSlotEligibleForEventProcessing(nationIndex) != 0 &&
        nationIndex != this->nationSlot) {
      TGreatPower* allyState = g_apNationStates[nationIndex];
      alliedArmyForTarget += TruncatedScoreFactorToFloat(allyState->GetScoreFactorSlot23C());
      alliedNavyForTarget += TruncatedScoreFactorToFloat(allyState->GetScoreFactorSlot240());
    }
    ++nationIndex;
  }

  char borderLinked = 0;
  if (g_pGlobalMapState != 0) {
    borderLinked =
        g_pGlobalMapState->AreNationsBorderLinked(targetNation, static_cast<int>(this->nationSlot));
  }

  TGreatPower* targetState = g_apNationStates[targetNation];
  if (borderLinked != 0) {
    float targetArmyScore = TruncatedScoreFactorToFloat(targetState->GetScoreFactorSlot23C());
    float numerator =
        selfArmyScore + alliedArmyForSelf * (-g_Compute_Advisory_Peer_LookupTable_00653724);
    float denominator =
        targetArmyScore + alliedArmyForTarget * (-g_Compute_Advisory_Peer_LookupTable_00653724);
    return numerator / denominator;
  }

  float targetNavyScore = TruncatedScoreFactorToFloat(targetState->GetScoreFactorSlot240());
  float numerator =
      selfNavyScore + alliedNavyForSelf * (-g_Compute_Advisory_Peer_LookupTable_00653724);
  float denominator =
      targetNavyScore + alliedNavyForTarget * (-g_Compute_Advisory_Peer_LookupTable_00653724);
  return numerator / denominator;
}
#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004e2190
#pragma optimize("y", on)
void TGreatPower::NotifyWarResetSlot290(void) {}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004e21b0
void TGreatPower::ApplyJoinEmpireAcceptanceSideEffectsForTargetNation(int targetNationSlot,
                                                                      int mode) {
  CString sharedStringScope;

  ApplyJoinEmpireModeForTargetNation(targetNationSlot, mode);

  if (targetNationSlot >= 0 && targetNationSlot < kNationSlotCount) {
    TGreatPower* targetNation = g_apNationStates[targetNationSlot];
    if (targetNation != 0 && targetNation->field8d1 < 3) {
      targetNation->SetNationPendingActionStateAndPayload(9, this->nationSlot);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004e2270
void TGreatPower::RemoveRegionIdAndRunTrackedObjectCleanup(int regionId) {
  this->ownedRegionList->RemoveIntSlot34(regionId);
  this->NotifyRegionEventSlot298_Provisional(regionId);
}

// FUNCTION: IMPERIALISM 0x004e22b0
void TGreatPower::AddRegionIdToNationOwnedRegionListAndTriggerExpansionActionIfThresholdMet(void) {
  TPtrList* ownedRegionList = this->ownedRegionList;
  ownedRegionList->ResetSlot14();
  int ownedRegionCount = ownedRegionList->GetCountOrReleaseSlot28();

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
    void* diplomacyManager = g_pDiplomacyTurnStateManager;
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
      void* diplomacyManager = g_pDiplomacyTurnStateManager;
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
  TGlobalMapState* globalMapState = g_pGlobalMapState;
  TPtrList* filteredList = this->trackedObjectList;
  for (int index = filteredList->GetCountSlot48(); index != 0; --index) {
    TTrackedObjectListEntry* entry = static_cast<TTrackedObjectListEntry*>(
        filteredList->GetTrackedEntrySlot4C(index));
    if (entry == 0 || globalMapState == 0 || globalMapState->terrainStateTable == 0) {
      continue;
    }

    short mapOwnerClass = globalMapState->terrainStateTable[entry->regionIndex].cityRecordIndex;
    if (mapOwnerClass == ownerClass) {
      void* trackedObject = entry->object;
      if (trackedObject != 0) {
        static_cast<TTrackedObject*>(trackedObject)->Call30();
      }
      if (trackedObject != 0) {
        static_cast<TTrackedObject*>(trackedObject)->Release1C();
      }
    }
  }

  TPtrList* unassignedList = this->militaryUnitList44;
  for (int unassignedIndex = unassignedList->GetCountSlot48(); unassignedIndex != 0;
       --unassignedIndex) {
    TTrackedObjectListEntry* entry = static_cast<TTrackedObjectListEntry*>(
        unassignedList->GetTrackedEntrySlot4C(unassignedIndex));
    if (entry != 0 && entry->regionIndex == -1) {
      if (entry->object != 0) {
        static_cast<TTrackedObject*>(entry->object)->Release1C();
      }
    }
  }
}
// FUNCTION: IMPERIALISM 0x004e25c0
void TGreatPower::ResetNationDiplomacySlotsAndMarkRelatedNations(int targetNation) {
  this->ResetDiplomacyLevelForNationSlot12_Provisional(targetNation, 100);
  this->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(targetNation, -1);
  for (int nation = 0; nation < 0x17; ++nation) {
    if (g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(this->nationSlot, nation) != 0) {
      this->CallSlotA8_Provisional(nation);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004e2630
void TGreatPower::CallSlotA8_Provisional(int targetNationSlot) {
  const int kMajorPolicyNation = 7;
  int tableIndex = 0;
  while (tableIndex < 16) {
    if (g_apMinorNationCapabilityObjects[tableIndex] != 0) {
      TMinor* auxRuntimeState = g_apNationAuxRuntimeStateSlots[tableIndex];
      if (auxRuntimeState != 0 &&
          auxRuntimeState->HasMinorStandingLinkSlot5C(this->nationSlot) != 0 &&
          g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(kMajorPolicyNation,
                                                                  targetNationSlot) == 0) {
        g_pDiplomacyTurnStateManager->SetRelationCodeSlot74WithMode(kMajorPolicyNation,
                                                                    targetNationSlot, 6, 0);
        if (targetNationSlot < kMajorNationCount &&
            IsNationSlotEligibleForEventProcessing(targetNationSlot) != 0) {
          TGreatPower* targetState = g_apNationStates[targetNationSlot];
          if (targetState != 0 && targetState->diplomacyEligibilityA0 == 0) {
            targetState->NotifyActionSlot94(kMajorPolicyNation, 0x131);
          }
        }
        VCall_TMinor_NationAuxRuntimeClearGrantSlotC4(auxRuntimeState, -1);
        VCall_TMinor_NationAuxRuntimeFinalizeSlotC0(auxRuntimeState);
      }
    }
    ++tableIndex;
  }
}

// FUNCTION: IMPERIALISM 0x004e2720
void TGreatPower::CallSlotA9_Provisional(int targetNationSlot) {
  const int kMajorPolicyNation = 7;
  int tableIndex = 0;
  while (tableIndex < 16) {
    if (g_apMinorNationCapabilityObjects[tableIndex] != 0) {
      TMinor* auxRuntimeState = g_apNationAuxRuntimeStateSlots[tableIndex];
      if (auxRuntimeState != 0 &&
          auxRuntimeState->HasMinorStandingLinkSlot5C(this->nationSlot) != 0) {
        g_pDiplomacyTurnStateManager->SetRelationCodeSlot78Final(kMajorPolicyNation,
                                                                 targetNationSlot, 4);
        if (this->colonyBoycottFlags[targetNationSlot] == 0) {
          auxRuntimeState->SetDiplomacyStandingSlot48(targetNationSlot, 100);
        }
      }
    }
    ++tableIndex;
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

// FUNCTION: IMPERIALISM 0x004e27f0
void TGreatPower::ApplyDiplomacyRelationCodeAndNotifyThirdPartySlot284(int targetNationSlot,
                                                                       int policyCode,
                                                                       int sourceNationSlot) {
  void* diplomacyManager = g_pDiplomacyTurnStateManager;
  QueueNationPairWarTransition(diplomacyManager, this->nationSlot,
                               static_cast<short>(targetNationSlot));

  short proposalCode = static_cast<short>(policyCode);
  if ((proposalCode != 1) && (proposalCode != 0x132)) {
    return;
  }

  TMinor* secondaryNationState = g_apSecondaryNationStateSlots[sourceNationSlot];
  if (secondaryNationState == 0) {
    return;
  }

  short selectedSlot = DecodeSecondaryNationOwnerSlot(secondaryNationState);

  if (selectedSlot == this->nationSlot) {
    return;
  }

  secondaryNationState->VTableSlot4C_Provisional(this->nationSlot, 1);
}

// FUNCTION: IMPERIALISM 0x004e2880
#pragma optimize("y", on)
int TGreatPower::ClassifyNationProductionTierVsPeers(void) {
  if (this->city == 0) {
    return 0;
  }
  float sampleCount = 0.0f;
  float productionSum = 0.0f;
  float productionSquares = 0.0f;
  int slot = 0;
  TGreatPower** nationCursor = g_apNationStates;
  do {
    if (IsNationSlotEligibleForEventProcessing(slot) != 0) {
      TCity* peerMgr = (*nationCursor != 0) ? (*nationCursor)->city : 0;
      if (peerMgr != 0) {
        int production = 4;
        for (int buildingSlot = 0; buildingSlot < 7; ++buildingSlot) {
          peerMgr = (*nationCursor != 0) ? (*nationCursor)->city : 0;
          production += static_cast<short>(
              peerMgr->GetBuildingProductionValueBySlot(static_cast<short>(buildingSlot)));
        }
        sampleCount = sampleCount - g_Classify_Nation_Military_Value_00653704;
        productionSum = static_cast<float>(production) + productionSum;
        productionSquares = static_cast<float>(production * production) + productionSquares;
      }
    }
    ++nationCursor;
    ++slot;
  } while (nationCursor < g_apNationStates + 7);
  if (sampleCount < g_Classify_Nation_Military_Value_00653708) {
    return 2;
  }
  float mean = productionSum / sampleCount;
  float deviation = static_cast<float>(
      sqrt(((mean * mean * sampleCount - (mean * productionSum + mean * productionSum)) +
            productionSquares) /
           (sampleCount - g_Classify_Nation_Military_Value_0065370C)));
  int ownProduction = 4;
  for (int buildingSlot = 0; buildingSlot < 7; ++buildingSlot) {
    ownProduction += static_cast<short>(
        this->city->GetBuildingProductionValueBySlot(static_cast<short>(buildingSlot)));
  }
  float ownScore = static_cast<float>(ownProduction);
  if (mean - deviation * g_Classify_Nation_Military_Value_00653710 < ownScore) {
    return 4;
  }
  if (deviation + mean < ownScore) {
    return 3;
  }
  if (mean - deviation <= ownScore) {
    return 2;
  }
  if (mean - (deviation + deviation) <= ownScore) {
    return 1;
  }
  return 0;
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004e2b00
void TGreatPower::DispatchTurnOrderActionSlotB0(short orderKind, short payload, short flags) {
  struct TurnOrderDispatchPacket {
    short turnTick;
    short orderKind;
    short payload;
    short flags;
  };

  short turnTick = 0;
  TLocalizationRuntime* localizationRuntime = g_pLocalizationTable;
  if (localizationRuntime != 0) {
    turnTick = localizationRuntime->GetTurnTickSlot3C();
  }

  TurnOrderDispatchPacket packet;
  packet.turnTick = turnTick;
  packet.orderKind = orderKind;
  packet.payload = payload;
  packet.flags = flags;

  TTurnEventQueue* turnSummaryQueue = reinterpret_cast<TTurnEventQueue*>(this->turnSummaryQueue);
  if (turnSummaryQueue != 0) {
    turnSummaryQueue->EnqueueSlot38(&packet);
  }
}

// FUNCTION: IMPERIALISM 0x004e2b70
void TGreatPower::BuildGreatPowerTurnMessageSummaryAndDispatch(void) {
  if (this->turnSummaryQueue == 0) {
    return;
  }

  TQueueObject* summaryQueue = this->turnSummaryQueue;
  int queueCount = reinterpret_cast<TPtrList*>(summaryQueue)->GetCountSlot48();
  if (queueCount <= 0) {
    return;
  }

  short activeTurn = 0;
  TLocalizationRuntime* localizationRuntime = g_pLocalizationTable;
  if (localizationRuntime != 0) {
    activeTurn = static_cast<short>(localizationRuntime->GetTurnTickSlot3C() - 1);
  }

  int mergedNationMask = 0;
  bool foundCurrentTurnEntry = false;

  for (int queueIndex = 1; queueIndex <= queueCount; ++queueIndex) {
    short* entry =
        static_cast<short*>(summaryQueue->GetEntryAt1BasedSlot2C(queueIndex));
    if (entry == 0 || entry[0] != activeTurn) {
      continue;
    }

    foundCurrentTurnEntry = true;
    mergedNationMask |= 1 << (static_cast<int>(entry[1]) & 0x1F);
  }

  if (!foundCurrentTurnEntry) {
    return;
  }

  TInterNationEventQueueManager* queueManager =
      g_pInterNationEventQueueManager;
  if (queueManager != 0) {
    queueManager->QueueInterNationEventIntoNationBucket(0x13A0, mergedNationMask, '\0');
  }
}

// FUNCTION: IMPERIALISM 0x004e72c0
void TGreatPower::InitializeMapActionCandidateStateAndQueueMission(int arg1) {
  TStream* stream = reinterpret_cast<TStream*>(arg1);
  this->ReadFrom(stream);
  stream->ReadBytes(this->actionMetricByQuarter, 0x0C);
  SwapShortArrayBytes(this->actionMetricByQuarter, 6);

  stream->ReadBytes(this->mapNodeStateFlags, 0x180);
  stream->ReadBytes(this->portZoneStateFlags, 0x70);

  TPtrList* missionQueue = this->missionQueue;
  if (missionQueue->GetCountSlot48() != 0) {
    missionQueue->Call54();
  }
  missionQueue->Call18(arg1);

  int missionContext = 0;
  stream->ReadBytes(&missionContext, 4);
  for (int queueIndex = 1; queueIndex < 0x71; ++queueIndex) {
    missionContext = 0;
    char hasMission = stream->ReadByte(&missionContext);
    if (hasMission != 0) {
      missionQueue->AddTail30(reinterpret_cast<void*>(missionContext));
    }
  }

  if (*reinterpret_cast<int*>(kAddrAdvanceTurnMachineState) < 0x39) {
    this->QueueMapActionMissionFromCandidateAndMarkState(5, -1, 0, -1);
  }
}

// FUNCTION: IMPERIALISM 0x004e73f0
#pragma optimize("y", on)
void TGreatPower::WrapperFor_HandleCityDialogHintClusterUpdate_At004e73f0(void* pMessage) {
  this->WriteTo(static_cast<TStream*>(pMessage));

  TMessageObject* message = reinterpret_cast<TMessageObject*>(pMessage);
  short* quarterMetric = this->actionMetricByQuarter;
  int remaining = 6;
  do {
    short value = *quarterMetric;
    unsigned char* bytes = reinterpret_cast<unsigned char*>(&value);
    unsigned char tmp = bytes[0];
    bytes[0] = bytes[1];
    bytes[1] = tmp;
    message->AppendBytesSlot78(&value, 2);
    ++quarterMetric;
    --remaining;
  } while (remaining != 0);

  message->AppendBytesSlot78(this->mapNodeStateFlags, 0x180);
  message->AppendBytesSlot78(this->portZoneStateFlags, 0x70);

  TPtrList* missionQueue = this->missionQueue;
  missionQueue->ResetSlot14(pMessage);
  int missionQueueCount = missionQueue->GetCountSlot48();

  int zeroWord = 0;
  message->AppendBytesSlot78(&zeroWord, 4);
  int index = 1;
  if (index <= missionQueueCount) {
    do {
      int value = reinterpret_cast<int>(missionQueue->GetTrackedEntrySlot4C(index));
      message->WriteEntrySlotB4(value, 0);
      ++index;
    } while (index <= missionQueueCount);
  }
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004e7630
void TGreatPower::WrapperFor_TGreatPower_VtblSlot32_At004e7630(int arg1, int arg2, int arg3) {
  if (arg2 < 0 && arg1 > 6 && arg1 < 0x0D) {
    this->needCurrentByType[arg1] = static_cast<short>(this->needCurrentByType[arg1] + arg2);
  }

  this->TGreatPower::ApplyIndexedResourceDeltaAndAdjustNationTotals(arg1, arg2, arg3);
}

// FUNCTION: IMPERIALISM 0x004e78d0
void TGreatPower::DispatchNationField98CallbackD4(void) {
  static_cast<TCityInteriorMinister*>(this->interiorMinister)->CallD4();
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
  this->TGreatPower::ApplyDiplomacyPolicyStateForTargetWithCostChecks(arg1, arg2);
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
    void* diplomacyState = g_pDiplomacyTurnStateManager;
    if (diplomacyState != 0) {
      char hasAllianceGuard =
          g_pDiplomacyTurnStateManager->HasAllianceGuardSlot60(arg1, this->nationSlot);
      if (hasAllianceGuard == 0) {
        this->QueueDiplomacyProposalCodeForTargetNation(static_cast<short>(arg2),
                                                        static_cast<short>(arg1));
      }
    }
    return;
  }
  default:
    this->QueueDiplomacyProposalCodeForTargetNation(static_cast<short>(arg2),
                                                    static_cast<short>(arg1));
    return;
  }
}

// FUNCTION: IMPERIALISM 0x004e7c50
void TGreatPower::ApplyImmediateDiplomacyPolicySideEffectsWithSelectionHook(int arg1, int arg2) {
  if (static_cast<short>(arg2) == 0x131) {
    this->VTableSlot84_Provisional(static_cast<short>(arg1));
  }
  this->TGreatPower::NotifyActionSlot94(arg1, arg2);
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
      TMission::CreateByKindAndNodeContext(this->nationSlot, missionKind, arg2, arg3, arg4);
  if (missionObj == 0) {
    GAME_FAIL_NIL_POINTER();
    TemporarilyClearAndRestoreUiInvalidationFlag(kUCountryAutoCppPath, kAssertLineQueueMapAction);
  }

  TPtrList* missionQueue = this->missionQueue;
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

// FUNCTION: IMPERIALISM 0x004e8750
float TGreatPower::ComputeAdvisoryMapNodeScoreFactorByCaseMetric(int metricCase, int cityIndex,
                                                                 int relationTargetNation,
                                                                 int selectedNationSlot) {
  switch (metricCase - 1) {
  case 0: {
    float sum = 0.0f;
    float selected = 0.0f;
    TGreatPower** nationCursor = g_apNationStates;

    for (; reinterpret_cast<int>(nationCursor) < reinterpret_cast<int>(g_apNationStates_End);
         ++nationCursor) {
      int slot = static_cast<int>(nationCursor - g_apNationStates);
      if (IsNationSlotEligibleForEventProcessing(static_cast<short>(slot)) == 0) {
        continue;
      }
      TGreatPower* nationObj = *nationCursor;
      float slotValue = nationObj->GetScoreFactorSlot23C();
      sum += slotValue;
      if (slot == selectedNationSlot) {
        selected = slotValue;
      }
    }

    if (selected == g_Compute_Advisory_Zero_00653FD0) {
      selected = kOne;
    }
    int field30 = g_pLocalizationTable->GetField30();
    float denominator =
        static_cast<float>(field30) * selected - static_cast<float>(g_Compute_Advisory_MinusSix_00653FE8);
    float numerator = sum - static_cast<float>(g_Compute_Advisory_MinusSix_00653FE8);
    return numerator / denominator;
  }
  case 1: {
    float sum = 0.0f;
    float selected = 0.0f;
    TGreatPower** nationCursor = g_apNationStates;

    for (; reinterpret_cast<int>(nationCursor) < reinterpret_cast<int>(g_apNationStates_End);
         ++nationCursor) {
      int slot = static_cast<int>(nationCursor - g_apNationStates);
      if (IsNationSlotEligibleForEventProcessing(static_cast<short>(slot)) == 0) {
        continue;
      }
      TGreatPower* nationObj = *nationCursor;
      float slotValue = nationObj->GetScoreFactorSlot240();
      sum += slotValue;
      if (slot == selectedNationSlot) {
        selected = slotValue;
      }
    }

    if (selected == g_Compute_Advisory_Zero_00653FD0) {
      selected = kOne;
    }
    int field30 = g_pLocalizationTable->GetField30();
    float denominator =
        static_cast<float>(field30) * selected - static_cast<float>(g_Compute_Advisory_MinusSix_00653FE8);
    float numerator = sum - static_cast<float>(g_Compute_Advisory_MinusSix_00653FE8);
    return numerator / denominator;
  }
  case 2: {
    TTerrainDescriptor* terrainView =
        reinterpret_cast<TTerrainDescriptor*>(g_apTerrainTypeDescriptorTable[selectedNationSlot]);
    if (terrainView == 0) {
      return kOne;
    }

    if (terrainView->linkedNodeList90 == 0) {
      return kOne;
    }

    int nodeWeight = terrainView->linkedNodeList90->GetCountOrReleaseSlot28();
    int weightedNeighbor = ComputeWeightedNeighborLinkScoreForNode(relationTargetNation);
    int linkedNodeTotal = SumWeightedNeighborLinkScoreForLinkedNodes(terrainView);

    float denominator = static_cast<float>(weightedNeighbor * nodeWeight) -
                        static_cast<float>(g_Compute_Advisory_Map_Value_00653FD4);
    if (denominator == g_Compute_Advisory_Zero_00653FD0) {
      return kOne;
    }
    return (static_cast<float>(linkedNodeTotal) -
            static_cast<float>(g_Compute_Advisory_MinusHundred_00653FF0)) /
           denominator;
  }
  case 3: {
    if (selectedNationSlot < 0 || selectedNationSlot >= 7) {
      return g_Compute_Advisory_Zero_00653FD0;
    }

    TGreatPower* nationObj = g_apNationStates[selectedNationSlot];
    if (nationObj == 0) {
      return g_Compute_Advisory_Zero_00653FD0;
    }

    int priorityForNode =
        SumNavyOrderPriorityForNationAndNodeType(nationObj, relationTargetNation);
    int nodeMultiplier = nationObj->GetMultiplierSlot21C();
    int totalPriority = SumNavyOrderPriorityForNation(nationObj);

    float denominator = static_cast<float>(priorityForNode * nodeMultiplier) -
                        static_cast<float>(g_Compute_Advisory_MinusSix_00653FE8);
    if (denominator == g_Compute_Advisory_Zero_00653FD0) {
      return g_Compute_Advisory_Zero_00653FD0;
    }
    return (static_cast<float>(totalPriority) -
            static_cast<float>(g_Compute_Advisory_MinusSix_00653FE8)) /
           denominator;
  }
  case 4: {
    void* mgr = g_pDiplomacyTurnStateManager;
    if (mgr == 0) {
      return kOne;
    }
    short relationValue =
        g_pDiplomacyTurnStateManager
            ->relationStandingScoreMatrix79c[(relationTargetNation) * 0x17 + (this->nationSlot)];
    if (relationValue == 0) {
      return kOne;
    }
    return static_cast<float>(g_Compute_Advisory_Hundred_00654000) / static_cast<float>(relationValue);
  }
  case 5: {
    TGlobalMapState* globalMapState = g_pGlobalMapState;
    if (globalMapState == 0) {
      return kOne;
    }
    if (globalMapState->cityScoreTable == 0 || globalMapState->cityScoreTotal == 0) {
      return kOne;
    }
    int cityScore = GlobalMapState_ReadCityScoreValue(globalMapState, cityIndex);
    float scoreRatio =
        static_cast<float>(cityScore) / static_cast<float>(globalMapState->cityScoreTotal);

    const unsigned char* cityBytes = reinterpret_cast<const unsigned char*>(
        GlobalMapState_GetCityRecord(globalMapState, cityIndex));
    signed char primaryNation = static_cast<signed char>(cityBytes[0]);
    signed char controllingNation = static_cast<signed char>(cityBytes[1]);
    if (controllingNation == this->nationSlot && primaryNation != this->nationSlot) {
      void* diplomacyManager = g_pDiplomacyTurnStateManager;
      if (diplomacyManager != 0 && g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(
                                       this->nationSlot, primaryNation) != 0) {
        scoreRatio = scoreRatio * static_cast<float>(g_Compute_Advisory_OnePointFive_00654008);
      }
    }
    return scoreRatio;
  }
  case 6: {
    int globalAverage = ComputeGlobalMapActionContextNodeValueAverage();
    if (globalAverage == 0) {
      return kOne;
    }
    unsigned int nodeValue = this->ComputeMapActionContextNodeValueAverage();
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
    TSortedByRelationshipList* relationshipList =
        TSortedByRelationshipList::CreateTSortedByRelationshipListInstance();
    if (relationshipList != 0) {
      relationshipList->relationType = 4;
    }

    void* diplomacyManager = g_pDiplomacyTurnStateManager;
    if (diplomacyManager != 0 && relationshipList != 0) {
      g_pDiplomacyTurnStateManager->BuildRelationshipListSlot88(this->nationSlot, 1,
                                                                relationshipList);
    }

    if (relationshipList != 0) {
      short* firstEntry = static_cast<short*>(relationshipList->GetEntrySlot2C(1));
      if (firstEntry != 0) {
        selectedCandidateIndex = static_cast<int>(*firstEntry);
      }
      relationshipList->ReleaseSlot24();
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

    for (i = 0; i < 7; ++i) {
      if (candidateFlags[i] != 0) {
        navyPriorities[i] = static_cast<short>(
            SumNavyOrderPriorityForNationAndNodeType(g_apNationStates[i], nodeType));
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
        ComputeAdvisoryMapNodeScoreFactorByCaseMetric(2, -1, nodeType, selectedCandidateIndex);
    float factor4 =
        ComputeAdvisoryMapNodeScoreFactorByCaseMetric(4, -1, nodeType, selectedCandidateIndex);
    float factor5 =
        ComputeAdvisoryMapNodeScoreFactorByCaseMetric(5, -1, nodeType, selectedCandidateIndex);
    float factor7 =
        ComputeAdvisoryMapNodeScoreFactorByCaseMetric(7, -1, nodeType, selectedCandidateIndex);
    compositeScore = factor2 * factor4 * factor5 * factor7;
  }

  return compositeScore;
}

// FUNCTION: IMPERIALISM 0x004e9a50
void TGreatPower::SelectAndQueueAdvisoryMapMissionsCase16(void) {
  if (this->city == 0) {
    return;
  }

  // TEMP: 0x004e92b0 (PopulateCase16AdvisoryMapNodeCandidateState) is still an
  // autogen stub; call it through the generic thunk declaration until it is ported.
  PopulateCase16AdvisoryMapNodeCandidateState();

  int bestNodeIndex = -1;
  float bestNodeScore = 0.0f;

  for (int nodeIndex = 0; nodeIndex < 0x180; ++nodeIndex) {
    if (this->mapNodeStateFlags[nodeIndex] != 1) {
      continue;
    }

    float nodeScore = this->ComputeMapActionContextCompositeScoreForNation(nodeIndex);
    if (bestNodeIndex < 0 || nodeScore > bestNodeScore) {
      bestNodeIndex = nodeIndex;
      bestNodeScore = nodeScore;
    }
  }

  if (bestNodeIndex < 0) {
    return;
  }

  this->QueueMapActionMissionFromCandidateAndMarkState(3, bestNodeIndex, 0, -1);

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
    this->QueueInterNationEventType0FForNationPairContext(static_cast<short>(strongestNation),
                                                          this->nationSlot);
  }
}

// FUNCTION: IMPERIALISM 0x004e9ed0
#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif
void TGreatPower::QueueWarTransitionFromAdvisoryAction(int arg1, int arg2, int arg3) {
  this->VTableSlot84_Provisional(arg1);
  this->ApplyDiplomacyRelationCodeAndNotifyThirdPartySlot284(arg1, arg2, arg3);
}
#if defined(_MSC_VER)
#pragma optimize("", on)
#endif

// FUNCTION: IMPERIALISM 0x004ea150
void TGreatPower::ApplyJoinEmpireResetAndClearDiplomacyCaches(int arg1) {
  this->TGreatPower::ApplyJoinEmpireMode0GlobalDiplomacyReset(arg1);

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
}

// FUNCTION: IMPERIALISM 0x004ea290
void TGreatPower::AddRegionToNationAndQueueMapActionMission(int arg1) {
  this->AddRegionIdToNationOwnedRegionListAndTriggerExpansionActionIfThresholdMet();

  if (arg1 >= 0 && arg1 < kMapNodeCount) {
    this->mapNodeStateFlags[arg1] = 1;
    this->QueueMapActionMissionFromCandidateAndMarkState(3, arg1, 0, -1);
  }
}

// FUNCTION: IMPERIALISM 0x004ea470
void TGreatPower::RebuildNationResourceYieldsAndRollField134Into136(void) {
  this->RebuildNationResourceYieldCountersAndDevelopmentTargets();
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
    TTurnEventPacketRoutingPrefix routing;
    int packetTag;
    unsigned char activeNationId;
    unsigned char padAfterActiveNation;
    short sourceNation;
    short proposalCode;
    short targetNationId;
  };

  this->QueueDiplomacyProposalCodeForTargetNation(static_cast<short>(proposalCode),
                                                  static_cast<short>(targetNationId));

  TurnEvent16PacketPayload packetPayload;
  packetPayload.packetTag = 0x74696D65;
  packetPayload.activeNationId =
      static_cast<unsigned char>(g_pUiRuntimeContext->GetActiveNationId());
  packetPayload.sourceNation = this->nationSlot;
  packetPayload.routing.eventCode = 0x16;
  packetPayload.routing.payloadSize = 0x20;
  packetPayload.proposalCode = static_cast<short>(proposalCode);
  packetPayload.targetNationId = static_cast<short>(targetNationId);

  packetPayload.routing.SetPayloadNationIdFromSlotIndex(static_cast<int>(this->nationSlot));
  packetPayload.routing.EnqueueOrSendTurnEventPacketToNation(0);
}

// FUNCTION: IMPERIALISM 0x00541080
void TGreatPower::TryDispatchNationActionViaUiThenTurnEvent(int arg1, int arg2, int arg3,
                                                            int arg4) {
  char dispatchedViaUi =
      this->TryDispatchNationActionViaUiContextOrFallback(arg1, arg2, arg3, arg4);
  if (dispatchedViaUi != 0) {
    reinterpret_cast<void(__stdcall*)(int, int, int, int, int)>(
        thunk_DispatchTurnEvent1AWithNationActionPayload)(this->nationSlot, arg1, arg2, arg3, arg4);
  }
}

// FUNCTION: IMPERIALISM 0x005410f0
void TGreatPower::ProcessPendingDiplomacyThenDispatchTurnEvent29A(void) {
  this->ProcessPendingDiplomacyProposalQueue();
  int nationSlot = 0;

  do {
    TGreatPower* nationState = g_apNationStates[nationSlot];
    if (nationState != 0 && nationState->diplomacyEligibilityA0 == 0) {
      ClearTurnResumeNationPendingBitAndMaybeFlushTelemetry(g_pGameFlowState, nationSlot);
    }
    ++nationSlot;
  } while (nationSlot < 7);

  static_cast<TUiRuntimeContext*>(g_pGlobalUiRootController)
      ->RequestDiplomacyDecisionSlot90(this->nationSlot, this->nationSlot, 0x29A);
}

// FUNCTION: IMPERIALISM 0x005416b0
void TGreatPower::ApplyClientGreatPowerCommand69AndEmitTurnEvent1E(int arg1, int arg2) {
  struct TurnEvent1EPacketPayload {
    TTurnEventPacketRoutingPrefix routing;
    int packetTag;
    unsigned char activeNationIdAfterTag;
    unsigned char activeNationIdBeforePayload;
    unsigned char acceptedFlag;
    unsigned char commandCode;
    unsigned char commandArgA;
    unsigned char commandArgB;
  };

  bool accepted = this->ExecuteAdvisoryPromptAndApplyActionType1(arg1, arg2);
  TurnEvent1EPacketPayload packetPayload;
  packetPayload.packetTag = 0x74696D65;
  packetPayload.activeNationIdAfterTag =
      static_cast<unsigned char>(g_pUiRuntimeContext->GetActiveNationId());
  packetPayload.routing.eventCode = 0x1E;
  packetPayload.routing.payloadSize = 0x24;
  reinterpret_cast<void(__cdecl*)(void)>(thunk_SetTimeEmitPacketGameFlowTurnId)();
  packetPayload.routing.targetNationId = -1;
  packetPayload.activeNationIdBeforePayload =
      static_cast<unsigned char>(g_pUiRuntimeContext->GetActiveNationId());
  packetPayload.acceptedFlag = accepted ? 1 : 0;
  packetPayload.commandCode = 0x69;
  packetPayload.commandArgA = static_cast<unsigned char>(arg1);
  packetPayload.commandArgB = static_cast<unsigned char>(arg2);
  packetPayload.routing.EnqueueOrSendTurnEventPacketToNation(0);
}

// FUNCTION: IMPERIALISM 0x0055f140
unsigned int TGreatPower::ComputeMapActionContextNodeValueAverage(void) {
  TGlobalMapState* globalMapState = g_pGlobalMapState;
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

// FUNCTION: IMPERIALISM 0x00582630
void TGreatPower::HandleTurnInstruction_Civi_DeserializeAndCreateWorkOrder(void* pInstructionRaw) {
  STurnInstructionCiviCursor* instruction =
      reinterpret_cast<STurnInstructionCiviCursor*>(pInstructionRaw);
  if (instruction == 0 || instruction->tokenCursor == 0) {
    return;
  }

  unsigned int* cursor = instruction->tokenCursor;
  unsigned int token0 = *cursor++;
  unsigned int token1 = *cursor++;
  instruction->tokenCursor = cursor;

  short workOrderType = static_cast<short>((token0 >> 0x10) & 0xFFFF);
  short ownerNationSlot = static_cast<short>((token1 >> 0x10) & 0xFFFF);

  signed char cityOwnerTag = 0;
  if (g_pGlobalMapState != 0) {
    TTerrainStateRecordView* tileTable = g_pGlobalMapState->terrainStateTable;
    if (tileTable != 0) {
      cityOwnerTag = tileTable[ownerNationSlot].ownerNationTag04;
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

int TGreatPower::GetMultiplierSlot21C(void) {
  return 0;
}
