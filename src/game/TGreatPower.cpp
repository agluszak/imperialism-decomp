#include "game/TNavyMission.h"
#include "game/TCountry.h"
#include "game/TMinor.h"
#include "game/TNationInteractionStateManager.h"
#include "game/nation_slot_eligibility.h"
#include "game/TSimMgr.h"
#include "game/CIterator.h"
#include "game/TTown.h"
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
#include "game/diplomacy_globals.h"
#include "game/TNavyMgr.h"
#include "game/turn_event_packets.h"
#include "game/diplomacy_policy_hooks.h"
#include "game/map_action_context_helpers.h"
#include "game/TTurnEventPacket.h"
#include "game/turn_flow_cooldown.h"
#include "game/ui_invalidation_guard.h"
#include "game/TTurnInstructionCiviCursor.h"
#include "game/TViewMgr.h"
#include "game/TGameWindow.h"

#include <new>
// Manual decompilation file.
// Seeded from ghidra autogen and normalized into compile-safe wrappers.

#include <math.h>
#include "decomp_types.h"
#include "game/GameAssert.h"
#include "game/CString.h"
#include "game/TGreatPower.h"

#include "game/mfc.h"
#include "game/TObject.h"
#include "game/TGreatPower_internal.h"
#include "game/diplomacy_globals.h"
#include "game/TDiplomacyMgr.h"
#include "game/TInterNationEventQueueManager.h"
#include "game/TTurnEventQueue.h"
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

static __inline void InvokeDiplomacyPolicyStateChangedHook(int policyOrGrant, int targetNation,
                                                           char acceptedFlag) {
  (void)policyOrGrant;
  (void)targetNation;
  (void)acceptedFlag;
  NoOpDiplomacyPolicyStateChangedHook();
}
float ComputeMapActionContextCompositeScoreForNation(void);
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
int AllocateWithFallbackHandler(undefined4 size_bytes);
undefined4 thunk_QueueInterNationEventRecordDeduped(void);
undefined4 thunk_InitializeCityProductionState(void);
undefined4 WrapperFor_InitializeLinkedListSentinelNodeWithOwnerContext_At004a8640(void);
undefined4 thunk_RebuildMinorNationDispositionLookupTables(void);
undefined4 thunk_ClearTurnResumeNationPendingBitAndMaybeFlushTelemetry(void);
undefined4 GenerateThreadLocalRandom15(void);
undefined4 ReallocateHeapBlockWithAllocatorTracking(void);

// EH-body order/state globals (defined in global_data_tables.cpp). Direct absolute
// loads in the original; declaring them as real symbols lets reccmp pair the loads.
extern "C" {
extern TMinor* g_apNationAuxRuntimeStateSlots[];
}

#include "game/TUnit.h"
#include "game/TZone.h"
#include "game/TCivUnit.h"
#include "game/TAdmiral.h"
#include "game/TTrackedObjectListEntry.h"

#include "game/TQueueObject.h"
#include "game/TStream.h"
#include "game/nation_stream_serialization.h"
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
TG_LAYOUT_ASSERT(TGreatPower_Offset_city_0x894, offsetof(TGreatPower, city) == 0x894);
TG_LAYOUT_ASSERT(TGreatPower_Size_AtLeast_0x964, sizeof(TGreatPower) >= 0x964);
TG_LAYOUT_ASSERT(TGreatPower_Offset_actionMetricByQuarter_0x964,
                 offsetof(TGreatPower, actionMetricByQuarter) == 0x964);
TG_LAYOUT_ASSERT(TGreatPower_Offset_mapNodeStateFlags_0x970,
                 offsetof(TGreatPower, mapNodeStateFlags) == 0x970);
TG_LAYOUT_ASSERT(TGreatPower_Offset_portZoneStateFlags_0xAF0,
                 offsetof(TGreatPower, portZoneStateFlags) == 0xAF0);
TG_LAYOUT_ASSERT(TGreatPower_Offset_missionQueue_0xB60,
                 offsetof(TGreatPower, missionQueue) == 0xB60);
#undef TG_LAYOUT_ASSERT

// Keep a small runtime probe table for quick logging/inspection.
enum {
  kTGreatPowerOffset_turnEventQueue = offsetof(TGreatPower, turnEventQueue),
  kTGreatPowerOffset_pendingAidTotal = offsetof(TGreatPower, pendingAidTotal),
  kTGreatPowerOffset_actionMetricByQuarter = offsetof(TGreatPower, actionMetricByQuarter),
};

extern "C" UiRuntimeContext* g_pUiRuntimeContext;

static __inline TGlobalMapCityScoreRecord*
GlobalMapState_GetCityRecord(const TMapMgr* globalMapState, int cityIndex) {
  return globalMapState->cityScoreTable + cityIndex;
}

static __inline int GlobalMapState_ReadCityScoreValue(const TMapMgr* globalMapState,
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

template <typename T> static __inline void ReleaseAndClearFree(T** slot) {
  if (*slot != 0) {
    (*slot)->Free();
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
  return static_cast<TViewMgr*>(uiRuntimeContext)
      ->RequestDiplomacyDecisionSlot90(sourceNation, targetNation, proposalCode);
}

static __inline char IsTurnCooldownCounterActiveOrResetFlagAsChar(void) {
  return IsTurnCooldownCounterActiveOrResetFlag();
}

static __inline short DecodeSecondaryNationOwnerSlot(const TMinor* secondaryNationState) {
  short ownerNationSlot = secondaryNationState->encodedNationSlot;
  if (ownerNationSlot < 200) {
    if (ownerNationSlot < 100) {
      ownerNationSlot = secondaryNationState->nationSlot;
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

// Real body ported at 0x005b7f50 (file end, ascending-address order). Genuine __stdcall
// predicate: returns 1 when the resource index is in [13,16].
char __stdcall IsSpecialNationInteractionResource(short resourceIndex);

static __inline TPtrList* AllocateBattleListOwnerWithPtrListSentinel(void) {
  return new TPtrList();
}

static __inline TPtrList* AllocateBattleListOwnerWithLinkedSentinel(void) {
  TPtrList* owner = new TPtrList();
  if (owner != 0) {
    reinterpret_cast<void(__fastcall*)(void*, int)>(
        WrapperFor_InitializeLinkedListSentinelNodeWithOwnerContext_At004a8640)(
        static_cast<void*>(&owner->listState), 0);
  }
  return owner;
}

static __inline bool IsQuarterlyLocalizationGateOpen(void) {
  TSimMgr* localizationTable = g_pLocalizationTable;
  if (localizationTable == 0) {
    return false;
  }

  int localizationTick = static_cast<int>(localizationTable->quarterGateTick2c);
  int quarterGate = (localizationTick + ((localizationTick >> 0x1f) & 3)) >> 2;
  return static_cast<short>(quarterGate) != 0;
}

static __inline void DispatchQuarterlyGreatPowerPressureMessage(int statusLevel) {
  CString& sharedRef = *reinterpret_cast<CString*>(kAddrShGreatPowerPressureMessageRef);
  CString dispatchMessage;
  ::new ((void*)&dispatchMessage) CString(sharedRef);
  reinterpret_cast<TViewMgr*>(g_pUiRuntimeContext)
      ->DispatchLocalizedUiMessageWithTemplateA13A0(statusLevel, &dispatchMessage);
}

static const int kMapNodeCount = 0x180;
static const int kPortZoneCount = 0x70;
static const int kAidAllocationRowCount = 0x10;
static const int kAidAllocationColumnCount = 0x17;
static const int kMajorNationCount = 7;
static const int kDiplomacyTrackedSlotCount = 0x11;

struct SharedRefPairScope {
  CString first;
  CString second;

  SharedRefPairScope() {}

  ~SharedRefPairScope() {}
};

struct SharedRefTripleScope {
  CString first;
  CString second;
  CString third;

  SharedRefTripleScope() {}

  ~SharedRefTripleScope() {}
};

static __inline void DispatchCityRedrawInvalidateEventForRegion(short regionId) {
  ::DispatchCityRedrawInvalidateEvent(regionId);
}

// TEMP: preamble bridge cluster — map-action score wrappers (retire to TGlobalMapState/TZone).
static __inline void* ReallocateBufferWithAllocatorTracking(void* buffer, int sizeBytes) {
  return reinterpret_cast<void*(__cdecl*)(void*, int)>(ReallocateHeapBlockWithAllocatorTracking)(
      buffer, sizeBytes);
}

static __inline unsigned int GenerateThreadLocalRandom15Value(void) {
  return reinterpret_cast<unsigned int(__cdecl*)(void)>(GenerateThreadLocalRandom15)();
}


static __inline void QueueNationPairWarTransition(TDiplomacyMgr* diplomacyManager,
                                                  short sourceNation, short targetNation) {
  diplomacyManager->QueueNationPairWarTransition(sourceNation, targetNation);
}

static __inline short GetShortAtOffset14OrInvalidValue(void) {
  return GetShortAtOffset14OrInvalid(g_pMapActionContextListHead);
}

static __inline void TemporarilyClearAndRestoreUiInvalidationFlag(const char* path, int line) {
  (void)path;
  (void)line;
  ::TemporarilyClearAndRestoreUiInvalidationFlag();
}

// --- File-scope helpers/types hoisted here so the IMPERIALISM markers below stay in
// ascending-address order (reccmp-decomplint function_out_of_order). ---

#include "game/TOcean.h"

static const char kUCountryCppPath[] = "D:\\Ambit\\Cross\\UCountry.cpp";

static const float kOne = 1.0f;

extern "C" {
extern float g_Classify_Nation_Military_Value_00653704; // -1.0f
extern float g_Classify_Nation_Military_Value_00653708; // 2.0f
extern float g_Classify_Nation_Military_Value_0065370C; // 1.0f
extern float g_Classify_Nation_Military_Value_00653710; // -2.0f
extern short g_Rebuild_Primary_Nation_Value_00653570[6][0x17];
}

// Each dispatch reloads the UI-context global, as the original does.
static __inline void UiRuntime_QueueTurnStatusPrompt(int promptIndex, int payload) {
  g_pUiRuntimeContext
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

static __inline int* GreatPower_HomeRegionIndex88(TGreatPower* self) {
  return reinterpret_cast<int*>(&self->ownerNationSlot);
}

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

// FUNCTION: IMPERIALISM 0x004d89f0
TGreatPower::TGreatPower()
    : foreignMinister(0), interiorMinister(0), defenseMinister(0), diplomacyEligibilityA0(0),
      diplomacyCounterA2(0), tradeCapacity(0), needCapA6(0), needsOverCapFlag(0), grantTotalCost(0),
      diplomacyCounterB0(0), budgetPoolBase(0), budgetPoolDelta(0), turnEventQueue(0),
      proposalQueue(0), city(0), townMarkerList(0), trackedObjectList(0), scenarioInitFlag(0),
      diplomacyBudgetBase(0), escalationCounter(0), pendingCommitmentCost(0), pressureCounter(0),
      field900(0), turnSummaryQueue(0), missionNodeQueue(0), field910(0), aidAllocationTotal(0),
      pendingAidTotal(0), missionQueue(0) {
  // TCountry base scalars (identity strings constructed by the TCountry ctor).
  this->nationSlot = 0;
  this->encodedNationSlot = 0;
  this->treasuryValue10 = 0;
  this->field42 = 0;
  this->militaryUnitList44 = 0;
  this->ownerNationSlot = 0;
  this->ownedRegionList = 0;

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

// FUNCTION: IMPERIALISM 0x004d8bc0
void TGreatPower::NoOpTailStateHookSlot2B4(void) {}

// FUNCTION: IMPERIALISM 0x004d8be0
void TGreatPower::NoOpTailStateHookSlot2B8(int arg) {
  (void)arg;
}

// SYNTHETIC: IMPERIALISM 0x004d8c20
// TGreatPower::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x004d8c50
TGreatPower::~TGreatPower() {}

// FUNCTION: IMPERIALISM 0x004d8cc0
void TGreatPower::InitializeNationStateRuntimeSubsystems(int arg1, int arg2) {
  this->InitializeNationStateIdentityAndOwnedRegionList(static_cast<short>(arg1));

  TSimMgr* localizationRuntime = g_pLocalizationTable;
  if (localizationRuntime != 0) {
    int runtimeIndex = localizationRuntime->runtimeSubsystemIndex;
    this->treasuryValue10 = ReadGlobalIntStep(kAddrNationRuntimeSubsystemCache, runtimeIndex);
  } else {
    this->treasuryValue10 = 0;
  }

  this->diplomacyEligibilityA0 = (static_cast<short>(arg2) == 1) ? 1 : 0;

  void* cityModel = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x20));
  if (cityModel != 0) {
    reinterpret_cast<TCity*>(cityModel)->TCity::TCity();
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
    this->city->Free();
  }
  this->city = 0;
  if (this->turnEventQueue != 0) {
    this->turnEventQueue->ReleaseSlot24();
  }
  this->turnEventQueue = 0;
  if (this->proposalQueue != 0) {
    this->proposalQueue->ReleaseSlot24();
  }
  this->proposalQueue = 0;
  if (this->foreignMinister != 0) {
    this->foreignMinister->Free();
  }
  this->foreignMinister = 0;
  if (this->interiorMinister != 0) {
    this->interiorMinister->Free();
  }
  this->interiorMinister = 0;
  if (this->defenseMinister != 0) {
    this->defenseMinister->Free();
  }
  this->defenseMinister = 0;
  TQueueObject** trackedSlots = this->diplomacyTrackedSlots;
  int trackedSlotCount = 0x11;
  do {
    if (*trackedSlots != 0) {
      (*trackedSlots)->ReleaseSlot24();
    }
    *trackedSlots = 0;
    ++trackedSlots;
    trackedSlotCount = trackedSlotCount + -1;
  } while (trackedSlotCount != 0);
  if (this->townMarkerList != 0) {
    this->townMarkerList->FreePayloadsAndDestroySlot58();
  }
  this->townMarkerList = 0;
  if (this->trackedObjectList != 0) {
    this->trackedObjectList->FreePayloadsAndDestroySlot58();
  }
  this->trackedObjectList = 0;
  if (this->turnSummaryQueue != 0) {
    this->turnSummaryQueue->ReleaseSlot24();
  }
  this->turnSummaryQueue = 0;
  if (this->missionNodeQueue != 0) {
    this->missionNodeQueue->FreePayloadsAndDestroySlot58();
  }
  this->missionNodeQueue = 0;
  if (this->militaryUnitList44 != 0) {
    this->militaryUnitList44->FreePayloadsAndDestroySlot58();
  }
  this->militaryUnitList44 = 0;
  if (this->ownedRegionList != 0) {
    this->ownedRegionList->AddTailSlot38();
    this->ownedRegionList = 0;
  }
  delete this;
}

// FUNCTION: IMPERIALISM 0x004d92e0
void TGreatPower::ReadFrom(TStream* stream) {
  TCountry::ReadFrom(stream);
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

  this->turnEventQueue->slot18();
  this->proposalQueue->slot18();
  int listIndex = 0;
  while (listIndex < kDiplomacyTrackedSlotCount) {
    this->diplomacyTrackedSlots[listIndex]->slot18();
    ++listIndex;
  }

  if (*reinterpret_cast<int*>(kAddrAdvanceTurnMachineState) < 0x1D) {
    if (this->encodedNationSlot == -1) {
      char gate = this->ShouldDispatchImmediatelySlot28();
      if (gate == 0) {
        this->foreignMinister->ReadFrom(stream);
        this->interiorMinister->ReadFrom(stream);
        this->defenseMinister->ReadFrom(stream);
      }
      this->city->ReadFrom(stream);
    } else {
      ReleaseAndClearFree(&this->foreignMinister);
      ReleaseAndClearFree(&this->interiorMinister);
      ReleaseAndClearFree(&this->defenseMinister);
      ReleaseAndClearFree(&this->city);
    }
  } else {
    int ministerMask = static_cast<TStream*>(stream)->ReadInteger();

    if ((ministerMask & 1) == 0) {
      ReleaseAndClearFree(&this->foreignMinister);
    } else {
      TMinister* foreignMinister = this->foreignMinister;
      if (foreignMinister == 0) {
        TForeignMinister* created = new TForeignMinister();
        created->InitializeStateAndCounters();
        this->foreignMinister = created;
        foreignMinister = created;
      }
      if (foreignMinister != 0) {
        foreignMinister->ReadFrom(stream);
      }
    }

    if ((ministerMask & 2) == 0) {
      ReleaseAndClearFree(&this->interiorMinister);
    } else {
      TMinister* interiorMinister = this->interiorMinister;
      if (interiorMinister == 0) {
        TCityInteriorMinister* created = new TCityInteriorMinister();
        created->InitializeCityInteriorState();
        this->interiorMinister = created;
        interiorMinister = created;
      }
      if (interiorMinister != 0) {
        interiorMinister->ReadFrom(stream);
      }
    }

    if ((ministerMask & 4) == 0) {
      ReleaseAndClearFree(&this->defenseMinister);
    } else {
      TMinister* defenseMinister = this->defenseMinister;
      if (defenseMinister == 0) {
        TDefenseMinister* created = new TDefenseMinister();
        created->InitializeBaseOrderArrayMetrics();
        this->defenseMinister = created;
        defenseMinister = created;
      }
      if (defenseMinister != 0) {
        defenseMinister->ReadFrom(stream);
      }
    }

    if ((ministerMask & 8) == 0) {
      ReleaseAndClearFree(&this->city);
    } else {
      void* cityObject = this->city;
      if (cityObject != 0) {
        static_cast<TCity*>(cityObject)->ReadFrom(stream);
      }
    }
  }

  void* townMarkerList = this->townMarkerList;
  int hasItems = static_cast<TPtrList*>(townMarkerList)->GetCountSlot48();
  if (hasItems != 0) {
    static_cast<TPtrList*>(townMarkerList)->FreePayloadsSlot54();
  }
  static_cast<TPtrList*>(townMarkerList)->ReadFrom(stream);

  int townCount = 0;
  static_cast<TStream*>(stream)->ReadBytes(&townCount, 4);

  if (townCount > 0) {
    int townOrdinal = 1;
    while (townOrdinal <= townCount) {
      void* townMarker = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x20));
      if (townMarker != 0) {
        reinterpret_cast<TTown*>(townMarker)->TTown::TTown();
        static_cast<TTown*>(townMarker)->ReadFrom(stream);
        static_cast<TPtrList*>(townMarkerList)->AddTailSlot30(townMarker);
      }
      ++townOrdinal;
    }
  }

  if (townCount > 0) {
    this->city->AdoptSelectedOrderSlot44(
        static_cast<TPtrList*>(townMarkerList)->GetEntryByOrdinalSlot4C());
  }

  void* trackedObjectList = this->trackedObjectList;
  hasItems = static_cast<TPtrList*>(trackedObjectList)->GetCountSlot48();
  if (hasItems != 0) {
    static_cast<TPtrList*>(trackedObjectList)->FreePayloadsSlot54();
  }
  static_cast<TPtrList*>(trackedObjectList)->ReadFrom(stream);

  int unusedOrderCount = 0;
  static_cast<TStream*>(stream)->ReadBytes(&unusedOrderCount, 4);

  int orderOrdinal = 1;
  while (orderOrdinal < 5) {
    TCivUnit* civOrderObj = new TCivUnit();
    if (civOrderObj != nullptr) {
      civOrderObj->InitializeCivWorkOrderState(0, -1, this->nationSlot);
      civOrderObj->ReadFrom(stream);
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
    static_cast<TPtrList*>(missionNodeQueue)->ReadFrom(stream);

    int nodeCount = 0;
    static_cast<TStream*>(stream)->ReadBytes(&nodeCount, 4);
    if (nodeCount > 0) {
      int nodeOrdinal = 1;
      while (nodeOrdinal <= nodeCount) {
        unsigned char hasNode = 0;
        char markerOk = static_cast<TStream*>(stream)->ReadByte(&hasNode);
        if (markerOk != 0) {
          static_cast<TPtrList*>(missionNodeQueue)->AddTailSlot30(0);
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
  TCountry::WriteTo(stream);

  stream->WriteBytesSlot78(&this->diplomacyEligibilityA0, 1);
  stream->WriteBytesSlot78(&this->diplomacyCounterA2, 2);
  stream->WriteBytesSlot78(&this->tradeCapacity, 2);
  stream->WriteBytesSlot78(&this->needCapA6, 2);
  stream->WriteBytesSlot78(&this->needsOverCapFlag, 2);
  stream->WriteBytesSlot78(&this->grantTotalCost, 4);
  stream->WriteBytesSlot78(&this->diplomacyCounterB0, 2);

  WriteShortArrayElems(stream, this->diplomacyPolicyByNation, 0x17);
  WriteShortArrayElems(stream, this->diplomacyGrantByNation, 0x17);
  WriteShortArrayElems(stream, this->needCurrentByType, 0x17);
  WriteShortArrayElems(stream, this->needTargetByType, 0x17);
  WriteShortArrayElems(stream, this->relationDeltaCurrent, 0x17);
  WriteShortArrayElems(stream, this->relationDeltaSnapshot, 0x17);
  WriteShortArrayElems(stream, this->diplomacyState1c6, 0x17);
  WriteShortArrayElems(stream, this->diplomacyState1f4, 0x17);
  WriteShortArrayElems(stream, this->diplomacyState222, 0x17);
  WriteShortArrayElems(stream, this->diplomacyState250, 0x17);

  stream->WriteBytesSlot78(&this->budgetPoolBase, 4);
  stream->WriteBytesSlot78(&this->budgetPoolDelta, 4);
  WriteIntArrayElems(stream, this->aidAllocationMatrix, 0x170);

  stream->WriteBytesSlot78(&this->serializedStatusFlags[0], 0xd);
  WriteShortArrayElems(stream, this->field8d6, 0xd);

  this->turnEventQueue->slot14(stream);
  this->proposalQueue->slot14(stream);
  for (int slotIndex = 0; slotIndex < kDiplomacyTrackedSlotCount; ++slotIndex) {
    this->diplomacyTrackedSlots[slotIndex]->slot14(stream);
  }

  unsigned char presenceFlags = 0;
  if (this->foreignMinister != 0) {
    presenceFlags = 1;
  }
  if (this->interiorMinister != 0) {
    presenceFlags = static_cast<unsigned char>(presenceFlags | 2);
  }
  if (this->defenseMinister != 0) {
    presenceFlags = static_cast<unsigned char>(presenceFlags | 4);
  }
  if (this->city != 0) {
    presenceFlags = static_cast<unsigned char>(presenceFlags | 8);
  }
  stream->streamSlot7c(presenceFlags);
  if (this->foreignMinister != 0) {
    this->foreignMinister->WriteTo(stream);
  }
  if (this->interiorMinister != 0) {
    this->interiorMinister->WriteTo(stream);
  }
  if (this->defenseMinister != 0) {
    this->defenseMinister->WriteTo(stream);
  }
  if (this->city != 0) {
    this->city->ForwardQueueSlot20Slot50(stream);
  }

  WriteTrackedListToStream(stream, this->townMarkerList);
  WriteTrackedListToStream(stream, this->trackedObjectList);

  stream->WriteBytesSlot78(this->candidateNationFlags, 0x17);
  stream->WriteBytesSlot78(&this->diplomacyBudgetBase, 4);
  stream->WriteBytesSlot78(&this->escalationCounter, 1);
  stream->WriteBytesSlot78(&this->pendingCommitmentCost, 4);
  stream->WriteBytesSlot78(&this->pressureCounter, 1);
  stream->WriteBytesSlot78(&this->field900, 4);
  stream->WriteBytesSlot78(&this->field904, 1);

  this->missionNodeQueue->WriteTo(stream);
  int missionNodeCount = this->missionNodeQueue->GetCountSlot48();
  stream->WriteBytesSlot78(&missionNodeCount, 4);
  for (int nodeOrdinal = 1; nodeOrdinal <= missionNodeCount; ++nodeOrdinal) {
    void* node = this->missionNodeQueue->GetEntryByOrdinalSlot4C(nodeOrdinal);
    stream->WriteObjectSlotB4(node, 0);
  }

  stream->WriteBytesSlot78(&this->field910, 4);
  stream->WriteBytesSlot78(&this->aidAllocationTotal, 4);
  stream->WriteBytesSlot78(this->colonyBoycottFlags, 0x17);
  stream->WriteBytesSlot78(&this->pendingAidTotal, 4);
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004da3e0
void TGreatPower::ReadCoreFieldsFromStream(TStream* stream, int unusedArg) {
  TCountry::ReadCoreFieldsFromStream(stream, unusedArg);

  if (this->trackedObjectList->GetCountSlot48() != 0) {
    this->trackedObjectList->FreePayloadsSlot54();
  }
  this->trackedObjectList->ReadFrom(stream);

  int orderCount = stream->ReadShort();
  for (; orderCount > 0; --orderCount) {
    TCivUnit* civOrder = new TCivUnit();
    civOrder->InitializeCivWorkOrderState(0, -1, this->nationSlot);
    civOrder->ReadFrom(stream);
  }
}

// --- Slot 0x0a/0x0b stream serialization pair and status-flag slots 0x2b-0x33 ---

// FUNCTION: IMPERIALISM 0x004da500
void TGreatPower::WriteCoreFieldsToStream(TStream* stream) {
  TCountry::WriteCoreFieldsToStream(stream);

  this->trackedObjectList->WriteTo(stream);
  int orderCount = this->trackedObjectList->GetCountSlot48();
  stream->WriteCountSlot88(orderCount);
  for (int ordinal = 1; ordinal <= orderCount; ++ordinal) {
    TUnit* order =
        reinterpret_cast<TUnit*>(this->trackedObjectList->GetEntryByOrdinalSlot4C(ordinal));
    order->WriteTo(stream);
  }
}

// FUNCTION: IMPERIALISM 0x004da5c0
void TGreatPower::NoOpNationPendingActionHook(void) {}

// FUNCTION: IMPERIALISM 0x004da5e0
#pragma optimize("y", on)
void TGreatPower::DispatchPendingStatusPrompts(void) {
  unsigned char* flags = this->serializedStatusFlags;
  char flag5Handled = static_cast<signed char>(flags[5]) >= 0x33;
  if (!flag5Handled && CityOrderCapabilityState()->orderCapRows277[this->nationSlot].flag == 2) {
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
  if (!flag5Handled && CityOrderCapabilityState()->orderCapRows277[this->nationSlot].flag == 2) {
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
    flags[0] = static_cast<unsigned char>(*reinterpret_cast<char*>(&this->field8d6[0]) + 0x33);
  }
  if (flags[1] == 0x32) {
    flags[1] = static_cast<unsigned char>(*reinterpret_cast<char*>(&this->field8d6[1]) + 0x33);
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
  this->missionNodeQueue->AddTailSlot30(node);
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004daa80
#pragma optimize("y", on)
void TGreatPower::DispatchMissionNodeCallbacksAndClearQueue(void) {
  CIterator nodeIter(this->missionNodeQueue);
  for (TMission* node = static_cast<TMission*>(nodeIter.Reset());
       nodeIter.More(); node = static_cast<TMission*>(nodeIter.Advance())) {
    node->DispatchMissionNodeSlot28();
  }
  static_cast<TPtrList*>(this->missionNodeQueue)->FreePayloadsSlot54();
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004dab00
void TGreatPower::NoOpNationQueuedOrderHook(void) {}

// FUNCTION: IMPERIALISM 0x004dae70
#pragma optimize("y", on)
char TGreatPower::HasTrackedOrderOfType7(void) {
  char found = 0;
  CIterator orderIter(this->trackedObjectList);
  TUnit* order = static_cast<TUnit*>(orderIter.Reset());
  if (orderIter.More()) {
    while (order->orderType != 7) {
      order = static_cast<TUnit*>(orderIter.Advance());
      if (!orderIter.More()) {
        return 0;
      }
    }
    found = 1;
  }
  return found;
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004daf00
void TGreatPower::DispatchTurnEvent11F8NoPayloadSlot2AC(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x004daf30
void TGreatPower::CompileGreatPowerRelationshipDeltaLinesAndDispatchMessage(void) {
  static const short kNationPriorityOrder[] = {0x0F, 0x0E, 0x0D, 0x10, 0x0C, 0x08, 0x0A, 0x09, 0x0B,
                                               0x06, 0x03, 0x04, 0x05, 0x00, 0x01, 0x02, 0x07, -1};

  if (this->ShouldDispatchImmediatelySlot28() != 0) {
    return;
  }

  TSimMgr* localizationRuntime = g_pLocalizationTable;
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
        interactionScore = g_pNationInteractionStateManager->QueryProposalWeightSlot4C(nationSlot);
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
    CString dispatchMessage;
    ::new ((void*)&dispatchMessage) CString(localizedRefs.second);
    reinterpret_cast<TViewMgr*>(g_pUiRuntimeContext)
        ->DispatchLocalizedUiMessageWithTemplateA13A0(2, &dispatchMessage);
  }
}

// FUNCTION: IMPERIALISM 0x004db380
void TGreatPower::UpdateGreatPowerPressureStateAndDispatchEscalationMessage(void) {
  TSimMgr* localizationRuntime = g_pLocalizationTable;
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
        CString dispatchMessage;
        ::new ((void*)&dispatchMessage) CString(sharedMessageRef);
        reinterpret_cast<TViewMgr*>(g_pUiRuntimeContext)
            ->DispatchLocalizedUiMessageWithTemplateA13A0(4, &dispatchMessage);
        return;
      }

      if (pressureTier < compileThreshold) {
        if (localizationRuntime != 0) {
          int statusId = (pressureTier == (compileThreshold - 1)) ? 3 : 2;
          localizationRuntime->GetString(
              0x274b, static_cast<short>(statusId),
              reinterpret_cast<CString*>(kAddrShGreatPowerPressureMessageRef));
        }
        DispatchQuarterlyGreatPowerPressureMessage(1);
      } else {
        if (localizationRuntime != 0) {
          localizationRuntime->GetString(
              0x274b, 1, reinterpret_cast<CString*>(kAddrShGreatPowerPressureMessageRef));
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
  TTown* marker = static_cast<TTown*>(markerCursor.Reset());
  while (markerCursor.More() != 0 &&
         static_cast<int>(marker->regionId14) != *GreatPower_HomeRegionIndex88(this)) {
    marker = static_cast<TTown*>(markerCursor.Advance());
  }
  char homeLinked = static_cast<TTown*>(marker)->IsTransportLinkedAndEnabled();
  if (homeLinked == 0) {
    this->MarkConnectedOwnedRegionsFrom(reinterpret_cast<unsigned char*>(influenceMap),
                                        marker->regionId14);
    marker = static_cast<TTown*>(markerCursor.Reset());
    while (markerCursor.More() != 0 && homeLinked == 0) {
      if (influenceMap[marker->regionId14] != 0 &&
          static_cast<TTown*>(marker)->IsTransportLinkedAndEnabled() != 0) {
        homeLinked = 1;
      }
      marker = static_cast<TTown*>(markerCursor.Advance());
    }
  }
  marker = static_cast<TTown*>(markerCursor.Reset());
  while (markerCursor.More() != 0) {
    if (static_cast<TTown*>(marker)->IsTransportLinkedAndEnabled() != 0 && homeLinked != 0 &&
        marker->activeFlag4f != 0 && influenceMap[marker->regionId14] == 0) {
      this->MarkConnectedOwnedRegionsFrom(reinterpret_cast<unsigned char*>(influenceMap),
                                          marker->regionId14);
    }
    marker = static_cast<TTown*>(markerCursor.Advance());
  }
  marker = static_cast<TTown*>(markerCursor.Reset());
  while (markerCursor.More() != 0) {
    if ((influenceMap[marker->regionId14] == 0 || marker->activeFlag4f == 0) &&
        (static_cast<TTown*>(marker)->IsTransportLinkedAndEnabled() == 0 ||
         homeLinked == 0)) {
      marker->transportLinkedFlag4c = 0;
    } else {
      marker->transportLinkedFlag4c = 1;
    }
    marker = static_cast<TTown*>(markerCursor.Advance());
  }
  if (outInfluenceMap != 0) {
    marker = static_cast<TTown*>(markerCursor.Reset());
    while (markerCursor.More() != 0) {
      if (static_cast<TTown*>(marker)->IsTransportLinkedAndEnabled() != 0 &&
          homeLinked != 0) {
        influenceMap[marker->regionId14] = 1;
      }
      marker = static_cast<TTown*>(markerCursor.Advance());
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
            TMapMgr::GetWrappedHexNeighborTileIndexByDirection(regionId, direction);
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
  TMapMgr* globalMapState = g_pGlobalMapState;
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
              char contribution = globalMapState->CallMetricSlotC4(regionIndex, edgeIndex);
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

  int totalRegions = regionList->GetCountSlot48();
  int regionOrdinal = 1;
  while (regionOrdinal <= totalRegions) {
    short regionId = static_cast<short>(regionList->GetIntByOrdinalSlot24(regionOrdinal));
    unsigned char pendingStage = 0;
    unsigned char needsRedraw = 0;

    TMapMgr* globalMapState = g_pGlobalMapState;
    TSimMgr* localizationRuntime = g_pLocalizationTable;
    if (globalMapState != 0 && localizationRuntime != 0 && globalMapState->cityScoreTable != 0 &&
        globalMapState->terrainStateTable != 0) {
      TGlobalMapCityScoreRecord* cityTable = globalMapState->cityScoreTable;
      TTerrainStateRecordView* terrainTable = globalMapState->terrainStateTable;
      TGlobalMapCityScoreRecord* cityRecord = cityTable + regionId;
      short ownerSlot = this->ownerNationSlot;
      if (cityRecord->ownerNationSlot != ownerSlot) {
        unsigned int turnDelta =
            static_cast<unsigned int>(static_cast<int>(localizationRuntime->GetTurnTickSlot3C()) -
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
                resourceSums[resourceType] +=
                    static_cast<int>(globalMapState->CallMetricSlotC4(linkedRegion, edge));
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
              int prod = this->city->GetBuildingProductionValueBySlot(1);
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
              int prod = this->city->GetBuildingProductionValueBySlot(5);
              int prodLimit = (prod + ((prod >> 0x1f) & 3U)) >> 2;
              if (static_cast<int>(*stage1CounterB) < prodLimit &&
                  static_cast<int>(*stage1CounterB) < resourceSums[2] / 2) {
                pendingStage = 1;
                *stage1CounterB = static_cast<short>(*stage1CounterB + 1);
                needsRedraw = 1;
              }
            }

            if (resourceSums[3] != 0) {
              int prod = this->city->GetBuildingProductionValueBySlot(3);
              int prodLimit = (prod + ((prod >> 0x1f) & 3U)) >> 2;
              if (static_cast<int>(*stage1CounterC) < prodLimit &&
                  static_cast<int>(*stage1CounterC) < resourceSums[3] / 2) {
                pendingStage = 1;
                *stage1CounterC = static_cast<short>(*stage1CounterC + 1);
                needsRedraw = 1;
              }
            }

            TTechMgr* orderCapabilityState = CityOrderCapabilityState();
            int capabilityScore = this->city->GetBuildingProductionValueBySlot(7);
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
          DispatchCityRedrawInvalidateEventForRegion(regionId);
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
    float crossNationScore =
        TDefendProvinceMission::ComputeCrossNationSupportVectorScore(nodeContext);
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
    GetShortAtOffset14OrInvalid(contextEntry);
    if (this->ContainsPointerArrayEntryMatchingByteKey(this->nationSlot) != 0) {
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
    TTown* marker = static_cast<TTown*>(cursor.current);
    if (marker != 0 && marker->enabledFlag4d != 0 && marker->transportLinkedFlag4c == 0) {
      CString messageRef;
      CString scratchRef;
      g_pGlobalMapState->AssignSharedStringFromIndexedA8EntryNameField(
          g_pGlobalMapState->terrainStateTable[marker->regionId14].cityRecordIndex, &messageRef);
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

// FUNCTION: IMPERIALISM 0x004dca80
void TGreatPower::OrphanRetStub_004dca80(void) {}

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

// FUNCTION: IMPERIALISM 0x004dcc30
void TGreatPower::OrphanRetStub_004dcc30(void) {}

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
void TGreatPower::ResetDiplomacyLevelForNationSlot12(NationSlot targetNationSlot, int resetLevel) {
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
    short relationWeight = *reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(this->city) +
                                                     0x5C + resourceType * 2);
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
      static_cast<TMission*>(trackedObject)->Free();
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
  TSimMgr* localizationTable = g_pLocalizationTable;
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
  cityPtr->fieldB6[targetSlot] = static_cast<short>(cityPtr->fieldB6[targetSlot] + value);
  cityPtr->Refresh80();
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004dd7f0
#pragma optimize("y", on)
unsigned int TGreatPower::ComputeProductionMetricForOrderKind(short orderKind) {
  switch (orderKind) {
  case 0:
  case 1: {
    int production = this->city->GetBuildingProductionValueBySlot(0);
    return production + production;
  }
  case 2: {
    int production = this->city->GetBuildingProductionValueBySlot(4);
    return production + production;
  }
  case 3:
  case 4:
    return this->city->GetBuildingProductionValueBySlot(2);
  case 6: {
    int production = this->city->GetBuildingProductionValueBySlot(6);
    return production + production;
  }
  case 8: {
    int production = this->city->GetBuildingProductionValueBySlot(1);
    return production + production;
  }
  case 9:
  case 10: {
    int production = this->city->GetBuildingProductionValueBySlot(5);
    return production + production;
  }
  case 0xb: {
    int production = this->city->GetBuildingProductionValueBySlot(3);
    return production + production;
  }
  case 0xc: {
    int production = this->city->GetBuildingProductionValueBySlot(0xb);
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
void TGreatPower::AssignNeedSlotFromSourceSlot19C(short targetNationSlot, short sourceNationSlot) {
  TInterNationEventQueueManager* queueManager = g_pInterNationEventQueueManager;
  if (queueManager != 0) {
    queueManager->QueueInterNationEventType0FWithBitmaskMerge(this->nationSlot, sourceNationSlot,
                                                              targetNationSlot, '\0');
  }
}

void TGreatPower::QueueInterNationEventType0FForNationPairContext(short targetNationSlot,
                                                                  short sourceNationSlot) {
  this->AssignNeedSlotFromSourceSlot19C(targetNationSlot, sourceNationSlot);
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
    TViewMgr* uiRuntimeContext = g_pUiRuntimeContext;
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
    TSimMgr* localizationTable = g_pLocalizationTable;
    if (localizationTable != 0 && localizationTable->mode == 6) {
      this->ApplyDiplomacyRelationCodeAndNotifyThirdPartySlot284(targetClass, 4, -1);
    }

    void* diplomacyManager = g_pDiplomacyTurnStateManager;
    short relationTier =
        g_pDiplomacyTurnStateManager->GetRelationTierSlot70(targetClass, this->nationSlot);
    if (relationTier == 2) {
      g_pDiplomacyTurnStateManager->ApplyRelationCode4Slot7c(this->nationSlot, targetClass, 1);
    }

    TCountry* terrainDescriptor = g_apTerrainTypeDescriptorTable[targetClass];
    if (terrainDescriptor != 0) {
      const TCountry* terrain = terrainDescriptor;
      short encodedNationSlot = terrain->encodedNationSlot;
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

// FUNCTION: IMPERIALISM 0x004de2b0
void TGreatPower::BeginTurnDiplomacyPrePassSlot1c8() {}

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
        TSimMgr* localizationRuntime = g_pLocalizationTable;
        if (localizationRuntime != 0) {
          localizationRuntime->GetString(0x2753, 0, &sharedRefs.first);
          localizationRuntime->GetString(0x2753, 0, &sharedRefs.second);
        }
        CString primaryMessage;
        CString secondaryMessage;
        ::new ((void*)&primaryMessage) CString(sharedRefs.first);
        ::new ((void*)&secondaryMessage) CString(sharedRefs.second);
        (void)primaryMessage;
        reinterpret_cast<TViewMgr*>(g_pUiRuntimeContext)
            ->DispatchLocalizedUiMessageWithTemplateA13A0(2, &secondaryMessage);
      }
    }
  }
  return accepted;
}

// FUNCTION: IMPERIALISM 0x004de5e0
#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif
void TGreatPower::RevokeDiplomacyGrantForTargetAndAdjustInfluenceSlot1d8(int arg1) {
  short targetNation = static_cast<short>(arg1);
  int grantValue = DecodeActiveGrantValue(this->diplomacyGrantByNation[targetNation]);
  if (grantValue <= 0) {
    return;
  }

  g_apTerrainTypeDescriptorTable[targetNation]->AddToNationMetricAtField10(grantValue);

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

void TGreatPower::RevokeDiplomacyGrantForTargetAndAdjustInfluence(int arg1) {
  this->RevokeDiplomacyGrantForTargetAndAdjustInfluenceSlot1d8(arg1);
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
void TGreatPower::NotifyWarResetSlotA5(void) {
  TPtrList* trackedList = this->trackedObjectList;
  if (trackedList == 0) {
    return;
  }

  int remaining = trackedList->GetCountSlot48();
  while (remaining > 0) {
    TTrackedObjectListEntry* entry =
        static_cast<TTrackedObjectListEntry*>(trackedList->GetEntryByOrdinalSlot4C(remaining));
    if (entry != 0) {
      reinterpret_cast<TMission*>(entry)->Call30();
    }
    if (entry != 0) {
      reinterpret_cast<TMission*>(entry)->Free();
    }
    --remaining;
  }
}

// FUNCTION: IMPERIALISM 0x004de860
void TGreatPower::SetNationTransferTargetCodeAndNotifyEligiblePeers(int arg1) {
  const int kResetDiplomacyLevel = 100;
  const int kResetPolicyCode = -1;
  const int kDipFlagRelation = 6;
  const int kDipFlagPolicy = 0x31;

  if (g_pInterNationEventQueueManager != 0) {
    g_pInterNationEventQueueManager->QueueInterNationEventRecordDeduped(0x1D, this->nationSlot, 7,
                                                                        '\0');
  }
  reinterpret_cast<void(__cdecl*)(void)>(thunk_RebuildMinorNationDispositionLookupTables)();

  this->encodedNationSlot = static_cast<short>(arg1 + 100);

  int nationSlot;
  for (nationSlot = 0; nationSlot < kNationSlotCount; ++nationSlot) {
    if (IsNationSlotEligibleForEventProcessing(nationSlot) != 0 && nationSlot != this->nationSlot &&
        nationSlot != arg1) {
      g_apTerrainTypeDescriptorTable[nationSlot]->SetNationPercentFieldByModeAndDescriptorLinks(
          this->nationSlot, kResetDiplomacyLevel);
    }
  }

  g_pDiplomacyTurnStateManager->ResetTerrainAdjacencyMatrixRowAndSymmetricLink(this->nationSlot);

  this->treasuryValue10 = 0;

  ReleaseAndClearFree(&this->foreignMinister);
  ReleaseAndClearFree(&this->interiorMinister);
  ReleaseAndClearFree(&this->defenseMinister);

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
    this->proposalQueue->ResetPtrListRecordsSlot1C();
  }
  if (this->turnEventQueue != 0) {
    this->turnEventQueue->ResetPtrListRecordsSlot1C();
  }

  this->ReleaseDiplomacyTrackedObjectSlots850();

  void* relationPanelManager = this->city;
  if (relationPanelManager != 0) {
    static_cast<TMission*>(relationPanelManager)->Free();
  }
  this->city = 0;

  this->NotifyWarResetSlotA5();

  for (nationSlot = 0; nationSlot < kNationSlotCount; ++nationSlot) {
    if (nationSlot != this->nationSlot && IsNationSlotEligibleForEventProcessing(nationSlot) != 0) {
      g_pDiplomacyTurnStateManager->SetRelationCodeSlot74WithMode(this->nationSlot, nationSlot,
                                                                  kDipFlagRelation, 0);
      g_pDiplomacyTurnStateManager->SetStandingScoreSlot28(this->nationSlot, nationSlot,
                                                           kDipFlagPolicy);
      TGreatPower* nationState = g_apNationStates[nationSlot];
      if (nationState->diplomacyEligibilityA0 == 0) {
        nationState->NotifyActionSlot94(this->nationSlot, 0x131);
      }
      this->ResetDiplomacyLevelForNationSlot12(static_cast<NationSlot>(nationSlot),
                                               kResetDiplomacyLevel);
      this->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(nationSlot, kResetPolicyCode);
    }
  }

  int secondarySlot;
  for (secondarySlot = kMajorNationCount; secondarySlot < kNationSlotCount; ++secondarySlot) {
    TMinor* secondaryState = g_apSecondaryNationStateSlots[secondarySlot];
    bool directReset = true;
    short encodedOwnerNation = secondaryState->encodedNationSlot;
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

    this->ResetDiplomacyLevelForNationSlot12(static_cast<NationSlot>(secondarySlot),
                                             kResetDiplomacyLevel);
    this->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(secondarySlot, kResetPolicyCode);

    if (g_apTerrainTypeDescriptorTable[secondarySlot] != 0) {
      secondaryState->SetDiplomacyStandingSlot48(this->nationSlot, kResetDiplomacyLevel);
    }
  }

  if (g_pNavyOrderManager != 0) {
    g_pNavyOrderManager->RemoveOrdersByNationFromPrimarySecondaryAndTaskForceLists(
        this->nationSlot);
  }
  g_pGlobalMapState->ApplyJoinEmpireMode0GlobalDiplomacyReset(this->nationSlot);

  TSimMgr* localizationTable = g_pLocalizationTable;
  if (localizationTable != 0 && localizationTable->redrawEnabled != 0) {
    DispatchTaggedGameStateEvent1F20(0x6e616d65, this->nationSlot, 0xfffffffd);
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

    char immediateDispatch = this->ShouldDispatchImmediatelySlot28();
    if (immediateDispatch == 0) {
      if (g_pInterNationEventQueueManager != 0) {
        g_pInterNationEventQueueManager->QueueInterNationEventIntoNationBucket(
            static_cast<int>(this->nationSlot), reinterpret_cast<int>(&payload), '\0');
      }
    } else {
      CreateAndSendTurnEvent13_NationAndNineDwords(static_cast<int>(this->nationSlot),
                                                     reinterpret_cast<int*>(&payload));
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
    this->ApplyJoinEmpireModeForTargetNation(static_cast<int>(proposal->targetNationSlot), 1);
    if (g_pInterNationEventQueueManager != 0) {
      g_pInterNationEventQueueManager->QueueInterNationEventRecordDeduped(
          3, this->nationSlot, static_cast<int>(proposal->targetNationSlot), '\0');
    }
    break;

  case 1: {
    g_pDiplomacyTurnStateManager->SetRelationCodeSlot78Final(
        this->nationSlot, static_cast<int>(proposal->targetNationSlot), 2);
    if (g_pInterNationEventQueueManager != 0) {
      g_pInterNationEventQueueManager->QueueInterNationEventRecordDeduped(
          4, this->nationSlot, static_cast<int>(proposal->targetNationSlot), '\0');
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
      g_pInterNationEventQueueManager->QueueInterNationEventRecordDeduped(
          5, this->nationSlot, static_cast<int>(proposal->targetNationSlot), '\0');
    }
    break;

  case 3: {
    g_pDiplomacyTurnStateManager->SetRelationCodeSlot78Final(
        this->nationSlot, static_cast<int>(proposal->targetNationSlot), 4);
    if (g_pInterNationEventQueueManager != 0) {
      g_pInterNationEventQueueManager->QueueInterNationEventRecordDeduped(
          2, this->nationSlot, static_cast<int>(proposal->targetNationSlot), '\0');
    }
    if (g_pDiplomacyTurnStateManager->HasFlag84ForNationSlot84(
            static_cast<int>(proposal->targetNationSlot)) != 0) {
      for (int nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
        if (IsNationSlotEligibleForEventProcessing(nationSlot) != 0 &&
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
    g_apTerrainTypeDescriptorTable[static_cast<int>(proposal->targetNationSlot)]
        ->ApplyJoinEmpireModeForTargetNation(this->nationSlot, 1);
    if (g_pInterNationEventQueueManager != 0) {
      g_pInterNationEventQueueManager->QueueInterNationEventRecordDeduped(
          3, static_cast<int>(proposal->targetNationSlot), this->nationSlot, '\0');
    }
    break;
  }

  default:
    break;
  }

  if (g_pDiplomacyTurnStateManager->HasFlag84ForNationSlot84(
          static_cast<int>(proposal->targetNationSlot)) != 0 &&
      IsNationSlotEligibleForEventProcessing(static_cast<int>(proposal->targetNationSlot)) != 0) {
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

  short* proposalEntry = static_cast<short*>(queue->GetEntryAt1BasedSlot2C(queueOrdinal));
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
      g_pInterNationEventQueueManager->QueueInterNationEventRecordDeduped(kEvent09, targetNation,
                                                                          this->nationSlot, '\0');
    }
    return;
  case kProposalCode12E:
    if (g_pInterNationEventQueueManager != 0) {
      g_pInterNationEventQueueManager->QueueInterNationEventRecordDeduped(kEvent0B, targetNation,
                                                                          this->nationSlot, '\0');
    }
    return;
  case kProposalCode12F:
    if (g_pInterNationEventQueueManager != 0) {
      g_pInterNationEventQueueManager->QueueInterNationEventRecordDeduped(kEvent0D, targetNation,
                                                                          this->nationSlot, '\0');
    }
    return;
  case kProposalCode130:
    if (g_pInterNationEventQueueManager != 0) {
      g_pInterNationEventQueueManager->QueueInterNationEventRecordDeduped(kEvent07, targetNation,
                                                                          this->nationSlot, '\0');
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
    static_cast<TQueueObject*>(proposalQueue)->ResetPtrListRecordsSlot1C();
  }
}

// FUNCTION: IMPERIALISM 0x004df5c0
void TGreatPower::DispatchTurnEvent2103WithNationFromRecord(void) {
  void* uiRuntimeContext = g_pUiRuntimeContext;
  if (uiRuntimeContext == 0) {
    return;
  }

  static_cast<TViewMgr*>(uiRuntimeContext)->DispatchTurnEventSlot4C(0x2103, this->nationSlot);
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
      short* proposalEntry = static_cast<short*>(queue->GetEntryAt1BasedSlot2C(queueIndex));
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
  TPopulationMgr* notifySink = mgr->productionSummary1d8;
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
  TSimMgr* localization = g_pLocalizationTable;
  if (this->diplomacyEligibilityA0 == 0 || localization->runtimeSubsystemIndex < 2 ||
      localization->stateFlag114 != 0) {
    if (this->ShouldDispatchImmediatelySlot28() == 0 || localization->stateFlag114 != 0) {
      this->CreateFrogCityAtHomeRegionAndAttach(mgr);
      return;
    }
  }
  this->CreateFrogCityTownMarkerAndAttach(mgr);
}
#pragma optimize("", on)

#pragma optimize("y", on)

// FUNCTION: IMPERIALISM 0x004dfa20
void TGreatPower::CreateFrogCityTownMarkerAndAttach(void* receiver) {
  TTown* marker = new TTown();
  marker->InitializeTownMarker("Frog City", 0, 1, this->nationSlot);
  static_cast<TCity*>(receiver)->AdoptSelectedOrderSlot44(marker);
  marker->activeFlag4f = 1;
  this->townMarkerList->AddTailSlot30(marker);
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004dfae0
#pragma optimize("y", on)
void TGreatPower::CreateFrogCityAtHomeRegionAndAttach(void* receiver) {
  TSimMgr* localization = g_pLocalizationTable;
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
      reinterpret_cast<TViewMgr*>(g_pUiRuntimeContext)
          ->RunControlStringProviderAndDispatchLocalizedMessage(&message);
    }
  }
  *GreatPower_HomeRegionIndex88(this) = static_cast<short>(homeRegionIndex);
  TTown* marker = new TTown();
  marker->InitializeTownMarker("FrogCity", homeRegionIndex, 1, this->nationSlot);
  static_cast<TCity*>(receiver)->AdoptSelectedOrderSlot44(marker);
  marker->activeFlag4f = 1;
  this->townMarkerList->AddTailSlot30(marker);
  g_pGlobalMapState->LinkRegionToNationSlot134(marker->regionId14, this->nationSlot);
  if (this->diplomacyEligibilityA0 == 0 && this->interiorMinister != 0) {
    this->interiorMinister->NoOpForeignMinisterUtilityStub(receiver);
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
  for (TUnit* order = static_cast<TUnit*>(orderIter.Reset()); orderIter.More();
       order = static_cast<TUnit*>(orderIter.Advance())) {
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
    void* entryOuter = this->trackedObjectList->GetEntryByOrdinalSlot4C(outer);
    short outerPriority =
        g_DAT_006966d0_Value_006966D0[static_cast<TUnit*>(entryOuter)->orderType];
    for (int inner = outer + 1; inner <= total; ++inner) {
      void* entryInner = this->trackedObjectList->GetEntryByOrdinalSlot4C(inner);
      short innerPriority =
          g_DAT_006966d0_Value_006966D0[static_cast<TUnit*>(entryInner)->orderType];
      if (innerPriority < outerPriority) {
        static_cast<TPtrList*>(this->trackedObjectList)
            ->SetAtOrdinalSlot60(outer, &entryInner, 1);
        static_cast<TPtrList*>(this->trackedObjectList)
            ->SetAtOrdinalSlot60(inner, &entryOuter, 1);
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

// FUNCTION: IMPERIALISM 0x004e0400
char TGreatPower::HasActiveCandidateNationSlots() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004e0420
void TGreatPower::SetCandidateNationFlagAndPortZoneState(int targetNation) {
  (void)targetNation;
}

// FUNCTION: IMPERIALISM 0x004e0440
void TGreatPower::NotifyAllianceSlot214(int targetNation) {
  (void)targetNation;
}

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
  return g_DAT_006533e8_Value_006533E8[this->foreignMinister->skillIndexC] +
         g_DAT_Value_00653408[this->defenseMinister->skillIndexC];
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
    return static_cast<short>(this->city->GetBuildingProductionValueBySlot(buildingSlot));
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
  TTechMgr* capabilityState = CityOrderCapabilityState();
  int shipProduction;
  if (capabilityState->shipCapabilityFlag1a8 != 0) {
    shipProduction = this->GetCityBuildingProductionSlot8D(2);
  } else if (capabilityState->shipCapabilityFlag1a5 != 0) {
    shipProduction =
        (this->GetCityBuildingProductionSlot8D(4) + this->GetCityBuildingProductionSlot8D(2)) / 2;
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
  float targetScore = g_apNationStates[targetNation]->GetScoreFactorSlot23C();
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
  float targetScore = g_apNationStates[targetNation]->GetScoreFactorSlot23C();
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
  float targetScore = g_apNationStates[targetNation]->GetScoreFactorSlot240();
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
  float targetScore = g_apNationStates[targetNation]->GetScoreFactorSlot240();
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
  int secondaryPower =
      SumMilitaryUnitPowerWeights(g_apSecondaryNationStateSlots[secondarySlot]->militaryUnitList44);
  float combinedScore = static_cast<float>(secondaryPower) + selfScore;
  char borderLinked = g_pGlobalMapState->AreNationsBorderLinked(targetNation, secondarySlot);
  float targetScore;
  if (borderLinked != 0) {
    targetScore = g_apNationStates[targetNation]->GetScoreFactorSlot23C();
  } else {
    targetScore = g_apNationStates[targetNation]->GetScoreFactorSlot240();
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
    targetScore = g_apNationStates[targetNation]->GetScoreFactorSlot23C();
  } else {
    targetScore = g_apNationStates[targetNation]->GetScoreFactorSlot240();
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
  int secondaryPower =
      SumMilitaryUnitPowerWeights(g_apSecondaryNationStateSlots[secondarySlot]->militaryUnitList44);
  float combinedScore = static_cast<float>(secondaryPower) + selfScore;
  char borderLinked = g_pGlobalMapState->AreNationsBorderLinked(targetNation, secondarySlot);
  float targetScore;
  if (borderLinked != 0) {
    targetScore = g_apNationStates[targetNation]->GetScoreFactorSlot23C();
  } else {
    targetScore = g_apNationStates[targetNation]->GetScoreFactorSlot240();
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
    targetScore = g_apNationStates[targetNation]->GetScoreFactorSlot23C();
  } else {
    targetScore = g_apNationStates[targetNation]->GetScoreFactorSlot240();
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
  float opponentScore = g_apNationStates[opponentNation]->GetScoreFactorSlot23C();
  float partnerScore = g_apNationStates[partnerNation]->GetScoreFactorSlot23C();
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
  float opponentScore = g_apNationStates[opponentNation]->GetScoreFactorSlot23C();
  float partnerScore = g_apNationStates[partnerNation]->GetScoreFactorSlot23C();
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
  float opponentScore = g_apNationStates[opponentNation]->GetScoreFactorSlot240();
  float partnerScore = g_apNationStates[partnerNation]->GetScoreFactorSlot240();
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
  float opponentScore = g_apNationStates[opponentNation]->GetScoreFactorSlot240();
  float partnerScore = g_apNationStates[partnerNation]->GetScoreFactorSlot240();
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
char TGreatPower::ReturnZeroSlot9D(int targetNation) {
  (void)targetNation;
  return 0;
}

// FUNCTION: IMPERIALISM 0x004e1c20
char TGreatPower::EvaluateJoinWarAgainstNationAndQueueEvent(int targetNation) {
  // Result intentionally ignored in the original; keep the call for its side effects.
  g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(this->nationSlot, targetNation);
  char joinsWar = 0;
  TGreatPower* targetState = g_apNationStates[targetNation];
  if (targetState->CompareMissionScoreVariantsByMode(0) == 0 &&
      targetState->CompareMissionScoreVariantsByMode(1) == 0) {
    float warThreshold = this->ComputeWarThresholdSlotA3(targetNation);
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
    g_pInterNationEventQueueManager->QueueInterNationEventRecordDeduped(0x1c, targetNation,
                                                                        this->nationSlot, 0);
  }
  return joinsWar;
}

#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x004e1d50
int TGreatPower::CheckTransitionSlot27C(int arg1, int arg2) {
  char result = 0;
  TViewMgr* uiRuntimeContext = g_pUiRuntimeContext;

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
          secondaryNationState->ApplyJoinEmpireModeForTargetNation(this->nationSlot, 1);
        }
      }
    }
  }
  return result != 0;
}

bool TGreatPower::ExecuteAdvisoryPromptAndApplyActionType1(int arg1, int arg2) {
  return this->CheckTransitionSlot27C(arg1, arg2) != 0;
}

// FUNCTION: IMPERIALISM 0x004e1e40
int TGreatPower::PropagateWarTransitionSlot280(int targetNation, int sourceNation, int mode) {
  this->SetCandidateNationFlagAndPortZoneState(targetNation);
  this->ApplyDiplomacyRelationCodeAndNotifyThirdPartySlot284(targetNation, mode, sourceNation);
  return 1;
}

// FUNCTION: IMPERIALISM 0x004e1f20
void TGreatPower::NoOpSlotA2(void) {}

// --- Relative military/naval power score family (vtable slots 0x8e-0x9e) ---
// Helpers live in TGreatPower_power_score.cpp (TGreatPower_internal.h).

// FUNCTION: IMPERIALISM 0x004e1f40
#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif
float TGreatPower::ComputeWarThresholdSlotA3(int targetNation) {
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
        IsNationSlotEligibleForEventProcessing(nationIndex) != 0 && nationIndex != targetNation) {
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
void TGreatPower::PruneInvalidTrackedEntriesAndNotifyOwner(void) {}

// FUNCTION: IMPERIALISM 0x004e21b0
void TGreatPower::ApplyJoinEmpireModeForTargetNation(int targetNationSlot, int mode) {
  CString sharedStringScope;

  TCountry::ApplyJoinEmpireModeForTargetNation(targetNationSlot, mode);

  if (targetNationSlot >= 0 && targetNationSlot < kNationSlotCount) {
    TGreatPower* targetNation = g_apNationStates[targetNationSlot];
    if (targetNation != 0 && targetNation->field8d1 < 3) {
      targetNation->SetNationPendingActionStateAndPayload(9, this->nationSlot);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004e2270
void TGreatPower::RemoveRegionIdFromNationOwnedRegionList(int regionId) {
  this->ownedRegionList->AddTailSlot34(reinterpret_cast<void*>(regionId));
  this->NotifyRegionEventSlot298(regionId);
}

// FUNCTION: IMPERIALISM 0x004e22b0
void TGreatPower::AddRegionIdToNationOwnedRegionList(int regionId) {
  this->ownedRegionList->AddHeadSlot28(reinterpret_cast<void*>(regionId));
  int ownedRegionCount = this->ownedRegionList->GetCountSlot48();

  unsigned char pressureGate = this->serializedStatusFlags[6];
  unsigned char nationGate = this->expansionEventGate;
  if (ownedRegionCount > 8 && pressureGate > 0x32 && nationGate < 3) {
    this->SetNationPendingActionStateAndPayload(0x0C, -1);
  }
}

// FUNCTION: IMPERIALISM 0x004e2330
void TGreatPower::SetNationPercentFieldByModeAndDescriptorLinks(int targetNationSlot,
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
    this->SetCandidateNationFlagAndPortZoneState(targetNation);
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

  this->SetCandidateNationFlagAndPortZoneState(targetNation);
}

// FUNCTION: IMPERIALISM 0x004e2500
void TGreatPower::NotifyRegionEventSlot298(int ownerClass) {
  TMapMgr* globalMapState = g_pGlobalMapState;
  TPtrList* filteredList = this->trackedObjectList;
  for (int index = filteredList->GetCountSlot48(); index != 0; --index) {
    TTrackedObjectListEntry* entry =
        static_cast<TTrackedObjectListEntry*>(filteredList->GetEntryByOrdinalSlot4C(index));
    if (entry == 0 || globalMapState == 0 || globalMapState->terrainStateTable == 0) {
      continue;
    }

    short mapOwnerClass = globalMapState->terrainStateTable[entry->regionIndex].cityRecordIndex;
    if (mapOwnerClass == ownerClass) {
      void* trackedObject = entry->object;
      if (trackedObject != 0) {
        static_cast<TMission*>(trackedObject)->Call30();
      }
      if (trackedObject != 0) {
        static_cast<TMission*>(trackedObject)->Free();
      }
    }
  }

  TPtrList* unassignedList = this->militaryUnitList44;
  for (int unassignedIndex = unassignedList->GetCountSlot48(); unassignedIndex != 0;
       --unassignedIndex) {
    TTrackedObjectListEntry* entry = static_cast<TTrackedObjectListEntry*>(
        unassignedList->GetEntryByOrdinalSlot4C(unassignedIndex));
    if (entry != 0 && entry->regionIndex == -1) {
      if (entry->object != 0) {
        static_cast<TMission*>(entry->object)->Free();
      }
    }
  }
}

void TGreatPower::ReleaseTrackedObjectsByMapOwnerAndUnassignedEntries(int ownerClass) {
  this->NotifyRegionEventSlot298(ownerClass);
}

// FUNCTION: IMPERIALISM 0x004e25c0
void TGreatPower::ResetNationDiplomacySlotsAndMarkRelatedNations(int targetNation) {
  this->ResetDiplomacyLevelForNationSlot12(static_cast<NationSlot>(targetNation), 100);
  this->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(targetNation, -1);
  for (int nation = 0; nation < 0x17; ++nation) {
    if (g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(this->nationSlot, nation) != 0) {
      this->CallSlotA8(nation);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004e2630
void TGreatPower::CallSlotA8(int targetNationSlot) {
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
        auxRuntimeState->ClearNationAuxRuntimeGrantSlotC4(-1);
        auxRuntimeState->NotifyNationAuxRuntimeFinalizeSlotC0();
      }
    }
    ++tableIndex;
  }
}

// FUNCTION: IMPERIALISM 0x004e2720
void TGreatPower::CallSlotA9(int targetNationSlot) {
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
    this->CallSlotA8(targetNationSlot);
    return;
  }

  this->CallSlotA9(targetNationSlot);
}

// FUNCTION: IMPERIALISM 0x004e27f0
void TGreatPower::ApplyDiplomacyRelationCodeAndNotifyThirdPartySlot284(int targetNationSlot,
                                                                       int policyCode,
                                                                       int sourceNationSlot) {
  void* diplomacyManager = g_pDiplomacyTurnStateManager;
  QueueNationPairWarTransition(static_cast<TDiplomacyMgr*>(diplomacyManager), this->nationSlot,
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

  secondaryNationState->ApplyJoinEmpireModeForTargetNation(this->nationSlot, 1);
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
  } while (reinterpret_cast<int>(nationCursor) < reinterpret_cast<int>(&g_apNationStates_End));
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
  TSimMgr* localizationRuntime = g_pLocalizationTable;
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
  TSimMgr* localizationRuntime = g_pLocalizationTable;
  if (localizationRuntime != 0) {
    activeTurn = static_cast<short>(localizationRuntime->GetTurnTickSlot3C() - 1);
  }

  int mergedNationMask = 0;
  bool foundCurrentTurnEntry = false;

  for (int queueIndex = 1; queueIndex <= queueCount; ++queueIndex) {
    short* entry = static_cast<short*>(summaryQueue->GetEntryAt1BasedSlot2C(queueIndex));
    if (entry == 0 || entry[0] != activeTurn) {
      continue;
    }

    foundCurrentTurnEntry = true;
    mergedNationMask |= 1 << (static_cast<int>(entry[1]) & 0x1F);
  }

  if (!foundCurrentTurnEntry) {
    return;
  }

  TInterNationEventQueueManager* queueManager = g_pInterNationEventQueueManager;
  if (queueManager != 0) {
    queueManager->QueueInterNationEventIntoNationBucket(0x13A0, mergedNationMask, '\0');
  }
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
  missionQueue->AddTailSlot30(missionObj);

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
    float denominator = static_cast<float>(field30) * selected -
                        static_cast<float>(g_Compute_Advisory_MinusSix_00653FE8);
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
    float denominator = static_cast<float>(field30) * selected -
                        static_cast<float>(g_Compute_Advisory_MinusSix_00653FE8);
    float numerator = sum - static_cast<float>(g_Compute_Advisory_MinusSix_00653FE8);
    return numerator / denominator;
  }
  case 2: {
    TCountry* terrainView = g_apTerrainTypeDescriptorTable[selectedNationSlot];
    if (terrainView == 0) {
      return kOne;
    }

    if (terrainView->ownedRegionList == 0) {
      return kOne;
    }

    int nodeWeight = terrainView->ownedRegionList->GetCountSlot48();
    int weightedNeighbor = ComputeWeightedNeighborLinkScoreForNode(relationTargetNation);
    int linkedNodeTotal = terrainView->SumWeightedNeighborLinkScoreForLinkedNodes();

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

    int priorityForNode = SumNavyOrderPriorityForNationAndNodeType(nationObj, relationTargetNation);
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
    return static_cast<float>(g_Compute_Advisory_Hundred_00654000) /
           static_cast<float>(relationValue);
  }
  case 5: {
    TMapMgr* globalMapState = g_pGlobalMapState;
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

// FUNCTION: IMPERIALISM 0x004ffc10
void TGreatPower::ConstructTurnOrderNavigationWindowEntryViewportAdaptive(void) {
  // Ghidra attributes this TGameWindow tail-init entry to TGreatPower; receiver is TGameWindow storage.
  TGameWindow::InitViewportAdaptiveTurnOrderNavTailAt(this);
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

// FUNCTION: IMPERIALISM 0x0055f140
unsigned int TGreatPower::ComputeMapActionContextNodeValueAverage(void) {
  TMapMgr* globalMapState = g_pGlobalMapState;
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

// FUNCTION: IMPERIALISM 0x0055f4d0
char TGreatPower::ContainsPointerArrayEntryMatchingByteKey(short nationSlotKey) {
  unsigned int entryCount =
      *reinterpret_cast<unsigned int*>(reinterpret_cast<char*>(this) + 0x40);
  if (entryCount == 0) {
    return 0;
  }
  for (unsigned int entryIndex = 0; entryIndex < entryCount; ++entryIndex) {
    void** entrySlot = reinterpret_cast<void**>(
        *reinterpret_cast<int*>(reinterpret_cast<char*>(this) + 0x38) + entryIndex * 4);
    if (*reinterpret_cast<char*>(*entrySlot) == static_cast<char>(nationSlotKey)) {
      return 1;
    }
  }
  return 0;
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

  TCivUnit* orderObject = new TCivUnit();
  if (orderObject == nullptr) {
    return;
  }
  orderObject->InitializeCivWorkOrderState(workOrderType, ownerNationSlot,
                                           static_cast<int>(cityOwnerTag));
}



int TGreatPower::GetMultiplierSlot21C(void) { return 0; }
void TGreatPower::AbsorbCityNeedVectorSlotFC(short *) {}

// Ghidra mislabels this 0x005b7f50 leaf "ApplyIndexedResourceDeltaAndAdjustNationTotals_Impl";
// the body is a pure range predicate (no resource delta, no nation totals), renamed by
// behavior per Hard Rule 6. Genuinely __stdcall (RET 0x4, single stacked short, no ecx);
// FPO leaf (no ebp frame) so it is wrapped in the frame-pointer-omission pragma.
#pragma optimize("y", on)
// FUNCTION: IMPERIALISM 0x005b7f50
char __stdcall IsSpecialNationInteractionResource(short resourceIndex) {
  if (resourceIndex >= 0xD && resourceIndex <= 0x10) {
    return 1;
  }
  return 0;
}
#pragma optimize("", on)
