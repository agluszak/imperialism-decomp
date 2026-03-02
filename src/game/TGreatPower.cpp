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
undefined4 InitializeGreatPowerMinisterRosterAndScenarioState(void);
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
undefined4 thunk_ComputeGlobalMapActionContextNodeValueAverage(void);

struct TDiplomacyTurnStateManager {
  void* vftable;
};

static const unsigned int kAddrUiRuntimeContextPtr = 0x006A21BC;
static const unsigned int kAddrSecondaryNationStateSlots = 0x006A4280;
static const unsigned int kAddrDiplomacyTurnStateManagerPtr = 0x006A43D0;
static const unsigned int kAddrGlobalMapStatePtr = 0x006A43D4;
static const unsigned int kAddrInterNationEventQueueManagerPtr = 0x006A43E8;
static const unsigned int kAddrEligibilityManagerPtr = 0x006A43E0;
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
  void thunk_QueueMapActionMissionFromCandidateAndMarkState(int arg1, int arg2, int arg3,
                                                            int arg4);
  float thunk_ComputeAdvisoryMapNodeScoreFactorByCaseMetric(int arg1, int arg2, int arg3);
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
  void thunk_AddRegionIdToNationOwnedRegionListAndTriggerExpansionActionIfThresholdMet_At00404246(
      void);
  void thunk_ResetDiplomacyNeedScoresAndClearAidAllocationMatrix_At004048f4(void);
  void thunk_InitializeCivWorkOrderState(int nOrderType, int pOwnerContext,
                                         int nOrderOwnerNationId);
  void thunk_TryDispatchNationActionViaUiContextOrFallback_At00404ce1(int arg1, int arg2);
  void thunk_QueueInterNationEventType0FForNationPairContext_At00405ac9(short targetNationSlot,
                                                                          short sourceNationSlot);

  void QueueMapActionMissionFromCandidateAndMarkState(int arg1, int arg2, int arg3, int arg4);
  float ComputeAdvisoryMapNodeScoreFactorByCaseMetric(int arg1, int arg2, int arg3, int arg4);
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

static __inline void* ReadGlobalPointer(unsigned int address) {
  return *reinterpret_cast<void**>(address);
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
void TGreatPower::thunk_QueueMapActionMissionFromCandidateAndMarkState(int arg1, int arg2,
                                                                        int arg3, int arg4) {
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
float TGreatPower::thunk_ComputeAdvisoryMapNodeScoreFactorByCaseMetric(int arg1, int arg2,
                                                                        int arg3) {
  return ComputeAdvisoryMapNodeScoreFactorByCaseMetric(arg1, arg2, arg3, arg3);
}

// FUNCTION: IMPERIALISM 0x00401CBC
void TGreatPower::thunk_ProcessPendingDiplomacyProposalQueue_At00401cbc(void) {
  ProcessPendingDiplomacyProposalQueue();
}

// FUNCTION: IMPERIALISM 0x00402185
void TGreatPower::thunk_UpdateGreatPowerPressureStateAndDispatchEscalationMessage_At00402185(
    void) {
  UpdateGreatPowerPressureStateAndDispatchEscalationMessage();
}

// FUNCTION: IMPERIALISM 0x00402919
void thunk_DispatchGreatPowerQuarterlyStatusMessageLevel2_At00402919(void) {
  DispatchGreatPowerQuarterlyStatusMessageLevel2();
}

// FUNCTION: IMPERIALISM 0x00402BDA
bool TGreatPower::thunk_ExecuteAdvisoryPromptAndApplyActionType2OrFallback_At00402bda(
    int arg1, int arg2, int arg3) {
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
  (void)arg1;
  InitializeGreatPowerMinisterRosterAndScenarioState();
}

// FUNCTION: IMPERIALISM 0x0040389B
void thunk_DispatchTurnEvent11F8WithNoPayload_At0040389b(void) {
  DispatchTurnEvent11F8WithNoPayload();
}

// FUNCTION: IMPERIALISM 0x00403C15
bool TGreatPower::thunk_ExecuteAdvisoryPromptAndApplyActionType1_At00403c15(void) {
  return ExecuteAdvisoryPromptAndApplyActionType1(this, 0);
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
  void** secondaryNationStateSlots =
      reinterpret_cast<void**>(kAddrSecondaryNationStateSlots);

  if (diplomacyTurnStateManager != 0 && diplomacyTurnStateManager->vftable != 0) {
    DiplomacyTurnStateSlot44Fn diplomacySlot44 =
        *reinterpret_cast<DiplomacyTurnStateSlot44Fn*>(
            reinterpret_cast<unsigned char*>(diplomacyTurnStateManager->vftable) + 0x44);
    if (diplomacySlot44 != 0) {
      result = diplomacySlot44(self->field0c);
    }
  }

  UiRuntimeSlot94Fn uiSlot94 = 0;
  if (uiRuntimeContext != 0) {
    void* uiVtable = *reinterpret_cast<void**>(uiRuntimeContext);
    uiSlot94 = *reinterpret_cast<UiRuntimeSlot94Fn*>(reinterpret_cast<unsigned char*>(uiVtable) +
                                                     0x94);
  }

  if (result == 0) {
    result = (uiSlot94 != 0) ? uiSlot94(uiRuntimeContext, 0, self->field0c, targetNationSlot) :
                               0;
    if (result != 0) {
      GreatPowerSlotA1Fn slotA1 = reinterpret_cast<GreatPowerSlotA1Fn>(self->field00[0xA1]);
      if (slotA1 != 0) {
        slotA1(self, 0);
      }
      return true;
    }
  } else {
    result = (uiSlot94 != 0) ? uiSlot94(uiRuntimeContext, 0, self->field0c, targetNationSlot) :
                               0;
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
void TGreatPower::thunk_AddRegionIdToNationOwnedRegionListAndTriggerExpansionActionIfThresholdMet_At00404246(
    void) {
  AddRegionIdToNationOwnedRegionListAndTriggerExpansionActionIfThresholdMet();
}

// FUNCTION: IMPERIALISM 0x004048F4
void TGreatPower::thunk_ResetDiplomacyNeedScoresAndClearAidAllocationMatrix_At004048f4(void) {
  ResetDiplomacyNeedScoresAndClearAidAllocationMatrix();
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
      UiRuntimeSlot98Fn uiSlot98 = *reinterpret_cast<UiRuntimeSlot98Fn*>(
          reinterpret_cast<unsigned char*>(uiVtable) + 0x98);
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

// FUNCTION: IMPERIALISM 0x004DDA90
void TGreatPower::QueueInterNationEventType0FForNationPairContext(short targetNationSlot,
                                                                   short sourceNationSlot) {
  QueueInterNationEventMergeFn mergeFn =
      reinterpret_cast<QueueInterNationEventMergeFn>(thunk_QueueInterNationEventType0FWithBitmaskMerge);
  mergeFn(ReadGlobalPointer(kAddrInterNationEventQueueManagerPtr), 0, this->field0c,
          sourceNationSlot, targetNationSlot, 0);
}

// FUNCTION: IMPERIALISM 0x004E8540
void TGreatPower::QueueMapActionMissionFromCandidateAndMarkState(int arg1, int arg2, int arg3,
                                                                  int arg4) {
  if (arg2 != -1 &&
      *(reinterpret_cast<unsigned char*>(this) + 0x970 + arg2) != 1) {
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
    typedef void(__cdecl* UiInvalidationAssertFn)(const char*, int);
    UiInvalidationAssertFn uiInvalidationAssert =
        reinterpret_cast<UiInvalidationAssertFn>(thunk_TemporarilyClearAndRestoreUiInvalidationFlag);
    uiInvalidationAssert(kUCountryAutoCppPath, kAssertLineQueueMapAction);
  }

  void* missionQueue = *reinterpret_cast<void**>(reinterpret_cast<unsigned char*>(this) + 0xB60);
  void* queueVtable = *reinterpret_cast<void**>(missionQueue);
  reinterpret_cast<void(__fastcall*)(void*, int, void*)>(
      *reinterpret_cast<void**>(reinterpret_cast<unsigned char*>(queueVtable) + 0x30))(
      missionQueue, 0, missionObj);

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
  EligibilityThunkFn fn = reinterpret_cast<EligibilityThunkFn>(
      thunk_IsNationSlotEligibleForEventProcessing);
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
  IntThunkWithObjectFn fn = reinterpret_cast<IntThunkWithObjectFn>(thunk_SumNavyOrderPriorityForNation);
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

#pragma optimize("y", on) // omit frame pointer (helps match old prolog/epilog)
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
      short relationValue =
          *reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(mgr) + 0x79C +
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
                                              arg2 * 0xA8);
      return (float)cityValue / (float)total;
    }
    case 6:
    default:
      return kOne;
  }
}
