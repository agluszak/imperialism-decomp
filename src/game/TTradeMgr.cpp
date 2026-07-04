#include "decomp_types.h"
#include "game/TTradeMgr.h"

#include "game/TDealList.h"
#include "game/TSortedPtrList.h"
#include "game/mfc.h"
#include "game/TGreatPower.h"
#include "game/TSimMgr.h"
#include "game/TDiplomacyMgr.h"
#include "game/global_data_tables.h"
#include "game/TMinor.h"
#include "game/TForeignMinister.h"

// Preset seed table for the metric rows (original global @ 0x69a910) and the proposal-code
// lookup used by the code-resolver. Kept file-local until modeled as recovered globals.
static short kNationMetricCategoryPresetValues[0x11];
static short kNationMetricCodeLookup[0x20];

extern undefined4 CreateAndSendTurnEvent1C_BoolAndSixShorts(void);

static void InvokeCreateAndSendTurnEvent1C(int arg0, int arg1, int arg2, int arg3, int arg4,
                                           int arg5, int arg6) {
  typedef void(__cdecl * CreateEventFn)(int, int, int, int, int, int, int);
  reinterpret_cast<CreateEventFn>(CreateAndSendTurnEvent1C_BoolAndSixShorts)(arg0, arg1, arg2, arg3,
                                                                             arg4, arg5, arg6);
}

typedef void(__fastcall* MinorSlot80Fn)(TMinor* self, int unusedEdx, int arg1, int arg2, int arg3);
typedef void(__fastcall* MinorSlot6CFn)(TMinor* self, int unusedEdx, int arg);

static void CallMinorSlot80(TMinor* self, int arg1, int arg2, int arg3) {
  MinorSlot80Fn slotFn =
      reinterpret_cast<MinorSlot80Fn>(reinterpret_cast<int*>(*reinterpret_cast<int**>(self))[0x20]);
  slotFn(self, 0, arg1, arg2, arg3);
}

static void CallMinorSlot6C(TMinor* self, int arg) {
  MinorSlot6CFn slotFn =
      reinterpret_cast<MinorSlot6CFn>(reinterpret_cast<int*>(*reinterpret_cast<int**>(self))[0x1b]);
  slotFn(self, 0, arg);
}

// SYNTHETIC: IMPERIALISM 0x005b79d0
// TTradeMgr::CreateObject

// SYNTHETIC: IMPERIALISM 0x005b7a00
// TTradeMgr::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTradeMgr, TObject)

// FUNCTION: IMPERIALISM 0x005b7a20
TTradeMgr::TTradeMgr() {}

// SYNTHETIC: IMPERIALISM 0x005b7a40
// TTradeMgr::`scalar deleting destructor'
TTradeMgr::~TTradeMgr() {}

// FUNCTION: IMPERIALISM 0x005b7a90
void TTradeMgr::InitializeNationInteractionStateManagerDefaults() {
  short* presetCursor = kNationMetricCategoryPresetValues;
  TDealList** rankListCursor = this->categoryRankLists;
  char* rowCursor = reinterpret_cast<char*>(this) + 0x0e;
  int rowCount = 0x11;
  do {
    *reinterpret_cast<short*>(rowCursor - 0x02) = 0;
    *reinterpret_cast<short*>(rowCursor + 0x00) = 0;
    *reinterpret_cast<short*>(rowCursor + 0x0a) = 0;
    *reinterpret_cast<int*>(rowCursor + 0x02) = 0;
    *reinterpret_cast<int*>(rowCursor + 0x06) = 0;

    short presetValue = *presetCursor;
    *reinterpret_cast<short*>(rowCursor - 0x06) = presetValue;
    *reinterpret_cast<short*>(rowCursor - 0x04) = presetValue;
    *reinterpret_cast<short*>(rowCursor + 0x0c) = *reinterpret_cast<short*>(rowCursor - 0x06);

    TDealList* list = new TDealList();
    list->relationType = 0x10;
    *rankListCursor = list;

    short* cellCursor = reinterpret_cast<short*>(rowCursor + 0x6a);
    int cellCount = 0x17;
    do {
      cellCursor[-0x2e] = 0;
      *cellCursor = 0;
      cellCursor[-0x17] = 0;
      cellCursor = cellCursor + 1;
      cellCount = cellCount + -1;
    } while (cellCount != 0);

    rankListCursor = rankListCursor + 1;
    presetCursor = presetCursor + 1;
    rowCursor = rowCursor + 0xa0;
    rowCount = rowCount + -1;
  } while (rowCount != 0);
}

// FUNCTION: IMPERIALISM 0x005b7bc0
void TTradeMgr::Free() {}

// FUNCTION: IMPERIALISM 0x005b7c10
void TTradeMgr::ReadFrom(TStream* stream) {
  (void)stream;
}

// FUNCTION: IMPERIALISM 0x005b7d90
void TTradeMgr::WriteTo(TStream* stream) {
  (void)stream;
}

// FUNCTION: IMPERIALISM 0x005b7fc0
undefined4 TTradeMgr::OrphanCallChain_C3_I50_005b7fc0() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005b8080
undefined4 TTradeMgr::AccumulateDiplomacyRelationChangesAndQueueEvents() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005b8aa0
undefined4 TTradeMgr::DispatchNationMetricUpdatePassForAllSlots() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005b8ad0
undefined4 TTradeMgr::ComputeNationMetricBaselineValueForSlot() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005b8d40
undefined4 TTradeMgr::GetNationMetricWeightedScoreForSlot() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005b8d70
short TTradeMgr::IsCapabilityCategoryActiveSlot3C(short category) {
  return this->categoryRows[category].capabilityActiveFlag14;
}

// FUNCTION: IMPERIALISM 0x005b8da0
undefined4 TTradeMgr::ComputeNationMetricDispatchScoreAndResolveScale() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005b8f80
undefined4 TTradeMgr::GetNationMetricRosterWordAtOffset0E() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005b8fb0
undefined4 TTradeMgr::GetNationMetricRosterWordAtOffset0C() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005b8fe0
short TTradeMgr::QueryProposalWeightSlot4C(short metricSlot) {
  if (metricSlot == 0x16) {
    return 200;
  }
  if (metricSlot == 0x15) {
    return 500;
  }
  return this->categoryRows[metricSlot].proposalWeightScale06;
}

// FUNCTION: IMPERIALISM 0x005b9030
undefined4 TTradeMgr::GetNationMetricBucketValueByIndex() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005b9060
undefined4 TTradeMgr::ApplyDiplomacyTransferEffectsAcrossNationMetricRoster() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005b9190
undefined4 TTradeMgr::ProcessPendingDiplomacyTransferEntriesUntilBlockedWrapper() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005b9410
undefined4 TTradeMgr::RebuildNationMetricPassesAndClampRowsByBaseline() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005b94d0
void TTradeMgr::DispatchProposalAmountSlot60(short ownerNation, int sourceContext, int amount,
                                             int maxAmount, int targetNation, char emitEventFlag,
                                             char skipLocalizationBranch) {
  if ((skipLocalizationBranch == 0) && (g_pLocalizationTable->redrawEnabled == 2)) {
    InvokeCreateAndSendTurnEvent1C(1, ownerNation, sourceContext, amount, maxAmount, targetNation,
                                   emitEventFlag);
    return;
  }
  if (g_pLocalizationTable->redrawEnabled == 1) {
    InvokeCreateAndSendTurnEvent1C(0, ownerNation, sourceContext, amount, maxAmount, targetNation,
                                   emitEventFlag);
  }

  short ownerSlot = ownerNation;
  if (emitEventFlag != 0) {
    if (g_pDiplomacyTurnStateManager->HasFlag84ForNationSlot84(ownerNation) != 0) {
      g_apNationStates[ownerSlot]->ClearDiplomacyState1c6ForTarget(
          static_cast<short>(targetNation));
    }
  }
  if (static_cast<short>(amount) < 1) {
    if (g_pDiplomacyTurnStateManager->HasFlag84ForNationSlot84(ownerNation) != 0) {
      g_apNationStates[ownerSlot]->AppendTrackedSlotEntry(
          1, ownerNation, static_cast<short>(amount), static_cast<short>(targetNation), amount);
    }
  } else {
    int ownerIndex = static_cast<int>(ownerSlot);
    CallMinorSlot80(static_cast<TMinor*>(g_apTerrainTypeDescriptorTable[ownerIndex]), targetNation,
                    amount, maxAmount);
    CallMinorSlot80(
        static_cast<TMinor*>(g_apTerrainTypeDescriptorTable[static_cast<short>(sourceContext)]),
        targetNation, -amount, ownerNation);
    if (g_pDiplomacyTurnStateManager->HasFlag84ForNationSlot84(maxAmount) != 0) {
      if (g_pDiplomacyTurnStateManager->HasFlag84ForNationSlot84(ownerNation) == 0) {
        CallMinorSlot6C(static_cast<TMinor*>(g_apTerrainTypeDescriptorTable[sourceContext]),
                        amount);
      }
    }
    short relationBump = g_pDiplomacyTurnStateManager->LookupOrderCompatibilityMatrixValue(
        ownerSlot, static_cast<short>(sourceContext));
    if (relationBump > 0) {
      int matrixIndex = ownerIndex * 0x17 + sourceContext;
      short standingScore =
          g_pDiplomacyTurnStateManager->relationStandingScoreMatrix79c[matrixIndex];
      g_pDiplomacyTurnStateManager->SetStandingScoreSlot28(ownerNation, maxAmount,
                                                           static_cast<short>(standingScore + 1));
    }
    short targetCode = static_cast<short>(maxAmount);
    if (g_pDiplomacyTurnStateManager->HasFlag84ForNationSlot84(maxAmount) != 0) {
      g_apNationStates[static_cast<short>(targetNation)]->AppendTrackedSlotEntry(
          0, ownerNation, static_cast<short>(amount), static_cast<short>(targetNation),
          sourceContext);
    }
    if (g_pDiplomacyTurnStateManager->HasFlag84ForNationSlot84(ownerNation) != 0) {
      g_apNationStates[ownerIndex]->AppendTrackedSlotEntry(
          1, targetNation, static_cast<short>(amount), static_cast<short>(targetNation),
          targetCode);
    }
  }
}

// FUNCTION: IMPERIALISM 0x005b9790
undefined4 TTradeMgr::SetNationMetricCellValueByIndex() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005b97c0
undefined4 TTradeMgr::RunNationUpdatePassesAndResetTransitionFlags() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005b9890
undefined4 TTradeMgr::RunNationMetricPreUpdatePassAcrossSecondaryNations() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005b98d0
undefined4 TTradeMgr::BuildEligibleNationMetricBucketsAndWeightedTrendScores() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005b9b30
undefined4 TTradeMgr::BuildSecondaryNationMetricBucketsAndWeightedTrendScores() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005b9f30
undefined4 TTradeMgr::ComputeNationMetricPowerScale() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005b9f70
undefined4 TTradeMgr::IsNationMetricCellNegative() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005b9fa0
undefined4 TTradeMgr::IsNationMetricCellPositive() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005b9fd0
undefined4 TTradeMgr::AllocateAndPopulateLinkedValueCollectionFromRosterFilter() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005ba090
short TTradeMgr::ResolveProposalCodeForCategorySlot84(int proposalCode, int category) {
  short* lookupCursor = kNationMetricCodeLookup;
  short resolvedCode = static_cast<short>(proposalCode);
  while ((*lookupCursor != static_cast<short>(proposalCode)) &&
         (resolvedCode = static_cast<short>(category),
          *lookupCursor != static_cast<short>(category))) {
    lookupCursor = lookupCursor + 1;
    if (reinterpret_cast<int>(lookupCursor) >
        reinterpret_cast<int>(kNationMetricCodeLookup + 0x20)) {
      return static_cast<short>(proposalCode);
    }
  }
  return resolvedCode;
}
