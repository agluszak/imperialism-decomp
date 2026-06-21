#include "decomp_types.h"
#include "game/TDealList.h"

#include "game/mfc.h"
#include "game/TGreatPower.h"
#include "game/TSimMgr.h"
#include "game/TSortedPtrList.h"
#include "game/TDiplomacyMgr.h"
#include "game/diplomacy_globals.h"
#include "game/TMinor.h"
#include "game/TForeignMinister.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

#include "decomp_types.h"

static short kNationMetricCategoryPresetValues[0x11];
static short kNationMetricCodeLookup[0x20];
static const int kTDealListIndexAndRankListVtableAddr = 0x0066da38;

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

TDealList* g_pNationInteractionStateManager = 0;

// FUNCTION: IMPERIALISM 0x005B7A20
TDealList::TDealList() : CObject() {}

// FUNCTION: IMPERIALISM 0x005B7A90
void TDealList::InitializeNationInteractionStateManagerDefaults() {
  short* presetCursor = kNationMetricCategoryPresetValues;
  TIndexAndRankList** listCursor = this->categoryRankLists;
  char* rowCursor = reinterpret_cast<char*>(this->categoryRows);
  int rowCount = 0x11;
  do {
    short presetValue = *presetCursor;
    *reinterpret_cast<short*>(rowCursor + 0x08) = presetValue;
    *reinterpret_cast<short*>(rowCursor + 0x0a) = presetValue;
    *reinterpret_cast<short*>(rowCursor + 0x0c) = 0;
    *reinterpret_cast<short*>(rowCursor + 0x0e) = 0;
    *reinterpret_cast<short*>(rowCursor + 0x18) = 0;
    *reinterpret_cast<int*>(rowCursor + 0x10) = 0;
    *reinterpret_cast<int*>(rowCursor + 0x14) = 0;
    *reinterpret_cast<short*>(rowCursor + 0x1a) = presetValue;

    TIndexAndRankList* list =
        reinterpret_cast<TIndexAndRankList*>(AllocateWithFallbackHandler(0x18));
    if (list == 0) {
      list = 0;
    } else {
      list->TIndexAndRankList::TIndexAndRankList();
      *reinterpret_cast<void***>(list) =
          reinterpret_cast<void**>(kTDealListIndexAndRankListVtableAddr);
    }
    reinterpret_cast<TSortedPtrList*>(list)->relationType = 0x10;
    *listCursor = list;

    short* nationCellCursor = reinterpret_cast<short*>(rowCursor + 0x3c);
    int nationCount = 0x17;
    do {
      nationCellCursor[-0x2e] = 0;
      *nationCellCursor = 0;
      nationCellCursor[-0x17] = 0;
      nationCellCursor = nationCellCursor + 1;
      nationCount = nationCount + -1;
    } while (nationCount != 0);

    listCursor = listCursor + 1;
    presetCursor = presetCursor + 1;
    rowCursor = rowCursor + 0x50;
    rowCount = rowCount + -1;
  } while (rowCount != 0);
}

CRuntimeClass* TDealList::GetRuntimeClass() const {
  return 0;
}

void TDealList::Serialize(CArchive& ar) {
  (void)ar;
}

void TDealList::AssertValid() const {}

void TDealList::Dump(CDumpContext& unused) const {
  (void)unused;
}

// FUNCTION: IMPERIALISM 0x005B8D70
short TDealList::IsCapabilityCategoryActiveSlot3C(int category) {
  return this->categoryRows[category].capabilityActiveFlag18;
}

// FUNCTION: IMPERIALISM 0x005B8FE0
short TDealList::QueryProposalWeightSlot4C(int metricSlot) {
  if (metricSlot == 0x16) {
    return 200;
  }
  if (metricSlot == 0x15) {
    return 500;
  }
  return this->categoryRows[metricSlot].proposalWeightScale0a;
}

// FUNCTION: IMPERIALISM 0x005B94D0
void TDealList::DispatchProposalAmountSlot60(short ownerNation, int sourceContext, int amount,
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

#if defined(_MSC_VER)
#pragma optimize("", on)
#endif

// FUNCTION: IMPERIALISM 0x005BA090
short TDealList::ResolveProposalCodeForCategorySlot84(int proposalCode, int category) {
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
