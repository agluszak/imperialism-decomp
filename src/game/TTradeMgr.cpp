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
#include "game/TCountry.h"
#include "game/nation_slot_eligibility.h"
#include "game/TStream.h"
#include "game/TSoundChannelNode.h"

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
void TTradeMgr::Free() {
  TDealList** p = this->categoryRankLists;
  int i = 0x11;
  do {
    if (*p != 0) {
      (*p)->ReleaseSlot24();
    }
    *p = 0;
    p = p + 1;
    i = i + -1;
  } while (i != 0);
  delete this;
}

// FUNCTION: IMPERIALISM 0x005b7c10
void TTradeMgr::ReadFrom(TStream* stream) {
  if (g_nSaveFormatVersion < 0x27) {
    stream->ReadBytes(reinterpret_cast<char*>(this) + 0x8, 0xaa0);
  } else {
    char* rowCursor = reinterpret_cast<char*>(this) + 0xa;
    int rows = 0x11;
    do {
      stream->ReadBytes(rowCursor - 2, 2);
      stream->ReadBytes(rowCursor, 2);
      stream->ReadBytes(rowCursor + 2, 2);
      stream->ReadBytes(rowCursor + 4, 2);
      stream->ReadBytes(rowCursor + 6, 8);
      stream->ReadBytes(rowCursor + 0xe, 2);
      stream->ReadBytes(rowCursor + 0x10, 2);
      char* cell = rowCursor + 0x12;
      stream->ReadBytes(cell, 0x2e);
      int c = 0x17;
      do {
        char t = cell[0];
        cell[0] = cell[1];
        cell[1] = t;
        cell = cell + 2;
        c = c + -1;
      } while (c != 0);
      cell = rowCursor + 0x40;
      stream->ReadBytes(cell, 0x2e);
      c = 0x17;
      do {
        char t = cell[0];
        cell[0] = cell[1];
        cell[1] = t;
        cell = cell + 2;
        c = c + -1;
      } while (c != 0);
      cell = rowCursor + 0x6e;
      stream->ReadBytes(cell, 0x2e);
      c = 0x17;
      do {
        char t = cell[0];
        cell[0] = cell[1];
        cell[1] = t;
        cell = cell + 2;
        c = c + -1;
      } while (c != 0);
      rowCursor = rowCursor + 0xa0;
      rows = rows + -1;
    } while (rows != 0);
  }
  TDealList** p = this->categoryRankLists;
  int i = 0x11;
  do {
    (*p)->ResetPtrListRecordsSlot1C();
    (*p)->slot18();
    p = p + 1;
    i = i + -1;
  } while (i != 0);
}

// FUNCTION: IMPERIALISM 0x005b7d90
void TTradeMgr::WriteTo(TStream* stream) {
  char* rowCursor = reinterpret_cast<char*>(this) + 0xa;
  int rows = 0x11;
  do {
    stream->WriteBytesSlot78(rowCursor - 2, 2);
    stream->WriteBytesSlot78(rowCursor, 2);
    stream->WriteBytesSlot78(rowCursor + 2, 2);
    stream->WriteBytesSlot78(rowCursor + 4, 2);
    stream->WriteBytesSlot78(rowCursor + 6, 8);
    stream->WriteBytesSlot78(rowCursor + 0xe, 2);
    stream->WriteBytesSlot78(rowCursor + 0x10, 2);
    char* cell = rowCursor + 0x12;
    int c = 0x17;
    do {
      short swapped = static_cast<short>((cell[0] & 0xff) | (cell[1] << 8));
      stream->WriteBytesSlot78(&swapped, 2);
      cell = cell + 2;
      c = c + -1;
    } while (c != 0);
    cell = rowCursor + 0x40;
    c = 0x17;
    do {
      short swapped = static_cast<short>((cell[0] & 0xff) | (cell[1] << 8));
      stream->WriteBytesSlot78(&swapped, 2);
      cell = cell + 2;
      c = c + -1;
    } while (c != 0);
    cell = rowCursor + 0x6e;
    c = 0x17;
    do {
      short swapped = static_cast<short>((cell[0] & 0xff) | (cell[1] << 8));
      stream->WriteBytesSlot78(&swapped, 2);
      cell = cell + 2;
      c = c + -1;
    } while (c != 0);
    rowCursor = rowCursor + 0xa0;
    rows = rows + -1;
  } while (rows != 0);

  TDealList** p = this->categoryRankLists;
  int i = 0x11;
  do {
    (*p)->ResetPtrListRecordsSlot1C();
    (*p)->slot18();
    p = p + 1;
    i = i + -1;
  } while (i != 0);
}

// FUNCTION: IMPERIALISM 0x005b7fc0
void TTradeMgr::OrphanCallChain_C3_I50_005b7fc0() {
  short* rowCursor = reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x0e);
  int rows = 0x11;
  do {
    rowCursor[-1] = 0;
    rowCursor[0] = 0;
    rowCursor[5] = 0;
    *reinterpret_cast<int*>(rowCursor + 1) = 0;
    *reinterpret_cast<int*>(rowCursor + 3) = 0;
    short* cell = rowCursor + 0x1e;
    int c = 0x17;
    do {
      cell[-0x17] = 0;
      *cell = 0;
      cell = cell + 1;
      c = c + -1;
    } while (c != 0);
    rowCursor = rowCursor + 0x50;
    rows = rows + -1;
  } while (rows != 0);

  TDealList** p = &this->categoryRankLists[0xd];
  int i = 4;
  do {
    (*p)->ResetPtrListRecordsSlot1C();
    p = p + 1;
    i = i + -1;
  } while (i != 0);
  p = &this->categoryRankLists[7];
  i = 6;
  do {
    (*p)->ResetPtrListRecordsSlot1C();
    p = p + 1;
    i = i + -1;
  } while (i != 0);
  p = &this->categoryRankLists[0];
  i = 7;
  do {
    (*p)->ResetPtrListRecordsSlot1C();
    p = p + 1;
    i = i + -1;
  } while (i != 0);
}

// FUNCTION: IMPERIALISM 0x005b8080
undefined4 TTradeMgr::AccumulateDiplomacyRelationChangesAndQueueEvents() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005b8aa0
void TTradeMgr::DispatchNationMetricUpdatePassForAllSlots() {
  int slot = 0;
  do {
    this->ComputeNationMetricBaselineValueForSlot(static_cast<short>(slot));
    slot = slot + 1;
  } while (static_cast<short>(slot) < 0x11);
}

// FUNCTION: IMPERIALISM 0x005b8ad0
void TTradeMgr::ComputeNationMetricBaselineValueForSlot(short slot) {
  NationMetricCategoryRow* row = &this->categoryRows[slot];
  row->presetSeed04 = row->proposalWeightScale06;

  int result;
  short via;
  switch (slot) {
  case 8:
    result = (int)this->categoryRows[0].proposalWeightScale06 +
             (int)this->categoryRows[1].proposalWeightScale06;
    via = this->categoryRows[0xd].proposalWeightScale06;
    result = ((int)via / 3 + (result / 2) * 3) / 2;
    break;
  case 9:
    result = ((int)this->categoryRows[0xe].proposalWeightScale06 / 3 +
              this->categoryRows[2].proposalWeightScale06 * 3) /
             2;
    break;
  case 0xa:
    result = this->categoryRows[2].proposalWeightScale06 * 3;
    break;
  case 0xb:
    result = (int)this->categoryRows[4].proposalWeightScale06 +
             (int)this->categoryRows[3].proposalWeightScale06;
    via = this->categoryRows[0xf].proposalWeightScale06;
    result = ((int)via / 3 + (result / 2) * 3) / 2;
    break;
  case 0xc:
    result = this->categoryRows[6].proposalWeightScale06 * 3;
    break;
  case 0x10:
    result = ((int)this->categoryRows[0xf].proposalWeightScale06 +
              this->categoryRows[0xb].proposalWeightScale06 * 3) /
             2;
    break;
  default: {
    double weighted = *reinterpret_cast<double*>(&row->weightedScore0c);
    double diff = (double)(int)row->field08 - weighted;
    int pw = (int)row->proposalWeightScale06;
    int a = (int)((double)pw + diff);
    int b = (int)((1.0 + diff * 0.01) * (double)pw);
    if (diff < 0.0) {
      result = (a <= b) ? a : b;
    } else {
      result = (b <= a) ? a : b;
    }
    if ((double)result < (double)(int)row->field16 * 0.1) {
      result = (int)((double)(int)row->field16 * 0.1);
    }
    break;
  }
  }
  if (result >= 32000) {
    result = 32000;
  }
  row->proposalWeightScale06 = (short)result;
}

// FUNCTION: IMPERIALISM 0x005b8d40
double TTradeMgr::GetNationMetricWeightedScoreForSlot(short category) {
  return *reinterpret_cast<double*>(&this->categoryRows[category].weightedScore0c);
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
short TTradeMgr::GetNationMetricRosterWordAtOffset0E(short category) {
  return this->categoryRows[category].field0a;
}

// FUNCTION: IMPERIALISM 0x005b8fb0
short TTradeMgr::GetNationMetricRosterWordAtOffset0C(short category) {
  return this->categoryRows[category].field08;
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
short TTradeMgr::GetNationMetricBucketValueByIndex(short category) {
  return this->categoryRows[category].field16;
}

// FUNCTION: IMPERIALISM 0x005b9060
void TTradeMgr::ApplyDiplomacyTransferEffectsAcrossNationMetricRoster(short slot) {
  TDealList* list = this->categoryRankLists[slot];
  int count = *reinterpret_cast<int*>(reinterpret_cast<char*>(list) + 8);
  short idx = 1;
  int i = 1;
  if (0 < count) {
    do {
      short* entry = reinterpret_cast<short*>(list->GetEntrySlot2C(i));
      int transfer =
          g_apTerrainTypeDescriptorTable[entry[1]]->SumDiplomacyState1c6AndRelationDeltaSnapshot(
              slot);
      char inPlay = g_pDiplomacyTurnStateManager->IsPrimaryNationSlotIndex(entry[1]);
      if ((inPlay != 0) &&
          (g_pDiplomacyTurnStateManager->IsPrimaryNationSlotIndex(entry[0]) == 0) &&
          (g_apTerrainTypeDescriptorTable[entry[1]]->GetDiplomacyCounterA2() < transfer)) {
        transfer = g_apTerrainTypeDescriptorTable[entry[1]]->GetDiplomacyCounterA2();
      }
      if (0 < transfer) {
        g_apTerrainTypeDescriptorTable[entry[0]]->TryDispatchNationActionViaUiContextOrFallback(
            entry[1], transfer, entry[4], slot);
      }
      idx = idx + 1;
      i = static_cast<int>(idx);
    } while (i <= count);
  }
}

// FUNCTION: IMPERIALISM 0x005b9190
void TTradeMgr::ProcessPendingDiplomacyTransferEntriesUntilBlockedWrapper() {
  char* self = reinterpret_cast<char*>(this);
  *reinterpret_cast<short*>(self + 0x6) = 1;
  *reinterpret_cast<short*>(self + 0x4) = 0;
  short next = 0;
  do {
    short i = *reinterpret_cast<short*>(self + 0x4);
    short idx = g_nationMetricSlotDispatchOrder006d810[i];
    TDealList* list = this->categoryRankLists[idx];
    if (*reinterpret_cast<int*>(reinterpret_cast<char*>(list) + 8) != 0) {
      break;
    }
    next = *reinterpret_cast<short*>(self + 0x4) + 1;
    *reinterpret_cast<short*>(self + 0x4) = next;
  } while (next < 0x11);
  this->ProcessPendingDiplomacyTransferEntriesUntilBlocked();
}

// FUNCTION: IMPERIALISM 0x005b91e0
void TTradeMgr::ProcessPendingDiplomacyTransferEntriesUntilBlocked() {}

// FUNCTION: IMPERIALISM 0x005b9410
void TTradeMgr::RebuildNationMetricPassesAndClampRowsByBaseline() {
  int slot = 0xd;
  do {
    this->ApplyDiplomacyTransferEffectsAcrossNationMetricRoster(static_cast<short>(slot));
    slot = slot + 1;
  } while (static_cast<short>(slot) < 0x11);
  slot = 7;
  do {
    this->ApplyDiplomacyTransferEffectsAcrossNationMetricRoster(static_cast<short>(slot));
    slot = slot + 1;
  } while (static_cast<short>(slot) < 0xd);
  slot = 0;
  do {
    this->ApplyDiplomacyTransferEffectsAcrossNationMetricRoster(static_cast<short>(slot));
    slot = slot + 1;
  } while (static_cast<short>(slot) < 7);

  TGreatPower** np = g_apNationStates;
  int i = 7;
  do {
    if (*np != 0) {
      (*np)->ClearDiplomacyState1c6Block();
    }
    np = np + 1;
    i = i + -1;
  } while (i != 0);

  short* base = reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x78);
  int rows = 0x11;
  do {
    short* q = base;
    int c = 0x17;
    do {
      if (*q < q[-0x17]) {
        *q = q[-0x17];
      }
      q = q + 1;
      c = c + -1;
    } while (c != 0);
    base = base + 0x50;
    rows = rows + -1;
  } while (rows != 0);
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
void TTradeMgr::SetNationMetricCellValueByIndex(short category, short value) {
  this->categoryRows[category].proposalWeightScale06 = value;
}

// FUNCTION: IMPERIALISM 0x005b97c0
void TTradeMgr::RunNationUpdatePassesAndResetTransitionFlags() {
  int slot = 0;
  TGreatPower** np = g_apNationStates;
  do {
    if ((IsNationSlotEligibleForEventProcessing(static_cast<short>(slot)) != 0) && (*np != 0)) {
      (*np)->ResetDiplomacyNeedScoresAndClearAidAllocationMatrix();
    }
    slot = slot + 1;
    np = np + 1;
  } while (static_cast<short>(slot) < 7);

  TMinor** mp = g_apSecondaryNationStateSlots + 7;
  int i = 0x10;
  do {
    if (*mp != 0) {
      (*mp)->RebuildDiplomacyEconomicPressureFromMapState();
    }
    mp = mp + 1;
    i = i + -1;
  } while (i != 0);

  slot = 0;
  np = g_apNationStates;
  do {
    if ((IsNationSlotEligibleForEventProcessing(static_cast<short>(slot)) != 0) && (*np != 0)) {
      (*np)->ResetDiplomacyNeedSlots7012AndRefreshIfModeGateMatches();
    }
    slot = slot + 1;
    np = np + 1;
  } while (static_cast<short>(slot) < 7);

  *reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x4) = 0;
  *reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x6) = 1;
}

// FUNCTION: IMPERIALISM 0x005b9890
void TTradeMgr::RunNationMetricPreUpdatePassAcrossSecondaryNations() {
  TMinor** p = g_apSecondaryNationStateSlots + 7;
  int i = 0x10;
  do {
    if (*p != 0) {
      (*p)->SeedRandomDiplomacyPolicyThresholds();
    }
    p = p + 1;
    i = i + -1;
  } while (i != 0);
  this->BuildSecondaryNationMetricBucketsAndWeightedTrendScores();
}

// FUNCTION: IMPERIALISM 0x005b98d0
void TTradeMgr::BuildEligibleNationMetricBucketsAndWeightedTrendScores() {
  short turnCount = *reinterpret_cast<short*>(reinterpret_cast<char*>(g_pLocalizationTable) + 0x2c);
  short bucket = static_cast<short>(
      (static_cast<int>(turnCount) + (static_cast<int>(turnCount) >> 0x1f & 3U)) >> 2);
  double base;
  if (bucket < 0xb) {
    base = 1.1;
  } else if (bucket < 0x15) {
    base = 1.08;
  } else if (bucket < 0x1f) {
    base = 1.06;
  } else if (bucket < 0x29) {
    base = 1.04;
  } else if (bucket < 0x33) {
    base = 1.03;
  } else if (bucket < 0x3d) {
    base = 1.02;
  } else {
    base = 1.01;
  }

  int nation = 0;
  TGreatPower** np = g_apNationStates;
  do {
    if (IsNationSlotEligibleForEventProcessing(static_cast<short>(nation)) != 0) {
      (*np)->AssignFallbackNationsToUnfilledDiplomacyNeedSlots();
    }
    nation = nation + 1;
    np = np + 1;
  } while (static_cast<short>(nation) < 7);

  int metricRow = 0;
  int cellBase = 0;
  short* cursor = reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0xe);
  do {
    int col = 0;
    np = g_apNationStates;
    int slot = 0;
    do {
      if (IsNationSlotEligibleForEventProcessing(static_cast<short>(slot)) != 0) {
        short metric = (*np)->QueryNationMetricBySlot7C(static_cast<short>(metricRow));
        *reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x1c + (cellBase + col) * 2) =
            metric;
        if (metric < 0) {
          cursor[-1] = cursor[-1] + 1;
        } else if (0 < metric) {
          *cursor = *cursor + 1;
          cursor[5] = cursor[5] + metric;
          double factor;
          if (metric == 1) {
            factor = 1.0;
          } else {
            int exponent = (metric < 0x19) ? (metric - 1) : 0x17;
            factor = this->ComputeNationMetricPowerScale(base, static_cast<short>(exponent));
            if (2.0 < factor) {
              factor = 2.0;
            }
          }
          *reinterpret_cast<double*>(cursor + 1) = factor + *reinterpret_cast<double*>(cursor + 1);
        }
      }
      np = np + 1;
      slot = slot + 1;
      col = col + 1;
    } while (static_cast<short>(slot) < 7);
    metricRow = metricRow + 1;
    cellBase = cellBase + 0x50;
    cursor = cursor + 0x50;
  } while (static_cast<short>(metricRow) < 0x11);
}

// FUNCTION: IMPERIALISM 0x005b9b30
void TTradeMgr::BuildSecondaryNationMetricBucketsAndWeightedTrendScores() {
  short turnCount = *reinterpret_cast<short*>(reinterpret_cast<char*>(g_pLocalizationTable) + 0x2c);
  short band = static_cast<short>(
      (static_cast<int>(turnCount) + (static_cast<int>(turnCount) >> 0x1f & 3U)) >> 2);
  double base;
  if (band < 0xb) {
    base = 1.1;
  } else if (band < 0x15) {
    base = 1.09;
  } else if (band < 0x1f) {
    base = 1.08;
  } else if (band < 0x29) {
    base = 1.07;
  } else if (band < 0x33) {
    base = 1.06;
  } else if (band < 0x3d) {
    base = 1.05;
  } else if (band < 0x47) {
    base = 1.04;
  } else if (band < 0x51) {
    base = 1.03;
  } else if (band < 0x5b) {
    base = 1.02;
  } else {
    base = 1.01;
  }

  char* self = reinterpret_cast<char*>(this);
  short* psVar4 = reinterpret_cast<short*>(self + 0xe);
  int metricRow = 0;
  do {
    short* cellCursor = psVar4 + 0xe;
    TMinor** mp = g_apSecondaryNationStateSlots + 7;
    int remaining = 0x10;
    do {
      short metric = (*mp)->QueryNationMetricBySlot7C(static_cast<short>(metricRow));
      *cellCursor = metric;
      if (0 < metric) {
        int value = metric;
        if ((*mp)->GetDiplomacyExternalStateByTarget(static_cast<short>(metricRow)) < metric) {
          value = (*mp)->GetDiplomacyExternalStateByTarget(static_cast<short>(metricRow));
        }
        *psVar4 = *psVar4 + 1;
        short sv = static_cast<short>(value);
        psVar4[5] = psVar4[5] + sv;
        double factor;
        if (this->QueryProposalWeightSlot4C(static_cast<short>(metricRow)) <
            *reinterpret_cast<short*>(reinterpret_cast<char*>(*mp) + 0x124)) {
          factor = 0.0;
        } else if (sv == 1) {
          factor = 1.0;
        } else {
          int exponent = (sv < 0x19) ? (value - 1) : 0x17;
          factor = this->ComputeNationMetricPowerScale(base, static_cast<short>(exponent));
        }
        *reinterpret_cast<double*>(psVar4 + 1) = factor + *reinterpret_cast<double*>(psVar4 + 1);
      }
      cellCursor = cellCursor + 1;
      mp = mp + 1;
      remaining = remaining + -1;
    } while (remaining != 0);
    psVar4 = psVar4 + 0x50;
    metricRow = metricRow + 1;
  } while (static_cast<short>(metricRow) < 7);

  TMinor** mp = g_apSecondaryNationStateSlots + 7;
  short* aggCursor = reinterpret_cast<short*>(self + 0x48a);
  int count = 0x10;
  do {
    short metric = (*mp)->QueryNationMetricBySlot7C(7);
    *aggCursor = metric;
    if (0 < metric) {
      *reinterpret_cast<short*>(self + 0x46e) = *reinterpret_cast<short*>(self + 0x46e) + 1;
      *reinterpret_cast<short*>(self + 0x478) =
          static_cast<short>(*reinterpret_cast<short*>(self + 0x478) + metric);
      double factor;
      if (metric == 1) {
        factor = 1.0;
      } else {
        int exponent = (metric < 0x19) ? (metric - 1) : 0x17;
        factor = this->ComputeNationMetricPowerScale(base, static_cast<short>(exponent));
      }
      *reinterpret_cast<double*>(self + 0x470) = factor + *reinterpret_cast<double*>(self + 0x470);
    }
    aggCursor = aggCursor + 1;
    mp = mp + 1;
    count = count + -1;
  } while (count != 0);

  short* negCursor = reinterpret_cast<short*>(self + 0x82c);
  int metricSlot = 0xd;
  int cellBase = 0x410;
  do {
    int col = 7;
    mp = g_apSecondaryNationStateSlots + 7;
    int rem = 0x10;
    do {
      if (*mp != 0) {
        short metric = (*mp)->QueryNationMetricBySlot7C(static_cast<short>(metricSlot));
        *reinterpret_cast<short*>(self + 0x1c + (cellBase + col) * 2) = metric;
        if (metric < 0) {
          *negCursor = *negCursor + 1;
        }
      }
      col = col + 1;
      mp = mp + 1;
      rem = rem + -1;
    } while (rem != 0);
    metricSlot = metricSlot + 1;
    cellBase = cellBase + 0x50;
    negCursor = negCursor + 0x50;
  } while (static_cast<short>(metricSlot) < 0x19);
}

// FUNCTION: IMPERIALISM 0x005b9f30
double TTradeMgr::ComputeNationMetricPowerScale(double base, short exponent) {
  double result = 1.0;
  if (exponent > 0) {
    int remaining = exponent;
    do {
      result = result * base;
      remaining = remaining + -1;
    } while (remaining != 0);
  }
  return result;
}

// FUNCTION: IMPERIALISM 0x005b9f70
char TTradeMgr::IsNationMetricCellNegative(int row, int col) {
  short* cells = &this->categoryRows[0].cells18[0];
  return cells[row * 0x50 + col] < 0;
}

// FUNCTION: IMPERIALISM 0x005b9fa0
char TTradeMgr::IsNationMetricCellPositive(int row, int col) {
  short* cells = &this->categoryRows[0].cells18[0];
  return 0 < cells[row * 0x50 + col];
}

// FUNCTION: IMPERIALISM 0x005b9fd0
TSoundChannelNode*
TTradeMgr::AllocateAndPopulateLinkedValueCollectionFromRosterFilter(int rosterSlot,
                                                                    int filterValue) {
  TSoundChannelNode* node = new TSoundChannelNode();
  short idx = 1;
  TDealList* list = this->categoryRankLists[rosterSlot];
  int count = *reinterpret_cast<int*>(reinterpret_cast<char*>(list) + 8);
  if (0 < count) {
    int i = 1;
    do {
      short* entry = reinterpret_cast<short*>(list->GetEntrySlot2C(i));
      if (entry[1] == filterValue) {
        node->SoundChannelNodeDummy00(*entry);
      }
      idx = idx + 1;
      i = static_cast<int>(idx);
    } while (i <= count);
  }
  return node;
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
