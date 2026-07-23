#include "decomp_types.h"
#include "game/ui_widgets/TTradeMgr.h"

#include "game/ui_widgets/TDealList.h"
#include "game/ui_core/TSortedPtrList.h"
#include "game/mfc.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/nation/TMinor.h"
#include "game/map/TForeignMinister.h"
#include "game/city_ui/TCountry.h"
#include "game/core/TStream.h"
#include "game/city_ui/TLongintList.h"
#include "game/net/TMultiplayerMgr.h"
#include "game/nation_stream_serialization.h"

// SYNTHETIC: IMPERIALISM 0x005b79d0
// TTradeMgr::CreateObject

// SYNTHETIC: IMPERIALISM 0x005b7a00
// TTradeMgr::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTradeMgr, TObject)

// FUNCTION: IMPERIALISM 0x005b7a20
TTradeMgr::TTradeMgr() {}

// SYNTHETIC: IMPERIALISM 0x005b7a40
// TTradeMgr::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x005b7a70
TTradeMgr::~TTradeMgr() {}

// FUNCTION: IMPERIALISM 0x005b7a90
void TTradeMgr::InitializeNationInteractionStateManagerDefaults() {
  const short* presetCursor = g_aTradeItemBasePriceByCategory_0069A910;
  TDealList** rankListCursor = this->categoryRankLists;
  NationMetricCategoryRow* row = this->categoryRows;
  int rowCount = 0x11;
  do {
    row->field08 = 0;
    row->field0a = 0;
    row->capabilityActiveFlag14 = 0;
    row->weightedScore0c = 0.0;

    short presetValue = *presetCursor;
    row->presetSeed04 = presetValue;
    row->proposalWeightScale06 = presetValue;
    row->field16 = row->presetSeed04;

    TDealList* list = new TDealList();
    list->recordSize14 = 0x10;
    *rankListCursor = list;

    short* cellCursor = &row->cells18[46];
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
    row = row + 1;
    rowCount = rowCount + -1;
  } while (rowCount != 0);
}

// FUNCTION: IMPERIALISM 0x005b7bc0
void TTradeMgr::Free() {
  TDealList** p = this->categoryRankLists;
  int i = 0x11;
  do {
    if (*p != 0) {
      (*p)->ReleasePtrList();
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
    stream->ReadBytes(&categoryRows[0].presetSeed04, 0xaa0);
  } else {
    NationMetricCategoryRow* row = categoryRows;
    int rows = 0x11;
    do {
      stream->ReadBytes(&row->presetSeed04, 2);
      stream->ReadBytes(&row->proposalWeightScale06, 2);
      stream->ReadBytes(&row->field08, 2);
      stream->ReadBytes(&row->field0a, 2);
      stream->ReadBytes(&row->weightedScore0c, 8);
      stream->ReadBytes(&row->capabilityActiveFlag14, 2);
      stream->ReadBytes(&row->field16, 2);
      stream->ReadBytes(&row->cells18[0], 0x2e);
      SwapShortArrayBytes(&row->cells18[0], 0x17);
      stream->ReadBytes(&row->cells18[23], 0x2e);
      SwapShortArrayBytes(&row->cells18[23], 0x17);
      stream->ReadBytes(&row->cells18[46], 0x2e);
      SwapShortArrayBytes(&row->cells18[46], 0x17);
      row = row + 1;
      rows = rows + -1;
    } while (rows != 0);
  }
  TDealList** p = this->categoryRankLists;
  int i = 0x11;
  do {
    (*p)->ClearAndFreeAllPtrListRecords();
    (*p)->ReadFrom(stream);
    p = p + 1;
    i = i + -1;
  } while (i != 0);
}

// FUNCTION: IMPERIALISM 0x005b7d90
void TTradeMgr::WriteTo(TStream* stream) {
  NationMetricCategoryRow* row = categoryRows;
  int rows = 0x11;
  do {
    stream->WriteBytesSlot78(&row->presetSeed04, 2);
    stream->WriteBytesSlot78(&row->proposalWeightScale06, 2);
    stream->WriteBytesSlot78(&row->field08, 2);
    stream->WriteBytesSlot78(&row->field0a, 2);
    stream->WriteBytesSlot78(&row->weightedScore0c, 8);
    stream->WriteBytesSlot78(&row->capabilityActiveFlag14, 2);
    stream->WriteBytesSlot78(&row->field16, 2);
    WriteShortArrayElems(stream, &row->cells18[0], 0x17);
    WriteShortArrayElems(stream, &row->cells18[23], 0x17);
    WriteShortArrayElems(stream, &row->cells18[46], 0x17);
    row = row + 1;
    rows = rows + -1;
  } while (rows != 0);

  TDealList** p = this->categoryRankLists;
  int i = 0x11;
  do {
    // The original WriteTo loop only serializes; the previous port wrongly copied the
    // ReadFrom pair here and cleared every category rank list during a save.
    (*p)->WriteTo(stream);
    p = p + 1;
    i = i + -1;
  } while (i != 0);
}

// FUNCTION: IMPERIALISM 0x005b7fc0
void TTradeMgr::ResetNationMetricRowsAndClearCategoryRankLists() {
  NationMetricCategoryRow* row = categoryRows;
  int rows = 0x11;
  do {
    row->field08 = 0;
    row->field0a = 0;
    row->capabilityActiveFlag14 = 0;
    row->weightedScore0c = 0.0;
    short* cell = &row->cells18[23];
    int c = 0x17;
    do {
      cell[-0x17] = 0;
      *cell = 0;
      cell = cell + 1;
      c = c + -1;
    } while (c != 0);
    row = row + 1;
    rows = rows + -1;
  } while (rows != 0);

  TDealList** p = &this->categoryRankLists[0xd];
  int i = 4;
  do {
    (*p)->ClearAndFreeAllPtrListRecords();
    p = p + 1;
    i = i + -1;
  } while (i != 0);
  p = &this->categoryRankLists[7];
  i = 6;
  do {
    (*p)->ClearAndFreeAllPtrListRecords();
    p = p + 1;
    i = i + -1;
  } while (i != 0);
  p = &this->categoryRankLists[0];
  i = 7;
  do {
    (*p)->ClearAndFreeAllPtrListRecords();
    p = p + 1;
    i = i + -1;
  } while (i != 0);
}

namespace {
// The event record queued into a rank list per accumulated relation change.
struct DiplomacyRelationEvent {
  short sourceSlot;
  short targetSlot;
  short cellValue;
  short relationScore;
};

// TDiplomacyMgr relation-standing-score matrix (+0x79c), row stride 0x17 shorts.
inline short RelationStanding(TDiplomacyMgr* mgr, int source, int target) {
  return *reinterpret_cast<short*>(reinterpret_cast<char*>(mgr) + 0x79c +
                                   (source * 0x17 + target) * 2);
}
} // namespace

// FUNCTION: IMPERIALISM 0x005b8080
void TTradeMgr::AccumulateDiplomacyRelationChangesAndQueueEvents() {
  // cells18 is laid out as three 23-entry (kTerrainTypeDescriptorTableCount) sub-rows per
  // category row: [0..22] this-turn delta per nation slot, [23..45] running accumulated
  // total per nation slot (index target+23), [46..67(+1 overflow)] running max -- the
  // latter consumed by RefreshNationStateAndEmitTurnEvent3Mode18. Only the delta and
  // accumulated sub-rows are touched here. The original walks both as flat short arrays
  // with the 0x50-short category-row stride.
  short* cells = &categoryRows[0].cells18[0];
  short* accum = &categoryRows[0].cells18[23];

  // Rows 0..6: primary-nation category rows get BOTH target ranges processed here --
  // primary targets (0..6) and secondary/minor targets (7..0x16).
  int row = 0;
  do {
    int target = 0;
    do {
      if (g_apTerrainTypeDescriptorTable[target] != 0) {
        short cell = cells[row * 0x50 + target];
        if (0 < cell) {
          accum[row * 0x50 + target] = static_cast<short>(accum[row * 0x50 + target] + cell);
          int source = 0;
          do {
            if ((g_apTerrainTypeDescriptorTable[source] != 0) && (cells[row * 0x50 + source] < 0) &&
                (g_pDiplomacyTurnStateManager->HasNationPairNeedLevel300(source, target) == 0) &&
                (g_pDiplomacyTurnStateManager->IsNationPairAtWar(source, target) == 0)) {
              DiplomacyRelationEvent event;
              event.sourceSlot = static_cast<short>(source);
              event.targetSlot = static_cast<short>(target);
              event.cellValue = cell;
              event.relationScore = RelationStanding(g_pDiplomacyTurnStateManager, source, target);
              // Fixed: scoreA/scoreB are the row's OWN proposalWeightScale06/field16, not
              // target-relative cells (confirmed via psVar6[-8]/*psVar6 anchored at the
              // row's field06/field16 in the raw disassembly).
              this->ComputeNationMetricDispatchScoreAndResolveScale(
                  static_cast<short>(source), static_cast<short>(target),
                  categoryRows[row].proposalWeightScale06, categoryRows[row].field16);
              this->categoryRankLists[row]->InsertCopiedRecordSortedByComparator(&event);
            }
            source = source + 1;
          } while (source < 7);
        }
      }
      target = target + 1;
    } while (target < 7);

    // Rows 0..6: secondary-nation targets (slots 7..0x16).
    int secTarget = 7;
    do {
      if (g_apTerrainTypeDescriptorTable[secTarget] != 0) {
        short cell = cells[row * 0x50 + secTarget];
        if (0 < cell) {
          accum[row * 0x50 + secTarget] = static_cast<short>(accum[row * 0x50 + secTarget] + cell);
          int source = 0;
          do {
            if ((g_apTerrainTypeDescriptorTable[source] != 0) && (cells[row * 0x50 + source] < 0) &&
                (g_pDiplomacyTurnStateManager->HasNationPairNeedLevel300(source, secTarget) == 0) &&
                (g_pDiplomacyTurnStateManager->IsNationPairAtWar(source, secTarget) == 0)) {
              DiplomacyRelationEvent event;
              event.sourceSlot = static_cast<short>(source);
              event.targetSlot = static_cast<short>(secTarget);
              event.cellValue = cell;
              event.relationScore =
                  RelationStanding(g_pDiplomacyTurnStateManager, source, secTarget);
              this->ComputeNationMetricDispatchScoreAndResolveScale(
                  static_cast<short>(source), static_cast<short>(secTarget),
                  categoryRows[row].proposalWeightScale06, categoryRows[row].field16);
              this->categoryRankLists[row]->InsertCopiedRecordSortedByComparator(&event);
            }
            source = source + 1;
          } while (source < 7);
        }
      }
      secTarget = secTarget + 1;
    } while (secTarget < 0x17);

    row = row + 1;
  } while (row < 7);

  // Rows 7..0xc: only the primary target range (0..6) gets generic processing.
  int midRow = 7;
  do {
    int target = 0;
    do {
      if (g_apTerrainTypeDescriptorTable[target] != 0) {
        short cell = cells[midRow * 0x50 + target];
        if (0 < cell) {
          accum[midRow * 0x50 + target] = static_cast<short>(accum[midRow * 0x50 + target] + cell);
          int source = 0;
          do {
            if ((g_apTerrainTypeDescriptorTable[source] != 0) &&
                (cells[midRow * 0x50 + source] < 0) &&
                (g_pDiplomacyTurnStateManager->HasNationPairNeedLevel300(source, target) == 0) &&
                (g_pDiplomacyTurnStateManager->IsNationPairAtWar(source, target) == 0)) {
              DiplomacyRelationEvent event;
              event.sourceSlot = static_cast<short>(source);
              event.targetSlot = static_cast<short>(target);
              event.cellValue = cell;
              event.relationScore = RelationStanding(g_pDiplomacyTurnStateManager, source, target);
              this->ComputeNationMetricDispatchScoreAndResolveScale(
                  static_cast<short>(source), static_cast<short>(target),
                  categoryRows[midRow].proposalWeightScale06, categoryRows[midRow].field16);
              this->categoryRankLists[midRow]->InsertCopiedRecordSortedByComparator(&event);
            }
            source = source + 1;
          } while (source < 7);
        }
      }
      target = target + 1;
    } while (target < 7);

    // Quirk (reproduced verbatim, not "fixed"): only row 7 additionally gets its
    // secondary/minor target range (7..0x16) processed here, hardcoded to row 7's own
    // fields and its own categoryRankLists[7] -- rows 8..0xc never get that range
    // processed at all in this function.
    if (midRow == 7) {
      int secTarget = 7;
      do {
        if (g_apTerrainTypeDescriptorTable[secTarget] != 0) {
          short cell = cells[7 * 0x50 + secTarget];
          if (0 < cell) {
            accum[7 * 0x50 + secTarget] = static_cast<short>(accum[7 * 0x50 + secTarget] + cell);
            int source = 0;
            do {
              if ((g_apTerrainTypeDescriptorTable[source] != 0) && (cells[7 * 0x50 + source] < 0) &&
                  (g_pDiplomacyTurnStateManager->HasNationPairNeedLevel300(source, secTarget) ==
                   0) &&
                  (g_pDiplomacyTurnStateManager->IsNationPairAtWar(source, secTarget) == 0)) {
                DiplomacyRelationEvent event;
                event.sourceSlot = static_cast<short>(source);
                event.targetSlot = static_cast<short>(secTarget);
                event.cellValue = cell;
                event.relationScore =
                    RelationStanding(g_pDiplomacyTurnStateManager, source, secTarget);
                this->ComputeNationMetricDispatchScoreAndResolveScale(
                    static_cast<short>(source), static_cast<short>(secTarget),
                    categoryRows[7].proposalWeightScale06, categoryRows[7].field16);
                this->categoryRankLists[7]->InsertCopiedRecordSortedByComparator(&event);
              }
              source = source + 1;
            } while (source < 7);
          }
        }
        secTarget = secTarget + 1;
      } while (secTarget < 0x17);
    }

    midRow = midRow + 1;
  } while (midRow < 0xd);

  // Rows 0xd..0x10: only the primary target range (0..6), no row-7-style special case.
  int lastRow = 0xd;
  do {
    int target = 0;
    do {
      if (g_apTerrainTypeDescriptorTable[target] != 0) {
        short cell = cells[lastRow * 0x50 + target];
        if (0 < cell) {
          accum[lastRow * 0x50 + target] =
              static_cast<short>(accum[lastRow * 0x50 + target] + cell);
          int source = 0;
          do {
            if ((g_apTerrainTypeDescriptorTable[source] != 0) &&
                (cells[lastRow * 0x50 + source] < 0) &&
                (g_pDiplomacyTurnStateManager->HasNationPairNeedLevel300(source, target) == 0) &&
                (g_pDiplomacyTurnStateManager->IsNationPairAtWar(source, target) == 0)) {
              DiplomacyRelationEvent event;
              event.sourceSlot = static_cast<short>(source);
              event.targetSlot = static_cast<short>(target);
              event.cellValue = cell;
              event.relationScore = RelationStanding(g_pDiplomacyTurnStateManager, source, target);
              this->ComputeNationMetricDispatchScoreAndResolveScale(
                  static_cast<short>(source), static_cast<short>(target),
                  categoryRows[lastRow].proposalWeightScale06, categoryRows[lastRow].field16);
              this->categoryRankLists[lastRow]->InsertCopiedRecordSortedByComparator(&event);
            }
            source = source + 1;
          } while (source < 7);
        }
      }
      target = target + 1;
    } while (target < 7);
    lastRow = lastRow + 1;
  } while (lastRow < 0x11);
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
    double weighted = row->weightedScore0c;
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
  return this->categoryRows[category].weightedScore0c;
}

// FUNCTION: IMPERIALISM 0x005b8d70
short TTradeMgr::IsCapabilityCategoryActiveSlot3C(short category) {
  return this->categoryRows[category].capabilityActiveFlag14;
}

// FUNCTION: IMPERIALISM 0x005b8da0
int TTradeMgr::ComputeNationMetricDispatchScoreAndResolveScale(short sourceSlot, short targetSlot,
                                                               short scoreA, short scoreB) {
  if (g_pDiplomacyTurnStateManager->IsNationPairAtWar(sourceSlot, targetSlot) != 0) {
    return -1;
  }

  short prefTarget = *reinterpret_cast<short*>(
      reinterpret_cast<char*>(g_apTerrainTypeDescriptorTable[targetSlot]) + 0xe);
  if (prefTarget >= 200) {
    prefTarget = static_cast<short>(prefTarget - 200);
  } else if (prefTarget >= 100) {
    prefTarget = static_cast<short>(prefTarget - 100);
  } else {
    prefTarget = *reinterpret_cast<short*>(
        reinterpret_cast<char*>(g_apTerrainTypeDescriptorTable[targetSlot]) + 0xc);
  }
  if (prefTarget == sourceSlot) {
    return (scoreA < scoreB) ? scoreA : scoreB;
  }

  short prefSource = *reinterpret_cast<short*>(
      reinterpret_cast<char*>(g_apTerrainTypeDescriptorTable[sourceSlot]) + 0xe);
  if (prefSource >= 200) {
    prefSource = static_cast<short>(prefSource - 200);
  } else if (prefSource >= 100) {
    prefSource = static_cast<short>(prefSource - 100);
  } else {
    prefSource = *reinterpret_cast<short*>(
        reinterpret_cast<char*>(g_apTerrainTypeDescriptorTable[sourceSlot]) + 0xc);
  }
  if (prefSource == targetSlot) {
    return (scoreA > scoreB) ? scoreA : scoreB;
  }

  if (g_pDiplomacyTurnStateManager->IsMajorNationSlot(targetSlot) != 0) {
    int relation = *reinterpret_cast<short*>(reinterpret_cast<char*>(g_apNationStates[targetSlot]) +
                                             0x14 + sourceSlot * 2);
    if (relation == 100) {
      return scoreA;
    }
    if (relation == 300) {
      return -1;
    }
    return static_cast<int>(static_cast<double>(scoreA * relation) * 0.01);
  }
  int relation = *reinterpret_cast<short*>(reinterpret_cast<char*>(g_apNationStates[sourceSlot]) +
                                           0x14 + targetSlot * 2);
  if (relation == 100) {
    return scoreA;
  }
  if (relation == 300) {
    return -1;
  }
  int inverse = 200 - relation;
  return static_cast<int>(static_cast<double>(scoreA) * static_cast<double>(inverse) * 0.01);
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
  int count = list->GetSize();
  short idx = 1;
  int i = 1;
  if (0 < count) {
    do {
      short* entry = reinterpret_cast<short*>(list->GetPtrListEntryByOneBasedIndex(i));
      int transfer =
          g_apTerrainTypeDescriptorTable[entry[1]]->SumDiplomacyState1c6AndRelationDeltaSnapshot(
              slot);
      bool inPlay = g_pDiplomacyTurnStateManager->IsMajorNationSlot(entry[1]);
      if ((inPlay != 0) && (g_pDiplomacyTurnStateManager->IsMajorNationSlot(entry[0]) == 0) &&
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
void TTradeMgr::InitializePendingDiplomacyTransferCursorAndProcess() {
  categoryRows[0].resetTransitionFlagB02 = 1;
  categoryRows[0].resetTransitionFlagA00 = 0;
  short next = 0;
  do {
    short i = categoryRows[0].resetTransitionFlagA00;
    short idx = g_aTradeDealCategoryOrder_0066D810[i];
    TDealList* list = this->categoryRankLists[idx];
    if (list->GetSize() != 0) {
      break;
    }
    next = categoryRows[0].resetTransitionFlagA00 + 1;
    categoryRows[0].resetTransitionFlagA00 = next;
  } while (next < 0x11);
  this->ProcessPendingDiplomacyTransferEntriesUntilBlocked();
}

// FUNCTION: IMPERIALISM 0x005b91e0
void TTradeMgr::ProcessPendingDiplomacyTransferEntriesUntilBlocked() {
  // Reuses categoryRows[0]'s resetTransitionFlagA00/B02 pair as persistent (row, ordinal)
  // cursor state across calls -- matches the wrapper's own this+4/this+6 use of the same
  // pair (see InitializePendingDiplomacyTransferCursorAndProcess above).
  bool blocked = false;
  do {
    if (categoryRows[0].resetTransitionFlagA00 > 0x10) {
      break;
    }
    short dispatchIdx = g_aTradeDealCategoryOrder_0066D810[categoryRows[0].resetTransitionFlagA00];
    TDealList* list = categoryRankLists[dispatchIdx];
    // TDealList entry record layout not yet recovered: entry[0]=source nation slot,
    // entry[1]=target nation slot, entry[4]=amount-ish field (raw short offsets, matching
    // the original's own untyped short* walk over the GetPtrListEntryByOneBasedIndex result).
    short* entry = static_cast<short*>(
        list->GetPtrListEntryByOneBasedIndex(categoryRows[0].resetTransitionFlagB02));

    int relationDelta =
        g_apTerrainTypeDescriptorTable[entry[1]]->SumDiplomacyState1c6AndRelationDeltaSnapshot(
            dispatchIdx);
    if (g_pDiplomacyTurnStateManager->IsMajorNationSlot(entry[1]) != 0 &&
        g_pDiplomacyTurnStateManager->IsMajorNationSlot(entry[0]) == 0) {
      if (g_apTerrainTypeDescriptorTable[entry[1]]->GetDiplomacyCounterA2() < relationDelta) {
        relationDelta = g_apTerrainTypeDescriptorTable[entry[1]]->GetDiplomacyCounterA2();
      }
    }

    if (relationDelta > 0) {
      blocked =
          g_apTerrainTypeDescriptorTable[entry[0]]->TryDispatchNationActionViaUiContextOrFallback(
              entry[1], relationDelta, entry[4], dispatchIdx) != 0;
    } else {
      blocked = false;
    }

    ++categoryRows[0].resetTransitionFlagB02;
    if (categoryRows[0].resetTransitionFlagB02 > list->GetSize()) {
      do {
        ++categoryRows[0].resetTransitionFlagA00;
        if (categoryRows[0].resetTransitionFlagA00 > 0x10) {
          break;
        }
      } while (categoryRankLists
                   [g_aTradeDealCategoryOrder_0066D810[categoryRows[0].resetTransitionFlagA00]]
                       ->GetSize() == 0);
      categoryRows[0].resetTransitionFlagB02 = 1;
    }
  } while (!blocked);

  if (!blocked) {
    RefreshNationStateAndEmitTurnEvent3Mode18();
  }
}

// FUNCTION: IMPERIALISM 0x005b9370
void TTradeMgr::RefreshNationStateAndEmitTurnEvent3Mode18() {
  TGreatPower** nationCursor = g_apNationStates;
  do {
    if (*nationCursor != 0) {
      (*nationCursor)->ClearDiplomacyState1c6Block();
    }
    ++nationCursor;
  } while (nationCursor < &g_apNationStates_End);

  short* rowCursor = &categoryRows[0].cells18[46];
  int rowCount = 0x11;
  do {
    short* cellCursor = rowCursor;
    int cellCount = 0x17;
    do {
      short priorValue = cellCursor[-0x17];
      if (priorValue > *cellCursor) {
        *cellCursor = priorValue;
      }
      ++cellCursor;
      --cellCount;
    } while (cellCount != 0);
    rowCursor += 0x50;
    --rowCount;
  } while (rowCount != 0);

  unsigned char isHost = g_pSimMgr->multiplayerSessionRole == 1;
  if (isHost != 0) {
    g_pGameFlowState->EmitTurnEvent3Mode18WithActiveNation();
  } else {
    g_pSimMgr->StartNextPhase();
  }
}

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

  short* base = &categoryRows[0].cells18[46];
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
  if ((skipLocalizationBranch == 0) && (g_pSimMgr->difficultyLevel == 2)) {
    g_pGameFlowState->CreateAndSendTurnEvent1C_BoolAndSixShorts(
        true, ownerNation, static_cast<short>(sourceContext), static_cast<short>(amount),
        static_cast<short>(maxAmount), static_cast<short>(targetNation), emitEventFlag);
    return;
  }
  if (g_pSimMgr->difficultyLevel == 1) {
    g_pGameFlowState->CreateAndSendTurnEvent1C_BoolAndSixShorts(
        false, ownerNation, static_cast<short>(sourceContext), static_cast<short>(amount),
        static_cast<short>(maxAmount), static_cast<short>(targetNation), emitEventFlag);
  }

  short ownerSlot = ownerNation;
  if (emitEventFlag != 0) {
    if (g_pDiplomacyTurnStateManager->IsMajorNationSlot(ownerNation) != 0) {
      g_apNationStates[ownerSlot]->ClearDiplomacyState1c6ForTarget(
          static_cast<short>(targetNation));
    }
  }
  if (static_cast<short>(amount) < 1) {
    if (g_pDiplomacyTurnStateManager->IsMajorNationSlot(ownerNation) != 0) {
      g_apNationStates[ownerSlot]->AppendTrackedSlotEntry(kTrackedSlotOfferEntry, ownerNation,
                                                          static_cast<short>(amount),
                                                          static_cast<short>(targetNation), amount);
    }
  } else {
    int ownerIndex = static_cast<int>(ownerSlot);
    static_cast<TMinor*>(g_apTerrainTypeDescriptorTable[ownerIndex])
        ->ApplyIndexedResourceDeltaAndAdjustNationTotals(targetNation, amount, maxAmount);
    static_cast<TMinor*>(g_apTerrainTypeDescriptorTable[static_cast<short>(sourceContext)])
        ->ApplyIndexedResourceDeltaAndAdjustNationTotals(targetNation, -amount, ownerNation);
    if (g_pDiplomacyTurnStateManager->IsMajorNationSlot(maxAmount) != 0) {
      if (g_pDiplomacyTurnStateManager->IsMajorNationSlot(ownerNation) == 0) {
        static_cast<TMinor*>(g_apTerrainTypeDescriptorTable[sourceContext])
            ->DecrementDiplomacyCounterA2ByValue(amount);
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
    if (g_pDiplomacyTurnStateManager->IsMajorNationSlot(maxAmount) != 0) {
      g_apNationStates[static_cast<short>(targetNation)]->AppendTrackedSlotEntry(
          kTrackedSlotAcceptEntry, ownerNation, static_cast<short>(amount),
          static_cast<short>(targetNation), sourceContext);
    }
    if (g_pDiplomacyTurnStateManager->IsMajorNationSlot(ownerNation) != 0) {
      g_apNationStates[ownerIndex]->AppendTrackedSlotEntry(
          kTrackedSlotOfferEntry, targetNation, static_cast<short>(amount),
          static_cast<short>(targetNation), targetCode);
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
    if ((g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(slot)) != 0) &&
        (*np != 0)) {
      (*np)->ResetDiplomacyNeedScoresAndClearAidAllocationMatrix();
    }
    slot = slot + 1;
    np = np + 1;
  } while (static_cast<short>(slot) < 7);

  TMinor** mp = g_apNationAuxRuntimeStateSlots;
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
    if ((g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(slot)) != 0) &&
        (*np != 0)) {
      (*np)->ResetDiplomacyNeedSlots7012AndRefreshIfModeGateMatches();
    }
    slot = slot + 1;
    np = np + 1;
  } while (static_cast<short>(slot) < 7);

  categoryRows[0].resetTransitionFlagA00 = 0;
  categoryRows[0].resetTransitionFlagB02 = 1;
}

// FUNCTION: IMPERIALISM 0x005b9890
void TTradeMgr::RunNationMetricPreUpdatePassAcrossSecondaryNations() {
  TMinor** p = g_apNationAuxRuntimeStateSlots;
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
  short turnCount = g_pSimMgr->economicTurn;
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
    if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(nation)) != 0) {
      (*np)->AssignFallbackNationsToUnfilledDiplomacyNeedSlots();
    }
    nation = nation + 1;
    np = np + 1;
  } while (static_cast<short>(nation) < 7);

  int metricRow = 0;
  NationMetricCategoryRow* row = categoryRows;
  short* cells = &categoryRows[0].cells18[0];
  do {
    int col = 0;
    np = g_apNationStates;
    int slot = 0;
    do {
      if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(slot)) != 0) {
        short metric = (*np)->QueryNationMetricBySlot7C(static_cast<short>(metricRow));
        cells[metricRow * 0x50 + col] = metric;
        if (metric < 0) {
          row->field08 = row->field08 + 1;
        } else if (0 < metric) {
          row->field0a = row->field0a + 1;
          row->capabilityActiveFlag14 = row->capabilityActiveFlag14 + metric;
          double factor;
          if (metric == 1) {
            factor = 1.0;
          } else {
            int exponent = (metric < 0x19) ? (metric - 1) : 0x17;
            factor = this->Power(base, static_cast<short>(exponent));
            if (2.0 < factor) {
              factor = 2.0;
            }
          }
          row->weightedScore0c = factor + row->weightedScore0c;
        }
      }
      np = np + 1;
      slot = slot + 1;
      col = col + 1;
    } while (static_cast<short>(slot) < 7);
    metricRow = metricRow + 1;
    row = row + 1;
  } while (static_cast<short>(metricRow) < 0x11);
}

// FUNCTION: IMPERIALISM 0x005b9b30
void TTradeMgr::BuildSecondaryNationMetricBucketsAndWeightedTrendScores() {
  short turnCount = g_pSimMgr->economicTurn;
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

  NationMetricCategoryRow* row = categoryRows;
  int metricRow = 0;
  do {
    short* cellCursor = &row->cells18[7];
    TMinor** mp = g_apNationAuxRuntimeStateSlots;
    int remaining = 0x10;
    do {
      short metric = (*mp)->QueryNationMetricBySlot7C(static_cast<short>(metricRow));
      *cellCursor = metric;
      if (0 < metric) {
        int value = metric;
        if ((*mp)->GetDiplomacyExternalStateByTarget(static_cast<short>(metricRow)) < metric) {
          value = (*mp)->GetDiplomacyExternalStateByTarget(static_cast<short>(metricRow));
        }
        row->field0a = row->field0a + 1;
        short sv = static_cast<short>(value);
        row->capabilityActiveFlag14 = row->capabilityActiveFlag14 + sv;
        double factor;
        if (this->QueryProposalWeightSlot4C(static_cast<short>(metricRow)) <
            (*mp)->GetDiplomacyRandomThreshold124()) {
          factor = 0.0;
        } else if (sv == 1) {
          factor = 1.0;
        } else {
          int exponent = (sv < 0x19) ? (value - 1) : 0x17;
          factor = this->Power(base, static_cast<short>(exponent));
        }
        row->weightedScore0c = factor + row->weightedScore0c;
      }
      cellCursor = cellCursor + 1;
      mp = mp + 1;
      remaining = remaining + -1;
    } while (remaining != 0);
    row = row + 1;
    metricRow = metricRow + 1;
  } while (static_cast<short>(metricRow) < 7);

  TMinor** mp = g_apNationAuxRuntimeStateSlots;
  NationMetricCategoryRow* aggregateRow = &categoryRows[7];
  short* aggCursor = &aggregateRow->cells18[7];
  int count = 0x10;
  do {
    short metric = (*mp)->QueryNationMetricBySlot7C(7);
    *aggCursor = metric;
    if (0 < metric) {
      aggregateRow->field0a = aggregateRow->field0a + 1;
      aggregateRow->capabilityActiveFlag14 =
          static_cast<short>(aggregateRow->capabilityActiveFlag14 + metric);
      double factor;
      if (metric == 1) {
        factor = 1.0;
      } else {
        int exponent = (metric < 0x19) ? (metric - 1) : 0x17;
        factor = this->Power(base, static_cast<short>(exponent));
      }
      aggregateRow->weightedScore0c = factor + aggregateRow->weightedScore0c;
    }
    aggCursor = aggCursor + 1;
    mp = mp + 1;
    count = count + -1;
  } while (count != 0);

  row = &categoryRows[0xd];
  int metricSlot = 0xd;
  do {
    int col = 7;
    mp = g_apNationAuxRuntimeStateSlots;
    int rem = 0x10;
    do {
      if (*mp != 0) {
        short metric = (*mp)->QueryNationMetricBySlot7C(static_cast<short>(metricSlot));
        row->cells18[col] = metric;
        if (metric < 0) {
          row->field08 = row->field08 + 1;
        }
      }
      col = col + 1;
      mp = mp + 1;
      rem = rem + -1;
    } while (rem != 0);
    metricSlot = metricSlot + 1;
    row = row + 1;
  } while (static_cast<short>(metricSlot) < 0x11);
}

// FUNCTION: IMPERIALISM 0x005b9f30
double TTradeMgr::Power(double base, short exponent) {
  double result = g_TradePowerIdentity_0066D8E0;
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
TLongintList* TTradeMgr::AllocateAndPopulateLinkedValueCollectionFromRosterFilter(int rosterSlot,
                                                                                  int filterValue) {
  TLongintList* node = new TLongintList();
  short idx = 1;
  TDealList* list = this->categoryRankLists[rosterSlot];
  int count = list->GetSize();
  if (0 < count) {
    int i = 1;
    do {
      short* entry = reinterpret_cast<short*>(list->GetPtrListEntryByOneBasedIndex(i));
      if (entry[1] == filterValue) {
        node->InsertLast(*entry);
      }
      idx = idx + 1;
      i = static_cast<int>(idx);
    } while (i <= count);
  }
  return node;
}

// Scan the 0x11-entry metric-slot dispatch table for whichever of the two codes appears
// first, preferring proposalCode at each slot; fall through to proposalCode if neither is
// present. Word-wide args; the slot value is read once at the loop head. (Residual diff is
// loop-rotation only: MSVC peels the first iteration where the original keeps a single
// bottom-tested body — logic, registers, global ref and read-once all match.)
// FUNCTION: IMPERIALISM 0x005ba090
short TTradeMgr::ResolveProposalCodeForCategorySlot84(short proposalCode, short category) {
  short* lookupCursor = g_aTradeDealCategoryOrder_0066D810;
  do {
    short slotValue = *lookupCursor;
    if (slotValue == proposalCode) {
      return proposalCode;
    }
    if (slotValue == category) {
      return category;
    }
    lookupCursor = lookupCursor + 1;
  } while (lookupCursor < &g_aTradeDealCategoryOrder_0066D810[0x11]);
  return proposalCode;
}

// FUNCTION: IMPERIALISM 0x005ba0e0
int TTradeMgr::ComputeAverageProposalWeightDeltaAcrossCategoryRows() {
  int sum = 0;
  NationMetricCategoryRow* row = categoryRows;
  for (int remaining = 0x11; remaining != 0; --remaining) {
    short* weights = &row->presetSeed04;
    sum += weights[1] - weights[0];
    ++row;
  }
  return sum / 0x11;
}
