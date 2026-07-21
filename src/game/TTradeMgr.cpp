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
#include "game/TLongintList.h"
#include "game/TMultiplayerMgr.h"

// Preset seed table for the metric rows (original global @ 0x69a910). Kept file-local until
// modeled as a recovered global. (The proposal-code lookup formerly here was replaced by the
// real global g_nationMetricSlotDispatchOrder006d810.)
static short kNationMetricCategoryPresetValues[0x11];

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
    list->recordSize14 = 0x10;
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
    (*p)->ClearAndFreeAllPtrListRecords();
    (*p)->ReadFrom(stream);
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
    // The original WriteTo loop only serializes; the previous port wrongly copied the
    // ReadFrom pair here and cleared every category rank list during a save.
    (*p)->WriteTo(stream);
    p = p + 1;
    i = i + -1;
  } while (i != 0);
}

// FUNCTION: IMPERIALISM 0x005b7fc0
void TTradeMgr::OrphanCallChain_C3_I50_005b7fc0() {
  short* rowCursor = reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x0e);
  int rows = 0x11;
  do {
    NationMetricCategoryRow* row = reinterpret_cast<NationMetricCategoryRow*>(rowCursor - 5);
    row->field08 = 0;
    row->field0a = 0;
    row->capabilityActiveFlag14 = 0;
    *reinterpret_cast<int*>(row->weightedScore0c) = 0;
    *reinterpret_cast<int*>(row->weightedScore0c + 4) = 0;
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
  // accumulated sub-rows are touched here. self+0x1c/self+0x4a are those two sub-rows'
  // bases (categoryRows[0].cells18[0] and categoryRows[0].cells18[23]), walked with a
  // flat row*0x50 index -- matches the original's own flat short* addressing exactly.
  char* self = reinterpret_cast<char*>(this);
  short* cells = reinterpret_cast<short*>(self + 0x1c);
  short* accum = reinterpret_cast<short*>(self + 0x4a);

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
                (g_pDiplomacyTurnStateManager->HasState300LinkBetweenNationPair(source, target) ==
                 0) &&
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
                (g_pDiplomacyTurnStateManager->HasState300LinkBetweenNationPair(source,
                                                                                secTarget) == 0) &&
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
                (g_pDiplomacyTurnStateManager->HasState300LinkBetweenNationPair(source, target) ==
                 0) &&
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
                  (g_pDiplomacyTurnStateManager->HasState300LinkBetweenNationPair(
                       source, secTarget) == 0) &&
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
                (g_pDiplomacyTurnStateManager->HasState300LinkBetweenNationPair(source, target) ==
                 0) &&
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

  if (g_pDiplomacyTurnStateManager->IsPrimaryNationSlotIndex(targetSlot) != 0) {
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
    if (list->GetSize() != 0) {
      break;
    }
    next = *reinterpret_cast<short*>(self + 0x4) + 1;
    *reinterpret_cast<short*>(self + 0x4) = next;
  } while (next < 0x11);
  this->ProcessPendingDiplomacyTransferEntriesUntilBlocked();
}

// FUNCTION: IMPERIALISM 0x005b91e0
void TTradeMgr::ProcessPendingDiplomacyTransferEntriesUntilBlocked() {
  // Reuses categoryRows[0]'s resetTransitionFlagA00/B02 pair as persistent (row, ordinal)
  // cursor state across calls -- matches the wrapper's own this+4/this+6 use of the same
  // pair (see ProcessPendingDiplomacyTransferEntriesUntilBlockedWrapper above).
  bool blocked = false;
  do {
    if (categoryRows[0].resetTransitionFlagA00 > 0x10) {
      break;
    }
    short dispatchIdx =
        g_nationMetricSlotDispatchOrder006d810[categoryRows[0].resetTransitionFlagA00];
    TDealList* list = categoryRankLists[dispatchIdx];
    // TDealList entry record layout not yet recovered: entry[0]=source nation slot,
    // entry[1]=target nation slot, entry[4]=amount-ish field (raw short offsets, matching
    // the original's own untyped short* walk over the GetPtrListEntryByOneBasedIndex result).
    short* entry = static_cast<short*>(
        list->GetPtrListEntryByOneBasedIndex(categoryRows[0].resetTransitionFlagB02));

    int relationDelta =
        g_apTerrainTypeDescriptorTable[entry[1]]->SumDiplomacyState1c6AndRelationDeltaSnapshot(
            dispatchIdx);
    if (g_pDiplomacyTurnStateManager->IsPrimaryNationSlotIndex(entry[1]) != 0 &&
        g_pDiplomacyTurnStateManager->IsPrimaryNationSlotIndex(entry[0]) == 0) {
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
                   [g_nationMetricSlotDispatchOrder006d810[categoryRows[0].resetTransitionFlagA00]]
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
  for (TGreatPower** cursor = g_apNationStates;
       reinterpret_cast<int>(cursor) < reinterpret_cast<int>(&g_apNationStates_End); ++cursor) {
    if (*cursor != 0) {
      (*cursor)->ClearDiplomacyState1c6Block();
    }
  }

  short* rowCursor = &categoryRows[0].cells18[46];
  for (int row = 0; row < 0x11; ++row) {
    for (int i = 0; i < 0x17; ++i) {
      if (rowCursor[i] < rowCursor[i - 0x17]) {
        rowCursor[i] = rowCursor[i - 0x17];
      }
    }
    rowCursor += 0x50;
  }

  if (*reinterpret_cast<int*>(&g_pSimMgr->preferenceValues[0]) == 1) {
    g_pGameFlowState->EmitTurnEvent3Mode18WithActiveNation();
  } else {
    g_pSimMgr->PostMainWindowCommand100ForTurnFlow();
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
  if ((skipLocalizationBranch == 0) && (g_pSimMgr->redrawEnabled == 2)) {
    g_pGameFlowState->CreateAndSendTurnEvent1C_BoolAndSixShorts(
        true, ownerNation, static_cast<short>(sourceContext), static_cast<short>(amount),
        static_cast<short>(maxAmount), static_cast<short>(targetNation), emitEventFlag);
    return;
  }
  if (g_pSimMgr->redrawEnabled == 1) {
    g_pGameFlowState->CreateAndSendTurnEvent1C_BoolAndSixShorts(
        false, ownerNation, static_cast<short>(sourceContext), static_cast<short>(amount),
        static_cast<short>(maxAmount), static_cast<short>(targetNation), emitEventFlag);
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
    static_cast<TMinor*>(g_apTerrainTypeDescriptorTable[ownerIndex])
        ->ApplyIndexedResourceDeltaAndAdjustNationTotals(targetNation, amount, maxAmount);
    static_cast<TMinor*>(g_apTerrainTypeDescriptorTable[static_cast<short>(sourceContext)])
        ->ApplyIndexedResourceDeltaAndAdjustNationTotals(targetNation, -amount, ownerNation);
    if (g_pDiplomacyTurnStateManager->HasFlag84ForNationSlot84(maxAmount) != 0) {
      if (g_pDiplomacyTurnStateManager->HasFlag84ForNationSlot84(ownerNation) == 0) {
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
    if ((g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(slot)) != 0) &&
        (*np != 0)) {
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
  short turnCount = g_pSimMgr->quarterGateTick2c;
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
  int cellBase = 0;
  short* cursor = reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0xe);
  do {
    NationMetricCategoryRow* row = reinterpret_cast<NationMetricCategoryRow*>(cursor - 5);
    int col = 0;
    np = g_apNationStates;
    int slot = 0;
    do {
      if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(slot)) != 0) {
        short metric = (*np)->QueryNationMetricBySlot7C(static_cast<short>(metricRow));
        *reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x1c + (cellBase + col) * 2) =
            metric;
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
            factor = this->ComputeNationMetricPowerScale(base, static_cast<short>(exponent));
            if (2.0 < factor) {
              factor = 2.0;
            }
          }
          *reinterpret_cast<double*>(row->weightedScore0c) =
              factor + *reinterpret_cast<double*>(row->weightedScore0c);
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
  short turnCount = g_pSimMgr->quarterGateTick2c;
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
  short* lookupCursor = g_nationMetricSlotDispatchOrder006d810;
  do {
    short slotValue = *lookupCursor;
    if (slotValue == proposalCode) {
      return proposalCode;
    }
    if (slotValue == category) {
      return category;
    }
    lookupCursor = lookupCursor + 1;
  } while (lookupCursor < &g_nationMetricSlotDispatchOrder006d810[0x11]);
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
