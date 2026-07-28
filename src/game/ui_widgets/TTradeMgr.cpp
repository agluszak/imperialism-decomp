#include "decomp_types.h"
#include "game/ui_widgets/TTradeMgr.h"

#include "game/ui_widgets/TDealList.h"
#include "game/ui_core/TSortedPtrList.h"
#include "game/mfc.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/globals/global_types.h"
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
void TTradeMgr::ITradeMgr() {
  const short* presetCursor = g_aTradeItemBasePriceByCategory_0069A910;
  TDealList** rankListCursor = this->categoryRankLists;
  NationMetricCategoryRow* row = this->categoryRows;
  int rowCount = 0x11;
  do {
    row->numRequests = 0;
    row->numOffers = 0;
    row->amountOffered = 0;
    row->adjustedNumOffers = 0.0;

    short presetValue = *presetCursor;
    row->previousPrice = presetValue;
    row->price = presetValue;
    row->basePrice = row->previousPrice;

    TDealList* list = new TDealList();
    list->recordSize14 = 0x10;
    *rankListCursor = list;

    short* cellCursor = &row->tradeOfferCells[46];
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
  // The empty base call is real (0x5b7c20) and was missing from the port. The version
  // test is written the way the original branches it: CMP 0x27 / JL sends the legacy
  // whole-block read to the jump target, so the per-row arm is the fall-through.
  TObject::ReadFrom(stream);
  if (g_nSaveFormatVersion >= 0x27) {
    NationMetricCategoryRow* row = categoryRows;
    int rows = 0x11;
    do {
      stream->ReadBytes(&row->previousPrice, 2);
      stream->ReadBytes(&row->price, 2);
      stream->ReadBytes(&row->numRequests, 2);
      stream->ReadBytes(&row->numOffers, 2);
      stream->ReadBytes(&row->adjustedNumOffers, 8);
      stream->ReadBytes(&row->amountOffered, 2);
      stream->ReadBytes(&row->basePrice, 2);
      stream->ReadBytes(&row->tradeOfferCells[0], 0x2e);
      SwapShortArrayBytes(&row->tradeOfferCells[0], 0x17);
      stream->ReadBytes(&row->tradeOfferCells[23], 0x2e);
      SwapShortArrayBytes(&row->tradeOfferCells[23], 0x17);
      stream->ReadBytes(&row->tradeOfferCells[46], 0x2e);
      SwapShortArrayBytes(&row->tradeOfferCells[46], 0x17);
      row = row + 1;
      rows = rows + -1;
    } while (rows != 0);
  } else {
    stream->ReadBytes(&categoryRows[0].previousPrice, 0xaa0);
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
    stream->WriteBytes(&row->previousPrice, 2);
    stream->WriteBytes(&row->price, 2);
    stream->WriteBytes(&row->numRequests, 2);
    stream->WriteBytes(&row->numOffers, 2);
    stream->WriteBytes(&row->adjustedNumOffers, 8);
    stream->WriteBytes(&row->amountOffered, 2);
    stream->WriteBytes(&row->basePrice, 2);
    WriteShortArrayElems(stream, &row->tradeOfferCells[0], 0x17);
    WriteShortArrayElems(stream, &row->tradeOfferCells[23], 0x17);
    WriteShortArrayElems(stream, &row->tradeOfferCells[46], 0x17);
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
    row->numRequests = 0;
    row->numOffers = 0;
    row->amountOffered = 0;
    row->adjustedNumOffers = 0.0;
    short* cell = &row->tradeOfferCells[23];
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
// TDiplomacyMgr relation-standing-score matrix, row stride 0x17 shorts.
inline short RelationStanding(TDiplomacyMgr* mgr, int source, int target) {
  return mgr->relationStandingScores[source * kNationSlotCount + target];
}
} // namespace

// FUNCTION: IMPERIALISM 0x005b8080
void TTradeMgr::CalculateDealOrder() {
  // tradeOfferCells is laid out as three 23-entry (kTerrainTypeDescriptorTableCount) sub-rows per
  // category row: [0..22] this-turn delta per nation slot, [23..45] running accumulated
  // total per nation slot (index target+23), [46..67(+1 overflow)] running max -- the
  // latter consumed by EndTradeOffers. Only the delta and
  // accumulated sub-rows are touched here. The original walks both as flat short arrays
  // with the 0x50-short category-row stride.
  short* cells = &categoryRows[0].tradeOfferCells[0];
  short* accum = &categoryRows[0].tradeOfferCells[23];

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
              TradeDealEntry event;
              event.sourceNationSlot = static_cast<short>(source);
              event.targetNationSlot = static_cast<short>(target);
              event.relationDelta04 = cell;
              event.relationStanding06 =
                  RelationStanding(g_pDiplomacyTurnStateManager, source, target);
              // Fixed: scoreA/scoreB are the row's OWN price/basePrice, not
              // target-relative cells (confirmed via psVar6[-8]/*psVar6 anchored at the
              // row's field06/basePrice in the raw disassembly).
              event.dispatchScore08 =
                  this->GetDealPrice(static_cast<short>(source), static_cast<short>(target),
                                     categoryRows[row].price, categoryRows[row].basePrice);
              event.category0c = static_cast<short>(row);
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
              TradeDealEntry event;
              event.sourceNationSlot = static_cast<short>(source);
              event.targetNationSlot = static_cast<short>(secTarget);
              event.relationDelta04 = cell;
              event.relationStanding06 =
                  RelationStanding(g_pDiplomacyTurnStateManager, source, secTarget);
              event.dispatchScore08 =
                  this->GetDealPrice(static_cast<short>(source), static_cast<short>(secTarget),
                                     categoryRows[row].price, categoryRows[row].basePrice);
              event.category0c = static_cast<short>(row);
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
              TradeDealEntry event;
              event.sourceNationSlot = static_cast<short>(source);
              event.targetNationSlot = static_cast<short>(target);
              event.relationDelta04 = cell;
              event.relationStanding06 =
                  RelationStanding(g_pDiplomacyTurnStateManager, source, target);
              event.dispatchScore08 =
                  this->GetDealPrice(static_cast<short>(source), static_cast<short>(target),
                                     categoryRows[midRow].price, categoryRows[midRow].basePrice);
              event.category0c = static_cast<short>(midRow);
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
                TradeDealEntry event;
                event.sourceNationSlot = static_cast<short>(source);
                event.targetNationSlot = static_cast<short>(secTarget);
                event.relationDelta04 = cell;
                event.relationStanding06 =
                    RelationStanding(g_pDiplomacyTurnStateManager, source, secTarget);
                event.dispatchScore08 =
                    this->GetDealPrice(static_cast<short>(source), static_cast<short>(secTarget),
                                       categoryRows[7].price, categoryRows[7].basePrice);
                event.category0c = 7;
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
              TradeDealEntry event;
              event.sourceNationSlot = static_cast<short>(source);
              event.targetNationSlot = static_cast<short>(target);
              event.relationDelta04 = cell;
              event.relationStanding06 =
                  RelationStanding(g_pDiplomacyTurnStateManager, source, target);
              event.dispatchScore08 =
                  this->GetDealPrice(static_cast<short>(source), static_cast<short>(target),
                                     categoryRows[lastRow].price, categoryRows[lastRow].basePrice);
              event.category0c = static_cast<short>(lastRow);
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
void TTradeMgr::CalculateNewWorldPrices() {
  int slot = 0;
  do {
    this->CalculateNewItemPrice(static_cast<short>(slot));
    slot = slot + 1;
  } while (static_cast<short>(slot) < 0x11);
}

// FUNCTION: IMPERIALISM 0x005b8ad0
void TTradeMgr::CalculateNewItemPrice(short item) {
  NationMetricCategoryRow* row = &this->categoryRows[item];
  row->previousPrice = row->price;

  int result;
  short via;
  switch (item) {
  case 8:
    result = (int)this->categoryRows[0].price + (int)this->categoryRows[1].price;
    via = this->categoryRows[0xd].price;
    result = ((int)via / 3 + (result / 2) * 3) / 2;
    break;
  case 9:
    result = ((int)this->categoryRows[0xe].price / 3 + this->categoryRows[2].price * 3) / 2;
    break;
  case 0xa:
    result = this->categoryRows[2].price * 3;
    break;
  case 0xb:
    result = (int)this->categoryRows[4].price + (int)this->categoryRows[3].price;
    via = this->categoryRows[0xf].price;
    result = ((int)via / 3 + (result / 2) * 3) / 2;
    break;
  case 0xc:
    result = this->categoryRows[6].price * 3;
    break;
  case 0x10:
    result = ((int)this->categoryRows[0xf].price + this->categoryRows[0xb].price * 3) / 2;
    break;
  default: {
    double weighted = row->adjustedNumOffers;
    double diff = (double)(int)row->numRequests - weighted;
    int pw = (int)row->price;
    int a = (int)((double)pw + diff);
    int b = (int)((1.0 + diff * 0.01) * (double)pw);
    if (diff < 0.0) {
      result = (a <= b) ? a : b;
    } else {
      result = (b <= a) ? a : b;
    }
    if ((double)result < (double)(int)row->basePrice * 0.1) {
      result = (int)((double)(int)row->basePrice * 0.1);
    }
    break;
  }
  }
  if (result >= 32000) {
    result = 32000;
  }
  row->price = (short)result;
}

// FUNCTION: IMPERIALISM 0x005b8d40
double TTradeMgr::GetAdjNumOffers(short item) {
  return this->categoryRows[item].adjustedNumOffers;
}

// FUNCTION: IMPERIALISM 0x005b8d70
short TTradeMgr::GetAmtOffered(short item) {
  return this->categoryRows[item].amountOffered;
}

// FUNCTION: IMPERIALISM 0x005b8da0
int TTradeMgr::GetDealPrice(short sourceSlot, short targetSlot, short scoreA, short scoreB) {
  if (g_pDiplomacyTurnStateManager->IsNationPairAtWar(sourceSlot, targetSlot) != 0) {
    return -1;
  }

  short prefTarget = g_apTerrainTypeDescriptorTable[targetSlot]->encodedNationSlot;
  if (prefTarget >= 200) {
    prefTarget = static_cast<short>(prefTarget - 200);
  } else if (prefTarget >= 100) {
    prefTarget = static_cast<short>(prefTarget - 100);
  } else {
    prefTarget = g_apTerrainTypeDescriptorTable[targetSlot]->nationSlot;
  }
  if (prefTarget == sourceSlot) {
    return (scoreA < scoreB) ? scoreA : scoreB;
  }

  short prefSource = g_apTerrainTypeDescriptorTable[sourceSlot]->encodedNationSlot;
  if (prefSource >= 200) {
    prefSource = static_cast<short>(prefSource - 200);
  } else if (prefSource >= 100) {
    prefSource = static_cast<short>(prefSource - 100);
  } else {
    prefSource = g_apTerrainTypeDescriptorTable[sourceSlot]->nationSlot;
  }
  if (prefSource == targetSlot) {
    return (scoreA > scoreB) ? scoreA : scoreB;
  }

  if (g_pDiplomacyTurnStateManager->IsGreatPower(targetSlot) != 0) {
    int relation = g_apNationStates[targetSlot]->needLevelByNation[sourceSlot];
    if (relation == 100) {
      return scoreA;
    }
    if (relation == 300) {
      return -1;
    }
    return static_cast<int>(static_cast<double>(scoreA * relation) * 0.01);
  }
  int relation = g_apNationStates[sourceSlot]->needLevelByNation[targetSlot];
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
short TTradeMgr::GetNumOffers(short item) {
  return this->categoryRows[item].numOffers;
}

// FUNCTION: IMPERIALISM 0x005b8fb0
short TTradeMgr::GetNumRequests(short item) {
  return this->categoryRows[item].numRequests;
}

// FUNCTION: IMPERIALISM 0x005b8fe0
short TTradeMgr::GetPrice(short item) {
  if (item == 0x16) {
    return 200;
  }
  if (item == 0x15) {
    return 500;
  }
  return this->categoryRows[item].price;
}

// FUNCTION: IMPERIALISM 0x005b9030
short TTradeMgr::GetBasePrice(short item) {
  return this->categoryRows[item].basePrice;
}

// FUNCTION: IMPERIALISM 0x005b9060
void TTradeMgr::OfferItemDeals(short item) {
  TDealList* list = this->categoryRankLists[item];
  int count = list->GetSize();
  short idx = 1;
  int i = 1;
  if (0 < count) {
    do {
      TradeDealEntry* entry = static_cast<TradeDealEntry*>(list->GetPtrListEntryByOneBasedIndex(i));
      int transfer =
          g_apTerrainTypeDescriptorTable[entry->targetNationSlot]->GetIndustrialNeed(item);
      bool inPlay = g_pDiplomacyTurnStateManager->IsGreatPower(entry->targetNationSlot);
      if ((inPlay != 0) &&
          (g_pDiplomacyTurnStateManager->IsGreatPower(entry->sourceNationSlot) == 0) &&
          (g_apTerrainTypeDescriptorTable[entry->targetNationSlot]->GetAvailableMerchantCapacity() <
           transfer)) {
        transfer =
            g_apTerrainTypeDescriptorTable[entry->targetNationSlot]->GetAvailableMerchantCapacity();
      }
      if (0 < transfer) {
        g_apTerrainTypeDescriptorTable[entry->sourceNationSlot]
            ->TryDispatchNationActionViaUiContextOrFallback(
                entry->targetNationSlot, transfer, static_cast<short>(entry->dispatchScore08),
                item);
      }
      idx = idx + 1;
      i = static_cast<int>(idx);
    } while (i <= count);
  }
}

// FUNCTION: IMPERIALISM 0x005b9190
void TTradeMgr::StartDeals() {
  categoryRows[0].dealEntryOrdinal = 1;
  categoryRows[0].dealCategoryOrderIndex = 0;
  short next = 0;
  do {
    short i = categoryRows[0].dealCategoryOrderIndex;
    short idx = g_aTradeDealCategoryOrder_0066D810[i];
    TDealList* list = this->categoryRankLists[idx];
    if (list->GetSize() != 0) {
      break;
    }
    next = categoryRows[0].dealCategoryOrderIndex + 1;
    categoryRows[0].dealCategoryOrderIndex = next;
  } while (next < 0x11);
  this->NextTradeDeal();
}

// FUNCTION: IMPERIALISM 0x005b91e0
void TTradeMgr::NextTradeDeal() {
  // Reuses categoryRows[0]'s dealCategoryOrderIndex/dealEntryOrdinal pair as persistent (row, ordinal)
  // cursor state across calls -- matches the wrapper's own this+4/this+6 use of the same
  // pair (see StartDeals above).
  bool blocked = false;
  do {
    if (categoryRows[0].dealCategoryOrderIndex > 0x10) {
      break;
    }
    short dispatchIdx = g_aTradeDealCategoryOrder_0066D810[categoryRows[0].dealCategoryOrderIndex];
    TDealList* list = categoryRankLists[dispatchIdx];
    TradeDealEntry* entry = static_cast<TradeDealEntry*>(
        list->GetPtrListEntryByOneBasedIndex(categoryRows[0].dealEntryOrdinal));

    int relationDelta =
        g_apTerrainTypeDescriptorTable[entry->targetNationSlot]->GetIndustrialNeed(dispatchIdx);
    if (g_pDiplomacyTurnStateManager->IsGreatPower(entry->targetNationSlot) != 0 &&
        g_pDiplomacyTurnStateManager->IsGreatPower(entry->sourceNationSlot) == 0) {
      if (g_apTerrainTypeDescriptorTable[entry->targetNationSlot]->GetAvailableMerchantCapacity() <
          relationDelta) {
        relationDelta =
            g_apTerrainTypeDescriptorTable[entry->targetNationSlot]->GetAvailableMerchantCapacity();
      }
    }

    if (relationDelta > 0) {
      blocked = g_apTerrainTypeDescriptorTable[entry->sourceNationSlot]
                    ->TryDispatchNationActionViaUiContextOrFallback(
                        entry->targetNationSlot, relationDelta,
                        static_cast<short>(entry->dispatchScore08), dispatchIdx) != 0;
    } else {
      blocked = false;
    }

    ++categoryRows[0].dealEntryOrdinal;
    if (categoryRows[0].dealEntryOrdinal > list->GetSize()) {
      do {
        ++categoryRows[0].dealCategoryOrderIndex;
        if (categoryRows[0].dealCategoryOrderIndex > 0x10) {
          break;
        }
      } while (categoryRankLists
                   [g_aTradeDealCategoryOrder_0066D810[categoryRows[0].dealCategoryOrderIndex]]
                       ->GetSize() == 0);
      categoryRows[0].dealEntryOrdinal = 1;
    }
  } while (!blocked);

  if (!blocked) {
    EndTradeOffers();
  }
}

// FUNCTION: IMPERIALISM 0x005b9370
void TTradeMgr::EndTradeOffers() {
  TGreatPower** nationCursor = g_apNationStates;
  do {
    if (*nationCursor != 0) {
      (*nationCursor)->ClearTradeOffers();
    }
    ++nationCursor;
  } while (nationCursor < &g_apNationStates_End);

  short* rowCursor = &categoryRows[0].tradeOfferCells[46];
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
void TTradeMgr::OfferTradeDeals() {
  int slot = 0xd;
  do {
    this->OfferItemDeals(static_cast<short>(slot));
    slot = slot + 1;
  } while (static_cast<short>(slot) < 0x11);
  slot = 7;
  do {
    this->OfferItemDeals(static_cast<short>(slot));
    slot = slot + 1;
  } while (static_cast<short>(slot) < 0xd);
  slot = 0;
  do {
    this->OfferItemDeals(static_cast<short>(slot));
    slot = slot + 1;
  } while (static_cast<short>(slot) < 7);

  TGreatPower** np = g_apNationStates;
  int i = 7;
  do {
    if (*np != 0) {
      (*np)->ClearTradeOffers();
    }
    np = np + 1;
    i = i + -1;
  } while (i != 0);

  short* base = &categoryRows[0].tradeOfferCells[46];
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
void TTradeMgr::SetDealResults(short sourceNation, int targetNation, int amount, int maximumAmount,
                               int commodityType, char shortfallFlag, char remoteReplay) {
  if (remoteReplay == 0) {
    unsigned char isClient = g_pSimMgr->multiplayerSessionRole == 2;
    if (isClient != 0) {
      g_pGameFlowState->CreateAndSendTurnEvent1C_BoolAndSixShorts(
          true, sourceNation, static_cast<short>(targetNation), static_cast<short>(amount),
          static_cast<short>(maximumAmount), static_cast<short>(commodityType), shortfallFlag);
      return;
    }
  }
  unsigned char isHost = g_pSimMgr->multiplayerSessionRole == 1;
  if (isHost != 0) {
    g_pGameFlowState->CreateAndSendTurnEvent1C_BoolAndSixShorts(
        false, sourceNation, static_cast<short>(targetNation), static_cast<short>(amount),
        static_cast<short>(maximumAmount), static_cast<short>(commodityType), shortfallFlag);
  }

  if (shortfallFlag != 0 && g_pDiplomacyTurnStateManager->IsGreatPower(sourceNation) != 0) {
    g_apNationStates[sourceNation]->ClearTradeOfferForResource(static_cast<short>(commodityType));
  }
  if (static_cast<short>(amount) < 1) {
    if (g_pDiplomacyTurnStateManager->IsGreatPower(sourceNation) != 0) {
      g_apNationStates[sourceNation]->AppendTrackedSlotEntry(
          kTrackedSlotOfferEntry, targetNation, static_cast<short>(amount),
          static_cast<short>(commodityType), maximumAmount);
    }
  } else {
    int sourceNationIndex = static_cast<int>(sourceNation);
    static_cast<TMinor*>(g_apTerrainTypeDescriptorTable[sourceNationIndex])
        ->ApplyIndexedResourceDeltaAndAdjustNationTotals(commodityType, amount, maximumAmount);
    short targetNationSlot = static_cast<short>(targetNation);
    static_cast<TMinor*>(g_apTerrainTypeDescriptorTable[targetNationSlot])
        ->ApplyIndexedResourceDeltaAndAdjustNationTotals(commodityType, -amount, sourceNation);
    if (g_pDiplomacyTurnStateManager->IsGreatPower(targetNationSlot) != 0 &&
        g_pDiplomacyTurnStateManager->IsGreatPower(sourceNation) == 0) {
      static_cast<TMinor*>(g_apTerrainTypeDescriptorTable[targetNationSlot])
          ->ConsumeMerchantCapacity(amount);
    }
    short relationBump = g_pDiplomacyTurnStateManager->LookupOrderCompatibilityMatrixValue(
        sourceNation, targetNationSlot);
    if (relationBump > 0) {
      int matrixIndex = sourceNationIndex * kNationSlotCount + targetNation;
      short standingScore = g_pDiplomacyTurnStateManager->relationStandingScores[matrixIndex];
      g_pDiplomacyTurnStateManager->SetRelationship(sourceNation, targetNationSlot,
                                                    static_cast<short>(standingScore + 1));
    }
    if (g_pDiplomacyTurnStateManager->IsGreatPower(targetNationSlot) != 0) {
      g_apNationStates[targetNationSlot]->AppendTrackedSlotEntry(
          kTrackedSlotAcceptEntry, sourceNation, static_cast<short>(amount),
          static_cast<short>(commodityType), maximumAmount);
    }
    if (g_pDiplomacyTurnStateManager->IsGreatPower(sourceNation) != 0) {
      g_apNationStates[sourceNationIndex]->AppendTrackedSlotEntry(
          kTrackedSlotOfferEntry, targetNation, static_cast<short>(amount),
          static_cast<short>(commodityType), maximumAmount);
    }
  }
}

// FUNCTION: IMPERIALISM 0x005b9790
void TTradeMgr::UpdatePrice(short item, short value) {
  this->categoryRows[item].price = value;
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

  categoryRows[0].dealCategoryOrderIndex = 0;
  categoryRows[0].dealEntryOrdinal = 1;
}

// FUNCTION: IMPERIALISM 0x005b9890
void TTradeMgr::SetMinorsTradeBids() {
  TMinor** p = g_apNationAuxRuntimeStateSlots;
  int i = 0x10;
  do {
    if (*p != 0) {
      (*p)->SeedRandomDiplomacyPolicyThresholds();
    }
    p = p + 1;
    i = i + -1;
  } while (i != 0);
  this->TallyMinorsTradeBids();
}

// FUNCTION: IMPERIALISM 0x005b98d0
void TTradeMgr::TallyTradeBids() {
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
  short* cells = &categoryRows[0].tradeOfferCells[0];
  do {
    int col = 0;
    np = g_apNationStates;
    int slot = 0;
    do {
      if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(slot)) != 0) {
        short metric = (*np)->GetTradeOffersFor(static_cast<short>(metricRow));
        cells[metricRow * 0x50 + col] = metric;
        if (metric < 0) {
          row->numRequests = row->numRequests + 1;
        } else if (0 < metric) {
          row->numOffers = row->numOffers + 1;
          row->amountOffered = row->amountOffered + metric;
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
          row->adjustedNumOffers = factor + row->adjustedNumOffers;
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
void TTradeMgr::TallyMinorsTradeBids() {
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
    short* cellCursor = &row->tradeOfferCells[7];
    TMinor** mp = g_apNationAuxRuntimeStateSlots;
    int remaining = 0x10;
    do {
      short metric = (*mp)->GetTradeOffersFor(static_cast<short>(metricRow));
      *cellCursor = metric;
      if (0 < metric) {
        int value = metric;
        if ((*mp)->GetStockpile(static_cast<short>(metricRow)) < metric) {
          value = (*mp)->GetStockpile(static_cast<short>(metricRow));
        }
        row->numOffers = row->numOffers + 1;
        short sv = static_cast<short>(value);
        row->amountOffered = row->amountOffered + sv;
        double factor;
        if (this->GetPrice(static_cast<short>(metricRow)) <
            (*mp)->GetDiplomacyRandomThreshold124()) {
          factor = 0.0;
        } else if (sv == 1) {
          factor = 1.0;
        } else {
          int exponent = (sv < 0x19) ? (value - 1) : 0x17;
          factor = this->Power(base, static_cast<short>(exponent));
        }
        row->adjustedNumOffers = factor + row->adjustedNumOffers;
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
  short* aggCursor = &aggregateRow->tradeOfferCells[7];
  int count = 0x10;
  do {
    short metric = (*mp)->GetTradeOffersFor(kResourceFood);
    *aggCursor = metric;
    if (0 < metric) {
      aggregateRow->numOffers = aggregateRow->numOffers + 1;
      aggregateRow->amountOffered = static_cast<short>(aggregateRow->amountOffered + metric);
      double factor;
      if (metric == 1) {
        factor = 1.0;
      } else {
        int exponent = (metric < 0x19) ? (metric - 1) : 0x17;
        factor = this->Power(base, static_cast<short>(exponent));
      }
      aggregateRow->adjustedNumOffers = factor + aggregateRow->adjustedNumOffers;
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
        short metric = (*mp)->GetTradeOffersFor(static_cast<short>(metricSlot));
        row->tradeOfferCells[col] = metric;
        if (metric < 0) {
          row->numRequests = row->numRequests + 1;
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
char TTradeMgr::DidBidOn(int item, int nationSlot) {
  short* cells = &this->categoryRows[0].tradeOfferCells[0];
  return cells[item * 0x50 + nationSlot] < 0;
}

// FUNCTION: IMPERIALISM 0x005b9fa0
char TTradeMgr::DidOffer(int item, int nationSlot) {
  short* cells = &this->categoryRows[0].tradeOfferCells[0];
  return 0 < cells[item * 0x50 + nationSlot];
}

// FUNCTION: IMPERIALISM 0x005b9fd0
TLongintList* TTradeMgr::GetBidderList(int item, int nationSlot) {
  TLongintList* node = new TLongintList();
  short idx = 1;
  TDealList* list = this->categoryRankLists[item];
  int count = list->GetSize();
  if (0 < count) {
    int i = 1;
    do {
      TradeDealEntry* entry = static_cast<TradeDealEntry*>(list->GetPtrListEntryByOneBasedIndex(i));
      if (entry->targetNationSlot == nationSlot) {
        node->InsertLast(entry->sourceNationSlot);
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
short TTradeMgr::WhoTradesFirst(short proposalCode, short category) {
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
int TTradeMgr::GetMarketChange() {
  int sum = 0;
  NationMetricCategoryRow* row = categoryRows;
  for (int remaining = 0x11; remaining != 0; --remaining) {
    short* weights = &row->previousPrice;
    sum += weights[1] - weights[0];
    ++row;
  }
  return sum / 0x11;
}
