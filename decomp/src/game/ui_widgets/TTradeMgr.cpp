#include "game/nation_domain_types.h"
#include "decomp_types.h"
#include "game/ui_widgets/TTradeMgr.h"

#include "game/ui_widgets/TDealList.h"
#include "game/ui_core/TSortedPtrList.h"
#include "game/mfc.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/trade_ui_globals.h"
#include "game/globals/shared_globals.h"
#include "game/nation/TMinor.h"
#include "game/nation/TForeignMinister.h"
#include "game/city_ui/TCountry.h"
#include "game/core/TStream.h"
#include "game/city_ui/TLongintList.h"
#include "game/net/TMultiplayerMgr.h"
#include "game/nation_stream_serialization.h"

IMPLEMENT_DYNCREATE(TTradeMgr, TObject)

// FUNCTION: IMPERIALISM 0x005b7a20
TTradeMgr::TTradeMgr() {}

// FUNCTION: IMPERIALISM 0x005b7a70
TTradeMgr::~TTradeMgr() {}

// FUNCTION: IMPERIALISM 0x005b7a90
void TTradeMgr::ITradeMgr() {
  const short* presetCursor = g_aTradeItemBasePriceByCategory;
  TDealList** rankListCursor = categoryRankLists;
  NationMetricCategoryRow* row = categoryRows;
  for (int rowCount = 0; rowCount < 0x11; ++rowCount) {
    row->numRequests = 0;
    row->numOffers = 0;
    row->amountOffered = 0;
    row->adjustedNumOffers = 0.0;

    short presetValue = *presetCursor;
    row->previousPrice = presetValue;
    row->price = presetValue;
    row->basePrice = row->previousPrice;

    TDealList* list = new TDealList();
    list->recordSize = 0x10;
    *rankListCursor = list;

    short* cellCursor = &row->tradeOfferCells[46];
    for (int cellCount = 0; cellCount < 0x17; ++cellCount) {
      cellCursor[-0x2e] = 0;
      *cellCursor = 0;
      cellCursor[-0x17] = 0;
      ++cellCursor;
    }

    ++rankListCursor;
    ++presetCursor;
    ++row;
  }
}

// FUNCTION: IMPERIALISM 0x005b7bc0
void TTradeMgr::Free() {
  TDealList** p = categoryRankLists;
  for (int i = 0; i < 0x11; ++i) {
    if (*p != 0) {
      (*p)->FreeList();
    }
    *p = 0;
    ++p;
  }
  delete this;
}

// FUNCTION: IMPERIALISM 0x005b7c10
void TTradeMgr::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  if (g_nSaveFormatVersion >= 0x27) {
    NationMetricCategoryRow* row = categoryRows;
    for (int rows = 0; rows < 0x11; ++rows) {
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
      ++row;
    }
  } else {
    stream->ReadBytes(&categoryRows[0].previousPrice, 0xaa0);
  }
  TDealList** p = categoryRankLists;
  for (int i = 0; i < 0x11; ++i) {
    (*p)->DeleteAll();
    (*p)->ReadFrom(stream);
    ++p;
  }
}

// FUNCTION: IMPERIALISM 0x005b7d90
void TTradeMgr::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  NationMetricCategoryRow* row = categoryRows;
  for (int rows = 0; rows < 0x11; ++rows) {
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
    ++row;
  }

  TDealList** p = categoryRankLists;
  for (int i = 0; i < 0x11; ++i) {
    (*p)->WriteTo(stream);
    ++p;
  }
}

// FUNCTION: IMPERIALISM 0x005b7fc0
void TTradeMgr::ResetNationMetricRowsAndClearCategoryRankLists() {
  int i;
  for (i = 0; i < 0x11; ++i) {
    NationMetricCategoryRow* row = &categoryRows[i];
    row->numRequests = 0;
    row->numOffers = 0;
    row->amountOffered = 0;
    row->adjustedNumOffers = 0.0;
    for (int c = 0; c < 0x17; ++c) {
      row->tradeOfferCells[c] = 0;
      row->tradeOfferCells[23 + c] = 0;
    }
  }

  for (i = 0xd; i < 0x11; ++i) {
    categoryRankLists[i]->DeleteAll();
  }
  for (i = 7; i < 0xd; ++i) {
    categoryRankLists[i]->DeleteAll();
  }
  for (i = 0; i < 7; ++i) {
    categoryRankLists[i]->DeleteAll();
  }
}

namespace {
// TDiplomacyMgr relation-standing-score matrix, row stride 0x17 shorts.
inline short RelationStanding(TDiplomacyMgr* mgr, int source, int target) {
  return mgr->relationStandingScores[source * kNationSlotCount + target];
}
} // namespace

// FUNCTION: IMPERIALISM 0x005b8080
void TTradeMgr::CalculateDealOrder() {
  short* cells = &categoryRows[0].tradeOfferCells[0];
  short* accum = &categoryRows[0].tradeOfferCells[23];

  for (int row = 0; row < 7; ++row) {
    int target;
    for (target = 0; target < 7; ++target) {
      if (g_apTerrainTypeDescriptorTable[target] != 0) {
        short cell = cells[row * 0x50 + target];
        if (cell > 0) {
          accum[row * 0x50 + target] = static_cast<short>(accum[row * 0x50 + target] + cell);
          int source = 0;
          do {
            if ((g_apTerrainTypeDescriptorTable[source] != 0) && (cells[row * 0x50 + source] < 0) &&
                (!g_pDiplomacyTurnStateManager->IsBoycott(source, target)) &&
                (!g_pDiplomacyTurnStateManager->AreAtWar(source, target))) {
              TradeDealEntry event;
              event.sourceNationSlot = static_cast<short>(source);
              event.targetNationSlot = static_cast<short>(target);
              event.relationDelta = cell;
              event.relationStanding =
                  RelationStanding(g_pDiplomacyTurnStateManager, source, target);
              event.dispatchScore =
                  GetDealPrice(static_cast<short>(source), static_cast<short>(target),
                               categoryRows[row].price, categoryRows[row].basePrice);
              event.category = static_cast<short>(row);
              categoryRankLists[row]->Insert(&event);
            }
            ++source;
          } while (source < 7);
        }
      }
    }

    // Rows 0..6: secondary-nation targets (slots 7..0x16).
    int secTarget;
    for (secTarget = 7; secTarget < 0x17; ++secTarget) {
      if (g_apTerrainTypeDescriptorTable[secTarget] != 0) {
        short cell = cells[row * 0x50 + secTarget];
        if (cell > 0) {
          accum[row * 0x50 + secTarget] = static_cast<short>(accum[row * 0x50 + secTarget] + cell);
          int source = 0;
          do {
            if ((g_apTerrainTypeDescriptorTable[source] != 0) && (cells[row * 0x50 + source] < 0) &&
                (!g_pDiplomacyTurnStateManager->IsBoycott(source, secTarget)) &&
                (!g_pDiplomacyTurnStateManager->AreAtWar(source, secTarget))) {
              TradeDealEntry event;
              event.sourceNationSlot = static_cast<short>(source);
              event.targetNationSlot = static_cast<short>(secTarget);
              event.relationDelta = cell;
              event.relationStanding =
                  RelationStanding(g_pDiplomacyTurnStateManager, source, secTarget);
              event.dispatchScore =
                  GetDealPrice(static_cast<short>(source), static_cast<short>(secTarget),
                               categoryRows[row].price, categoryRows[row].basePrice);
              event.category = static_cast<short>(row);
              categoryRankLists[row]->Insert(&event);
            }
            ++source;
          } while (source < 7);
        }
      }
    }
  }

  // Rows 7..0xc: only the primary target range (0..6) gets generic processing.
  for (int midRow = 7; midRow < 0xd; ++midRow) {
    int target;
    for (target = 0; target < 7; ++target) {
      if (g_apTerrainTypeDescriptorTable[target] != 0) {
        short cell = cells[midRow * 0x50 + target];
        if (cell > 0) {
          accum[midRow * 0x50 + target] = static_cast<short>(accum[midRow * 0x50 + target] + cell);
          int source = 0;
          do {
            if ((g_apTerrainTypeDescriptorTable[source] != 0) &&
                (cells[midRow * 0x50 + source] < 0) &&
                (!g_pDiplomacyTurnStateManager->IsBoycott(source, target)) &&
                (!g_pDiplomacyTurnStateManager->AreAtWar(source, target))) {
              TradeDealEntry event;
              event.sourceNationSlot = static_cast<short>(source);
              event.targetNationSlot = static_cast<short>(target);
              event.relationDelta = cell;
              event.relationStanding =
                  RelationStanding(g_pDiplomacyTurnStateManager, source, target);
              event.dispatchScore =
                  GetDealPrice(static_cast<short>(source), static_cast<short>(target),
                               categoryRows[midRow].price, categoryRows[midRow].basePrice);
              event.category = static_cast<short>(midRow);
              categoryRankLists[midRow]->Insert(&event);
            }
            ++source;
          } while (source < 7);
        }
      }
    }

    if (midRow == 7) {
      for (int secTarget = 7; secTarget < 0x17; ++secTarget) {
        if (g_apTerrainTypeDescriptorTable[secTarget] != 0) {
          short cell = cells[7 * 0x50 + secTarget];
          if (cell > 0) {
            accum[7 * 0x50 + secTarget] = static_cast<short>(accum[7 * 0x50 + secTarget] + cell);
            int source = 0;
            do {
              if ((g_apTerrainTypeDescriptorTable[source] != 0) && (cells[7 * 0x50 + source] < 0) &&
                  (!g_pDiplomacyTurnStateManager->IsBoycott(source, secTarget)) &&
                  (!g_pDiplomacyTurnStateManager->AreAtWar(source, secTarget))) {
                TradeDealEntry event;
                event.sourceNationSlot = static_cast<short>(source);
                event.targetNationSlot = static_cast<short>(secTarget);
                event.relationDelta = cell;
                event.relationStanding =
                    RelationStanding(g_pDiplomacyTurnStateManager, source, secTarget);
                event.dispatchScore =
                    GetDealPrice(static_cast<short>(source), static_cast<short>(secTarget),
                                 categoryRows[7].price, categoryRows[7].basePrice);
                event.category = 7;
                categoryRankLists[7]->Insert(&event);
              }
              ++source;
            } while (source < 7);
          }
        }
      }
    }
  }

  // Rows 0xd..0x10 pair each primary target with both primary and secondary sources.
  for (int lastRow = 0xd; lastRow < 0x11; ++lastRow) {
    for (int target = 0; target < 7; ++target) {
      if (g_apTerrainTypeDescriptorTable[target] != 0) {
        short cell = cells[lastRow * 0x50 + target];
        if (cell > 0) {
          accum[lastRow * 0x50 + target] =
              static_cast<short>(accum[lastRow * 0x50 + target] + cell);
          int source = 0;
          do {
            if ((g_apTerrainTypeDescriptorTable[source] != 0) &&
                (cells[lastRow * 0x50 + source] < 0) &&
                (!g_pDiplomacyTurnStateManager->IsBoycott(source, target)) &&
                (!g_pDiplomacyTurnStateManager->AreAtWar(source, target))) {
              TradeDealEntry event;
              event.sourceNationSlot = static_cast<short>(source);
              event.targetNationSlot = static_cast<short>(target);
              event.relationDelta = cell;
              event.relationStanding =
                  RelationStanding(g_pDiplomacyTurnStateManager, source, target);
              event.dispatchScore =
                  GetDealPrice(static_cast<short>(source), static_cast<short>(target),
                               categoryRows[lastRow].price, categoryRows[lastRow].basePrice);
              event.category = static_cast<short>(lastRow);
              categoryRankLists[lastRow]->Insert(&event);
            }
            ++source;
          } while (source < 7);

          int secondarySource = 7;
          do {
            if ((g_apTerrainTypeDescriptorTable[secondarySource] != 0) &&
                (cells[lastRow * 0x50 + secondarySource] < 0) &&
                (!g_pDiplomacyTurnStateManager->IsBoycott(secondarySource, target)) &&
                (!g_pDiplomacyTurnStateManager->AreAtWar(secondarySource, target))) {
              TradeDealEntry event;
              event.sourceNationSlot = static_cast<short>(secondarySource);
              event.targetNationSlot = static_cast<short>(target);
              event.relationDelta = cell;
              event.relationStanding =
                  RelationStanding(g_pDiplomacyTurnStateManager, secondarySource, target);
              event.dispatchScore =
                  GetDealPrice(static_cast<short>(secondarySource), static_cast<short>(target),
                               categoryRows[lastRow].price, categoryRows[lastRow].basePrice);
              event.category = static_cast<short>(lastRow);
              categoryRankLists[lastRow]->Insert(&event);
            }
            ++secondarySource;
          } while (secondarySource < 0x17);
        }
      }
    }
  }
}
// FUNCTION: IMPERIALISM 0x005b8aa0
void TTradeMgr::CalculateNewWorldPrices() {
  int slot = 0;
  do {
    CalculateNewItemPrice(static_cast<short>(slot));
    ++slot;
  } while (static_cast<short>(slot) < 0x11);
}

// FUNCTION: IMPERIALISM 0x005b8ad0
void TTradeMgr::CalculateNewItemPrice(short item) {
  NationMetricCategoryRow* row = &categoryRows[item];
  row->previousPrice = row->price;

  int result;
  short via;
  switch (item) {
  case 8:
    result = static_cast<int>(categoryRows[0].price) + static_cast<int>(categoryRows[1].price);
    via = categoryRows[0xd].price;
    result = (static_cast<int>(via) / 3 + (result / 2) * 3) / 2;
    break;
  case 9:
    result = (static_cast<int>(categoryRows[0xe].price) / 3 + categoryRows[2].price * 3) / 2;
    break;
  case 0xa:
    result = categoryRows[2].price * 3;
    break;
  case 0xb:
    result = static_cast<int>(categoryRows[4].price) + static_cast<int>(categoryRows[3].price);
    via = categoryRows[0xf].price;
    result = (static_cast<int>(via) / 3 + (result / 2) * 3) / 2;
    break;
  case 0xc:
    result = categoryRows[6].price * 3;
    break;
  case 0x10:
    result = (static_cast<int>(categoryRows[0xf].price) + categoryRows[0xb].price * 3) / 2;
    break;
  default: {
    double weighted = row->adjustedNumOffers;
    double diff = static_cast<double>(row->numRequests) - weighted;
    int pw = row->price;
    if (diff < 0.0) {
      int a = static_cast<int>(static_cast<double>(pw) + diff);
      int b = static_cast<int>((1.0 + diff * 0.01) * static_cast<double>(pw));
      result = (a <= b) ? a : b;
    } else {
      int a = static_cast<int>(static_cast<double>(pw) + diff);
      int b = static_cast<int>((1.0 + diff * 0.01) * static_cast<double>(pw));
      result = (b <= a) ? a : b;
    }
    if (static_cast<double>(result) < static_cast<double>(row->basePrice) * 0.1) {
      result = static_cast<int>((double)(int)row->basePrice * 0.1);
    }
    break;
  }
  }
  if (result >= 32000) {
    result = 32000;
  }
  row->price = static_cast<short>(result);
}

// FUNCTION: IMPERIALISM 0x005b8d40
double TTradeMgr::GetAdjNumOffers(short item) {
  return categoryRows[item].adjustedNumOffers;
}

// FUNCTION: IMPERIALISM 0x005b8d70
short TTradeMgr::GetAmtOffered(short item) {
  return categoryRows[item].amountOffered;
}

// FUNCTION: IMPERIALISM 0x005b8da0
int TTradeMgr::GetDealPrice(short sourceSlot, short targetSlot, short scoreA, short scoreB) {
  if (g_pDiplomacyTurnStateManager->AreAtWar(sourceSlot, targetSlot)) {
    return -1;
  }

  short prefTarget = g_apTerrainTypeDescriptorTable[targetSlot]->encodedNationSlot;
  if (prefTarget >= 200) {
    prefTarget -= 200;
  } else if (prefTarget >= 100) {
    prefTarget -= 100;
  } else {
    prefTarget = g_apTerrainTypeDescriptorTable[targetSlot]->nationSlot;
  }
  if (prefTarget == sourceSlot) {
    return (scoreA < scoreB) ? scoreA : scoreB;
  }

  short prefSource = g_apTerrainTypeDescriptorTable[sourceSlot]->encodedNationSlot;
  if (prefSource >= 200) {
    prefSource -= 200;
  } else if (prefSource >= 100) {
    prefSource -= 100;
  } else {
    prefSource = g_apTerrainTypeDescriptorTable[sourceSlot]->nationSlot;
  }
  if (prefSource == targetSlot) {
    return (scoreA > scoreB) ? scoreA : scoreB;
  }

  if (g_pDiplomacyTurnStateManager->IsGreatPower(targetSlot)) {
    int relation = g_apNationStates[targetSlot]->tradePolicyByNation[sourceSlot];
    if (relation == kTradePolicyNormal) {
      return scoreA;
    }
    if (relation == kTradePolicyBoycott) {
      return -1;
    }
    return static_cast<int>(static_cast<double>(scoreA * relation) * 0.01);
  }
  int relation = g_apNationStates[sourceSlot]->tradePolicyByNation[targetSlot];
  if (relation == kTradePolicyNormal) {
    return scoreA;
  }
  if (relation == kTradePolicyBoycott) {
    return -1;
  }
  int inverse = 200 - relation;
  return static_cast<int>(static_cast<double>(scoreA) * static_cast<double>(inverse) * 0.01);
}

// FUNCTION: IMPERIALISM 0x005b8f80
short TTradeMgr::GetNumOffers(short item) {
  return categoryRows[item].numOffers;
}

// FUNCTION: IMPERIALISM 0x005b8fb0
short TTradeMgr::GetNumRequests(short item) {
  return categoryRows[item].numRequests;
}

// FUNCTION: IMPERIALISM 0x005b8fe0
short TTradeMgr::GetPrice(short item) {
  if (item == 0x16) {
    return 200;
  }
  if (item == 0x15) {
    return 500;
  }
  return categoryRows[item].price;
}

// FUNCTION: IMPERIALISM 0x005b9030
short TTradeMgr::GetBasePrice(short item) {
  return categoryRows[item].basePrice;
}

// FUNCTION: IMPERIALISM 0x005b9060
void TTradeMgr::OfferItemDeals(short item) {
  TDealList* list = categoryRankLists[item];
  short entryOrdinal = 1;
  while (entryOrdinal <= list->GetSize()) {
    TradeDealEntry* entry =
        static_cast<TradeDealEntry*>(list->GetPtrListEntryByOneBasedIndex(entryOrdinal));
    short transfer = g_apTerrainTypeDescriptorTable[entry->targetNationSlot]->GetAmtUnsold(item);
    if (g_pDiplomacyTurnStateManager->IsGreatPower(entry->targetNationSlot) &&
        !g_pDiplomacyTurnStateManager->IsGreatPower(entry->sourceNationSlot) &&
        transfer > g_apTerrainTypeDescriptorTable[entry->targetNationSlot]->GetMerchantCapacity()) {
      transfer = g_apTerrainTypeDescriptorTable[entry->targetNationSlot]->GetMerchantCapacity();
    }
    if (transfer >= 1) {
      g_apTerrainTypeDescriptorTable[entry->sourceNationSlot]->ReplyToTradeOffer(
          entry->targetNationSlot, transfer, static_cast<short>(entry->dispatchScore), item);
    }
    ++entryOrdinal;
  }
}

// FUNCTION: IMPERIALISM 0x005b9190
void TTradeMgr::StartDeals() {
  categoryRows[0].dealEntryOrdinal = 1;
  categoryRows[0].dealCategoryOrderIndex = 0;
  short next = 0;
  do {
    short i = categoryRows[0].dealCategoryOrderIndex;
    short idx = g_aTradeDealCategoryOrder[i];
    TDealList* list = categoryRankLists[idx];
    if (list->GetSize() != 0) {
      break;
    }
    next = categoryRows[0].dealCategoryOrderIndex + 1;
    categoryRows[0].dealCategoryOrderIndex = next;
  } while (next < 0x11);
  NextTradeDeal();
}

// FUNCTION: IMPERIALISM 0x005b91e0
void TTradeMgr::NextTradeDeal() {
  bool blocked = false;
  do {
    if (categoryRows[0].dealCategoryOrderIndex > 0x10) {
      break;
    }
    short dispatchIdx = g_aTradeDealCategoryOrder[categoryRows[0].dealCategoryOrderIndex];
    TDealList* list = categoryRankLists[dispatchIdx];
    TradeDealEntry* entry = static_cast<TradeDealEntry*>(
        list->GetPtrListEntryByOneBasedIndex(categoryRows[0].dealEntryOrdinal));

    int relationDelta =
        g_apTerrainTypeDescriptorTable[entry->targetNationSlot]->GetAmtUnsold(dispatchIdx);
    if (g_pDiplomacyTurnStateManager->IsGreatPower(entry->targetNationSlot) &&
        !g_pDiplomacyTurnStateManager->IsGreatPower(entry->sourceNationSlot)) {
      if (g_apTerrainTypeDescriptorTable[entry->targetNationSlot]->GetMerchantCapacity() <
          relationDelta) {
        relationDelta =
            g_apTerrainTypeDescriptorTable[entry->targetNationSlot]->GetMerchantCapacity();
      }
    }

    if (relationDelta > 0) {
      blocked = g_apTerrainTypeDescriptorTable[entry->sourceNationSlot]->ReplyToTradeOffer(
                    entry->targetNationSlot, relationDelta,
                    static_cast<short>(entry->dispatchScore), dispatchIdx) != 0;
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
      } while (categoryRankLists[g_aTradeDealCategoryOrder[categoryRows[0].dealCategoryOrderIndex]]
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
  for (int nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
    TGreatPower* nation = g_apNationStates[nationSlot];
    if (nation != 0) {
      nation->ClearTradeOffers();
    }
  }

  short* rowCursor = &categoryRows[0].tradeOfferCells[46];
  for (int rowCount = 0; rowCount < 0x11; ++rowCount) {
    short* cellCursor = rowCursor;
    for (int cellCount = 0; cellCount < 0x17; ++cellCount) {
      short priorValue = cellCursor[-0x17];
      if (priorValue > *cellCursor) {
        *cellCursor = priorValue;
      }
      ++cellCursor;
    }
    rowCursor += 0x50;
  }

  bool isHost = g_pSimMgr->multiplayerSessionRole == kSessionRoleHost;
  if (isHost) {
    g_pGameFlowState->EmitTurnEvent3Mode18WithActiveNation();
  } else {
    g_pSimMgr->StartNextPhase();
  }
}

// FUNCTION: IMPERIALISM 0x005b9410
void TTradeMgr::OfferTradeDeals() {
  short slot;
  for (slot = 0xd; slot <= 0x10; ++slot) {
    OfferItemDeals(slot);
  }
  for (slot = 7; slot <= 0xc; ++slot) {
    OfferItemDeals(slot);
  }
  for (slot = 0; slot <= 6; ++slot) {
    OfferItemDeals(slot);
  }

  TGreatPower** np = g_apNationStates;
  for (int i = 0; i < 7; ++i) {
    if (*np != 0) {
      (*np)->ClearTradeOffers();
    }
    ++np;
  }

  short* base = &categoryRows[0].tradeOfferCells[46];
  for (int rows = 0; rows < 0x11; ++rows) {
    short* q = base;
    for (int c = 0; c < 0x17; ++c) {
      if (q[-0x17] > *q) {
        *q = q[-0x17];
      }
      ++q;
    }
    base += 0x50;
  }
}

// FUNCTION: IMPERIALISM 0x005b94d0
void TTradeMgr::SetDealResults(NationSlot sourceNation, NationSlot targetNation, short amount,
                               short maximumAmount, ResourceKindStorage commodityType,
                               unsigned char shortfallFlag, bool remoteReplay) {
  if (!remoteReplay) {
    bool isClient = g_pSimMgr->multiplayerSessionRole == kSessionRoleClient;
    if (isClient) {
      g_pGameFlowState->SendDealResults(true, sourceNation, targetNation, amount, maximumAmount,
                                        commodityType, shortfallFlag);
      return;
    }
  }
  bool isHost = g_pSimMgr->multiplayerSessionRole == kSessionRoleHost;
  if (isHost) {
    g_pGameFlowState->SendDealResults(false, sourceNation, targetNation, amount, maximumAmount,
                                      commodityType, shortfallFlag);
  }

  if (shortfallFlag != 0 && g_pDiplomacyTurnStateManager->IsGreatPower(sourceNation)) {
    g_apNationStates[sourceNation]->ClearTradeOfferForResource(commodityType);
  }
  if (amount > 0) {
    int sourceNationIndex = sourceNation;
    g_apTerrainTypeDescriptorTable[sourceNationIndex]->PurchaseItem(commodityType, amount,
                                                                    maximumAmount);
    g_apTerrainTypeDescriptorTable[targetNation]->PurchaseItem(commodityType, -amount,
                                                               maximumAmount);
    if (g_pDiplomacyTurnStateManager->IsGreatPower(targetNation) &&
        !g_pDiplomacyTurnStateManager->IsGreatPower(sourceNation)) {
      g_apTerrainTypeDescriptorTable[targetNation]->DeliverItem(amount);
    }
    short relationBump = g_pDiplomacyTurnStateManager->GetEmbassyStatus(sourceNation, targetNation);
    if (relationBump >= 1) {
      int matrixIndex = sourceNationIndex * kNationSlotCount + targetNation;
      short standingScore = g_pDiplomacyTurnStateManager->relationStandingScores[matrixIndex];
      g_pDiplomacyTurnStateManager->SetRelationship(sourceNation, targetNation, standingScore + 1);
    }
    if (g_pDiplomacyTurnStateManager->IsGreatPower(targetNation)) {
      g_apNationStates[targetNation]->AddToDealBook(kTrackedSlotAcceptEntry, sourceNation, amount,
                                                    commodityType, maximumAmount);
    }
    if (g_pDiplomacyTurnStateManager->IsGreatPower(sourceNation)) {
      g_apNationStates[sourceNationIndex]->AddToDealBook(kTrackedSlotOfferEntry, targetNation,
                                                         amount, commodityType, maximumAmount);
    }
  } else if (g_pDiplomacyTurnStateManager->IsGreatPower(sourceNation)) {
    g_apNationStates[sourceNation]->AddToDealBook(kTrackedSlotOfferEntry, targetNation, amount,
                                                  commodityType, maximumAmount);
  }
}

// FUNCTION: IMPERIALISM 0x005b9790
void TTradeMgr::UpdatePrice(short item, short value) {
  categoryRows[item].price = value;
}

// FUNCTION: IMPERIALISM 0x005b97c0
void TTradeMgr::StartTradePhase() {
  int slot = 0;
  TGreatPower** np = g_apNationStates;
  do {
    if (g_pSimMgr->ReallyInTheGame(static_cast<short>(slot)) && *np != 0) {
      (*np)->InitializeTradeStatus();
    }
    ++slot;
    ++np;
  } while (static_cast<short>(slot) < 7);

  TMinor** mp = g_apNationAuxRuntimeStateSlots;
  for (int i = 0; i < 0x10; ++i) {
    if (*mp != 0) {
      (*mp)->InitializeTradeStatus();
    }
    ++mp;
  }

  slot = 0;
  np = g_apNationStates;
  do {
    if (g_pSimMgr->ReallyInTheGame(static_cast<short>(slot)) && *np != 0) {
      (*np)->SetTradeBids();
    }
    ++slot;
    ++np;
  } while (static_cast<short>(slot) < 7);

  categoryRows[0].dealCategoryOrderIndex = 0;
  categoryRows[0].dealEntryOrdinal = 1;
}

// FUNCTION: IMPERIALISM 0x005b9890
void TTradeMgr::SetMinorsTradeBids() {
  TMinor** p = g_apNationAuxRuntimeStateSlots;
  for (int i = 0; i < 0x10; ++i) {
    if (*p != 0) {
      (*p)->SetTradeBids();
    }
    ++p;
  }
  TallyMinorsTradeBids();
}

// FUNCTION: IMPERIALISM 0x005b98d0
void TTradeMgr::TallyTradeBids() {
  short turnCount = g_pSimMgr->economicTurn;
  short bucket = static_cast<int>(turnCount) / 4;
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
    if (g_pSimMgr->ReallyInTheGame(static_cast<short>(nation))) {
      (*np)->AssignFallbackNationsToUnfilledDiplomacyNeedSlots();
    }
    ++nation;
    ++np;
  } while (static_cast<short>(nation) < kMajorNationCount);

  int metricRow = 0;
  NationMetricCategoryRow* row = categoryRows;
  short* cells = &categoryRows[0].tradeOfferCells[0];
  do {
    int col = 0;
    np = g_apNationStates;
    int slot = 0;
    do {
      if (g_pSimMgr->ReallyInTheGame(static_cast<short>(slot))) {
        short metric = (*np)->GetTradeOffersFor(static_cast<short>(metricRow));
        cells[metricRow * 0x50 + col] = metric;
        if (metric < 0) {
          ++row->numRequests;
        } else if (metric > 0) {
          ++row->numOffers;
          row->amountOffered += metric;
          double factor;
          if (metric == 1) {
            factor = 1.0;
          } else {
            int exponent = (metric < 0x19) ? (metric - 1) : 0x17;
            factor = Power(base, static_cast<short>(exponent));
            if (2.0 < factor) {
              factor = 2.0;
            }
          }
          row->adjustedNumOffers = factor + row->adjustedNumOffers;
        }
      }
      ++np;
      ++slot;
      ++col;
    } while (static_cast<short>(slot) < 7);
    ++metricRow;
    ++row;
  } while (static_cast<short>(metricRow) < 0x11);
}

// FUNCTION: IMPERIALISM 0x005b9b30
void TTradeMgr::TallyMinorsTradeBids() {
  short turnCount = g_pSimMgr->economicTurn;
  short band = static_cast<int>(turnCount) / 4;
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
    for (int remaining = 0; remaining < 0x10; ++remaining) {
      short metric = (*mp)->GetTradeOffersFor(static_cast<short>(metricRow));
      *cellCursor = metric;
      if (metric > 0) {
        int value = metric;
        if ((*mp)->GetStockpile(static_cast<short>(metricRow)) < metric) {
          value = (*mp)->GetStockpile(static_cast<short>(metricRow));
        }
        ++row->numOffers;
        short sv = value;
        row->amountOffered += sv;
        double factor;
        if (GetPrice(static_cast<short>(metricRow)) < (*mp)->GetRandomOfferPriceThreshold()) {
          factor = 0.0;
        } else if (sv == 1) {
          factor = 1.0;
        } else {
          int exponent = (sv < 0x19) ? (value - 1) : 0x17;
          factor = Power(base, static_cast<short>(exponent));
        }
        row->adjustedNumOffers = factor + row->adjustedNumOffers;
      }
      ++cellCursor;
      ++mp;
    }
    ++row;
    ++metricRow;
  } while (static_cast<short>(metricRow) < 7);

  TMinor** mp = g_apNationAuxRuntimeStateSlots;
  NationMetricCategoryRow* aggregateRow = &categoryRows[kMajorNationCount];
  short* aggCursor = &aggregateRow->tradeOfferCells[7];
  for (int count = 0; count < 0x10; ++count) {
    short metric = (*mp)->GetTradeOffersFor(kResourceFood);
    *aggCursor = metric;
    if (metric > 0) {
      ++aggregateRow->numOffers;
      aggregateRow->amountOffered = static_cast<short>(aggregateRow->amountOffered + metric);
      double factor;
      if (metric == 1) {
        factor = 1.0;
      } else if (metric > 0x18) {
        factor = Power(base, 0x17);
      } else {
        factor = Power(base, static_cast<short>(metric - 1));
      }
      aggregateRow->adjustedNumOffers = factor + aggregateRow->adjustedNumOffers;
    }
    ++aggCursor;
    ++mp;
  }

  row = &categoryRows[0xd];
  int metricSlot = 0xd;
  do {
    int col = 7;
    mp = g_apNationAuxRuntimeStateSlots;
    for (int rem = 0; rem < 0x10; ++rem) {
      if (*mp != 0) {
        short metric = (*mp)->GetTradeOffersFor(static_cast<short>(metricSlot));
        row->tradeOfferCells[col] = metric;
        if (metric < 0) {
          ++row->numRequests;
        }
      }
      ++col;
      ++mp;
    }
    ++metricSlot;
    ++row;
  } while (static_cast<short>(metricSlot) < 0x11);
}

// FUNCTION: IMPERIALISM 0x005b9f30
double TTradeMgr::Power(double base, short exponent) {
  double result = g_TradePowerIdentity;
  if (exponent > 0) {
    int remaining = exponent;
    do {
      result *= base;
      --remaining;
    } while (remaining != 0);
  }
  return result;
}

// FUNCTION: IMPERIALISM 0x005b9f70
bool TTradeMgr::DidBidOn(int item, int nationSlot) {
  short* cells = &categoryRows[0].tradeOfferCells[0];
  return cells[item * 0x50 + nationSlot] < 0;
}

// FUNCTION: IMPERIALISM 0x005b9fa0
bool TTradeMgr::DidOffer(int item, int nationSlot) {
  short* cells = &categoryRows[0].tradeOfferCells[0];
  return 0 < cells[item * 0x50 + nationSlot];
}

// FUNCTION: IMPERIALISM 0x005b9fd0
TLongintList* TTradeMgr::GetBidderList(int item, int nationSlot) {
  TLongintList* node = new TLongintList();
  short idx = 1;
  TDealList* list = categoryRankLists[item];
  int count = list->GetSize();
  if (count > 0) {
    int i = 1;
    do {
      TradeDealEntry* entry = static_cast<TradeDealEntry*>(list->GetPtrListEntryByOneBasedIndex(i));
      if (entry->targetNationSlot == nationSlot) {
        node->InsertLast(entry->sourceNationSlot);
      }
      ++idx;
      i = static_cast<int>(idx);
    } while (i <= count);
  }
  return node;
}

// FUNCTION: IMPERIALISM 0x005ba090
short TTradeMgr::WhoTradesFirst(short proposalCode, short category) {
  short* lookupCursor = g_aTradeDealCategoryOrder;
  do {
    short slotValue = *lookupCursor;
    if (slotValue == proposalCode) {
      return proposalCode;
    }
    if (slotValue == category) {
      return category;
    }
    ++lookupCursor;
  } while (lookupCursor < &g_aTradeDealCategoryOrder[0x11]);
  return proposalCode;
}

// FUNCTION: IMPERIALISM 0x005ba0e0
int TTradeMgr::GetMarketChange() {
  int sum = 0;
  for (int category = 0; category < 0x11; ++category) {
    sum += categoryRows[category].price - categoryRows[category].previousPrice;
  }
  return sum / 0x11;
}
