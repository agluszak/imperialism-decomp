#include "decomp_types.h"
#include "game/ui_widgets/TDealList.h"

#include "game/mfc.h"
#include "game/ui_core/TSortedPtrList.h"
#include "game/ui_widgets/TradeDealEntry.h"

IMPLEMENT_DYNCREATE(TDealList, TSortedPtrList)

// FUNCTION: IMPERIALISM 0x005ba1c0
TDealList::TDealList() : TSortedPtrList() {}

// FUNCTION: IMPERIALISM 0x005ba220
TDealList::~TDealList() {}

// FUNCTION: IMPERIALISM 0x005ba240
void TDealList::IDealList() {
  recordSize = 0x10;
}

// FUNCTION: IMPERIALISM 0x005ba260
short TDealList::Compare(void* a, void* b) {
  TradeDealEntry* recA = static_cast<TradeDealEntry*>(a);
  TradeDealEntry* recB = static_cast<TradeDealEntry*>(b);
  short kind = recA->category;
  bool invertScore;
  if (kind < 0xd || kind > 0x10) {
    invertScore = false;
  } else {
    invertScore = true;
  }
  int valueA = recA->dispatchScore;
  int priorityA = recA->relationStanding;
  int scoreA;
  int scoreB;
  if (invertScore) {
    scoreA = (0xff - priorityA) * valueA;
    scoreB = (0xff - recB->relationStanding) * recB->dispatchScore;
  } else {
    scoreA = -(valueA * priorityA);
    scoreB = -(recB->dispatchScore * recB->relationStanding);
  }
  if (scoreA == scoreB) {
    scoreA = (recA->relationDelta * recA->sourceNationSlot + valueA +
              recA->targetNationSlot * priorityA + kind) %
             7;
    scoreB = (recB->category + recB->relationDelta * recB->sourceNationSlot + recB->dispatchScore +
              recB->targetNationSlot * recB->relationStanding) %
             7;
  }
  return scoreA <= scoreB ? -1 : 1;
}
