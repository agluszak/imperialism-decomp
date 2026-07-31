#include "decomp_types.h"
#include "game/ui_widgets/TDealList.h"

#include "game/mfc.h"
#include "game/ui_core/TSortedPtrList.h"
#include "game/ui_widgets/TradeDealEntry.h"

// SYNTHETIC: IMPERIALISM 0x005ba130
// TDealList::CreateObject

// SYNTHETIC: IMPERIALISM 0x005ba1a0
// TDealList::GetRuntimeClass

IMPLEMENT_DYNCREATE(TDealList, TSortedPtrList)

// FUNCTION: IMPERIALISM 0x005ba1c0
TDealList::TDealList() : TSortedPtrList() {}

// SYNTHETIC: IMPERIALISM 0x005ba1f0
// TDealList::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x005ba220
TDealList::~TDealList() {}

// FUNCTION: IMPERIALISM 0x005ba260
short TDealList::Compare(void* a, void* b) {
  TradeDealEntry* recA = static_cast<TradeDealEntry*>(a);
  TradeDealEntry* recB = static_cast<TradeDealEntry*>(b);
  short kind = recA->category0c;
  bool invertScore;
  if (kind < 0xd || 0x10 < kind) {
    invertScore = false;
  } else {
    invertScore = true;
  }
  int valueA = recA->dispatchScore08;
  int priorityA = recA->relationStanding06;
  int scoreA;
  int scoreB;
  if (invertScore) {
    scoreA = (0xff - priorityA) * valueA;
    scoreB = (0xff - recB->relationStanding06) * recB->dispatchScore08;
  } else {
    scoreA = -(valueA * priorityA);
    scoreB = -(recB->dispatchScore08 * recB->relationStanding06);
  }
  if (scoreA == scoreB) {
    scoreA = (recA->relationDelta04 * recA->sourceNationSlot + valueA +
              recA->targetNationSlot * priorityA + kind) %
             7;
    scoreB = (recB->category0c + recB->relationDelta04 * recB->sourceNationSlot +
              recB->dispatchScore08 + recB->targetNationSlot * recB->relationStanding06) %
             7;
  }
  return static_cast<short>(scoreA <= scoreB ? -1 : 1);
}
