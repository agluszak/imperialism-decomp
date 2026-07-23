#include "decomp_types.h"
#include "game/ui_widgets/TDealList.h"

#include "game/mfc.h"
#include "game/ui_core/TSortedPtrList.h"

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
  short* recA = static_cast<short*>(a);
  short* recB = static_cast<short*>(b);
  short kind = recA[6];
  bool invertScore;
  if (kind < 0xd || 0x10 < kind) {
    invertScore = false;
  } else {
    invertScore = true;
  }
  int valueA = *reinterpret_cast<int*>(recA + 4);
  int priorityA = recA[3];
  int scoreA;
  int scoreB;
  if (invertScore) {
    scoreA = (0xff - priorityA) * valueA;
    scoreB = (0xff - recB[3]) * *reinterpret_cast<int*>(recB + 4);
  } else {
    scoreA = -(valueA * priorityA);
    scoreB = -(*reinterpret_cast<int*>(recB + 4) * recB[3]);
  }
  if (scoreA == scoreB) {
    scoreA = (recA[2] * recA[0] + valueA + recA[1] * priorityA + kind) % 7;
    scoreB =
        (recB[6] + recB[2] * recB[0] + *reinterpret_cast<int*>(recB + 4) + recB[1] * recB[3]) % 7;
  }
  return static_cast<short>(scoreA <= scoreB ? 1 : -1);
}
