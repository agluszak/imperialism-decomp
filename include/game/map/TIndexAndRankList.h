#pragma once

#include "compat.h"
#include "game/ui_core/TSortedPtrList.h"

// VTABLE: IMPERIALISM 0x00659c58
class TIndexAndRankList : public TSortedPtrList {
public:
  DECLARE_DYNCREATE(TIndexAndRankList)

  TIndexAndRankList();
  // ~TIndexAndRankList is compiler-generated (implicit virtual dtor); see
  // the SYNTHETIC scalar deleting destructor in the .cpp.

  // The list-operation virtuals (slots 0x14-0x40) are inherited unchanged from
  // TSortedPtrList. The one override: ascending by the rank short at record+2
  // (ties compare as 1).
  short Compare(void* a, void* b) override; // slot 0x44 0x534910
};

ASSERT_SIZE(TIndexAndRankList, 0x18);
