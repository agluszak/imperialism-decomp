#pragma once

#include "compat.h"
#include "game/TSortedPtrList.h"

// VTABLE: IMPERIALISM 0x00659c58
class TIndexAndRankList : public TSortedPtrList {
public:
  DECLARE_DYNCREATE(TIndexAndRankList)

  TIndexAndRankList();
  // ~TIndexAndRankList is compiler-generated (implicit virtual dtor); see
  // the SYNTHETIC scalar deleting destructor in the .cpp.

  // The list-operation virtuals (slots 0x14-0x40) are inherited unchanged from
  // TSortedPtrList; TIndexAndRankList does not override them.
};

ASSERT_SIZE(TIndexAndRankList, 0x18);
