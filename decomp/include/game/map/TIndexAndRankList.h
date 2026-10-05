#pragma once

#include "compat.h"
#include "game/ui_core/TSortedPtrList.h"

struct IndexAndRankRecord {
  short index;
  short value;
  short rank;
};

ASSERT_SIZE(IndexAndRankRecord, 6);

// VTABLE: IMPERIALISM 0x00659c58
class TIndexAndRankList : public TSortedPtrList {
public:
  // FUNCTION: IMPERIALISM 0x005348d0
  ~TIndexAndRankList() override {}
  DECLARE_DYNCREATE(TIndexAndRankList)

  TIndexAndRankList();
  void IIndexAndRankList();
  // ~TIndexAndRankList is compiler-generated (implicit virtual dtor); see
  // the SYNTHETIC scalar deleting destructor in the .cpp.

  short Compare(void* a, void* b) override; // slot 0x44 0x534910
};

ASSERT_SIZE(TIndexAndRankList, 0x18);
