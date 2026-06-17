#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/TIndexAndRankList.h"

struct CRuntimeClass;

// VTABLE: IMPERIALISM 0x00649068
class TSortedPtrList : public TIndexAndRankList {
public:
  short relationType;
  short pad16;

  TSortedPtrList();
  CRuntimeClass* GetRuntimeClass() const override;
  static TSortedPtrList* ConstructTSortedPtrListBaseState();
};

ASSERT_SIZE(TSortedPtrList, 0x18);
