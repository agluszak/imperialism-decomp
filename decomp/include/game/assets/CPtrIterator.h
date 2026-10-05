#pragma once

#include "decomp_types.h"

class TSortedPtrList;

class CPtrIterator {
public:
  int nextIndex;
  TSortedPtrList* list;

  void* FirstPtr();
  int More();
  void* NextPtr();
};

ASSERT_SIZE(CPtrIterator, 0x8);
