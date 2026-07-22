#pragma once

#include "decomp_types.h"

class TSortedPtrList;

// Mac oracle: CPtrIterator. The iterator keeps the next one-based list index and
// the pointer-list being traversed; FirstPtr returns entry 1 and seeds NextPtr at 2.
class CPtrIterator {
public:
  int nextIndex;
  TSortedPtrList* list;

  void* FirstPtr();
  int More();
  void* NextPtr();
};

ASSERT_SIZE(CPtrIterator, 0x8);
