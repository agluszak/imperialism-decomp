#pragma once

#include "game/ui_core/TSortedList.h"

// CIterator (Mac name): a 12-byte cursor over a TSortedList (Reset/More/Advance).

class CIterator {
public:
  CIterator(TSortedList* list) : ownerList(list) {}

  void* Reset();
  int More();
  void* Advance();

  POSITION nextPosition;  // next CPtrList position to visit
  TSortedList* ownerList; // list wrapper
  void* current;          // payload of the current node
};
