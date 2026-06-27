#pragma once

#include "game/TSortedList.h"

// Mac CodeWarrior evidence names this class CIterator (Reset/More/Advance).
// 12-byte stack cursor over a TSortedList-backed game list.

class CIterator {
public:
  CIterator(TSortedList* list) : nextPosition(NULL), ownerList(list), current(0) {}

  void* Reset();
  int More();
  void* Advance();

  POSITION nextPosition; // +0x00 - next CPtrList position to visit
  TSortedList* ownerList; // +0x04 - list wrapper
  void* current;          // +0x08 - payload of the current node
};
