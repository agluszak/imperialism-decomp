#pragma once

#include "game/TSortedList.h"

// Mac CodeWarrior evidence names this class CIterator (Reset/More/Advance).
// 12-byte stack cursor over a TSortedList-backed game list.

class CIterator {
public:
  // The original ctor initializes ONLY ownerList (verified at 0x59f890, 0x5a53e0:
  // construction is a single store; Reset() seeds nextPosition/current before use).
  CIterator(TSortedList* list) : ownerList(list) {}

  void* Reset();
  int More();
  void* Advance();

  POSITION nextPosition;  // +0x00 - next CPtrList position to visit
  TSortedList* ownerList; // +0x04 - list wrapper
  void* current;          // +0x08 - payload of the current node
};
