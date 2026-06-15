#pragma once

#include "game/CPtrList.h"
#include "game/TPtrList.h"

// Mac CodeWarrior evidence names this class CIterator (Reset/More/Advance).
// 12-byte stack cursor over a TPtrList-backed game list: the inline constructor
// stores only the owner list; Reset/More/Advance walk the CPtrList node chain
// and cache the current payload.
class CIterator {
public:
  CIterator(TPtrList* list) : ownerList(list) {}

  void* Reset();
  int More();
  void* Advance();

  POSITION nextPos;  // +0x00 — list position to visit next
  TPtrList* ownerList; // +0x04 — list wrapper (CPtrList state at +4)
  void* current;     // +0x08 — payload of the current node
};
