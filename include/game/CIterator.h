#pragma once

#include "game/CPtrList.h"

class TListObject;

// Mac CodeWarrior evidence names this class CIterator (Reset/More/Advance).
// 12-byte stack cursor over a TPtrList-backed game list: the inline constructor
// stores only the owner list; Reset/More/Advance walk the CPtrList node chain
// and cache the current payload.
class CIterator {
public:
  CIterator(TListObject* list) : ownerList(list) {}

  void* Reset();
  int More();
  void* Advance();

  CPtrListNode* nextNode; // +0x00 — node to visit next
  TListObject* ownerList; // +0x04 — TPtrList-layout list (CPtrList state at +4)
  void* current;          // +0x08 — payload of the current node
};
