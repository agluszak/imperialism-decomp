#pragma once

#include "game/TPtrList.h"

// Mac CodeWarrior evidence names this class CIterator (Reset/More/Advance).
// 12-byte stack cursor over a TPtrList-backed game list: walks the embedded
// CPtrList node chain directly (not POSITION iteration).
struct CPtrListNodeLink {
  CPtrListNodeLink* pNext;
  void* data;
};

class CIterator {
public:
  CIterator(TPtrList* list) : nextNode(0), ownerList(list), current(0) {}

  void* Reset();
  int More();
  void* Advance();

  CPtrListNodeLink* nextNode; // +0x00 — next CPtrList node to visit
  TPtrList* ownerList;        // +0x04 — list wrapper (CPtrList at +4)
  void* current;              // +0x08 — payload of the current node
};
