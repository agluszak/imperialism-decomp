#pragma once

#include "compat.h"

class TShip;

// Owned 16-byte link in a task force or navy mission's ship chain. Both chains
// refer to TShip objects owned by the global ship roster. Deleting a link does
// not delete its ship; the defeated-ship pruning path frees each ship explicitly.
class TMapOrderChildLinkNode {
public:
  TShip* payload;               // +0x00
  TMapOrderChildLinkNode* next; // +0x04
  TMapOrderChildLinkNode* prev; // +0x08
  unsigned char active;         // +0x0c
  unsigned char padding0D[3];

  // Some insertion paths fill the fields after allocation.
  // NOOP: verified empty in original 0x00553c25.
  TMapOrderChildLinkNode() {}

  // Fills the cell and splices it between two existing cells, marking it active.
  // Either neighbour may be null. 0x005524d0, __thiscall.
  void InitAndLinkBetween(TShip* child, TMapOrderChildLinkNode* prevNode,
                          TMapOrderChildLinkNode* nextNode);
  // Unlinks this cell from wherever it currently sits, then splices it between the
  // two given cells. Either may be null. 0x00552540, __thiscall.
  void RelinkBetween(TMapOrderChildLinkNode* prevNode, TMapOrderChildLinkNode* nextNode);
  // Chain a new link in front of nextNode. The pad bytes stay uninitialized.
  TMapOrderChildLinkNode(TShip* child, TMapOrderChildLinkNode* nextNode) {
    next = nextNode;
    payload = child;
    prev = 0;
    active = 1;
    if (nextNode != 0) {
      nextNode->prev = this;
    }
    if (prev != 0) {
      prev->next = this;
    }
  }

  // Real __thiscall method (0x552510, ECX=this cell, one stack arg, RET 4).
  // Null-safe on `this`; finds the first link for child.
  TMapOrderChildLinkNode* FindNodeMatching(TShip* child); // 0x552510

  // Real __thiscall method (0x536f70, ECX=this cell, one stack arg, RET 4).
  // Null-safe on `this`; sets `active` on `this` and every following cell in the
  // `next` chain. Pure cell operation; the payload is untouched.
  void SetChainActiveFlag(unsigned char flag); // 0x536f70

  // Unlinks `this` from its siblings, frees ONLY the cell, and returns the old
  // `next`. Does not touch the payload. 0x552590.
  TMapOrderChildLinkNode* DeleteMapOrderChildLinkAndReturnNext();
  // Null-safe on `this`; unlinks the first matching link and returns the new
  // head, leaving the ship alive. 0x5525d0.
  TMapOrderChildLinkNode* RemoveLinkedOrderNodeByValueRecursive(TShip* child);
  // Allocate a new head before this link (which may be null). 0x552650.
  TMapOrderChildLinkNode* CreateLinkedOrderNode(TShip* child);
  // Frees ships with nonpositive strength after clearing their task-force
  // back-links, then removes their link cells. Null-safe on `this`. 0x5526e0.
  TMapOrderChildLinkNode* PruneDefeatedMapOrderChildrenAndReturnHead();
};

ASSERT_SIZE(TMapOrderChildLinkNode, 0x10);
