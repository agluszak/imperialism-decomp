#pragma once

#include "compat.h"

class TShip;

class TMapOrderChildLinkNode {
public:
  TShip* payload;               // +0x00
  TMapOrderChildLinkNode* next; // +0x04
  TMapOrderChildLinkNode* prev; // +0x08
  unsigned char active;         // +0x0c
  unsigned char padding0D[3];

  // NOOP: verified empty in original 0x00553c25
  TMapOrderChildLinkNode() {}

  void InitAndLinkBetween(TShip* child, TMapOrderChildLinkNode* prevNode,
                          TMapOrderChildLinkNode* nextNode);
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

  TMapOrderChildLinkNode* FindNodeMatching(TShip* child); // 0x552510

  void SetChainActiveFlag(unsigned char flag); // 0x536f70

  TMapOrderChildLinkNode* DeleteMapOrderChildLinkAndReturnNext();
  TMapOrderChildLinkNode* RemoveLinkedOrderNodeByValueRecursive(TShip* child);
  // Allocate a new head before this link (which may be null).
  TMapOrderChildLinkNode* CreateLinkedOrderNode(TShip* child);
  TMapOrderChildLinkNode* PruneDefeatedMapOrderChildrenAndReturnHead();
};

ASSERT_SIZE(TMapOrderChildLinkNode, 0x10);
