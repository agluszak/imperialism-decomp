#include "game/navy/TMapOrderChildLinkNode.h"

#include "game/navy/TShip.h"
#include "game/globals/prelude.h"
#include "game/globals/navy_globals.h"
#include "game/globals/shared_globals.h"
#include "game/gfx/ui_invalidation_guard.h"

// FUNCTION: IMPERIALISM 0x00536f70
void TMapOrderChildLinkNode::SetChainActiveFlag(unsigned char flag) {
  for (TMapOrderChildLinkNode* node = this; node != nullptr; node = node->next) {
    node->active = flag;
  }
}

// FUNCTION: IMPERIALISM 0x00552510
TMapOrderChildLinkNode* TMapOrderChildLinkNode::FindNodeMatching(TObject* child_node) {
  if (this == 0) {
    return 0;
  }
  TMapOrderChildLinkNode* node = this;
  while (node->payload != child_node) {
    node = node->next;
    if (node == 0) {
      return 0;
    }
  }
  return node;
}

// FUNCTION: IMPERIALISM 0x00552590
TMapOrderChildLinkNode* TMapOrderChildLinkNode::DeleteMapOrderChildLinkAndReturnNext() {
  TMapOrderChildLinkNode* next_node = this->next;
  if (next_node != 0) {
    next_node->prev = this->prev;
  }
  if (this->prev != 0) {
    this->prev->next = this->next;
  }

  delete this;
  return next_node;
}

// FUNCTION: IMPERIALISM 0x005525d0
TMapOrderChildLinkNode*
TMapOrderChildLinkNode::RemoveLinkedOrderNodeByValueRecursive(TObject* child_node) {
  if (this == 0) {
    return 0;
  }

  if (child_node == this->payload) {
    TMapOrderChildLinkNode* next_node = this->next;
    if (next_node != 0) {
      next_node->prev = this->prev;
    }
    if (this->prev != 0) {
      this->prev->next = this->next;
    }
    delete this;
    return next_node;
  }

  this->next->RemoveLinkedOrderNodeByValueRecursive(child_node);
  return this;
}

// FUNCTION: IMPERIALISM 0x00552650
TMapOrderChildLinkNode* TMapOrderChildLinkNode::CreateLinkedOrderNode(TObject* child_node) {
  TMapOrderChildLinkNode* new_node = new TMapOrderChildLinkNode(child_node, this);
  if (new_node == 0) {
    FailNilPointerWithAssert(s_SourcePathUNavy_006983C8, 0x64e);
  }
  return new_node;
}

// FUNCTION: IMPERIALISM 0x005526e0
TMapOrderChildLinkNode* TMapOrderChildLinkNode::PruneDefeatedMapOrderChildrenAndReturnHead() {
  TMapOrderChildLinkNode* head = this;
  while (head != 0) {
    TShip* child_node = static_cast<TShip*>(head->payload);
    unsigned char headDefeated = (child_node->strength <= 0);
    if (headDefeated != 0) {
      child_node->taskForce = 0;
      static_cast<TShip*>(head->payload)->Free();

      // Manual unlink (the original inlines the DeleteMapOrderChildLinkAndReturnNext
      // steps here rather than calling 0x552590).
      TMapOrderChildLinkNode* next_node = head->next;
      if (next_node != 0) {
        next_node->prev = head->prev;
      }
      if (head->prev != 0) {
        head->prev->next = head->next;
      }
      delete head;
      head = next_node;
    } else {
      // Surviving head: recursively prune the tail (nodes unlink themselves, so
      // the head stays valid) and return it.
      head->next->PruneDefeatedMapOrderChildrenAndReturnHead();
      return head;
    }
  }
  return 0;
}
