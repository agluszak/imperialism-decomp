#include "game/CIterator.h"

#include "game/TPtrList.h"

#pragma optimize("y", on) // omit frame pointer, as in the original bodies

// FUNCTION: IMPERIALISM 0x00487ef0
void* CIterator::Reset() {
  CPtrListNode* head = reinterpret_cast<TPtrList*>(ownerList)->listState.headNode;
  nextNode = head;
  if (head != 0) {
    nextNode = head->next;
    current = head->data;
    return current;
  }
  current = 0;
  return 0;
}

// FUNCTION: IMPERIALISM 0x00487f20
int CIterator::More() {
  return current != 0;
}

// FUNCTION: IMPERIALISM 0x00487f40
void* CIterator::Advance() {
  CPtrListNode* node = nextNode;
  if (node != 0) {
    nextNode = node->next;
    current = node->data;
    return current;
  }
  current = 0;
  return 0;
}
