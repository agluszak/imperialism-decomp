#include "game/CIterator.h"

#pragma optimize("y", on) // omit frame pointer, as in the original bodies

namespace {

CPtrListNodeLink* GetEmbeddedListHead(TPtrList* owner) {
  // TPtrList: RefCountedObjectBase (+0) then CPtrList (+4); m_pNodeHead at CPtrList+4.
  return *reinterpret_cast<CPtrListNodeLink**>(reinterpret_cast<char*>(owner) + 8);
}

} // namespace

// FUNCTION: IMPERIALISM 0x00487ef0
void* CIterator::Reset() {
  CPtrListNodeLink* node = GetEmbeddedListHead(ownerList);
  nextNode = node;
  if (node != 0) {
    nextNode = node->pNext;
    current = node->data;
    return current;
  }
  nextNode = 0;
  current = 0;
  return 0;
}

// FUNCTION: IMPERIALISM 0x00487f20
int CIterator::More() {
  return current != 0;
}

// FUNCTION: IMPERIALISM 0x00487f40
void* CIterator::Advance() {
  CPtrListNodeLink* node = nextNode;
  if (node != 0) {
    nextNode = node->pNext;
    current = node->data;
    return current;
  }
  current = 0;
  return 0;
}
