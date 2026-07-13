#include "game/CWMgrIterator.h"

// FUNCTION: IMPERIALISM 0x004923f0
void CWMgrIterator::Reset(unsigned char fForwardArg) {
  nextPosition = NULL;
  fForward = fForwardArg;
  current = 0;
}

// Arm the cursor on the head of the live-view registry: stash the head position, then read
// the first entry (advancing the position to the next node) or clear out when empty.
// FUNCTION: IMPERIALISM 0x00492440
void* CWMgrIterator::FirstWindow() {
  POSITION pos = g_LiveViewRegistry.GetHeadPosition();
  nextPosition = pos;
  if (pos == NULL) {
    current = 0;
    return 0;
  }
  current = g_LiveViewRegistry.GetNext(pos);
  nextPosition = pos;
  return current;
}

// FUNCTION: IMPERIALISM 0x00492470
void* CWMgrIterator::NextWindow() {
  POSITION pos = nextPosition;
  if (pos == NULL) {
    current = 0;
    return 0;
  }
  current = g_LiveViewRegistry.GetNext(pos);
  nextPosition = pos;
  return current;
}

// FUNCTION: IMPERIALISM 0x004924a0
int CWMgrIterator::More() {
  return current != 0;
}

// FUNCTION: IMPERIALISM 0x004924c0
int __stdcall PopSinglyLinkedListHeadPointer(int* head) {
  int* node = reinterpret_cast<int*>(*head);
  *head = *node;
  return reinterpret_cast<int>(node + 2);
}
