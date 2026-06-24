#include "game/TUiWindowTraversal.h"

// FUNCTION: IMPERIALISM 0x004923f0
void TUiWindowTraversal::Reset(char mode) {
  nextPosition = NULL;
  traversalMode = mode;
  current = 0;
}

// Arm the cursor on the head of the live-view registry: stash the head position, then read
// the first entry (advancing the position to the next node) or clear out when empty.
// FUNCTION: IMPERIALISM 0x00492440
void* TUiWindowTraversal::LoadFirst() {
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
void* TUiWindowTraversal::LoadNext() {
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
int TUiWindowTraversal::IsValid() {
  return current != 0;
}
