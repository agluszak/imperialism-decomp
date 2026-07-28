#include "game/ui_core/CWMgrIterator.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"
#include "game/globals/view_registries.h"

// FUNCTION: IMPERIALISM 0x004923f0
CWMgrIterator* CWMgrIterator::Reset(char fForwardArg) {
  // Returns this (original leaves this in eax at RET); the flag is a signed char stored
  // sign-extended into the int field (movsx), so the parameter is char, not unsigned char.
  nextPosition = NULL;
  fForward = fForwardArg;
  current = 0;
  return this;
}

// Arm the cursor on the head of the live-view registry: stash the head position, then read
// the first entry (advancing the position to the next node) or clear out when empty.
// FUNCTION: IMPERIALISM 0x00492440
void* CWMgrIterator::FirstWindow() {
  // Seed nextPosition directly in the field and let GetNext read-and-advance it (heuristic
  // 98) rather than caching in a local and re-storing.
  nextPosition = g_LiveViewRegistry.GetHeadPosition();
  if (nextPosition != NULL) {
    current = g_LiveViewRegistry.GetNext(nextPosition);
    return current;
  }
  current = 0;
  return 0;
}

// FUNCTION: IMPERIALISM 0x00492470
void* CWMgrIterator::NextWindow() {
  if (nextPosition != NULL) {
    current = g_LiveViewRegistry.GetNext(nextPosition);
    return current;
  }
  current = 0;
  return 0;
}

// FUNCTION: IMPERIALISM 0x004924a0
int CWMgrIterator::More() {
  return current != 0;
}
