#include "game/ui_core/CWMgrIterator.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"
#include "game/globals/view_registries.h"

// FUNCTION: IMPERIALISM 0x004923f0
CWMgrIterator* CWMgrIterator::Reset(bool fForwardArg) {
  nextPosition = NULL;
  fForward = fForwardArg;
  current = 0;
  return this;
}

// FUNCTION: IMPERIALISM 0x00492440
void* CWMgrIterator::FirstWindow() {
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
