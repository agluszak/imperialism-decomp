#include "game/ApplicationUiRootEmbeddedList.h"

extern "C" char g_pClassDescTBehavior;

// FUNCTION: IMPERIALISM 0x004871c0
void* ApplicationUiRootEmbeddedList::GetCObjectRuntimeClass() {
  return &g_pClassDescTBehavior;
}

ApplicationUiRootEmbeddedList::ApplicationUiRootEmbeddedList()
    : head(0), field08(0), field0c(0), field10(0), field14(0), blockSize(10) {}
