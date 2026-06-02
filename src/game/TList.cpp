#include "game/TList.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

extern "C" {
char g_pClassDescTList = 0;
char g_vtblTList = 0;
}

// FUNCTION: IMPERIALISM 0x00487E50
TList* TList::CreateTListInstance() {
  return new TList();
}

// FUNCTION: IMPERIALISM 0x00487ED0
void* TList::GetTListClassNamePointer() {
  return &g_pClassDescTList;
}
