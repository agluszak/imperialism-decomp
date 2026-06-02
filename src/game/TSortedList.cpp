#include "game/TSortedList.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

extern "C" {
char g_pClassDescTSortedList = 0;
char g_vtblTSortedList = 0;
}

// FUNCTION: IMPERIALISM 0x00487A90
TSortedList* TSortedList::CreateTSortedListInstance() {
  return new TSortedList();
}

// FUNCTION: IMPERIALISM 0x00487B10
void* TSortedList::GetTSortedListClassNamePointer() {
  return &g_pClassDescTSortedList;
}
