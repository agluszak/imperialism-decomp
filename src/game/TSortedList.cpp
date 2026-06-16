#include "game/TSortedList.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

extern "C" {
char g_pClassDescTSortedList = 0;
}

// FUNCTION: IMPERIALISM 0x00487a90
TSortedList* TSortedList::CreateTSortedListInstance() {
  return new TSortedList();
}

// FUNCTION: IMPERIALISM 0x00487b10
void* TSortedList::GetTSortedListClassNamePointer() {
  return &g_pClassDescTSortedList;
}

CRuntimeClass* TSortedList::GetRuntimeClass() const {
  return reinterpret_cast<CRuntimeClass*>(GetTSortedListClassNamePointer());
}
