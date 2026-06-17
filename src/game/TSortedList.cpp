#include "game/TSortedList.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

extern "C" {
CRuntimeClass g_pClassDescTSortedList = {nullptr, 0, 0, nullptr, nullptr};
}

// FUNCTION: IMPERIALISM 0x00487a90
TSortedList* TSortedList::CreateTSortedListInstance() {
  return new TSortedList();
}

// FUNCTION: IMPERIALISM 0x00487b10
CRuntimeClass* TSortedList::GetRuntimeClass() const {
  return &g_pClassDescTSortedList;
}

// Destructor is compiler-generated (implicit) from real TPtrList inheritance.
// SYNTHETIC: IMPERIALISM 0x004888f0
// TSortedList::`scalar deleting destructor'

#if defined(_MSC_VER)
#pragma optimize("", on)
#endif
