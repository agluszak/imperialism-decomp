#include "game/TList.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

extern "C" {
CRuntimeClass g_pClassDescTList = {nullptr, 0, 0, nullptr, nullptr};
}

// FUNCTION: IMPERIALISM 0x00487e50
TList* TList::CreateTListInstance() {
  return new TList();
}

// FUNCTION: IMPERIALISM 0x00487ed0
CRuntimeClass* TList::GetRuntimeClass() const {
  return &g_pClassDescTList;
}

// Destructor is compiler-generated (implicit) from real TPtrList inheritance.
// SYNTHETIC: IMPERIALISM 0x00488870
// TList::`scalar deleting destructor'

#if defined(_MSC_VER)
#pragma optimize("", on)
#endif
