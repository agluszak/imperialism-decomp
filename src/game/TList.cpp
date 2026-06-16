#include "game/TList.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

extern "C" {
char g_pClassDescTList = 0;
}

// FUNCTION: IMPERIALISM 0x00487e50
TList* TList::CreateTListInstance() {
  return new TList();
}

// FUNCTION: IMPERIALISM 0x00487ed0
void* TList::GetTListClassNamePointer() {
  return &g_pClassDescTList;
}

CRuntimeClass* TList::GetRuntimeClass() const {
  return reinterpret_cast<CRuntimeClass*>(GetTListClassNamePointer());
}
