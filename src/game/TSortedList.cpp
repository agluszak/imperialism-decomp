#include "game/TSortedList.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

extern "C" {
char g_pClassDescTSortedList = 0;
}

int AllocateWithFallbackHandler(undefined4 size_bytes);

namespace {

const unsigned int kAddrVtblRefCountedObjectBase = 0x006485C0;
const unsigned int kAddrVtblTSortedList = 0x00648EE0;

} // namespace

// FUNCTION: IMPERIALISM 0x00487A90
TSortedList* TSortedList::CreateTSortedListInstance() {
  TSortedList* list = reinterpret_cast<TSortedList*>(AllocateWithFallbackHandler(0x20));
  if (list != 0) {
    list->vftable = reinterpret_cast<void*>(kAddrVtblRefCountedObjectBase);
    list->listState.CPtrList(10);
    list->vftable = reinterpret_cast<void*>(kAddrVtblTSortedList);
  }
  return list;
}

// FUNCTION: IMPERIALISM 0x00487B10
void* TSortedList::GetTSortedListClassNamePointer() {
  return &g_pClassDescTSortedList;
}
