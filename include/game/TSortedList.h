#pragma once

#include "game/TPtrList.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);

extern "C" char g_vtblTSortedList;

struct TSortedList : public TPtrList {
  TSortedList() {
    // RefCountedObjectBase() (base ctor) installs g_vtblRefCountedObjectBase
    // first, then the member list is constructed and the derived vtable is
    // installed.
    listState.CPtrList(10);
    vftable = reinterpret_cast<void*>(&g_vtblTSortedList);
  }
  void* operator new(unsigned int size) {
    return reinterpret_cast<void*>(AllocateWithFallbackHandler(size));
  }
  void operator delete(void* ptr) { (void)ptr; }

  static TSortedList* CreateTSortedListInstance();
  static void* GetTSortedListClassNamePointer();
};

typedef char TSortedListSizeMustMatch[(sizeof(TSortedList) == 0x20) ? 1 : -1];
