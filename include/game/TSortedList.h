#pragma once

#include "compat.h"
#include "game/TPtrList.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);

extern "C" char g_vtblTSortedList;

// Sorted game list leaf sharing the TPtrList storage layout. Mac CodeWarrior
// names this as TSortedList, but Windows vtable membership is grounded by the
// constructor write to 0x00648ee0.
// VTABLE: IMPERIALISM 0x00648ee0
struct TSortedList : public TPtrList {
  TSortedList() {
    vftable = reinterpret_cast<void*>(&g_vtblTSortedList);
  }
  void* operator new(unsigned int size) {
    return reinterpret_cast<void*>(AllocateWithFallbackHandler(size));
  }
  void operator delete(void* ptr) {
    (void)ptr;
  }

  static TSortedList* CreateTSortedListInstance();
  static void* GetTSortedListClassNamePointer();
};

ASSERT_SIZE(TSortedList, 0x20);
