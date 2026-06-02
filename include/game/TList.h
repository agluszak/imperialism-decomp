#pragma once

#include "game/TPtrList.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);

extern "C" char g_vtblTList;

// VTABLE: IMPERIALISM 0x00648f78
struct TList : public TPtrList {
  TList() {
    vftable = reinterpret_cast<void*>(&g_vtblTList);
  }
  void* operator new(unsigned int size) {
    return reinterpret_cast<void*>(AllocateWithFallbackHandler(size));
  }
  void operator delete(void* ptr) { (void)ptr; }

  static TList* CreateTListInstance();
  static void* GetTListClassNamePointer();
};

typedef char TListSizeMustMatch[(sizeof(TList) == 0x20) ? 1 : -1];
