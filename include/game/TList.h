#pragma once

#include "compat.h"
#include "game/TPtrList.h"
#include "game/TListObject.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);

// Concrete game list leaf: RefCountedObjectBase vfptr at +0, CPtrList state at
// +4 through TPtrList, and the TList virtual interface described by TListObject.
// VTABLE: IMPERIALISM 0x00648f78
struct TList : public TPtrList {
  virtual void VMethod01() {}
  TList() {}
  void* operator new(unsigned int size) {
    return reinterpret_cast<void*>(AllocateWithFallbackHandler(size));
  }
  void operator delete(void* ptr) {
    (void)ptr;
  }

  static TList* CreateTListInstance();
  static void* GetTListClassNamePointer();
};

ASSERT_SIZE(TList, 0x20);
