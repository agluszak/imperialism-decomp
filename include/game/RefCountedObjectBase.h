#pragma once

#include "decomp_types.h"

extern "C" char g_vtblRefCountedObjectBase;

// VTABLE: IMPERIALISM 0x006485c0
struct RefCountedObjectBase {
  void* vftable;

  RefCountedObjectBase() {
    vftable = reinterpret_cast<void*>(&g_vtblRefCountedObjectBase);
  }
  ~RefCountedObjectBase() {}
};
