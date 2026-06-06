#pragma once

#include "decomp_types.h"

extern "C" char g_vtblRefCountedObjectBase;

// Game object root used by the TPtrList/TList wrapper family. This is distinct
// from MFC CObject: list wrappers store this vfptr at +0 and embed the MFC
// CPtrList engine at +4.
// VTABLE: IMPERIALISM 0x006485c0
struct RefCountedObjectBase {
  void* vftable;

  RefCountedObjectBase() {
    vftable = reinterpret_cast<void*>(&g_vtblRefCountedObjectBase);
  }
  ~RefCountedObjectBase() {}
};
