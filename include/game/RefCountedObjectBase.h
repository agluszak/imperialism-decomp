#pragma once

#include "decomp_types.h"

extern "C" char g_vtblRefCountedObjectBase;

// MFC CObject-style reference-counted base. The constructor installs the base
// vtable (matches InitializeRefCountedObjectBaseVtable at 0x00484970), and the
// non-trivial destructor is what makes MSVC emit the EH state machine for
// `new`-with-throwing-member-construction factories such as
// TSortedList::CreateTSortedListInstance (0x00487A90).
struct RefCountedObjectBase {
  void* vftable;

  RefCountedObjectBase() {
    vftable = reinterpret_cast<void*>(&g_vtblRefCountedObjectBase);
  }
  ~RefCountedObjectBase() {}
};
