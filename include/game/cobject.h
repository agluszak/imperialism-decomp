#pragma once

#include "decomp_types.h"

// MFC CObject / RuntimeObjectBase — the 4-byte (vptr-only) root of the
// serialized-object hierarchy. Real vtable @ 0x0066fec4 has 5 slots:
//   slot0 GetRuntimeClass, slot1 (scalar-deleting) destructor, slot2..slot4.
// The non-trivial virtual destructor is what makes MSVC emit the EH frame and
// the base vptr-restore in derived destructors.

// VTABLE: IMPERIALISM 0x0066fec4
class CObject {
 public:
  virtual void* GetRuntimeClass();
  virtual ~CObject() {}
  virtual int CObjectSlot08();
  virtual void CObjectSlot0c();
  virtual void CObjectSlot10();
};
