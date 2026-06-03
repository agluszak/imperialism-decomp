#pragma once

#include "decomp_types.h"

struct CArchive;

// MFC CObject - the 4-byte (vptr-only) root of the serialized-object hierarchy.
// VTABLE: IMPERIALISM 0x0066fec4
// Vtable order is the canonical MFC layout, confirmed by CArchive::WriteObject
// (0x006121e1) calling slot 0 = GetRuntimeClass and slot +0x8 = Serialize.
class CObject {
 public:
  virtual void* GetRuntimeClass();
  virtual ~CObject();
  virtual void Serialize(CArchive* ar);
  virtual int AssertValidOrSlot0c();
  virtual void DumpOrSlot10();
};
