#pragma once

#include "decomp_types.h"

// MFC CObject - the 4-byte (vptr-only) root of the serialized-object hierarchy.
// VTABLE: IMPERIALISM 0x0066fec4
class CObject {
 public:
  virtual void* GetRuntimeClass();
  virtual ~CObject();
  virtual int AssertValidOrSlot08();
  virtual void DumpOrSlot0c();
  virtual void SerializeOrSlot10();
};
