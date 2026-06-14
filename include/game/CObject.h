#pragma once

#include "decomp_types.h"

struct CArchive;
struct CRuntimeClass;

// MFC CObject - the 4-byte (vptr-only) root of the serialized-object hierarchy.
// Vtable order is the canonical MFC layout, confirmed by CArchive::WriteObject
// (0x006121e1) calling slot 0 = GetRuntimeClass and slot +0x8 = Serialize.
// VTABLE: IMPERIALISM 0x0066fec4
class CObject {
public:
  virtual CRuntimeClass* GetRuntimeClass();
  virtual ~CObject() {}
  virtual void Serialize(CArchive* ar);
  virtual void AssertValidOrSlot0c();
  virtual void DumpOrSlot10(int unused = 0);

  int IsKindOf(const CRuntimeClass* pClass);
};

CObject* AfxDynamicDownCast(CRuntimeClass* pClass, CObject* pObject);
