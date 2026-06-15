#pragma once

#include "decomp_types.h"

#include "game/CDumpContext.h"

class CArchive;
struct CRuntimeClass;

// MFC CObject - the 4-byte (vptr-only) root of the serialized-object hierarchy.
// Vtable order is the canonical MFC layout, confirmed by CArchive::WriteObject
// (0x006121e1) calling slot 0 = GetRuntimeClass and slot +0x8 = Serialize.
// VTABLE: IMPERIALISM 0x0066fec4
class CObject {
public:
  virtual CRuntimeClass* GetRuntimeClass() const;
  virtual ~CObject() {}
  virtual void Serialize(CArchive& ar);
  virtual void AssertValid() const;
  virtual void Dump(CDumpContext& dc) const;

  int IsKindOf(const CRuntimeClass* pClass) const;
};

CObject* AfxDynamicDownCast(CRuntimeClass* pClass, CObject* pObject);
