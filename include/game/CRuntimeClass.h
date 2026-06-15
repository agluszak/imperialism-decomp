#pragma once

#include "compat.h"
#include "decomp_types.h"

class CArchive;
class CObject;

struct CRuntimeClass {
  const char* m_lpszClassName;
  int m_nObjectSize;
  unsigned int m_wSchema;
  CObject* (*m_pfnCreateObject)();
  CRuntimeClass* m_pBaseClass;

  void Store(CArchive& ar) const;
  int IsDerivedFrom(const CRuntimeClass* pBaseClass) const;
};
