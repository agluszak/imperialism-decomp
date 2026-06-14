#pragma once

#include "compat.h"
#include "decomp_types.h"

struct CArchive;
class CObject;

// MFC CRuntimeClass - the per-class RTTI/serialization descriptor. No vtable;
// a plain record. Trailing MFC members (m_pNextClass, ...) remain unmodeled.
struct CRuntimeClass {
  const char* m_lpszClassName; // +0x00
  int m_nObjectSize;           // +0x04
  // 0xFFFF marks a class that opted out of serialization (WriteClass throws).
  unsigned int m_wSchema; // +0x08
  CObject* (*m_pfnCreateObject)(); // +0x0c
  CRuntimeClass* m_pBaseClass;     // +0x10

  // Write this class's schema, name length, and name into the archive.
  void Store(CArchive* ar);

  // Walks the m_pBaseClass chain; returns 1 if pBaseClass appears in the ancestry.
  int IsDerivedFrom(const CRuntimeClass* pBaseClass) const;
};
