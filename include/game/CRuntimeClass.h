#pragma once

#include "decomp_types.h"

struct CArchive;

// MFC CRuntimeClass - the per-class RTTI/serialization descriptor. No vtable;
// a plain record. Only the fields needed by the archive serializer are modeled
// so far; the trailing MFC members (m_pfnCreateObject, m_pBaseClass,
// m_pNextClass, ...) are left unmodeled.
struct CRuntimeClass {
  const char* m_lpszClassName;  // +0x00
  int m_nObjectSize;            // +0x04
  // 0xFFFF marks a class that opted out of serialization (WriteClass throws).
  unsigned int m_wSchema;       // +0x08

  // Write this class's schema, name length, and name into the archive.
  void Store(CArchive* ar);
};
