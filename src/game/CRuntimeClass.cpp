#include "game/CRuntimeClass.h"

#include <windows.h>

#include "game/CArchive.h"

// MFC foundation code was compiled favor-size with frame-pointer omission.
#if defined(_MSC_VER)
#pragma optimize("ys", on)
#endif

// Serialize the class identity ahead of an object: schema word, then the
// length-prefixed class name. Called by CArchive::WriteClass the first time a
// given class is emitted into the archive.
// FUNCTION: IMPERIALISM 0x00611b7c
void CRuntimeClass::Store(CArchive* ar) {
  unsigned int len = lstrlenA(m_lpszClassName);
  ar->WriteWordToSerializedBuffer(static_cast<unsigned short>(m_wSchema))
      ->WriteWordToSerializedBuffer(static_cast<unsigned short>(len));
  ar->WriteBytesToSerializedBuffer(m_lpszClassName, static_cast<unsigned short>(len));
}

// FUNCTION: IMPERIALISM 0x00607077
int CRuntimeClass::IsDerivedFrom(const CRuntimeClass* pBaseClass) const {
  const CRuntimeClass* cur = this;
  while (cur != 0) {
    if (cur == pBaseClass) {
      return 1;
    }
    cur = cur->m_pBaseClass;
  }
  return 0;
}
