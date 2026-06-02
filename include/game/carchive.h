#pragma once

#include "decomp_types.h"

// MFC CArchive serialization buffer: a write cursor (m_lpBufCur at +0x24) into
// a buffer whose end is m_lpBufMax (+0x28). The insertion operators flush when
// the next write would overrun the buffer, then append and advance.
struct CArchive {
  char pad_00[0x24];
  unsigned char* m_lpBufCur;
  unsigned char* m_lpBufMax;

  CArchive* WriteByteToSerializedBuffer(unsigned char value);
  CArchive* WriteWordToSerializedBuffer(unsigned short value);
  CArchive* WriteDwordToSerializedBuffer(unsigned int value);
};
