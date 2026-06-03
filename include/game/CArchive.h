#pragma once

#include "decomp_types.h"

// MFC CArchive serialization buffer: a write cursor (m_lpBufCur at +0x24) into
// a buffer whose end is m_lpBufMax (+0x28). The insertion operators flush when
// the next write would overrun the buffer, then append and advance.
struct CArchive {
  char pad_00[0x08];
  int m_bDirect;
  char pad_0c[0x10];
  int m_nBufSize;
  void* m_pFile;
  unsigned char* m_lpBufCur;
  unsigned char* m_lpBufMax;
  unsigned char* m_lpBufStart;

  CArchive* WriteByteToSerializedBuffer(unsigned char value);
  CArchive* WriteWordToSerializedBuffer(unsigned short value);
  CArchive* WriteDwordToSerializedBuffer(unsigned int value);
  void WriteBytesToSerializedBuffer(const void* src, unsigned int nCount);

  // Read side (symmetric to the write cursor): refill the buffer from the
  // backing CFile when the cursor would underrun, then extract and advance.
  void FillBuffer(unsigned int requiredBytes);
  CArchive* ReadWordFromSerializedBuffer(void* outWord);
  CArchive* ReadDwordFromSerializedBuffer(void* outDword);
  int ReadBytesFromSerializedBuffer(void* destination, unsigned int requestedCount);

  // Polymorphic object serialization (the autogen models these under the
  // provisional class name "TNetMgr" / a free "ReadObject"; they belong to this
  // same archive class). Bodies are still stub-owned; declared here so callers
  // link against the 0x006121e1 / 0x0061225e addresses by name.
  void WriteObject(void* objectRef);
  void* ReadObject(void* runtimeClassOrFactory);
};
