#include "game/CArchive.h"

#include "game/generated/vcall_facades.h"

// MFC CArchive code was compiled favor-size in the original.
#if defined(_MSC_VER)
#pragma optimize("ys", on)
#endif

undefined4 Flush(void);
undefined4 CopyMemoryPossiblyOverlapping(void);

namespace {

inline void FlushArchive(CArchive* archive) {
  reinterpret_cast<void(__fastcall*)(CArchive*)>(::Flush)(archive);
}

inline void CopyMemory(void* dst, const void* src, int size) {
  reinterpret_cast<void(__cdecl*)(void*, const void*, int)>(::CopyMemoryPossiblyOverlapping)(
      dst, src, size);
}

} // namespace

// FUNCTION: IMPERIALISM 0x005e6d04
CArchive* CArchive::WriteByteToSerializedBuffer(unsigned char value) {
  if (m_lpBufCur + 1 > m_lpBufMax) {
    FlushArchive(this);
  }
  *m_lpBufCur = value;
  ++m_lpBufCur;
  return this;
}

// FUNCTION: IMPERIALISM 0x005e6d27
CArchive* CArchive::WriteWordToSerializedBuffer(unsigned short value) {
  if (m_lpBufCur + 2 > m_lpBufMax) {
    FlushArchive(this);
  }
  *reinterpret_cast<unsigned short*>(m_lpBufCur) = value;
  m_lpBufCur += 2;
  return this;
}

// FUNCTION: IMPERIALISM 0x005e6d4e
CArchive* CArchive::WriteDwordToSerializedBuffer(unsigned int value) {
  if (m_lpBufCur + 4 > m_lpBufMax) {
    FlushArchive(this);
  }
  *reinterpret_cast<unsigned int*>(m_lpBufCur) = value;
  m_lpBufCur += 4;
  return this;
}

// FUNCTION: IMPERIALISM 0x00611e34
void CArchive::WriteBytesToSerializedBuffer(const void* src, unsigned int nCount) {
  if (nCount == 0) {
    return;
  }
  unsigned int avail = static_cast<unsigned int>(m_lpBufMax - m_lpBufCur);
  unsigned int copyLen = (nCount < avail) ? nCount : avail;
  CopyMemory(m_lpBufCur, src, copyLen);
  m_lpBufCur += copyLen;
  src = reinterpret_cast<const char*>(src) + copyLen;
  nCount -= copyLen;
  if (nCount == 0) {
    return;
  }

  FlushArchive(this);
  unsigned int fullChunk = nCount - (nCount % m_nBufSize);
  VCall_CFile_WriteBytesSlot40(m_pFile, const_cast<void*>(src), fullChunk);
  src = reinterpret_cast<const char*>(src) + fullChunk;
  nCount -= fullChunk;
  if (m_bDirect != 0) {
    VCall_CFile_GetBufferPtrSlot58(m_pFile, 1, m_nBufSize, &m_lpBufStart, &m_lpBufMax);
    m_lpBufCur = m_lpBufStart;
  }
  CopyMemory(m_lpBufCur, src, nCount);
  m_lpBufCur += nCount;
}
