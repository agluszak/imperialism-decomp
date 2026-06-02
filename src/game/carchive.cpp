#include "game/carchive.h"

// MFC CArchive code was compiled favor-size in the original.
#if defined(_MSC_VER)
#pragma optimize("ys", on)
#endif

undefined4 Flush(void);

namespace {

inline void FlushArchive(CArchive* archive) {
  reinterpret_cast<void(__fastcall*)(CArchive*)>(::Flush)(archive);
}

} // namespace

// FUNCTION: IMPERIALISM 0x005E6D04
CArchive* CArchive::WriteByteToSerializedBuffer(unsigned char value) {
  if (m_lpBufCur + 1 > m_lpBufMax) {
    FlushArchive(this);
  }
  *m_lpBufCur = value;
  ++m_lpBufCur;
  return this;
}

// FUNCTION: IMPERIALISM 0x005E6D27
CArchive* CArchive::WriteWordToSerializedBuffer(unsigned short value) {
  if (m_lpBufCur + 2 > m_lpBufMax) {
    FlushArchive(this);
  }
  *reinterpret_cast<unsigned short*>(m_lpBufCur) = value;
  m_lpBufCur += 2;
  return this;
}

// FUNCTION: IMPERIALISM 0x005E6D4E
CArchive* CArchive::WriteDwordToSerializedBuffer(unsigned int value) {
  if (m_lpBufCur + 4 > m_lpBufMax) {
    FlushArchive(this);
  }
  *reinterpret_cast<unsigned int*>(m_lpBufCur) = value;
  m_lpBufCur += 4;
  return this;
}
