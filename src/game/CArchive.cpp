#include "game/CArchive.h"

#include "game/generated/vcall_facades.h"

// MFC CArchive code was compiled favor-size in the original.
#if defined(_MSC_VER)
#pragma optimize("ys", on)
#endif

undefined4 Flush(void);
undefined4 CopyMemoryPossiblyOverlapping(void);
undefined4 MoveMemoryOverlapSafe(void);
undefined4 AfxThrowArchiveException(void);

namespace {

inline void FlushArchive(CArchive* archive) {
  reinterpret_cast<void(__fastcall*)(CArchive*)>(::Flush)(archive);
}

inline void CopyMemory(void* dst, const void* src, int size) {
  reinterpret_cast<void(__cdecl*)(void*, const void*, int)>(::CopyMemoryPossiblyOverlapping)(
      dst, src, size);
}

inline void MoveMemory(void* dst, const void* src, int size) {
  reinterpret_cast<void(__cdecl*)(void*, const void*, int)>(::MoveMemoryOverlapSafe)(dst, src, size);
}

inline void ThrowArchiveException(int errorCode, void* context) {
  reinterpret_cast<void(__stdcall*)(int, void*)>(::AfxThrowArchiveException)(errorCode, context);
}

} // namespace

extern "C" {
// MFC CRuntimeClass descriptor for the archive/net-manager class (0x0066f978).
char g_pClassDescTNetMgr = 0;
}

// FUNCTION: IMPERIALISM 0x005e33c0
void* GetTNetMgrClassNamePointer() {
  return &g_pClassDescTNetMgr;
}

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
  unsigned char* cur = m_lpBufCur;
  unsigned int copyLen = static_cast<unsigned int>(m_lpBufMax - cur);
  if (nCount < copyLen) {
    copyLen = nCount;
  }
  CopyMemory(cur, src, copyLen);
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

// Polymorphic object serialization. The autogen models the write side under the
// provisional class name "TNetMgr" and the read side as a free "ReadObject", but
// both are thiscall methods on this archive class. Owned here as real members so
// callers dispatch through the vtable-free member ABI instead of a cast bridge.
// Bodies are not yet ported (handle-map / class-token machinery: MapObject,
// WriteClass, CheckCount, NodeScanner::ReadClass, CreateObject, InsertAt ...).

// FUNCTION: IMPERIALISM 0x006121e1
void CArchive::WriteObject(void* objectRef) {
  (void)objectRef;
  // TODO(port): handle-map polymorphic write.
}

// FUNCTION: IMPERIALISM 0x0061225e
void* CArchive::ReadObject(void* runtimeClassOrFactory) {
  (void)runtimeClassOrFactory;
  // TODO(port): handle-map polymorphic read.
  return 0;
}

// Guards object-map counter growth; raises archive exception 5 once the counter
// reaches the safe ceiling. Used by the object serializer.
// FUNCTION: IMPERIALISM 0x006121cd
void CArchive::CheckCount() {
  if (m_nMapCount >= 0x3ffffffe) {
    ThrowArchiveException(5, m_pExceptionContext);
  }
}

// Flush the pending write buffer to the backing file, then detach the file so
// the archive can no longer be written through. (Ghidra named this
// "FlushSerializedArchiveBufferAndResetStreamCount"; the zeroed field at +0x20
// is m_pFile, not a count.)
// FUNCTION: IMPERIALISM 0x00611d18
void CArchive::Close() {
  FlushArchive(this);
  m_pFile = 0;
}

// FUNCTION: IMPERIALISM 0x00612000
void CArchive::WriteCount(unsigned int count) {
  if (count < 0xffff) {
    WriteWordToSerializedBuffer(static_cast<unsigned short>(count));
  } else {
    WriteWordToSerializedBuffer(0xffff);
    WriteDwordToSerializedBuffer(count);
  }
}

// FUNCTION: IMPERIALISM 0x00611f3e
void CArchive::FillBuffer(unsigned int requiredBytes) {
  unsigned int avail = static_cast<unsigned int>(m_lpBufMax - m_lpBufCur);
  unsigned int wanted = requiredBytes + avail;
  if (m_bDirect == 0) {
    unsigned char* dst = m_lpBufStart;
    if (dst < m_lpBufCur) {
      if (static_cast<int>(avail) > 0) {
        MoveMemory(dst, m_lpBufCur, static_cast<int>(avail));
        dst = m_lpBufStart;
        m_lpBufCur = dst;
        m_lpBufMax = dst + avail;
      }
      int room = m_nBufSize - static_cast<int>(avail);
      dst = dst + avail;
      do {
        int got = VCall_CFile_ReadBytesSlot3C(m_pFile, dst, room);
        avail += got;
        dst += got;
        room -= got;
        if (got == 0 || room == 0) {
          break;
        }
      } while (avail < requiredBytes);
      m_lpBufCur = m_lpBufStart;
      m_lpBufMax = m_lpBufStart + avail;
    }
  } else {
    if (avail != 0) {
      VCall_CFile_SeekSlot30(m_pFile, -static_cast<int>(avail), 1);
    }
    VCall_CFile_GetBufferPtrSlot58(m_pFile, 0, m_nBufSize, &m_lpBufStart, &m_lpBufMax);
    m_lpBufCur = m_lpBufStart;
  }
  if (static_cast<unsigned int>(m_lpBufMax - m_lpBufCur) < wanted) {
    ThrowArchiveException(3, 0);
  }
}

// FUNCTION: IMPERIALISM 0x005e6da3
CArchive* CArchive::ReadWordFromSerializedBuffer(void* outWord) {
  if (m_lpBufCur + 2 > m_lpBufMax) {
    FillBuffer(static_cast<unsigned int>(m_lpBufCur + 2 - m_lpBufMax));
  }
  *reinterpret_cast<unsigned short*>(outWord) = *reinterpret_cast<unsigned short*>(m_lpBufCur);
  m_lpBufCur += 2;
  return this;
}

// FUNCTION: IMPERIALISM 0x005e6dd6
CArchive* CArchive::ReadDwordFromSerializedBuffer(void* outDword) {
  if (m_lpBufCur + 4 > m_lpBufMax) {
    FillBuffer(static_cast<unsigned int>(m_lpBufCur + 4 - m_lpBufMax));
  }
  *reinterpret_cast<unsigned int*>(outDword) = *reinterpret_cast<unsigned int*>(m_lpBufCur);
  m_lpBufCur += 4;
  return this;
}

// FUNCTION: IMPERIALISM 0x00611d26
int CArchive::ReadBytesFromSerializedBuffer(void* destination, unsigned int requestedCount) {
  unsigned int remaining;
  if (requestedCount == 0) {
    return 0;
  }

  unsigned int fromBuffer = static_cast<unsigned int>(m_lpBufMax - m_lpBufCur);
  if (requestedCount < fromBuffer) {
    fromBuffer = requestedCount;
  }
  CopyMemory(destination, m_lpBufCur, fromBuffer);
  m_lpBufCur += fromBuffer;
  destination = reinterpret_cast<char*>(destination) + fromBuffer;
  remaining = requestedCount - fromBuffer;
  if (remaining != 0) {
    int fullChunk = remaining - remaining % m_nBufSize;
    int directDone = 0;
    int room = fullChunk;
    do {
      int got = VCall_CFile_ReadBytesSlot3C(m_pFile, destination, room);
      destination = reinterpret_cast<char*>(destination) + got;
      directDone += got;
      room -= got;
      if (got == 0) {
        break;
      }
    } while (room != 0);
    remaining -= directDone;
    if (directDone == fullChunk) {
      if (m_bDirect == 0) {
        unsigned int want = remaining;
        if (want <= static_cast<unsigned int>(m_nBufSize)) {
          want = m_nBufSize;
        }
        unsigned char* cur = m_lpBufStart;
        unsigned int filled = 0;
        do {
          int got = VCall_CFile_ReadBytesSlot3C(m_pFile, cur, want);
          cur += got;
          want -= got;
          filled += got;
          if (got == 0 || want == 0) {
            break;
          }
        } while (filled < remaining);
        m_lpBufCur = m_lpBufStart;
        m_lpBufMax = m_lpBufStart + filled;
      } else {
        VCall_CFile_GetBufferPtrSlot58(m_pFile, 0, m_nBufSize, &m_lpBufStart, &m_lpBufMax);
        m_lpBufCur = m_lpBufStart;
      }
      unsigned int chunk = static_cast<unsigned int>(m_lpBufMax - m_lpBufCur);
      if (remaining < chunk) {
        chunk = remaining;
      }
      CopyMemory(destination, m_lpBufStart, chunk);
      m_lpBufCur += chunk;
      remaining -= chunk;
    }
  }
  return requestedCount - remaining;
}
