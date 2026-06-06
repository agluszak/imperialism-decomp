#include "game/CArchive.h"

#include "game/CMapPtrToPtr.h"
#include "game/CObject.h"
#include "game/CRuntimeClass.h"
#include "game/CFile_Virtuals.h"
#include "game/generated/vcall_facades.h"

// MFC CArchive code was compiled favor-size in the original.
#if defined(_MSC_VER)
#pragma optimize("ys", on)
#endif

undefined4 Flush(void);
undefined4 CopyMemoryPossiblyOverlapping(void);
undefined4 MoveMemoryOverlapSafe(void);
undefined4 AfxThrowArchiveException(void);
undefined4 AfxThrowNotSupportedException(void);

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

inline void ThrowNotSupported() {
  reinterpret_cast<void(__cdecl*)()>(::AfxThrowNotSupportedException)();
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
  reinterpret_cast<CFile_Virtuals*>(m_pFile)->WriteBytesSlot40(const_cast<void*>(src), fullChunk);
  src = reinterpret_cast<const char*>(src) + fullChunk;
  nCount -= fullChunk;
  if (m_bDirect != 0) {
    reinterpret_cast<CFile_Virtuals*>(m_pFile)->GetBufferPtrSlot58(1, m_nBufSize, &m_lpBufStart, &m_lpBufMax);
    m_lpBufCur = m_lpBufStart;
  }
  CopyMemory(m_lpBufCur, src, nCount);
  m_lpBufCur += nCount;
}

// Polymorphic object serialization. The autogen models the write side under the
// provisional class name "TNetMgr" and the read side as a free "ReadObject", but
// both are thiscall methods on this archive class. Owned here as real members so
// callers dispatch through the vtable-free member ABI instead of a cast bridge.
// The object's own virtuals (GetRuntimeClass slot 0, Serialize slot +0x8) are
// called through a real CObject*, so the compiler caches the vtable in a register
// across both calls exactly like the original (no facade/edx indirection).
// Some helpers are still stubs (MapObject, WriteClass, ReadObject, NodeScanner::
// ReadClass, CreateObject, InsertAt ...).

// FUNCTION: IMPERIALISM 0x006121e1
void CArchive::WriteObject(void* objectRef) {
  MapObject(0);
  CObject* pOb = reinterpret_cast<CObject*>(objectRef);
  unsigned int nIndex;
  if (pOb == 0) {
    // NULL serializes as the reserved index 0.
    nIndex = 0;
  } else if ((nIndex = *reinterpret_cast<unsigned int*>(m_pStoreMap->GetOrCreateValueSlot(pOb))) != 0) {
    // Already serialized: fall through and emit its handle index below.
  } else {
    // First time this object is seen: emit its class, register a handle, then
    // serialize it.
    WriteClass(pOb->GetRuntimeClass());
    CheckCount();
    *reinterpret_cast<unsigned int*>(m_pStoreMap->GetOrCreateValueSlot(pOb)) = m_nMapCount;
    m_nMapCount = m_nMapCount + 1;
    pOb->Serialize(this);
    return;
  }

  // Write the tag: a 16-bit index, with a 0x7fff escape + 32-bit index for
  // values that do not fit.
  if (nIndex < 0x7fff) {
    WriteWordToSerializedBuffer(static_cast<unsigned short>(nIndex));
  } else {
    WriteWordToSerializedBuffer(0x7fff);
    WriteDwordToSerializedBuffer(nIndex);
  }
}

// FUNCTION: IMPERIALISM 0x0061225e
void* CArchive::ReadObject(void* runtimeClassOrFactory) {
  (void)runtimeClassOrFactory;
  // TODO(port): handle-map polymorphic read (NodeScanner::ReadClass + load array).
  return 0;
}

// FUNCTION: IMPERIALISM 0x00612315
void CArchive::MapObject(void* referenceNode) {
  (void)referenceNode;
  // TODO(port): SEH-framed lazy alloc of m_pStoreMap (write) / load CObArray
  // (read) and reference registration. Owned here so WriteObject links/pairs.
}

// FUNCTION: IMPERIALISM 0x0061240d
void CArchive::WriteClass(void* runtimeClass) {
  CRuntimeClass* pClassRef = reinterpret_cast<CRuntimeClass*>(runtimeClass);
  if (pClassRef->m_wSchema == 0xffff) {
    ThrowNotSupported();
  }
  MapObject(0);
  unsigned int nIndex =
      *reinterpret_cast<unsigned int*>(m_pStoreMap->GetOrCreateValueSlot(pClassRef));
  if (nIndex != 0) {
    // Already emitted: write its handle with the class tag bit set.
    if (nIndex < 0x7fff) {
      WriteWordToSerializedBuffer(static_cast<unsigned short>(nIndex | 0x8000));
    } else {
      WriteWordToSerializedBuffer(0x7fff);
      WriteDwordToSerializedBuffer(nIndex | 0x80000000);
    }
    return;
  }
  // First time: emit the new-class tag, store the class descriptor, register it.
  WriteWordToSerializedBuffer(0xffff);
  pClassRef->Store(this);
  CheckCount();
  *reinterpret_cast<unsigned int*>(m_pStoreMap->GetOrCreateValueSlot(pClassRef)) = m_nMapCount;
  m_nMapCount = m_nMapCount + 1;
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
        int got = reinterpret_cast<CFile_Virtuals*>(m_pFile)->ReadBytesSlot3C(dst, room);
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
      reinterpret_cast<CFile_Virtuals*>(m_pFile)->SeekSlot30(-static_cast<int>(avail), 1);
    }
    reinterpret_cast<CFile_Virtuals*>(m_pFile)->GetBufferPtrSlot58(0, m_nBufSize, &m_lpBufStart, &m_lpBufMax);
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
      int got = reinterpret_cast<CFile_Virtuals*>(m_pFile)->ReadBytesSlot3C(destination, room);
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
          int got = reinterpret_cast<CFile_Virtuals*>(m_pFile)->ReadBytesSlot3C(cur, want);
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
        reinterpret_cast<CFile_Virtuals*>(m_pFile)->GetBufferPtrSlot58(0, m_nBufSize, &m_lpBufStart, &m_lpBufMax);
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
