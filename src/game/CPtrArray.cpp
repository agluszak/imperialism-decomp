#include "game/CPtrArray.h"

#if defined(_MSC_VER)
#pragma optimize("ys", on)
#endif

void FreeHeapBufferIfNotNull(undefined4 ptrValue);
int AllocateWithFallbackHandler(undefined4 size_bytes);
undefined4 memset(void);
undefined4 CopyMemoryPossiblyOverlapping(void);
undefined4 MoveMemoryOverlapSafe(void);

namespace {

inline void FillMemory(void* dst, int value, int size) {
  reinterpret_cast<void(__cdecl*)(void*, int, int)>(::memset)(dst, value, size);
}

inline void CopyMemory(void* dst, const void* src, int size) {
  reinterpret_cast<void(__cdecl*)(void*, const void*, int)>(::CopyMemoryPossiblyOverlapping)(
      dst, src, size);
}

inline void MoveMemory(void* dst, const void* src, int size) {
  reinterpret_cast<void(__cdecl*)(void*, const void*, int)>(::MoveMemoryOverlapSafe)(dst, src, size);
}

} // namespace

CPtrArray::~CPtrArray() {
  if (this->entries != 0) {
    FreeHeapBufferIfNotNull(static_cast<undefined4>(reinterpret_cast<unsigned int>(this->entries)));
  }
}

// FUNCTION: IMPERIALISM 0x00601c14
void CPtrArray::SetSize(int nNewSize, int nGrowBy) {
  if (nGrowBy != -1) {
    this->growBy = nGrowBy;
  }
  if (nNewSize == 0) {
    FreeHeapBufferIfNotNull(static_cast<undefined4>(reinterpret_cast<unsigned int>(this->entries)));
    this->entries = 0;
    this->capacity = 0;
    this->count = 0;
  } else if (this->entries == 0) {
    this->entries = reinterpret_cast<void**>(AllocateWithFallbackHandler(nNewSize * 4));
    FillMemory(this->entries, 0, nNewSize * 4);
    this->capacity = nNewSize;
    this->count = nNewSize;
  } else if (nNewSize <= this->capacity) {
    if (nNewSize > this->count) {
      FillMemory(&this->entries[this->count], 0, (nNewSize - this->count) * 4);
    }
    this->count = nNewSize;
  } else {
    int grow = this->growBy;
    if (grow == 0) {
      grow = this->count / 8;
      grow = (grow < 4) ? 4 : ((grow > 1024) ? 1024 : grow);
    }
    int newMax;
    if (nNewSize < this->capacity + grow) {
      newMax = this->capacity + grow;
    } else {
      newMax = nNewSize;
    }
    void** newData = reinterpret_cast<void**>(AllocateWithFallbackHandler(newMax * 4));
    CopyMemory(newData, this->entries, this->count * 4);
    FillMemory(&newData[this->count], 0, (nNewSize - this->count) * 4);
    FreeHeapBufferIfNotNull(static_cast<undefined4>(reinterpret_cast<unsigned int>(this->entries)));
    this->entries = newData;
    this->count = nNewSize;
    this->capacity = newMax;
  }
}

// FUNCTION: IMPERIALISM 0x00601de3
void CPtrArray::SetAtGrow(int nIndex, void* newElement) {
  if (nIndex >= this->count) {
    this->SetSize(nIndex + 1, -1);
  }
  this->entries[nIndex] = newElement;
}

// FUNCTION: IMPERIALISM 0x00601e0a
void CPtrArray::InsertAt(int nIndex, void* newElement, int nCount) {
  if (nIndex >= this->count) {
    this->SetSize(nIndex + nCount, -1);
  } else {
    int nOldSize = this->count;
    this->SetSize(this->count + nCount, -1);
    MoveMemory(&this->entries[nIndex + nCount], &this->entries[nIndex],
               (nOldSize - nIndex) * 4);
    FillMemory(&this->entries[nIndex], 0, nCount * 4);
  }
  while (nCount-- != 0) {
    this->entries[nIndex++] = newElement;
  }
}

// FUNCTION: IMPERIALISM 0x00601e9f
void CPtrArray::RemoveAt(int nIndex, int nCount) {
  int nMoveCount = this->count - nIndex - nCount;
  if (nMoveCount != 0) {
    CopyMemory(&this->entries[nIndex], &this->entries[nIndex + nCount], nMoveCount * 4);
  }
  this->count -= nCount;
}
