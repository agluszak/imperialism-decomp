// TOverlayQuadRecordArray -- the UMapper overlay subsystem's growable 0x10-byte-record array.

#include "game/TOverlayQuadRecordArray.h"

#include "decomp_types.h"

// Allocator-tracked realloc (generic stub form; typed cast at the call sites).
extern undefined4 ReallocateHeapBlockWithAllocatorTracking(void);

namespace {

inline OverlayQuadRecord* ReallocRecords(OverlayQuadRecord* buffer, int bytes) {
  return reinterpret_cast<OverlayQuadRecord*>(reinterpret_cast<void*(__cdecl*)(void*, int)>(
      ReallocateHeapBlockWithAllocatorTracking)(buffer, bytes));
}

} // namespace

// FUNCTION: IMPERIALISM 0x0052d0d0
void TOverlayQuadRecordArray::ReserveCapacity(unsigned int newCount) {
  unsigned int newCapacity = newCount * 2;
  if (newCapacity > 0x7fffffff) {
    newCapacity = 0x7fffffff;
  }
  OverlayQuadRecord* grown = ReallocRecords(buffer, newCount << 5);
  if (grown == nullptr) {
    buffer = ReallocRecords(buffer, newCount << 4);
    capacity = newCount;
    return;
  }
  buffer = grown;
  capacity = newCapacity;
}

// FUNCTION: IMPERIALISM 0x0052d150
OverlayQuadRecord* TOverlayQuadRecordArray::GetOrCreateEntry(unsigned int index) {
  if (capacity <= index) {
    int want = index + 1;
    unsigned int newCapacity = want * 2;
    if (newCapacity > 0x7fffffff) {
      newCapacity = 0x7fffffff;
    }
    OverlayQuadRecord* grown = ReallocRecords(buffer, want * 0x20);
    if (grown == nullptr) {
      buffer = ReallocRecords(buffer, want * 0x10);
      capacity = want;
    } else {
      buffer = grown;
      capacity = newCapacity;
    }
  }
  if (count <= index) {
    count = index + 1;
  }
  return &buffer[index];
}
