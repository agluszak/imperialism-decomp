// TOverlaySpanRecordArray -- the UMapper region/route subsystem's growable 0x18-byte-record
// array (Reserve / GetOrCreate / Detach / Realloc).

#include "game/TOverlaySpanRecordArray.h"

#include "decomp_types.h"

// Allocator-tracked realloc (generic stub form; typed cast at the call sites).
extern undefined4 ReallocateHeapBlockWithAllocatorTracking(void);

namespace {

inline OverlaySpanRecord* ReallocRecords(OverlaySpanRecord* buffer, int bytes) {
  return reinterpret_cast<OverlaySpanRecord*>(reinterpret_cast<void*(__cdecl*)(void*, int)>(
      ReallocateHeapBlockWithAllocatorTracking)(buffer, bytes));
}

} // namespace

// FUNCTION: IMPERIALISM 0x0052b3e0
void TOverlaySpanRecordArray::ReserveCapacity(unsigned int newCount) {
  unsigned int newCapacity = newCount * 2;
  if (newCapacity > 0x7fffffff) {
    newCapacity = 0x7fffffff;
  }
  OverlaySpanRecord* grown = ReallocRecords(buffer, newCount * 0x30);
  if (grown == nullptr) {
    buffer = ReallocRecords(buffer, newCount * 0x18);
    capacity = newCount;
    return;
  }
  buffer = grown;
  capacity = newCapacity;
}

// FUNCTION: IMPERIALISM 0x0052b460
OverlaySpanRecord* TOverlaySpanRecordArray::GetOrCreateEntry(unsigned int index) {
  if (capacity <= index) {
    int want = index + 1;
    unsigned int newCapacity = want * 2;
    if (newCapacity > 0x7fffffff) {
      newCapacity = 0x7fffffff;
    }
    OverlaySpanRecord* grown = ReallocRecords(buffer, want * 0x30);
    if (grown == nullptr) {
      buffer = ReallocRecords(buffer, want * 0x18);
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

// FUNCTION: IMPERIALISM 0x0052b500
void* TOverlaySpanRecordArray::DetachBuffer() {
  void* detached = buffer;
  buffer = nullptr;
  capacity = 0;
  count = 0;
  return detached;
}

// FUNCTION: IMPERIALISM 0x0052e310
void TOverlaySpanRecordArray::ReallocBuffer(int newCount) {
  buffer = ReallocRecords(buffer, newCount * 0x18);
  capacity = newCount;
}
