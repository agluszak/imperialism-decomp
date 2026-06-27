#pragma once

#include "game/TSortedList.h"
#include "game/TStream.h"
#include "game/TUnit.h"

// Write-side serialization helpers shared by the nation classes (TCountry / TGreatPower).
// The original copies each array element into a stack temp, byte-swaps it to the stream's
// big-endian order, and writes it via the stream primitive WriteBytesSlot78 (slot 0x78).
// They are `static __inline` so each translation unit inlines them at the callsite (no
// emitted symbol), matching the original's inlined per-element loops.

static __inline void WriteShortArrayElems(TStream* stream, const short* values, int count) {
  for (int remaining = count; remaining != 0; --remaining) {
    short element = *values;
    unsigned char* elementBytes = reinterpret_cast<unsigned char*>(&element);
    unsigned char low = elementBytes[0];
    elementBytes[0] = elementBytes[1];
    elementBytes[1] = low;
    stream->WriteBytesSlot78(&element, 2);
    ++values;
  }
}

static __inline void WriteIntArrayElems(TStream* stream, const int* values, int count) {
  for (int remaining = count; remaining != 0; --remaining) {
    int element = *values;
    unsigned char* elementBytes = reinterpret_cast<unsigned char*>(&element);
    unsigned char b0 = elementBytes[0];
    unsigned char b1 = elementBytes[1];
    elementBytes[0] = elementBytes[3];
    elementBytes[1] = elementBytes[2];
    elementBytes[2] = b1;
    elementBytes[3] = b0;
    stream->WriteBytesSlot78(&element, 4);
    ++values;
  }
}

// Writes a TPtrList's tracked entries: the list itself (slot 0x14), then the entry
// count (slot 0x48), then each 1-based entry through its own slot 0x14 serializer.
static __inline void WriteTrackedListToStream(TStream* stream, TSortedList* list) {
  list->WriteTo(stream);
  int entryCount = list->GetCountSlot48();
  stream->WriteBytesSlot78(&entryCount, 4);
  for (int ordinal = 1; ordinal <= entryCount; ++ordinal) {
    TUnit* entry =
        reinterpret_cast<TUnit*>(list->GetEntryByOrdinalSlot4C(ordinal));
    entry->WriteTo(stream);
  }
}

// Writes a plain int list (ownedRegionList): the list write-header (slot 0x1c), then the
// entry count (slot 0x28), then each 1-based int value (slot 0x24).
static __inline void WriteIntListToStream(TStream* stream, TSortedList* list) {
  list->WriteTo(stream);
  int entryCount = list->GetCountSlot48();
  stream->WriteBytesSlot78(&entryCount, 4);
  for (int ordinal = 1; ordinal <= entryCount; ++ordinal) {
    int entryValue = list->GetIntByOrdinalSlot24(ordinal);
    stream->WriteBytesSlot78(&entryValue, 4);
  }
}
