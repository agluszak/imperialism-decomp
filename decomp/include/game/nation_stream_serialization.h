#pragma once

#include "game/city_ui/TLongintList.h"

#include "game/core/stream_byteswap.h"
#include "game/ui_core/TSortedList.h"
#include "game/core/TStream.h"
#include "game/military/TUnit.h"

// Collection serialization helpers shared by the nation classes (TCountry / TGreatPower /
// TMinor). The byte-order helpers these serializers also need now live in
// game/core/stream_byteswap.h, which this header pulls in so existing includers keep
// compiling unchanged.
//
// They are `static __inline` so each translation unit inlines them at the callsite (no
// emitted symbol), matching the original's inlined per-list loops.

// Writes a TPtrList's tracked entries: the list itself (slot 0x14), then the entry
// count (slot 0x48), then each 1-based entry through its own slot 0x14 serializer.
static __inline void WriteTrackedListToStream(TStream* stream, TSortedList* list) {
  list->WriteTo(stream);
  int entryCount = list->GetCount();
  stream->WriteBytes(&entryCount, 4);
  for (int ordinal = 1; ordinal <= entryCount; ++ordinal) {
    TUnit* entry = static_cast<TUnit*>(list->GetEntryByOrdinal(ordinal));
    entry->WriteTo(stream);
  }
}

// Writes a plain int list (ownedRegionList): the no-op write hook (slot 0x1c), then the
// entry count (slot 0x28), then each 1-based int value (slot 0x24).
static __inline void WriteIntListToStream(TStream* stream, TLongintList* list) {
  list->NoOpWriteTo(stream);
  int entryCount = list->GetSize();
  stream->WriteBytes(&entryCount, 4);
  for (int ordinal = 1; ordinal <= entryCount; ++ordinal) {
    int entryValue = list->At(ordinal);
    stream->WriteBytes(&entryValue, 4);
  }
}
