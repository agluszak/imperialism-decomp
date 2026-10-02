#include "game/nation_stream_serialization.h"

void WriteTrackedListToStream(TStream* stream, TSortedList* list) {
  list->WriteTo(stream);
  int entryCount = list->GetCount();
  stream->WriteBytes(&entryCount, 4);
  for (int ordinal = 1; ordinal <= entryCount; ++ordinal) {
    TUnit* entry = static_cast<TUnit*>(list->GetEntryByOrdinal(ordinal));
    entry->WriteTo(stream);
  }
}

void WriteIntListToStream(TStream* stream, TLongintList* list) {
  list->NoOpWriteTo(stream);
  int entryCount = list->GetSize();
  stream->WriteBytes(&entryCount, 4);
  for (int ordinal = 1; ordinal <= entryCount; ++ordinal) {
    int value = list->At(ordinal);
    stream->WriteBytes(&value, 4);
  }
}
