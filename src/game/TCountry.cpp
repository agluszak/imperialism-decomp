#include "game/TCountry.h"

#include "game/TMilitaryUnitOrderState.h"
#include "game/TStream.h"
#include "game/TUnitOrderState.h"
#include "game/diplomacy_globals.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);

// Serialization helpers (mirror the TGreatPower WriteCoreState idiom): the original
// copies each element into a stack temp, byte-swaps it, and writes it through the
// stream's primitive WriteBytesSlot78 (slot 0x78).
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

// Writes a TPtrList's tracked entries: the list itself (slot 0x14), then the entry
// count (slot 0x48), then each 1-based entry through its own slot 0x14 serializer.
static __inline void WriteTrackedListToStream(TStream* stream, TPtrList* list) {
  list->ResetSlot14(stream);
  int entryCount = list->GetCountSlot48();
  stream->WriteBytesSlot78(&entryCount, 4);
  for (int ordinal = 1; ordinal <= entryCount; ++ordinal) {
    TUnitOrderState* entry =
        reinterpret_cast<TUnitOrderState*>(list->GetTrackedEntrySlot4C(ordinal));
    entry->WriteToStreamSlot14(stream);
  }
}

// Writes a plain int list (ownedRegionList): the list write-header (slot 0x1c), then the
// entry count (slot 0x28), then each 1-based int value (slot 0x24).
static __inline void WriteIntListToStream(TStream* stream, TPtrList* list) {
  list->Release1C();
  int entryCount = list->GetCountOrReleaseSlot28();
  stream->WriteBytesSlot78(&entryCount, 4);
  for (int ordinal = 1; ordinal <= entryCount; ++ordinal) {
    int entryValue = list->GetIntByOrdinalSlot24(ordinal);
    stream->WriteBytesSlot78(&entryValue, 4);
  }
}

static void SwapAdjacentBytesInShortArray(short* entries, int pairCount) {
  for (int i = 0; i < pairCount; ++i) {
    unsigned char* bytes = reinterpret_cast<unsigned char*>(&entries[i]);
    unsigned char tmp = bytes[0];
    bytes[0] = bytes[1];
    bytes[1] = tmp;
  }
}

// FUNCTION: IMPERIALISM 0x004d6ba0
void TCountry::Free(void) {
  if (this->militaryUnitList44 != 0) {
    this->militaryUnitList44->Call58();
  }
  this->militaryUnitList44 = 0;
  if (this->ownedRegionList != 0) {
    this->ownedRegionList->Call38();
    this->ownedRegionList = 0;
  }
  delete this;
}

// FUNCTION: IMPERIALISM 0x004d6bf0
void TCountry::ReadFrom(TStream* stream) {
  int streamState = reinterpret_cast<int>(stream);
  stream->streamSlot70();
  stream->streamSlot70();

  CString* nationNameSource = reinterpret_cast<CString*>(
      reinterpret_cast<char*>(g_pLocalizationTable) + this->nationSlot * 4 + 0x7c);
  this->identitySharedString1 = *nationNameSource;
  stream->ReadBytes(&this->identitySharedString0, 4);

  stream->ReadBytes(&this->nationSlot, 2);
  stream->ReadBytes(&this->encodedNationSlot, 2);
  stream->ReadBytes(this->unitNameOrdinalByType, 0x3c);
  SwapAdjacentBytesInShortArray(this->unitNameOrdinalByType, 0x1e);

  stream->ReadBytes(&this->unitNameCounter84, 2);
  stream->ReadBytes(&this->treasuryValue10, 4);
  stream->ReadBytes(&this->ownerNationSlot, 4);
  stream->ReadBytes(&this->serializedField8c, 4);
  stream->ReadBytes(this->needLevelByNation, 0x2e);
  SwapAdjacentBytesInShortArray(this->needLevelByNation, 0x17);

  if (this->militaryUnitList44->GetCountSlot48() != 0) {
    this->militaryUnitList44->Call54();
  }
  this->militaryUnitList44->Call18(streamState);

  int recruitCount = 0;
  stream->ReadBytes(&recruitCount, 4);
  int recruitIndex = 1;
  if (recruitCount > 0) {
    do {
      void* raw = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x44));
      TMilitaryUnitOrderState* militaryOrder = 0;
      if (raw != 0) {
        militaryOrder = new (raw) TMilitaryUnitOrderState();
        militaryOrder->InitializeRecruitOrderState(0, 0, this->nationSlot);
        militaryOrder->ReadFromStreamSlot18(stream);
      }
      recruitIndex = recruitIndex + 1;
    } while (recruitIndex <= recruitCount);
  }

  if (this->ownedRegionList->GetCountOrReleaseSlot28() != 0) {
    this->ownedRegionList->Call38();
  }
  this->ownedRegionList->VTableSlot20();
  int regionDeserializeCount = 0;
  stream->ReadBytes(&regionDeserializeCount, 4);
  int regionIndex = 1;
  if (regionDeserializeCount > 0) {
    do {
      int entryValue = 0;
      stream->ReadBytes(&entryValue, 4);
      this->ownedRegionList->ResetSlot14(stream);
      regionIndex = regionIndex + 1;
    } while (regionIndex <= regionDeserializeCount);
  }
}

// Serializes the TCountry base sub-object: the identity strings (stream slot 0xac), the
// nation-slot metrics, the per-unit-type name ordinals, the military unit list and the
// owned-region list. The leading TObject::WriteTo is the no-op base-of-base (0x00485f70).
#pragma optimize("y", on)
// FUNCTION: IMPERIALISM 0x004d6e60
void TCountry::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);

  stream->streamSlotAc(&this->identitySharedString0);
  stream->streamSlotAc(&this->identitySharedString1);

  stream->WriteBytesSlot78(&this->nationSlot, 2);
  stream->WriteBytesSlot78(&this->encodedNationSlot, 2);
  WriteShortArrayElems(stream, this->unitNameOrdinalByType, 0x1e);
  stream->WriteBytesSlot78(&this->unitNameCounter84, 2);
  stream->WriteBytesSlot78(&this->treasuryValue10, 4);
  stream->WriteBytesSlot78(&this->ownerNationSlot, 4);
  stream->WriteBytesSlot78(&this->serializedField8c, 4);
  WriteShortArrayElems(stream, this->needLevelByNation, 0x17);

  WriteTrackedListToStream(stream, this->militaryUnitList44);
  WriteIntListToStream(stream, this->ownedRegionList);
}
#pragma optimize("", on)
