#include "game/TGreatPower.h"
#include "game/TStream.h"
#include "game/TMilitaryUnitOrderState.h"
#include "game/diplomacy_globals.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);

static void SwapAdjacentBytesInShortArray(short* entries, int pairCount) {
  for (int i = 0; i < pairCount; ++i) {
    unsigned char* bytes = reinterpret_cast<unsigned char*>(&entries[i]);
    unsigned char tmp = bytes[0];
    bytes[0] = bytes[1];
    bytes[1] = tmp;
  }
}

// FUNCTION: IMPERIALISM 0x004d6bf0
void TGreatPower::DeserializeRecruitScenarioAndInstantiateOrders(int streamState) {
  TStream* stream = reinterpret_cast<TStream*>(streamState);
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
