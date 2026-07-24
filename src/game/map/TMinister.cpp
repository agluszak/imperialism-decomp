#include "game/map/TMinister.h"

#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/mfc.h"
#include "game/city_ui/TCountry.h"
#include "game/nation/TGreatPower.h"
#include "game/TMinisterBaseOrderArray.h"
#include "game/navy/TShip.h"
#include "game/core/TStream.h"

#include <new>

namespace {

struct MinisterTerrainPreferenceEntry {
  short terrainType;
  short score;
};

} // namespace
// SYNTHETIC: IMPERIALISM 0x0052eb30
// TMinister::CreateObject

// SYNTHETIC: IMPERIALISM 0x0052eb60
// TMinister::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMinister, TObject)

// FUNCTION: IMPERIALISM 0x0052eb80
TMinister::TMinister() : ownerContextAt04(nullptr), field_8(0), skillIndexC(0) {}

// SYNTHETIC: IMPERIALISM 0x0052eba0
// TMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x0052ebd0
TMinister::~TMinister() {}

// FUNCTION: IMPERIALISM 0x0052ebf0
void TMinister::IMinister(TGreatPower* ownerContext) {
  this->ownerContextAt04 = ownerContext;
  this->field_8 = new TMinisterBaseOrderArray();
}

// FUNCTION: IMPERIALISM 0x0052ec80
void TMinister::Free() {
  if (this->field_8 != 0) {
    this->field_8->ReleasePtrList();
  }
  this->field_8 = 0;
  delete this;
}

// FUNCTION: IMPERIALISM 0x0052ecc0
void TMinister::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  stream->ReadBytes(&this->skillIndexC, 2);
}

// FUNCTION: IMPERIALISM 0x0052ecf0
void TMinister::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  stream->WriteBytesSlot78(&this->skillIndexC, 2);
}

void TMinister::SerializeTMinisterBaseOrderArrayHeader(TStream* stream) {
  WriteTo(stream);
}

// FUNCTION: IMPERIALISM 0x0052ed20
short TMinister::GetRankingCriterionForGP(short nationSlot) {
  return g_apNationStates[nationSlot]->GetDiplomacyExternalStateByTarget(0x10);
}

// FUNCTION: IMPERIALISM 0x0052ed50
void TMinister::RebuildTerrainPreferenceEntriesAndAssignRanks() {
  this->field_8->ClearAndFreeAllPtrListRecords();

  int terrainIndex = 0;
  TCountry** tableCursor = g_apTerrainTypeDescriptorTable;
  do {
    if (*tableCursor != 0) {
      MinisterTerrainPreferenceEntry entry;
      entry.terrainType = static_cast<short>(terrainIndex);
      entry.score = GetRankingCriterionForGP(static_cast<short>(terrainIndex));
      this->field_8->InsertCopiedRecordSortedByComparator(&entry);
    }
    terrainIndex = terrainIndex + 1;
    tableCursor = tableCursor + 1;
  } while (terrainIndex < 7);

  int entryIndex = 1;
  short rank = 1;
  if (1 < this->field_8->GetSize()) {
    do {
      short* currentEntry =
          static_cast<short*>(this->field_8->GetPtrListEntryByOneBasedIndex(entryIndex));
      short* nextEntry =
          static_cast<short*>(this->field_8->GetPtrListEntryByOneBasedIndex(entryIndex + 1));
      currentEntry[2] = rank;
      if (nextEntry[1] < currentEntry[1]) {
        rank = static_cast<short>(rank + 1);
      }
      nextEntry[2] = rank;
      entryIndex = entryIndex + 1;
    } while (entryIndex < this->field_8->GetSize());
  }
}

// FUNCTION: IMPERIALISM 0x0052ee20
short TMinister::MapTerrainTypeToPreferenceRank(short terrainType) {
  int entryIndex = 1;
  short result = terrainType;
  if (this->field_8 == 0 || this->field_8->GetSize() < 1) {
    return result;
  }
  do {
    short* entry = static_cast<short*>(this->field_8->GetPtrListEntryByOneBasedIndex(entryIndex));
    if (entry[0] == terrainType) {
      result = entry[2];
      break;
    }
    entryIndex = entryIndex + 1;
  } while (entryIndex <= this->field_8->GetSize());
  return result;
}

// FUNCTION: IMPERIALISM 0x0052eea0
short TMinister::MapPreferenceRankToTerrainType(short rank) {
  int entryIndex = 1;
  short result = rank;
  if (this->field_8 == 0 || this->field_8->GetSize() < 1) {
    return result;
  }
  do {
    short* entry = static_cast<short*>(this->field_8->GetPtrListEntryByOneBasedIndex(entryIndex));
    if (entry[2] == rank) {
      result = entry[0];
      break;
    }
    entryIndex = entryIndex + 1;
  } while (entryIndex <= this->field_8->GetSize());
  return result;
}

// FUNCTION: IMPERIALISM 0x0052ef20
short TMinister::GetPreferenceGroupRankByEntryIndex(short index) {
  short* entry = static_cast<short*>(this->field_8->GetPtrListEntryByOneBasedIndex(index));
  return entry[2];
}

// FUNCTION: IMPERIALISM 0x0052ef50
short TMinister::GetPreferenceScoreByEntryIndex(short index) {
  short* entry = static_cast<short*>(this->field_8->GetPtrListEntryByOneBasedIndex(index));
  return entry[1];
}

// FUNCTION: IMPERIALISM 0x0052ef80
short TMinister::GetPreferenceTerrainTypeByEntryIndex(short index) {
  short* entry = static_cast<short*>(this->field_8->GetPtrListEntryByOneBasedIndex(index));
  return entry[0];
}

// FUNCTION: IMPERIALISM 0x0052efb0
void TMinister::MakeNewCity(TCity* city) {
  (void)city;
}
