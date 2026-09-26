#include "game/map/TMinister.h"

#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/mfc.h"
#include "game/city_ui/TCountry.h"
#include "game/nation/TGreatPower.h"
#include "game/navy/TShip.h"
#include "game/core/TStream.h"

#include <new>

namespace {

struct MinisterCountryRankingEntry {
  short countrySlot;
  short criterion;
  short rank;
};
ASSERT_SIZE(MinisterCountryRankingEntry, 6);

} // namespace
// SYNTHETIC: IMPERIALISM 0x0052eb30
// TMinister::CreateObject

// SYNTHETIC: IMPERIALISM 0x0052eb60
// TMinister::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMinister, TObject)

// FUNCTION: IMPERIALISM 0x0052eb80
TMinister::TMinister() : ownerContextAt04(nullptr), countryRankings(0), skillIndexC(0) {}

// SYNTHETIC: IMPERIALISM 0x0052eba0
// TMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x0052ebf0
void TMinister::IMinister(TGreatPower* ownerContext) {
  this->ownerContextAt04 = ownerContext;
  countryRankings = new TIndexAndRankList();
  countryRankings->recordSize14 = sizeof(MinisterCountryRankingEntry);
}

// FUNCTION: IMPERIALISM 0x0052ec80
void TMinister::Free() {
  if (countryRankings != 0) {
    countryRankings->ReleasePtrList();
  }
  countryRankings = 0;
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
  stream->WriteBytes(&this->skillIndexC, 2);
}

// FUNCTION: IMPERIALISM 0x0052ed20
short TMinister::GetRankingCriterionForGP(short nationSlot) {
  return g_apNationStates[nationSlot]->GetStockpile(kResourceArms);
}

// FUNCTION: IMPERIALISM 0x0052ed50
void TMinister::FigureOutRanking() {
  countryRankings->ClearAndFreeAllPtrListRecords();

  for (short countrySlot = 0; countrySlot < 7; ++countrySlot) {
    if (g_apTerrainTypeDescriptorTable[countrySlot] != 0) {
      MinisterCountryRankingEntry entry;
      entry.countrySlot = countrySlot;
      entry.criterion = GetRankingCriterionForGP(countrySlot);
      countryRankings->InsertCopiedRecordSortedByComparator(&entry);
    }
  }

  short rank = 1;
  // Retail assigns ranks only when at least two entries were inserted.
  for (int entryIndex = 1; entryIndex < countryRankings->GetSize(); ++entryIndex) {
    MinisterCountryRankingEntry* currentEntry = static_cast<MinisterCountryRankingEntry*>(
        countryRankings->GetPtrListEntryByOneBasedIndex(entryIndex));
    MinisterCountryRankingEntry* nextEntry = static_cast<MinisterCountryRankingEntry*>(
        countryRankings->GetPtrListEntryByOneBasedIndex(entryIndex + 1));
    currentEntry->rank = rank;
    if (nextEntry->criterion < currentEntry->criterion) {
      ++rank;
    }
    nextEntry->rank = rank;
  }
}

// FUNCTION: IMPERIALISM 0x0052ee20
short TMinister::GetRankOf(short countrySlot) {
  for (int entryIndex = 1; entryIndex <= countryRankings->GetSize(); ++entryIndex) {
    MinisterCountryRankingEntry* entry = static_cast<MinisterCountryRankingEntry*>(
        countryRankings->GetPtrListEntryByOneBasedIndex(entryIndex));
    if (entry->countrySlot == countrySlot) {
      return entry->rank;
    }
  }
  return countrySlot;
}

// FUNCTION: IMPERIALISM 0x0052eea0
short TMinister::GetCountryInRank(short rank) {
  for (int entryIndex = 1; entryIndex <= countryRankings->GetSize(); ++entryIndex) {
    MinisterCountryRankingEntry* entry = static_cast<MinisterCountryRankingEntry*>(
        countryRankings->GetPtrListEntryByOneBasedIndex(entryIndex));
    if (entry->rank == rank) {
      return entry->countrySlot;
    }
  }
  return rank;
}

// FUNCTION: IMPERIALISM 0x0052ef20
short TMinister::GetRankOfCountryAt(short index) {
  MinisterCountryRankingEntry* entry = static_cast<MinisterCountryRankingEntry*>(
      countryRankings->GetPtrListEntryByOneBasedIndex(index));
  return entry->rank;
}

// FUNCTION: IMPERIALISM 0x0052ef50
short TMinister::GetInfoOfCountryAt(short index) {
  MinisterCountryRankingEntry* entry = static_cast<MinisterCountryRankingEntry*>(
      countryRankings->GetPtrListEntryByOneBasedIndex(index));
  return entry->criterion;
}

// FUNCTION: IMPERIALISM 0x0052ef80
short TMinister::GetCountryAt(short index) {
  MinisterCountryRankingEntry* entry = static_cast<MinisterCountryRankingEntry*>(
      countryRankings->GetPtrListEntryByOneBasedIndex(index));
  return entry->countrySlot;
}

// FUNCTION: IMPERIALISM 0x0052efb0
void TMinister::MakeNewCity(TCity* city) {
  (void)city;
}
