#include "game/map/TMinister.h"

#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/mfc.h"
#include "game/city_ui/TCountry.h"
#include "game/nation/TGreatPower.h"
#include "game/navy/TShip.h"
#include "game/core/TStream.h"

#include <new>

IMPLEMENT_DYNCREATE(TMinister, TObject)

// FUNCTION: IMPERIALISM 0x0052eb80
TMinister::TMinister() : greatPower(NULL), ranking(0), skillIndex(0) {}

// FUNCTION: IMPERIALISM 0x0052ebf0
void TMinister::IMinister(TGreatPower* ownerContext) {
  greatPower = ownerContext;
  ranking = new TIndexAndRankList();
  ranking->recordSize = 6;
}

// FUNCTION: IMPERIALISM 0x0052ec80
void TMinister::Free() {
  if (ranking != 0) {
    ranking->FreeList();
  }
  ranking = 0;
  delete this;
}

// FUNCTION: IMPERIALISM 0x0052ecc0
void TMinister::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  stream->ReadBytes(&skillIndex, 2);
}

// FUNCTION: IMPERIALISM 0x0052ecf0
void TMinister::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  stream->WriteBytes(&skillIndex, 2);
}

// FUNCTION: IMPERIALISM 0x0052ed20
short TMinister::GetRankingCriterionForGP(short nationSlot) {
  return g_apNationStates[nationSlot]->GetStockpile(kResourceArms);
}

// FUNCTION: IMPERIALISM 0x0052ed50
void TMinister::FigureOutRanking() {
  ranking->DeleteAll();

  int nationSlot = 0;
  TCountry** tableCursor = g_apTerrainTypeDescriptorTable;
  do {
    if (*tableCursor != 0) {
      IndexAndRankRecord entry;
      entry.index = static_cast<short>(nationSlot);
      entry.value = GetRankingCriterionForGP(static_cast<short>(nationSlot));
      ranking->Insert(&entry);
    }
    ++nationSlot;
    ++tableCursor;
  } while (nationSlot < kMajorNationCount);

  int entryIndex = 1;
  short rank = 1;
  if (ranking->GetSize() > 1) {
    do {
      IndexAndRankRecord* current =
          static_cast<IndexAndRankRecord*>(ranking->GetPtrListEntryByOneBasedIndex(entryIndex));
      IndexAndRankRecord* next =
          static_cast<IndexAndRankRecord*>(ranking->GetPtrListEntryByOneBasedIndex(entryIndex + 1));
      current->rank = rank;
      if (next->value < current->value) {
        ++rank;
      }
      next->rank = rank;
      ++entryIndex;
    } while (entryIndex < ranking->GetSize());
  }
}

// FUNCTION: IMPERIALISM 0x0052ee20
short TMinister::GetRankOf(short nationSlot) {
  int entryIndex = 1;
  short result = nationSlot;
  if (ranking->GetSize() < 1) {
    return result;
  }
  do {
    IndexAndRankRecord* entry =
        static_cast<IndexAndRankRecord*>(ranking->GetPtrListEntryByOneBasedIndex(entryIndex));
    if (entry->index == nationSlot) {
      result = entry->rank;
      entryIndex = ranking->GetSize() + 10;
    }
    ++entryIndex;
  } while (entryIndex <= ranking->GetSize());
  return result;
}

// FUNCTION: IMPERIALISM 0x0052eea0
short TMinister::GetCountryInRank(short rank) {
  int entryIndex = 1;
  short result = rank;
  if (ranking->GetSize() < 1) {
    return result;
  }
  do {
    IndexAndRankRecord* entry =
        static_cast<IndexAndRankRecord*>(ranking->GetPtrListEntryByOneBasedIndex(entryIndex));
    if (entry->rank == rank) {
      result = entry->index;
      entryIndex = ranking->GetSize() + 10;
    }
    ++entryIndex;
  } while (entryIndex <= ranking->GetSize());
  return result;
}

// FUNCTION: IMPERIALISM 0x0052ef20
short TMinister::GetRankOfCountryAt(short index) {
  IndexAndRankRecord* entry =
      static_cast<IndexAndRankRecord*>(ranking->GetPtrListEntryByOneBasedIndex(index));
  return entry->rank;
}

// FUNCTION: IMPERIALISM 0x0052ef50
short TMinister::GetInfoOfCountryAt(short index) {
  IndexAndRankRecord* entry =
      static_cast<IndexAndRankRecord*>(ranking->GetPtrListEntryByOneBasedIndex(index));
  return entry->value;
}

// FUNCTION: IMPERIALISM 0x0052ef80
short TMinister::GetCountryAt(short index) {
  IndexAndRankRecord* entry =
      static_cast<IndexAndRankRecord*>(ranking->GetPtrListEntryByOneBasedIndex(index));
  return entry->index;
}

// FUNCTION: IMPERIALISM 0x0052efb0
void TMinister::MakeNewCity(TCity* city) {}
