#include "game/TGlobalMapState.h"

#include "game/TPtrList.h"
#include "game/TMinor.h"
#include "game/diplomacy_globals.h"

#pragma optimize("y", on) // omit frame pointer, as in the original bodies

// FUNCTION: IMPERIALISM 0x00517c30
char TGlobalMapState::AreNationsBorderLinked(int nationA, int nationB) {
  TPtrList* regionList = g_apTerrainTypeDescriptorTable[nationA]->ownedRegionList90;
  if (regionList->GetCountOrReleaseSlot28() < 1) {
    return 0;
  }
  int ordinal = 1;
  do {
    int regionId = regionList->GetIntByOrdinalSlot24(ordinal);
    TGlobalMapCityScoreRecord* record = &cityScoreTable[regionId];
    char found = 0;
    int neighborCount = record->adjacentRegionCount08;
    if (neighborCount > 0) {
      for (int neighborIndex = 0; neighborIndex < neighborCount; ++neighborIndex) {
        short neighborRegionId = record->adjacentRegionIds0A[neighborIndex];
        if (cityScoreTable[neighborRegionId].ownerNationCode00 == nationB) {
          found = 1;
          break;
        }
      }
    }
    if (found != 0) {
      return 1;
    }
    ++ordinal;
  } while (ordinal <= regionList->GetCountOrReleaseSlot28());
  return 0;
}
