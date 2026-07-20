#include "game/TTown.h"

#include "game/TMapMgr.h"
#include "game/TSimMgr.h"
#include "game/TStream.h"
#include "game/TCity.h"
#include "game/TGreatPower.h"
#include "game/TTechMgr.h"
#include <string.h>

#include "game/global_data_tables.h"
#include "game/mfc.h"

static void SwapAdjacentBytePairs(unsigned char* bytes, int pairCount) {
  int remaining = pairCount;
  while (remaining > 0) {
    unsigned char first = bytes[0];
    bytes[0] = bytes[1];
    bytes[1] = first;
    bytes += 2;
    remaining--;
  }
}

// MFC-style GetRuntimeClass (slot 0): returns the class descriptor that precedes
// the vtable at 0x0066d7c8.
// SYNTHETIC: IMPERIALISM 0x005b6c10
// TTown::CreateObject

// SYNTHETIC: IMPERIALISM 0x005b6c40
// TTown::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTown, TObject)

// Bare vptr-write constructor; all field state comes from InitializeTownMarker.
// FUNCTION: IMPERIALISM 0x005b6c60
TTown::TTown() {}

// FUNCTION: IMPERIALISM 0x005b6cd0
void TTown::InitializeTownMarker(const char* markerName, short regionId, char enabledFlag,
                                 short ownerNation) {
  strcpy(this->name, markerName);
  this->ownerNation1c = ownerNation;
  this->regionId14 = regionId;
  this->enabledFlag4d = enabledFlag;
  this->activeFlag4f = enabledFlag == 0;
  this->flags16[0] = 0;
  this->flags16[1] = 0;
  this->flags16[2] = 0;
  this->flags16[3] = 0;
  this->createdTurnTick1a = g_pSimMgr->GetTurnTickSlot3C();
  this->transportLinkedFlag4c = 0;
  memset(this->resourceYieldByType, 0, sizeof(this->resourceYieldByType));
}

// FUNCTION: IMPERIALISM 0x005b6d70
void TTown::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  stream->ReadBytes(name, sizeof(name));
  stream->ReadBytes(&regionId14, 2);
  stream->ReadBytes(flags16, sizeof(flags16));
  stream->ReadBytes(&createdTurnTick1a, 2);
  stream->ReadBytes(&ownerNation1c, 2);
  stream->ReadBytes(resourceYieldByType, sizeof(resourceYieldByType));
  SwapAdjacentBytePairs(reinterpret_cast<unsigned char*>(resourceYieldByType), 0x17);
  stream->ReadBytes(&transportLinkedFlag4c, 1);
  stream->ReadBytes(&enabledFlag4d, 1);
  stream->ReadBytes(&hasAdjacentCity4e, 1);
  stream->ReadByte(&activeFlag4f);
}

// FUNCTION: IMPERIALISM 0x005b6e60
void TTown::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  stream->WriteBytesSlot78(name, sizeof(name));
  stream->WriteBytesSlot78(&regionId14, 2);
  stream->WriteBytesSlot78(flags16, sizeof(flags16));
  stream->WriteBytesSlot78(&createdTurnTick1a, 2);
  stream->WriteBytesSlot78(&ownerNation1c, 2);
  stream->WriteBytesSlot78(resourceYieldByType, sizeof(resourceYieldByType));
  stream->WriteBytesSlot78(&transportLinkedFlag4c, 1);
  stream->WriteBytesSlot78(&enabledFlag4d, 1);
  stream->WriteBytesSlot78(&hasAdjacentCity4e, 1);
  stream->streamSlot80(activeFlag4f);
}

static __inline short TownNeighborTile(TTown* town, int direction) {
  if (direction < 6) {
    return TMapMgr::GetWrappedHexNeighborTileIndexByDirection(town->regionId14,
                                                              static_cast<short>(direction));
  }
  return town->regionId14;
}

static __inline void AddAdjacentCityDevelopment(TTown* town, short tileIndex) {
  short cityRecordIndex = g_pGlobalMapState->terrainStateTable[tileIndex].cityRecordIndex;
  if (cityRecordIndex == -1 ||
      g_pGlobalMapState->cityScoreTable[cityRecordIndex].cityTileIndex04 != tileIndex) {
    return;
  }

  town->hasAdjacentCity4e = true;
  for (int resource = 0; resource < 10; ++resource) {
    town->resourceYieldByType[resource + 7] = static_cast<short>(
        town->resourceYieldByType[resource + 7] +
        g_pGlobalMapState->cityScoreTable[cityRecordIndex].resourceDevelopmentCounts82[resource]);
  }
}

// FUNCTION: IMPERIALISM 0x005b6f70
void TTown::CalculateRawResources() {
  hasAdjacentCity4e = false;
  memset(resourceYieldByType, 0, sizeof(resourceYieldByType));

  signed char townRegionClass = g_pGlobalMapState->terrainStateTable[regionId14].regionSubtypeTag05;
  for (int direction = 0; direction < 7; ++direction) {
    short tileIndex = TownNeighborTile(this, direction);
    if (tileIndex == -1) {
      continue;
    }

    TTerrainStateRecordView* tile = &g_pGlobalMapState->terrainStateTable[tileIndex];
    if (!((tile->ownerNationTag04 == ownerNation1c &&
           tile->regionSubtypeTag05 == townRegionClass) ||
          tile->terrainType00 == 5)) {
      continue;
    }

    for (short resource = 0; resource < 0x17; ++resource) {
      short amount =
          static_cast<short>(g_pGlobalMapState->FindResourceCapabilityRequirementLevelByType(
              tileIndex, static_cast<char>(resource)));
      if (resource != 0x13 || enabledFlag4d) {
        resourceYieldByType[resource] = static_cast<short>(resourceYieldByType[resource] + amount);
      }
    }
    if (tile->roadFlag != 0 && enabledFlag4d) {
      ++resourceYieldByType[0x13];
    }
    AddAdjacentCityDevelopment(this, tileIndex);
  }
}

// FUNCTION: IMPERIALISM 0x005b7140
void TTown::CalculateResources() {
  hasAdjacentCity4e = false;
  memset(resourceYieldByType, 0, sizeof(resourceYieldByType));

  signed char townRegionClass = g_pGlobalMapState->terrainStateTable[regionId14].regionSubtypeTag05;
  for (int direction = 0; direction < 7; ++direction) {
    short tileIndex = TownNeighborTile(this, direction);
    if (tileIndex == -1) {
      continue;
    }

    TTerrainStateRecordView* tile = &g_pGlobalMapState->terrainStateTable[tileIndex];
    if (tile->ownerNationTag04 != ownerNation1c ||
        (tile->regionSubtypeTag05 != townRegionClass && tile->regionSubtypeTag05 != -1)) {
      continue;
    }

    for (short edge = 0; edge < 2; ++edge) {
      signed char resource = tile->resourceTypeByEdge[edge];
      if (resource == -1) {
        continue;
      }

      bool temporarilyRaisedDevelopment = false;
      if (resource == 3 || resource == 4 || resource == 6 || resource == 0x15 || resource == 0x16) {
        temporarilyRaisedDevelopment =
            g_pGlobalMapState->GetTileCivilianWorkOrderCostClassNibble(tileIndex, 1) == 0;
        if (temporarilyRaisedDevelopment) {
          g_pGlobalMapState->SetCivilianDevelopmentClassNibble(tileIndex, 1, 1, 0);
        }
      }

      resourceYieldByType[resource] = static_cast<short>(
          resourceYieldByType[resource] +
          g_pGlobalMapState->FindResourceCapabilityRequirementLevel(tileIndex, edge));

      if (temporarilyRaisedDevelopment) {
        g_pGlobalMapState->SetCivilianDevelopmentClassNibble(tileIndex, 1, 0, 0);
      }
    }
    AddAdjacentCityDevelopment(this, tileIndex);
  }
}

// FUNCTION: IMPERIALISM 0x005b73e0
void TTown::CalculateCityResources() {
  memset(resourceYieldByType, 0, sizeof(resourceYieldByType));

  for (int direction = 0; direction < 7; ++direction) {
    short tileIndex = TownNeighborTile(this, direction);
    if (tileIndex == -1) {
      continue;
    }

    TTerrainStateRecordView* tile = &g_pGlobalMapState->terrainStateTable[tileIndex];
    if (tile->ownerNationTag04 != ownerNation1c && tile->terrainType00 != 5) {
      continue;
    }

    for (short resource = 0; resource < 0x17; ++resource) {
      short amount =
          static_cast<short>(g_pGlobalMapState->FindResourceCapabilityRequirementLevelByType(
              tileIndex, static_cast<char>(resource)));
      if (amount != 0 && g_abResourceTypeUsesHighNibbleFlag[tile->gateFlag] != 0) {
        short capability = g_pCityOrderCapabilityState
                               ->capabilityValueByNationAndResource[ownerNation1c][resource];
        amount = static_cast<short>(g_abUniversityRequirementLevelById[resource][capability]);
      }
      resourceYieldByType[resource] = static_cast<short>(resourceYieldByType[resource] + amount);
    }

    if (tile->roadFlag != 0 && enabledFlag4d) {
      ++resourceYieldByType[0x13];
    }
  }
}

// FUNCTION: IMPERIALISM 0x005b7570
void TTown::Grow() {
  TGreatPower* owner = g_apNationStates[ownerNation1c];
  TCity* city = owner != 0 ? owner->city : 0;
  short age = static_cast<short>(g_pSimMgr->GetTurnTickSlot3C() - createdTurnTick1a);

  if (age > 4 && (age & 1) == 0) {
    short rawTextile = static_cast<short>(resourceYieldByType[0] + resourceYieldByType[1]);
    if (rawTextile != 0) {
      short& fabric = resourceYieldByType[8];
      short capacity = static_cast<short>(city->GetBuildingType(1) / 4);
      if (fabric < capacity && fabric < rawTextile / 2) {
        ++fabric;
      }
    }

    if (resourceYieldByType[2] != 0) {
      short& lumber = resourceYieldByType[9];
      short capacity = static_cast<short>(city->GetBuildingType(5) / 4);
      if (lumber < capacity && lumber < resourceYieldByType[2] / 2) {
        ++lumber;
      }
    }

    if (resourceYieldByType[3] != 0 && resourceYieldByType[4] != 0) {
      short input = resourceYieldByType[3] < resourceYieldByType[4] ? resourceYieldByType[3]
                                                                    : resourceYieldByType[4];
      short& steel = resourceYieldByType[0xb];
      short capacity = static_cast<short>(city->GetBuildingType(3) / 4);
      if (steel < capacity && steel < input / 2) {
        ++steel;
      }
    }

    if (resourceYieldByType[6] != 0 &&
        g_pCityOrderCapabilityState->orderCapRows277[ownerNation1c].techStatusByTechId[0x14] == 2) {
      short& fuel = resourceYieldByType[0xc];
      if (fuel < resourceYieldByType[6] / 2) {
        ++fuel;
      }
    }
  }

  if (age > 9 && (age & 1) != 0) {
    short* citySummary = city->GetCitySummaryRecordSlot74();
    short finishedGoods =
        static_cast<short>(citySummary[0xd] + citySummary[0xe] + citySummary[0xf]);
    const short sourceResources[3] = {8, 9, 0xb};
    const short finishedResources[3] = {0xd, 0xe, 0xf};
    for (int index = 0; index < 3; ++index) {
      short source = sourceResources[index];
      short finished = finishedResources[index];
      if (resourceYieldByType[source] != 0 && resourceYieldByType[finished] < finishedGoods &&
          resourceYieldByType[finished] < resourceYieldByType[source] / 2) {
        ++resourceYieldByType[finished];
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x005b77e0
void TTown::SetName(const char* townName) {
  if (strlen(townName) < sizeof(name)) {
    strcpy(name, townName);
  }
}

TTown::~TTown() {}

// FUNCTION: IMPERIALISM 0x005b7830
int TTown::IsUnblockedPort(void) const {
  if (this->enabledFlag4d != 0) {
    if (g_pGlobalMapState->HasReachableSeaTileOutsideActiveType3Or4DiplomaticMask(
            this->regionId14) != 0) {
      return 1;
    }
  }
  return 0;
}

// SYNTHETIC: IMPERIALISM 0x005b6c80
// TTown::`scalar deleting destructor'
