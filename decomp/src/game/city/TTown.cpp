#include "game/resource_domain_types.h"
#include "game/city/TTown.h"

#include "game/map/TMapMgr.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/core/stream_byteswap.h"
#include "game/core/TStream.h"
#include "game/city/TCity.h"
#include "game/nation/TGreatPower.h"
#include "game/tactical_ui/TTechMgr.h"
#include <string.h>

#include "game/globals/global_types.h"
#include "game/globals/map_globals.h"
#include "game/globals/shared_globals.h"
#include "game/mfc.h"

// MFC-style GetRuntimeClass (slot 0): returns the class descriptor that precedes
// the vtable at 0x0066d7c8.

IMPLEMENT_DYNCREATE(TTown, TObject)

enum { kTownHarvestTileCount = kStrategicHexDirectionCount + 1 };

// Bare vptr-write constructor; all field state comes from ITown.
// FUNCTION: IMPERIALISM 0x005b6c60
TTown::TTown() {}

// FUNCTION: IMPERIALISM 0x005b6cb0
TTown::~TTown() {}

// FUNCTION: IMPERIALISM 0x005b6cd0
void TTown::ITown(const char* markerName, short tileIndex, bool enabledFlag, short ownerNation) {
  strcpy(this->name, markerName);
  this->ownerNation = ownerNation;
  this->tileIndex = tileIndex;
  this->enabledFlag = enabledFlag;
  this->activeFlag = !enabledFlag;
  this->field16 = 0;
  this->field18 = 0;
  this->createdTurnTick = g_pSimMgr->GetEconomicTurn();
  this->transportLinked = false;
  memset(this->resourceYieldByType, 0, sizeof(this->resourceYieldByType));
}

// FUNCTION: IMPERIALISM 0x005b6d70
void TTown::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  stream->ReadBytes(name, sizeof(name));
  stream->ReadBytes(&tileIndex, 2);
  stream->ReadBytes(&field16, 2);
  stream->ReadBytes(&field18, 2);
  stream->ReadBytes(&createdTurnTick, 2);
  stream->ReadBytes(&ownerNation, 2);
  stream->ReadBytes(resourceYieldByType, sizeof(resourceYieldByType));
  SwapShortArrayBytes(resourceYieldByType, kResourceKindCount);
  stream->ReadBytes(&transportLinked, 1);
  stream->ReadBytes(&enabledFlag, 1);
  stream->ReadBytes(&hasAdjacentCity, 1);
  if (g_nSaveFormatVersion < 0xa) {
    activeFlag = true;
  } else {
    activeFlag = stream->ReadBoolean() != 0;
  }
}

// FUNCTION: IMPERIALISM 0x005b6e60
void TTown::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  stream->WriteBytes(name, sizeof(name));
  stream->WriteBytes(&tileIndex, 2);
  stream->WriteBytes(&field16, 2);
  stream->WriteBytes(&field18, 2);
  stream->WriteBytes(&createdTurnTick, 2);
  stream->WriteBytes(&ownerNation, 2);
  WriteShortArrayElems(stream, resourceYieldByType, kResourceKindCount);
  stream->WriteBytes(&transportLinked, 1);
  stream->WriteBytes(&enabledFlag, 1);
  stream->WriteBytes(&hasAdjacentCity, 1);
  stream->WriteBoolean(activeFlag);
}

static short TownNeighborTile(TTown* town, int direction) {
  if (direction < kStrategicHexDirectionCount) {
    return TMapMgr::GetNeighborTileID(town->tileIndex, static_cast<short>(direction));
  }
  return town->tileIndex;
}

static void AddAdjacentCityDevelopment(TTown* town, short tileIndex) {
  short cityRecordIndex = g_pGlobalMapState->terrainStateTable[tileIndex].cityRecordIndex;
  if (cityRecordIndex == -1 ||
      g_pGlobalMapState->cityScoreTable[cityRecordIndex].cityTileIndex != tileIndex) {
    return;
  }

  town->hasAdjacentCity = true;
  for (int resource = 0; resource < kResourceManufacturedCount; ++resource) {
    town->resourceYieldByType[resource + kResourceManufacturedFirst] = static_cast<short>(
        town->resourceYieldByType[resource + kResourceManufacturedFirst] +
        g_pGlobalMapState->cityScoreTable[cityRecordIndex].resourceDevelopmentCounts[resource]);
  }
}

// FUNCTION: IMPERIALISM 0x005b6f70
void TTown::CalculateRawResources() {
  hasAdjacentCity = false;
  memset(resourceYieldByType, 0, sizeof(resourceYieldByType));

  signed char townRegionClass = g_pGlobalMapState->terrainStateTable[tileIndex].regionSubtypeTag;
  for (int direction = 0; direction < kTownHarvestTileCount; ++direction) {
    short tileIndex = TownNeighborTile(this, direction);
    if (tileIndex == -1) {
      continue;
    }

    TTerrainStateRecord* tile = &g_pGlobalMapState->terrainStateTable[tileIndex];
    if (!((tile->ownerNationTag == ownerNation && tile->regionSubtypeTag == townRegionClass) ||
          tile->GetTerrainKind() == kStrategicTerrainWater)) {
      continue;
    }

    for (short resource = 0; resource < kResourceKindCount; ++resource) {
      short amount =
          static_cast<short>(g_pGlobalMapState->FindResourceCapabilityRequirementLevelByType(
              tileIndex, static_cast<char>(resource)));
      if (resource != kResourceFish || enabledFlag) {
        resourceYieldByType[resource] = static_cast<short>(resourceYieldByType[resource] + amount);
      }
    }
    if (tile->riverSpriteCode != kRiverSpriteCodeNone && enabledFlag) {
      ++resourceYieldByType[kResourceFish];
    }
    AddAdjacentCityDevelopment(this, tileIndex);
  }
}

// FUNCTION: IMPERIALISM 0x005b7140
void TTown::CalculateResources() {
  hasAdjacentCity = false;
  memset(resourceYieldByType, 0, sizeof(resourceYieldByType));

  signed char townRegionClass = g_pGlobalMapState->terrainStateTable[tileIndex].regionSubtypeTag;
  for (int direction = 0; direction < kTownHarvestTileCount; ++direction) {
    short tileIndex = TownNeighborTile(this, direction);
    if (tileIndex == -1) {
      continue;
    }

    TTerrainStateRecord* tile = &g_pGlobalMapState->terrainStateTable[tileIndex];
    if (tile->ownerNationTag != ownerNation ||
        (tile->regionSubtypeTag != townRegionClass && tile->regionSubtypeTag != -1)) {
      continue;
    }

    for (short edge = 0; edge < 2; ++edge) {
      signed char resource = tile->resourceTypeByEdge[edge];
      if (resource == -1) {
        continue;
      }

      bool temporarilyRaisedDevelopment = false;
      if (resource == kResourceCoal || resource == kResourceIron || resource == kResourceOil ||
          resource == kResourceGems || resource == kResourceGold) {
        temporarilyRaisedDevelopment =
            g_pGlobalMapState->GetTileCivilianWorkOrderCostClassNibble(tileIndex, true) == 0;
        if (temporarilyRaisedDevelopment) {
          g_pGlobalMapState->SetDevelopmentLevel(tileIndex, true, 1, false);
        }
        resourceYieldByType[resource] = static_cast<short>(
            resourceYieldByType[resource] +
            g_pGlobalMapState->FindResourceCapabilityRequirementLevel(tileIndex, edge));
        if (temporarilyRaisedDevelopment) {
          g_pGlobalMapState->SetDevelopmentLevel(tileIndex, true, 0, false);
        }
      } else {
        resourceYieldByType[resource] = static_cast<short>(
            resourceYieldByType[resource] +
            g_pGlobalMapState->FindResourceCapabilityRequirementLevel(tileIndex, edge));
      }
    }
    AddAdjacentCityDevelopment(this, tileIndex);
  }
}

// FUNCTION: IMPERIALISM 0x005b73e0
void TTown::CalculateCityResources() {
  memset(resourceYieldByType, 0, sizeof(resourceYieldByType));

  for (int direction = 0; direction < kTownHarvestTileCount; ++direction) {
    short tileIndex = TownNeighborTile(this, direction);
    if (tileIndex == -1) {
      continue;
    }

    TTerrainStateRecord* tile = &g_pGlobalMapState->terrainStateTable[tileIndex];
    if (tile->ownerNationTag != ownerNation && tile->GetTerrainKind() != kStrategicTerrainWater) {
      continue;
    }

    for (short resource = 0; resource < kResourceKindCount; ++resource) {
      short amount =
          static_cast<short>(g_pGlobalMapState->FindResourceCapabilityRequirementLevelByType(
              tileIndex, static_cast<char>(resource)));
      if (amount != 0 && g_abResourceTypeUsesHighNibbleFlag[tile->gateFlag] != 0) {
        short capability = g_pTechMgr->capabilityValueByNationAndResource[ownerNation][resource];
        amount = static_cast<short>(g_abUniversityRequirementLevelById[resource][capability]);
      }
      resourceYieldByType[resource] = static_cast<short>(resourceYieldByType[resource] + amount);
    }

    if (tile->riverSpriteCode != kRiverSpriteCodeNone && enabledFlag) {
      ++resourceYieldByType[kResourceFish];
    }
  }
}

// FUNCTION: IMPERIALISM 0x005b7570
void TTown::Grow() {
  TGreatPower* owner = g_apNationStates[ownerNation];
  TCity* city = owner != 0 ? owner->city : 0;
  short age = static_cast<short>(g_pSimMgr->GetEconomicTurn() - createdTurnTick);

  if (age > 4 && (age & 1) == 0) {
    short rawTextile = static_cast<short>(resourceYieldByType[kResourceCotton] +
                                          resourceYieldByType[kResourceWool]);
    if (rawTextile != 0) {
      short& fabric = resourceYieldByType[kResourceFabric];
      short capacity = static_cast<short>(city->GetBuildingType(1) / 4);
      if (fabric < capacity && fabric < rawTextile / 2) {
        ++fabric;
      }
    }

    if (resourceYieldByType[kResourceTimber] != 0) {
      short& lumber = resourceYieldByType[kResourceLumber];
      short capacity = static_cast<short>(city->GetBuildingType(5) / 4);
      if (lumber < capacity && lumber < resourceYieldByType[kResourceTimber] / 2) {
        ++lumber;
      }
    }

    if (resourceYieldByType[kResourceCoal] != 0 && resourceYieldByType[kResourceIron] != 0) {
      short input = resourceYieldByType[kResourceCoal] < resourceYieldByType[kResourceIron]
                        ? resourceYieldByType[kResourceCoal]
                        : resourceYieldByType[kResourceIron];
      short& steel = resourceYieldByType[kResourceSteel];
      short capacity = static_cast<short>(city->GetBuildingType(3) / 4);
      if (steel < capacity && steel < input / 2) {
        ++steel;
      }
    }

    if (resourceYieldByType[kResourceOil] != 0 &&
        g_pTechMgr->orderCapRows277[ownerNation].techStatusByTechId[0x14] == 2) {
      short& fuel = resourceYieldByType[kResourceFuel];
      if (fuel < resourceYieldByType[kResourceOil] / 2) {
        ++fuel;
      }
    }
  }

  if (age > 9 && (age & 1) != 0) {
    short* citySummary = city->GetUnmetNeeds();
    short finishedGoods =
        static_cast<short>(citySummary[0xd] + citySummary[0xe] + citySummary[0xf]);
    const short sourceResources[3] = {kResourceFabric, kResourceLumber, kResourceSteel};
    const short finishedResources[3] = {kResourceClothing, kResourceFurniture, kResourceHardware};
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

// FUNCTION: IMPERIALISM 0x005b7830
int TTown::IsUnblockedPort(void) const {
  if (this->enabledFlag != 0) {
    if (g_pGlobalMapState->HasReachableSeaTileOutsideActiveType3Or4DiplomaticMask(
            this->tileIndex)) {
      return 1;
    }
  }
  return 0;
}
