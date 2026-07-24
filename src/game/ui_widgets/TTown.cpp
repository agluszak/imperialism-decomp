#include "game/ui_widgets/TTown.h"

#include "game/map/TMapMgr.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/core/stream_byteswap.h"
#include "game/core/TStream.h"
#include "game/city/TCity.h"
#include "game/nation/TGreatPower.h"
#include "game/tactical_ui/TTechMgr.h"
#include <string.h>

#include "game/globals/prelude.h"
#include "game/globals/map_globals.h"
#include "game/globals/shared_globals.h"
#include "game/mfc.h"

// MFC-style GetRuntimeClass (slot 0): returns the class descriptor that precedes
// the vtable at 0x0066d7c8.
// SYNTHETIC: IMPERIALISM 0x005b6c10
// TTown::CreateObject

// SYNTHETIC: IMPERIALISM 0x005b6c40
// TTown::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTown, TObject)

// Bare vptr-write constructor; all field state comes from ITown.
// FUNCTION: IMPERIALISM 0x005b6c60
TTown::TTown() {}

// SYNTHETIC: IMPERIALISM 0x005b6c80
// TTown::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x005b6cb0
TTown::~TTown() {}

// FUNCTION: IMPERIALISM 0x005b6cd0
void TTown::ITown(const char* markerName, short tileIndex, char enabledFlag, short ownerNation) {
  strcpy(this->name, markerName);
  this->ownerNation1c = ownerNation;
  this->tileIndex14 = tileIndex;
  this->enabledFlag4d = enabledFlag;
  this->activeFlag4f = enabledFlag == 0;
  this->field16 = 0;
  this->field18 = 0;
  this->createdTurnTick1a = g_pSimMgr->GetEconomicTurn();
  this->transportLinkedFlag4c = 0;
  memset(this->resourceYieldByType, 0, sizeof(this->resourceYieldByType));
}

// FUNCTION: IMPERIALISM 0x005b6d70
void TTown::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  stream->ReadBytes(name, sizeof(name));
  stream->ReadBytes(&tileIndex14, 2);
  stream->ReadBytes(&field16, 2);
  stream->ReadBytes(&field18, 2);
  stream->ReadBytes(&createdTurnTick1a, 2);
  stream->ReadBytes(&ownerNation1c, 2);
  stream->ReadBytes(resourceYieldByType, sizeof(resourceYieldByType));
  SwapShortArrayBytes(resourceYieldByType, 0x17);
  stream->ReadBytes(&transportLinkedFlag4c, 1);
  stream->ReadBytes(&enabledFlag4d, 1);
  stream->ReadBytes(&hasAdjacentCity4e, 1);
  // Saves older than 0xa predate the flag and default it on; newer ones carry it as a
  // plain 1-byte read (slot 0x44), not the polymorphic object read at slot 0xb0.
  if (g_nSaveFormatVersion < 0xa) {
    activeFlag4f = 1;
  } else {
    activeFlag4f = stream->streamSlot44() != 0;
  }
}

// FUNCTION: IMPERIALISM 0x005b6e60
void TTown::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  stream->WriteBytesSlot78(name, sizeof(name));
  stream->WriteBytesSlot78(&tileIndex14, 2);
  stream->WriteBytesSlot78(&field16, 2);
  stream->WriteBytesSlot78(&field18, 2);
  stream->WriteBytesSlot78(&createdTurnTick1a, 2);
  stream->WriteBytesSlot78(&ownerNation1c, 2);
  // Element-wise with a byte swap, mirroring ReadFrom: a raw block write here emitted
  // host-order shorts that the reader then swapped, corrupting every yield on reload.
  WriteShortArrayElems(stream, resourceYieldByType, 0x17);
  stream->WriteBytesSlot78(&transportLinkedFlag4c, 1);
  stream->WriteBytesSlot78(&enabledFlag4d, 1);
  stream->WriteBytesSlot78(&hasAdjacentCity4e, 1);
  stream->streamSlot80(activeFlag4f);
}

static __inline short TownNeighborTile(TTown* town, int direction) {
  if (direction < 6) {
    return TMapMgr::GetNeighborTileID(town->tileIndex14, static_cast<short>(direction));
  }
  return town->tileIndex14;
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

  signed char townRegionClass =
      g_pGlobalMapState->terrainStateTable[tileIndex14].regionSubtypeTag05;
  for (int direction = 0; direction < 7; ++direction) {
    short tileIndex = TownNeighborTile(this, direction);
    if (tileIndex == -1) {
      continue;
    }

    TTerrainStateRecordView* tile = &g_pGlobalMapState->terrainStateTable[tileIndex];
    if (!((tile->ownerNationTag04 == ownerNation1c &&
           tile->regionSubtypeTag05 == townRegionClass) ||
          tile->GetTerrainKind() == kStrategicTerrainWater)) {
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
    if (tile->riverSpriteCode != kRiverSpriteCodeNone && enabledFlag4d) {
      ++resourceYieldByType[0x13];
    }
    AddAdjacentCityDevelopment(this, tileIndex);
  }
}

// FUNCTION: IMPERIALISM 0x005b7140
void TTown::CalculateResources() {
  hasAdjacentCity4e = false;
  memset(resourceYieldByType, 0, sizeof(resourceYieldByType));

  signed char townRegionClass =
      g_pGlobalMapState->terrainStateTable[tileIndex14].regionSubtypeTag05;
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
    if (tile->ownerNationTag04 != ownerNation1c &&
        tile->GetTerrainKind() != kStrategicTerrainWater) {
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

    if (tile->riverSpriteCode != kRiverSpriteCodeNone && enabledFlag4d) {
      ++resourceYieldByType[0x13];
    }
  }
}

// FUNCTION: IMPERIALISM 0x005b7570
void TTown::Grow() {
  TGreatPower* owner = g_apNationStates[ownerNation1c];
  TCity* city = owner != 0 ? owner->city : 0;
  short age = static_cast<short>(g_pSimMgr->GetEconomicTurn() - createdTurnTick1a);

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

// FUNCTION: IMPERIALISM 0x005b7830
int TTown::IsUnblockedPort(void) const {
  if (this->enabledFlag4d != 0) {
    if (g_pGlobalMapState->HasReachableSeaTileOutsideActiveType3Or4DiplomaticMask(
            this->tileIndex14) != 0) {
      return 1;
    }
  }
  return 0;
}
