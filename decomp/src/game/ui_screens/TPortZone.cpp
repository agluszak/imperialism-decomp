#include "game/nation_domain_types.h"
#include "game/map_domain_types.h"
#include "game/ui_screens/TPortZone.h"

#include <new.h>

#include "game/map/TMapMgr.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/navy/TTaskForce.h"
#include "game/navy/TOcean.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/core/TStream.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/military/mapped_flavor_text.h"
#include "game/mfc.h"

// FUNCTION: IMPERIALISM 0x00561660
bool TPortZone::IsSeaZone() {
  return true;
}

// FUNCTION: IMPERIALISM 0x00561680
bool TPortZone::IsPortZone() {
  return true;
}

// FUNCTION: IMPERIALISM 0x005616a0
bool TPortZone::IsProvincial() {
  return false;
}

// FUNCTION: IMPERIALISM 0x005616f0
TPortZone::~TPortZone() {}

IMPLEMENT_DYNCREATE(TPortZone, TZone)

// FUNCTION: IMPERIALISM 0x005617f0
void TPortZone::ReadFrom(TStream* stream) {
  TZone::ReadFrom(stream);
  stream->ReadBytes(&portTileIndex, 2);
}

// FUNCTION: IMPERIALISM 0x00561820
void TPortZone::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  stream->WriteSharedString(&displayName);
  stream->WriteBytes(&statusCode, 2);
  stream->WriteBytes(&tileOrTerrainId, 4);
  stream->WriteBytes(&seedNationId, 2);
  stream->WriteBytes(&activeTileIndex, 2);
  stream->WriteBytes(&contextOrdinal, 2);
  stream->WriteBytes(&portTileIndex, 2);
}

// FUNCTION: IMPERIALISM 0x005618b0
void TPortZone::NameThyself(unsigned char* usedCityFlags, const char* overrideName) {
  short cityIndex = g_pGlobalMapState->terrainStateTable[portTileIndex].cityRecordIndex;
  Province* city = cityIndex == -1 ? 0 : &g_pGlobalMapState->cityScoreTable[cityIndex];
  CString headlineTemplate;
  CString expandedHeadline;
  g_pSimMgr->GetString(0x275a, statusCode, &headlineTemplate);
  scanBracketExpressions(g_pSimMgr, &expandedHeadline, static_cast<LPCSTR>(headlineTemplate),
                         static_cast<LPCSTR>(city->cityName));
  displayName = expandedHeadline;
}

// FUNCTION: IMPERIALISM 0x00561a70
void TPortZone::Free() {
  if (g_pGlobalMapState != 0) {
    if (activeTileIndex != -1) {
      g_pGlobalMapState->SetMapTileStateByteAndNotifyObserver(activeTileIndex, -1);
    }
    if (tileOrTerrainId != -1) {
      g_pGlobalMapState->SetMapTileStateByteAndNotifyObserver(static_cast<short>(tileOrTerrainId),
                                                              -1);
    }
  }
  if (g_pMapActionContextListHead == this) {
    g_pMapActionContextListHead = prevZone;
  }
  if (prevZone != 0) {
    prevZone->nextZone = nextZone;
  }
  if (nextZone != 0) {
    nextZone->prevZone = prevZone;
  }
  nextZone = 0;
  prevZone = 0;
  delete this;
}

// FUNCTION: IMPERIALISM 0x00561b10
bool TPortZone::IsFriendlyWith(NationSlot nationSlot) {
  return g_pGlobalMapState->terrainStateTable[portTileIndex].ownerNationTag == nationSlot;
}

// FUNCTION: IMPERIALISM 0x00561b50
bool TPortZone::IsEnemyOf(NationSlot nationSlot) {
  short ownerNation = g_pGlobalMapState->terrainStateTable[portTileIndex].ownerNationTag;
  return g_pDiplomacyTurnStateManager->AreInEstablishedWar(ownerNation, nationSlot);
}

// Returns the signed owner-nation tag for this port's coastal tile.
// FUNCTION: IMPERIALISM 0x00561bc0
short TPortZone::GetOriginalOwner() {
  return static_cast<short>(
      g_pGlobalMapState->terrainStateTable[portTileIndex].formerOwnerNationTag);
}

// Returns the final port-zone node in the global map-action-context chain.
// FUNCTION: IMPERIALISM 0x00561cc0
TPortZone* FindLastPortZoneInMapActionContextList() {
  TPortZone* lastPort = 0;
  for (TZone* zone = g_pMapActionContextListHead; zone != 0; zone = zone->prevZone) {
    if (zone->IsKindOf(RUNTIME_CLASS(TPortZone))) {
      lastPort = static_cast<TPortZone*>(zone);
    }
  }
  return lastPort;
}

// Finds the preceding port-zone node in the map-action-context chain.
// FUNCTION: IMPERIALISM 0x00561d80
TPortZone* TPortZone::GetPrevPort() {
  TZone* zone = prevZone;
  while (zone != 0 && !zone->IsKindOf(RUNTIME_CLASS(TPortZone))) {
    zone = zone->prevZone;
  }
  return static_cast<TPortZone*>(zone);
}

// FUNCTION: IMPERIALISM 0x00561dc0
bool TPortZone::CanBeTargetOf(TTaskForce* force) {
  bool zoneActive = distanceLevel > 0;
  if (zoneActive && force->location != this) {
    short ownerNation = g_pGlobalMapState->terrainStateTable[portTileIndex].ownerNationTag;
    if (force->nation == ownerNation ||
        g_pDiplomacyTurnStateManager->AreInEstablishedWar(ownerNation, force->nation)) {
      return true;
    }
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x00561e40
short TPortZone::PickPennantIngotTile() {
  short originTile = tileOrTerrainId;
  HexSpiralSearchState spiral;
  spiral.row = originTile / kStrategicMapColumns;
  spiral.col = originTile % kStrategicMapColumns;
  spiral.ring = 0;
  spiral.direction = 5;
  spiral.stepInRing = 1;
  TMapMgr::StepSpiral(&spiral);

  while (spiral.ring < 10) {
    short candidateTile = -1;
    if (spiral.row >= 0 && spiral.row < 60 && spiral.col >= 0 && spiral.col < 108) {
      candidateTile = static_cast<short>(spiral.col + spiral.row * 108);
    }
    if (candidateTile >= 0 && candidateTile < kStrategicTileCount) {
      TTerrainStateRecord& candidateRecord = g_pGlobalMapState->terrainStateTable[candidateTile];
      TZone* candidateContext = 0;
      if (candidateRecord.tileActionState == kMapTileActionStateAnchor ||
          candidateRecord.tileActionState == kMapTileActionStateDockedFleet) {
        candidateContext = TZone::GetFirstPort();
        while (candidateContext != 0 &&
               static_cast<short>(candidateContext->tileOrTerrainId) != candidateTile &&
               candidateContext->activeTileIndex != candidateTile &&
               static_cast<TPortZone*>(candidateContext)->portTileIndex != candidateTile) {
          candidateContext = candidateContext->GetNextPort();
        }
      } else {
        short nationCode = candidateRecord.ownerNationTag;
        if (nationCode >= kNationSlotCount) {
          candidateContext = &g_pActiveMapOrderContext->contextArray[nationCode - 0x17];
        }
      }

      TZone* expectedContext = primaryNeighbors[0];
      if (candidateContext == expectedContext && candidateRecord.tileActionState == -1) {
        return candidateTile;
      }
    }

    TMapMgr::StepSpiral(&spiral);
  }

  return -1;
}
