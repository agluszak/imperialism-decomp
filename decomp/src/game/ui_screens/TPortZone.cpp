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

// slot 0x0d — TZone::QueryZoneCapabilityFlagA override.
// FUNCTION: IMPERIALISM 0x00561660
bool TPortZone::QueryZoneCapabilityFlagA() {
  return true;
}

// slot 0x0e — TZone::QueryPortZoneCapability override.
// FUNCTION: IMPERIALISM 0x00561680
bool TPortZone::QueryPortZoneCapability() {
  return true;
}

// slot 0x0f — TZone::QueryZoneCapabilityFlagC override.
// FUNCTION: IMPERIALISM 0x005616a0
bool TPortZone::QueryZoneCapabilityFlagC() {
  return false;
}

// FUNCTION: IMPERIALISM 0x005616f0
TPortZone::~TPortZone() {}

// slot 0x00 — GetRuntimeClass override.

IMPLEMENT_DYNCREATE(TPortZone, TZone)

// slot 0x06 — TZone::ReadFrom override.
// FUNCTION: IMPERIALISM 0x005617f0
void TPortZone::ReadFrom(TStream* stream) {
  TZone::ReadFrom(stream);
  stream->ReadBytes(&portTileIndex, 2);
}

// slot 0x05 — TZone::WriteTo override.
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

// slot 0x0a — TZone::NameThyself override.
// FUNCTION: IMPERIALISM 0x005618b0
void TPortZone::NameThyself(unsigned char* usedCityFlags, const char* overrideName) {
  (void)usedCityFlags;
  (void)overrideName;
  short cityIndex = g_pGlobalMapState->terrainStateTable[portTileIndex].cityRecordIndex;
  Province* city = cityIndex == -1 ? 0 : &g_pGlobalMapState->cityScoreTable[cityIndex];
  CString headlineTemplate;
  CString expandedHeadline;
  g_pSimMgr->GetString(0x275a, statusCode, &headlineTemplate);
  scanBracketExpressions(g_pSimMgr, &expandedHeadline, static_cast<LPCSTR>(headlineTemplate),
                         static_cast<LPCSTR>(city->cityNameA4));
  displayName = expandedHeadline;
}

// slot 0x07 — TZone::Free override.
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
    g_pMapActionContextListHead = prev18;
  }
  if (prev18 != 0) {
    prev18->next1c = next1c;
  }
  if (next1c != 0) {
    next1c->prev18 = prev18;
  }
  next1c = 0;
  prev18 = 0;
  delete this;
}

// FUNCTION: IMPERIALISM 0x00561b10
bool TPortZone::QueryZoneCapabilityFlagD(NationSlot nationSlot) {
  return g_pGlobalMapState->terrainStateTable[portTileIndex].ownerNationTag == nationSlot;
}

// FUNCTION: IMPERIALISM 0x00561b50
bool TPortZone::QueryZoneCapabilityFlagE(NationSlot nationSlot) {
  short ownerNation = g_pGlobalMapState->terrainStateTable[portTileIndex].ownerNationTag;
  return g_pDiplomacyTurnStateManager->IsNationPairRelationTurnStampOutOfDate(ownerNation,
                                                                              nationSlot);
}

// Returns the signed owner-nation tag for this port's coastal tile.
// FUNCTION: IMPERIALISM 0x00561bc0
short TPortZone::GetPortTileFormerOwnerNationSlot() {
  return static_cast<short>(
      g_pGlobalMapState->terrainStateTable[portTileIndex].formerOwnerNationTag);
}

// Returns the final port-zone node in the global map-action-context chain.
// FUNCTION: IMPERIALISM 0x00561cc0
TPortZone* FindLastPortZoneInMapActionContextList() {
  TPortZone* lastPort = 0;
  for (TZone* zone = g_pMapActionContextListHead; zone != 0; zone = zone->prev18) {
    if (zone->IsKindOf(RUNTIME_CLASS(TPortZone))) {
      lastPort = static_cast<TPortZone*>(zone);
    }
  }
  return lastPort;
}

// Finds the preceding port-zone node in the map-action-context chain.
// FUNCTION: IMPERIALISM 0x00561d80
TPortZone* TPortZone::FindPreviousPortZone() {
  TZone* zone = prev18;
  while (zone != 0 && !zone->IsKindOf(RUNTIME_CLASS(TPortZone))) {
    zone = zone->prev18;
  }
  return static_cast<TPortZone*>(zone);
}

// FUNCTION: IMPERIALISM 0x00561dc0
bool TPortZone::CanBeTargetOf(TTaskForce* force) {
  bool zoneActive = distanceLevel > 0;
  if (zoneActive && force->location != this) {
    short ownerNation = g_pGlobalMapState->terrainStateTable[portTileIndex].ownerNationTag;
    if (force->nation == ownerNation ||
        g_pDiplomacyTurnStateManager->IsNationPairRelationTurnStampOutOfDate(ownerNation,
                                                                             force->nation)) {
      return true;
    }
  }
  return false;
}

// slot 0x13 — TZone::FindNearestActiveSeaContextTileFromOffset216 override.
// FUNCTION: IMPERIALISM 0x00561e40
short TPortZone::FindNearestActiveSeaContextTileFromOffset216() {
  short originTile = static_cast<short>(tileOrTerrainId);
  HexSpiralSearchState spiral;
  spiral.row = originTile / 0x6c;
  spiral.col = originTile % 0x6c;
  spiral.ring = 0;
  spiral.direction = 5;
  spiral.stepInRing = 1;
  TMapMgr::AdvanceSpiralSearchStateAndStepHexCoordinates(&spiral);

  while (spiral.ring < 10) {
    short candidateTile = -1;
    if (spiral.row >= 0 && spiral.row < 60 && spiral.col >= 0 && spiral.col < 108) {
      candidateTile = static_cast<short>(spiral.col + spiral.row * 108);
    }
    if (candidateTile >= 0 && candidateTile < 0x1950) {
      TTerrainStateRecord& candidateRecord = g_pGlobalMapState->terrainStateTable[candidateTile];
      TZone* candidateContext = 0;
      if (candidateRecord.tileActionState16 == kMapTileActionStateAnchor ||
          candidateRecord.tileActionState16 == kMapTileActionStateDockedFleet) {
        candidateContext = TZone::GetFirstPortZone();
        while (candidateContext != 0 &&
               static_cast<short>(candidateContext->tileOrTerrainId) != candidateTile &&
               candidateContext->activeTileIndex != candidateTile &&
               static_cast<TPortZone*>(candidateContext)->portTileIndex != candidateTile) {
          candidateContext = candidateContext->GetNextPortZone();
        }
      } else {
        short nationCode = static_cast<short>(candidateRecord.ownerNationTag);
        if (nationCode >= 0x17) {
          candidateContext = &g_pActiveMapOrderContext->contextArray[nationCode - 0x17];
        }
      }

      TZone* expectedContext = primaryNeighbors[0];
      if (candidateContext == expectedContext && candidateRecord.tileActionState16 == -1) {
        return candidateTile;
      }
    }

    TMapMgr::AdvanceSpiralSearchStateAndStepHexCoordinates(&spiral);
  }

  return -1;
}
