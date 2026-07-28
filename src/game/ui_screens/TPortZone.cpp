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

// SYNTHETIC: IMPERIALISM 0x005615e0
// TPortZone::CreateObject

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

// SYNTHETIC: IMPERIALISM 0x005616c0
// TPortZone::`scalar deleting destructor'
//
// TPortZone has no members of its own to destruct, so this body is empty; the original
// inlined TZone::~TZone's real cleanup body (0x5627a0) directly here instead of calling
// it out-of-line, the same compiler-inlining divergence documented elsewhere this
// session (e.g. TEscortMission::CreateObject).
// FUNCTION: IMPERIALISM 0x005616f0
TPortZone::~TPortZone() {}

// slot 0x00 — GetRuntimeClass override.
// SYNTHETIC: IMPERIALISM 0x005617d0
// TPortZone::GetRuntimeClass

IMPLEMENT_DYNCREATE(TPortZone, TZone)

// slot 0x06 — TZone::ReadFrom override.
// FUNCTION: IMPERIALISM 0x005617f0
void TPortZone::ReadFrom(TStream* stream) {
  TZone::ReadFrom(stream);
  stream->ReadBytes(&portTileIndex48, 2);
}

// slot 0x05 — TZone::WriteTo override.
// FUNCTION: IMPERIALISM 0x00561820
void TPortZone::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  stream->WriteSharedString(&displayName);
  stream->WriteBytes(&statusCode04, 2);
  stream->WriteBytes(&tileOrTerrainId0c, 4);
  stream->WriteBytes(&seedNationId12, 2);
  stream->WriteBytes(&activeTileIndex20, 2);
  stream->WriteBytes(&contextOrdinal14, 2);
  stream->WriteBytes(&portTileIndex48, 2);
}

// slot 0x0a — TZone::GenerateMapActionContextDisplayNameAndHeadline override.
// FUNCTION: IMPERIALISM 0x005618b0
void TPortZone::GenerateMapActionContextDisplayNameAndHeadline(unsigned char* usedCityFlags,
                                                               const char* overrideName) {
  (void)usedCityFlags;
  (void)overrideName;
  short cityIndex = g_pGlobalMapState->terrainStateTable[portTileIndex48].cityRecordIndex;
  Province* city = cityIndex == -1 ? 0 : &g_pGlobalMapState->cityScoreTable[cityIndex];
  CString headlineTemplate;
  CString expandedHeadline;
  g_pSimMgr->GetString(0x275a, statusCode04, &headlineTemplate);
  scanBracketExpressions(g_pSimMgr, &expandedHeadline, static_cast<LPCSTR>(headlineTemplate),
                         static_cast<LPCSTR>(city->cityNameA4));
  displayName = expandedHeadline;
}

// slot 0x07 — TZone::Free override.
// FUNCTION: IMPERIALISM 0x00561a70
void TPortZone::Free() {
  if (g_pGlobalMapState != 0) {
    if (activeTileIndex20 != -1) {
      g_pGlobalMapState->SetMapTileStateByteAndNotifyObserver(activeTileIndex20, -1);
    }
    if (tileOrTerrainId0c != -1) {
      g_pGlobalMapState->SetMapTileStateByteAndNotifyObserver(static_cast<short>(tileOrTerrainId0c),
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

// slot 0x10 — TZone::QueryZoneCapabilityFlagD override. The port belongs to nationSlot
// when the owner tag of its tile matches; the tag is a signed byte widened to 16 bits,
// so the compare is 16-bit (`CMP AX, word ptr [ESP+4]`), not int.
// FUNCTION: IMPERIALISM 0x00561b10
bool TPortZone::QueryZoneCapabilityFlagD(NationSlot nationSlot) {
  return g_pGlobalMapState->terrainStateTable[portTileIndex48].ownerNationTag04 == nationSlot;
}

// slot 0x11 — TZone::QueryZoneCapabilityFlagE override. Same owner tag as slot 0x10, but
// asks the diplomacy manager about the (owner, caller) pair instead of demanding identity.
// FUNCTION: IMPERIALISM 0x00561b50
bool TPortZone::QueryZoneCapabilityFlagE(NationSlot nationSlot) {
  short ownerNation = g_pGlobalMapState->terrainStateTable[portTileIndex48].ownerNationTag04;
  return g_pDiplomacyTurnStateManager->IsNationPairRelationTurnStampOutOfDate(ownerNation,
                                                                              nationSlot);
}

// slot 0x12 — TZone::HasZoneActiveChildCount override. Keeps the base's distance-level
// test, then rejects the force's own location and accepts the port only when the force's
// nation owns it or the diplomacy manager relates the pair.
// FUNCTION: IMPERIALISM 0x00561dc0
bool TPortZone::HasZoneActiveChildCount(TTaskForce* force) {
  bool zoneActive = distanceLevel44 > 0;
  if (zoneActive && force->location != this) {
    short ownerNation = g_pGlobalMapState->terrainStateTable[portTileIndex48].ownerNationTag04;
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
  short originTile = static_cast<short>(tileOrTerrainId0c);
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
      TTerrainStateRecordView& candidateRecord =
          g_pGlobalMapState->terrainStateTable[candidateTile];
      TZone* candidateContext = 0;
      if (candidateRecord.tileActionState16 == kMapTileActionStateAnchor ||
          candidateRecord.tileActionState16 == kMapTileActionStateDockedFleet) {
        candidateContext = TZone::GetFirstPortZone();
        while (candidateContext != 0 &&
               static_cast<short>(candidateContext->tileOrTerrainId0c) != candidateTile &&
               candidateContext->activeTileIndex20 != candidateTile &&
               static_cast<TPortZone*>(candidateContext)->portTileIndex48 != candidateTile) {
          candidateContext = candidateContext->GetNextPortZone();
        }
      } else {
        short nationCode = static_cast<short>(candidateRecord.ownerNationTag04);
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
