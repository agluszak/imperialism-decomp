#include "game/TPortZone.h"

#include <new.h>

#include "game/TMapMgr.h"
#include "game/TSimMgr.h"
#include "game/TStream.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/mapped_flavor_text.h"
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
  stream->streamSlotAc(&displayName);
  stream->WriteBytesSlot78(&statusCode04, 2);
  stream->WriteBytesSlot78(&tileOrTerrainId0c, 4);
  stream->WriteBytesSlot78(&seedNationId12, 2);
  stream->WriteBytesSlot78(&activeTileIndex20, 2);
  stream->WriteBytesSlot78(&contextOrdinal14, 2);
  stream->WriteBytesSlot78(&portTileIndex48, 2);
}

// slot 0x0a — TZone::GenerateMapActionContextDisplayNameAndHeadline override.
// FUNCTION: IMPERIALISM 0x005618b0
void TPortZone::GenerateMapActionContextDisplayNameAndHeadline(void* usedCityFlags,
                                                               void* overrideName) {
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

// slot 0x10 — TZone::QueryZoneCapabilityFlagD override.
// FUNCTION: IMPERIALISM 0x00561b10
bool TPortZone::QueryZoneCapabilityFlagD(int unused) {
  return false;
}

// slot 0x11 — TZone::QueryZoneCapabilityFlagE override.
// FUNCTION: IMPERIALISM 0x00561b50
bool TPortZone::QueryZoneCapabilityFlagE(int unused) {
  return false;
}

// slot 0x12 — TZone::HasZoneActiveChildCount override.
// FUNCTION: IMPERIALISM 0x00561dc0
bool TPortZone::HasZoneActiveChildCount(int unused) {
  return false;
}

// slot 0x13 — TZone::FindNearestActiveSeaContextTileFromOffset216 override.
// FUNCTION: IMPERIALISM 0x00561e40
short TPortZone::FindNearestActiveSeaContextTileFromOffset216() {
  return 0;
}
