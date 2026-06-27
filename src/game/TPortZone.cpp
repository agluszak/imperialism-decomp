#include "game/TPortZone.h"

#include <new.h>

#include "game/mfc.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

extern "C" char g_pClassDescTPortZone = 0;

// FUNCTION: IMPERIALISM 0x005615e0
TPortZone* TPortZone::CreateTPortZone() {
  return new TPortZone();
}

TPortZone::TPortZone() : TZone() {
  field48 = -1;
}

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
TPortZone::~TPortZone() {}

// slot 0x00 — GetRuntimeClass override.
IMPLEMENT_DYNCREATE(TPortZone, TZone)

// slot 0x06 — TZone::ReadFrom override.
// FUNCTION: IMPERIALISM 0x005617f0
void TPortZone::ReadFrom(TStream* stream) {}

// slot 0x05 — TZone::WriteTo override.
// FUNCTION: IMPERIALISM 0x00561820
void TPortZone::WriteTo(TStream* stream) {}

// slot 0x0a — TZone::GenerateMapActionContextDisplayNameAndHeadline override.
// FUNCTION: IMPERIALISM 0x005618b0
void TPortZone::GenerateMapActionContextDisplayNameAndHeadline(int arg1, void* arg2) {}

// slot 0x07 — TZone::Free override.
// FUNCTION: IMPERIALISM 0x00561a70
void TPortZone::Free() {}

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
