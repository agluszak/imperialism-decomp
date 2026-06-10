#pragma once

#include "decomp_types.h"

extern "C" void* g_pCityOrderCapabilityState;

// g_pCityOrderCapabilityState accessors (read-only data table, not a class region).
static __inline short CityOrderCapForNation(short nationSlot) {
  return *reinterpret_cast<short*>(reinterpret_cast<char*>(g_pCityOrderCapabilityState) +
                                   nationSlot * 0x14 + 0x1e8);
}
static __inline short CityOrderActiveZoneIndex(void) {
  return *reinterpret_cast<short*>(reinterpret_cast<char*>(g_pCityOrderCapabilityState) + 0x1d4);
}

// Per-zone recruit/secondary order counters on the relation-manager object (+0x894).
struct TRelationManagerOrderCountView {
  unsigned char pad00[0x5c];
  short recruitZoneCount5c[6]; // 0x5c..0x68, indexed by active zone
  short navySecondaryCount68;  // 0x68
};

struct TGreatPowerDiplomacyExternalStateView {
  unsigned char pad00[0x894];
  void* diplomacyExternalState894;
};
