#pragma once

#include "decomp_types.h"

extern "C" void* g_pCityOrderCapabilityState;

// Global city-order capability table (singleton at 0x006A43D8). Known fields are
// named; the record count of nationCapRows1e8 is still unconfirmed.
struct TCityOrderCapabilityState {
  unsigned char pad000[0x193];
  unsigned char hasProductionOrder193; // +0x193
  unsigned char pad194[0x1a5 - 0x194];
  unsigned char shipCapabilityFlag1a5; // +0x1a5 — averaged ship production (slot 0x90)
  unsigned char pad1a6[2];
  unsigned char shipCapabilityFlag1a8; // +0x1a8 — building-2 ship production (slot 0x90)
  unsigned char pad1a9[0x1d4 - 0x1a9];
  short activeZoneIndex1d4; // +0x1d4
  unsigned char pad1d6[0x1e8 - 0x1d6];
  struct NationCapRow {
    short cap; // +0x00 of each 0x14-byte row
    unsigned char pad02[0x14 - 0x02];
  };
  NationCapRow nationCapRows1e8[7]; // +0x1e8, one 0x14-byte row per major nation
  unsigned char pad274[0x277 - 0x274];
  struct OrderCapRow {
    unsigned char flag; // +0x00 of each 0x1d-byte row (status-flag-5 gate, slot 0x2b)
    unsigned char pad01[0x1d - 0x01];
  };
  OrderCapRow orderCapRows277[7]; // +0x277, one 0x1d-byte row per major nation
  unsigned char pad342[0x39d - 0x342];
  struct MilitaryCapRow {
    unsigned char recruitTierFlag; // +0x00 (file +0x39d) — recruit bonus 8 gate
    unsigned char pad01[7];
    unsigned char eliteRecruitFlag; // +0x08 (file +0x3a5) — recruit bonus 0x10 gate
    unsigned char pad09[0x1e - 0x09];
  };
  MilitaryCapRow militaryCapRows39d[7]; // +0x39d, one 0x1e-byte row per major nation
};

static __inline TCityOrderCapabilityState* CityOrderCapabilityState(void) {
  return static_cast<TCityOrderCapabilityState*>(g_pCityOrderCapabilityState);
}
static __inline short CityOrderCapForNation(short nationSlot) {
  return CityOrderCapabilityState()->nationCapRows1e8[nationSlot].cap;
}
static __inline short CityOrderActiveZoneIndex(void) {
  return CityOrderCapabilityState()->activeZoneIndex1d4;
}
