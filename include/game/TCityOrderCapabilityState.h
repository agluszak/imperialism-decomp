#pragma once

#include "decomp_types.h"

// VTABLE: IMPERIALISM 0x0066ad28
// Global city-order capability table (singleton g_pCityOrderCapabilityState @ 0x006A43D8).
class TCityOrderCapabilityState {
public:
  unsigned char pad000[0x193];
  unsigned char hasProductionOrder193;
  unsigned char pad194[0x1a5 - 0x194];
  unsigned char shipCapabilityFlag1a5;
  unsigned char pad1a6[2];
  unsigned char shipCapabilityFlag1a8;
  unsigned char pad1a9[0x1d4 - 0x1a9];
  short activeZoneIndex1d4;
  unsigned char pad1d6[0x1e8 - 0x1d6];
  struct NationCapRow {
    short cap;
    unsigned char pad02[0x14 - 0x02];
  };
  NationCapRow nationCapRows1e8[7];
  unsigned char pad274[0x277 - 0x274];
  struct OrderCapRow {
    unsigned char flag;
    unsigned char pad01[0x1d - 0x01];
  };
  OrderCapRow orderCapRows277[7];
  unsigned char pad342[0x39d - 0x342];
  struct MilitaryCapRow {
    unsigned char recruitTierFlag;
    unsigned char pad01[7];
    unsigned char eliteRecruitFlag;
    unsigned char pad09[0x1e - 0x09];
  };
  MilitaryCapRow militaryCapRows39d[7];

  // FUNCTION: IMPERIALISM 0x005aef80
  void ConstructCityOrderCapabilityStateVtable();
  // FUNCTION: IMPERIALISM 0x005aeff0
  void InitializeCityOrderCapabilityStateDefaults();
};

extern TCityOrderCapabilityState* g_pCityOrderCapabilityState;
