#pragma once

#include "game/TObject.h"

// Global city-order capability table (singleton g_pCityOrderCapabilityState @ 0x006A43D8).
// VTABLE: IMPERIALISM 0x0066ad28
class TTechMgr : public TObject {
public:
  DECLARE_DYNCREATE(TTechMgr)
  TTechMgr();
  void WriteTo(TStream* stream) override;  // slot 0x14 (0x005af710)
  void ReadFrom(TStream* stream) override; // slot 0x18 (0x005af460)
  // Priority-slot IDs: 3 zero-initialized slots followed by 26 generated slots, each a
  // short capability-priority identifier written by GenerateRandomCapabilityPrioritySlots
  // and serialized by ReadFrom/WriteTo as the base capability block at +0x004 (0x3a bytes).
  short prioritySlots[29];
  // Per-nation/per-resourceType capability value table, index = nationTag*23 + resourceType
  // (row stride 23 shorts). Evidenced independently by three TMapMgr functions that all
  // read this exact formula off g_pCityOrderCapabilityState+0x3e: 0x513720, 0x5155c0,
  // 0x515890. Row count (7) matches g_apNationStates[7]; column count (23) matches the
  // resourceType range used throughout TMapMgr (see resourceTypeByEdge).
  short capabilityValueByNationAndResource[7][23];
  unsigned char pad180[0x193 - 0x180];
  unsigned char hasProductionOrder193;
  unsigned char pad194[0x1a5 - 0x194];
  unsigned char shipCapabilityFlag1a5;
  unsigned char pad1a6[2];
  unsigned char shipCapabilityFlag1a8;
  unsigned char pad1a9[0x1d4 - 0x1a9];
  short activeZoneIndex1d4;
  unsigned char pad1d6[0x1e8 - 0x1d6];
  struct NationCapRow {
    union {
      short cap;
      short caps[10];
    };
  };
  NationCapRow nationCapRows1e8[7];
  unsigned char pad274[0x277 - 0x274];
  struct OrderCapRow {
    unsigned char flag;
    unsigned char pad01[3];
    unsigned char recruitTierFlag27b;
    unsigned char pad05[3];
    // Read via MarkSeedNeighborTilesUnavailableByCapabilityMaskProfileA off THIS row
    // (row[nationTag], not the previous-row reads below) -- gates DAT_00696f0b.
    unsigned char unknownFlag27f;
    unsigned char secondaryCapabilityFlag280;
    unsigned char pad06a[10];
    // The two fields below are read by MarkSeedNeighborTilesUnavailableByCapabilityMaskProfileA
    // off orderCapRows277[nationTag - 1] (the *previous* nation's row) -- confirmed by address
    // arithmetic: the original reads absolute offsets 0x26e/0x274 with the same 29-byte
    // per-nation stride as this array, which lands 9/3 bytes before this row's base (0x277),
    // i.e. 20/26 bytes into the previous row. Gate DAT_00696f0c / DAT_00696f0a respectively.
    // For nationTag == 0 this reads out of this array's bounds, into the tail of
    // nationCapRows1e8[6] and pad274 -- reproduced faithfully via orderCapRows277[-1].
    unsigned char unknownFlag28b;
    unsigned char pad06b[5];
    unsigned char unknownFlag291;
    unsigned char pad06c[2];
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

  void ConstructCityOrderCapabilityStateVtable();
  void InitializeCityOrderCapabilityStateDefaults();
  void GenerateRandomCapabilityPrioritySlots();

  ~TTechMgr() override;
};
