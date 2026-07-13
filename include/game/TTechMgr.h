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
  // Capability-priority selection slots (absolute this+0x4..0x3e). The first declared data
  // member sits 4 bytes into the object -- after the inherited TObject/CObject vtable pointer
  // -- so prioritySlots04[0] is at this+0x4 (verified empirically: the field below must land
  // at this+0x3e). GenerateRandomCapabilityPrioritySlots zeroes slots [0..2] then fills
  // [3..28] with unique random priority ids.
  short prioritySlots04[0x1d];
  // Per-nation/per-resourceType capability value table, index = nationTag*23 + resourceType
  // (row stride 23 shorts). Evidenced independently by three TMapMgr functions that all
  // read this exact formula off g_pCityOrderCapabilityState+0x3e: 0x513720, 0x5155c0,
  // 0x515890. Row count (7) matches g_apNationStates[7]; column count (23) matches the
  // resourceType range used throughout TMapMgr (see resourceTypeByEdge).
  short capabilityValueByNationAndResource[7][23];
  // Per-tech unlock flags, indexed by tech id (ApplyCityOrderCapabilityUnlockByTechId writes
  // perTechUnlockFlag180[nTechId] = 1). The declared span covers ids 0..0x12; higher ids the
  // original also marks here run one-past into hasProductionOrder193 and pad194 (intentional,
  // matching the flat write in the original -- see the sibling out-of-bounds reads below).
  unsigned char perTechUnlockFlag180[0x13];
  unsigned char hasProductionOrder193;
  unsigned char pad194[0x1a2 - 0x194];
  // City-order capability flags toggled as milestone techs are applied (each set to 1).
  unsigned char capabilityFlag1a2;
  unsigned char capabilityFlag1a3;
  unsigned char capabilityFlag1a4;
  unsigned char shipCapabilityFlag1a5;
  unsigned char capabilityFlag1a6;
  unsigned char capabilityFlag1a7;
  unsigned char shipCapabilityFlag1a8;
  unsigned char capabilityFlag1a9;
  unsigned char capabilityFlag1aa;
  unsigned char pad1ab[0x1d2 - 0x1ab];
  // Paired capability selector shorts updated at specific unlock milestones.
  short techSelectorShort1d2;
  short activeZoneIndex1d4;
  unsigned char pad1d6[0x1e8 - 0x1d6];
  struct NationCapRow {
    union {
      short cap;
      short caps[10];
      // On the special last row (index 6) the active-tech marker sits at caps[1] and a
      // 4-byte city-order rule-table pointer overlays caps[2..3]; expose it as a typed
      // member so the pointer write needs no reinterpret_cast.
      struct {
        short reserved[2];
        unsigned int ruleTablePointer264;
      } techState;
    };
  };
  NationCapRow nationCapRows1e8[7];
  unsigned char pad274[0x277 - 0x274];
  struct OrderCapRow {
    unsigned char flag;
    unsigned char pad01[3];
    unsigned char recruitTierFlag27b;
    unsigned char pad05[2];
    // Advanced-fortification flag (row offset +7). GetNationFortLevelCap reads it off
    // orderCapRows277[nationId]; when set the nation's fort cap is level 3.
    unsigned char advancedFortFlag;
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
    unsigned char pad06b[4];
    // Intermediate-fortification flag (row offset +25). GetNationFortLevelCap reads it off
    // the *previous* nation's row (orderCapRows277[nationId - 1]); when set the fort cap is
    // level 2. For nation 0 this resolves into pad274 / nationCapRows1e8 tail (documented
    // out-of-bounds read, same as the previous-row gates above).
    unsigned char intermediateFortFlag;
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
  void ApplyCityOrderCapabilityUnlockByTechId(int nTechId);
  int GetNationFortLevelCap(int nNationId);

  ~TTechMgr() override;
};
