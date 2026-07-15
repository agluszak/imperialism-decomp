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
  unsigned char pad194[0x19d - 0x194];
  unsigned char initFlags19d[4]; // defaults initializer sets all four to 1
  unsigned char initFlag1a1;     // set to 1
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
  unsigned char initFlags1ab[4]; // defaults initializer sets all four to 1
  unsigned char initFlags1af[4]; // set to 1
  unsigned char pad1b3[0x1c3 - 0x1b3];
  unsigned char flag1c3; // set to 1
  unsigned char pad1c4[0x1c9 - 0x1c4];
  unsigned char initFlags1c9[9]; // defaults initializer sets bytes {0,1,2,4,7} = 1, rest 0
  // Paired capability selector shorts updated at specific unlock milestones.
  short techSelectorShort1d2;
  short activeZoneIndex1d4;
  // Per-nation capability-slot table (true record base 0x1d6, stride 0x14 = 10 shorts). The
  // defaults initializer fills slots[0..7] = 0..7, slots[8] = 0x18, slots[9] = 0x1b. Gameplay
  // readers historically indexed this table from +0x12 (naming it "nationCapRows1e8" and
  // reading .cap/.caps[]); .cap is slots[9] and .caps[i] is slots[9 + i] in this true frame.
  struct NationCapRow {
    short slots[10];
  };
  NationCapRow nationCapRows1e8[7];
  // 0x262 active-tech marker + 0x264 city-order rule-table pointer (the 6-byte gap that sits
  // between the two per-nation tables). ApplyCityOrderCapabilityUnlockByTechId and the defaults
  // initializer write these; a stray reader used to reach 0x262 as nationCapRows1e8[6].caps[1].
  short marker262;
  unsigned int ruleTablePointer264;
  struct OrderCapRow {
    // True per-nation order record base 0x268, stride 0x1d. The defaults initializer sets the
    // first three bytes to 2 and zeroes the rest; the named flags below sit at their real
    // in-record offsets. Fields formerly reached via orderCapRows277[nationTag - 1] (the
    // apparent "previous row", an artifact of the old +0xf phase) are just in-record fields
    // here, read as orderCapRows277[nationTag].
    unsigned char initReadyFlag[3]; // +0x00
    unsigned char pad03[3];
    unsigned char unknownFlag28b; // +0x06 (TMapMgr gate DAT_00696f0c)
    unsigned char pad07[4];
    unsigned char intermediateFortFlag; // +0x0b (GetNationFortLevelCap level 2)
    unsigned char unknownFlag291;       // +0x0c (TMapMgr gate DAT_00696f0a)
    unsigned char pad0d[2];
    unsigned char flag; // +0x0f (0x277)
    unsigned char pad10[3];
    unsigned char recruitTierFlag27b; // +0x13 (0x27b)
    unsigned char pad14[2];
    unsigned char advancedFortFlag;           // +0x16 (0x27e; GetNationFortLevelCap level 3)
    unsigned char unknownFlag27f;             // +0x17 (0x27f; TMapMgr gate DAT_00696f0b)
    unsigned char secondaryCapabilityFlag280; // +0x18 (0x280)
    unsigned char pad19[4];
  };
  OrderCapRow orderCapRows277[7];
  // Per-nation table B (true base 0x333, stride 0xe); init-only, no gameplay readers yet.
  struct CapRowB {
    unsigned char flags[5]; // init sets [0..4] = 1
    unsigned char pad05[9];
  };
  CapRowB capRowsB333[7];
  struct MilitaryCapRow {
    // True per-nation military record base 0x395, stride 0x1e. recruitTierFlag/eliteRecruitFlag
    // keep their absolute addresses (0x39d/0x3a5) at these in-record offsets.
    unsigned char initFlags[8];    // +0x00 (init sets [0..7] = 1)
    unsigned char recruitTierFlag; // +0x08 (0x39d)
    unsigned char pad09[7];
    unsigned char eliteRecruitFlag; // +0x10 (0x3a5)
    unsigned char pad11[7];
    unsigned char initFlag18; // +0x18 (init = 1)
    unsigned char pad19[2];
    unsigned char initFlag1b; // +0x1b (init = 1)
    unsigned char pad1c[2];
  };
  MilitaryCapRow militaryCapRows39d[7];
  // Per-nation table D (true base 0x467, stride 9); init-only.
  struct CapRowD {
    unsigned char flags[9]; // init: [0,1,2,4,7] = 1, rest 0
  };
  CapRowD capRowsD467[7];
  // Per-nation table E (true base 0x4a6, stride 0x3a); init zeroes it. Ends at the real 0x63c
  // allocation size.
  struct CapRowE {
    unsigned char bytes[0x3a];
  };
  CapRowE capRowsE4a6[7];

  void ConstructCityOrderCapabilityStateVtable();
  void InitializeCityOrderCapabilityStateDefaults();
  void GenerateRandomCapabilityPrioritySlots();
  void ApplyCityOrderCapabilityUnlockByTechId(int nTechId);
  // True iff both capability flags of tech prerequisite-pair `prereqPairIndex` are
  // completed (== 2) in nation `nationIndex`'s orderCapRows277 row. 0x5b0a20.
  unsigned char AreTechItemPrerequisitePairCompleted(int prereqPairIndex, int nationIndex);
  // Reports the not-yet-completed capability field offsets of a prerequisite pair for a
  // nation into *outFirst/*outSecond (0 = none). 0x5b0a90.
  void SelectMissingTechItemPrerequisitesFromPair(int prereqPairIndex, int nationIndex,
                                                  int* outFirst, int* outSecond);
  // Purchase / refund a tech-item slot for a nation (spends/refunds the slot cost, sets or
  // clears the orderCapRows277 state byte + capRowsE4a6 tick word). 0x5b0b30 / 0x5b0bb0.
  void ApplyTechItemPurchaseCostAndState(int slot, int nationIndex);
  void RefundTechItemPurchaseCostAndClearState(int slot, int nationIndex);
  // Stores value*4 into prioritySlots04[index] (the "Tyer" turn-instruction handler). 0x5b0c70
  void SetCityOrderCapabilityTierScaledValueByIndex(int index, int value);
  int GetNationFortLevelCap(int nNationId);

  ~TTechMgr() override;
};
