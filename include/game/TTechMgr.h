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
  // Per-resource-type capability-enabled bytes (index = navy-order resource type,
  // 0..0xd -- the same 0xe domain as CapRowB below). RecomputeGlobalCapabilityAverages
  // (0x54fd50) indexes this dynamically ([0x19d + type]) to gate each type's
  // contribution to the g_aCategoryMetricBaselineAverage recompute, which is what
  // proves the region is one array. Defaults: types 0..4 = 1, rest 0; milestone techs
  // enable the higher types (ApplyCityOrderCapabilityUnlockByTechId). Former per-flag
  // names mapped to specific types:
  //   [0x5]=1a2  [0x6]=1a3  [0x7]=1a4  [0x8]=1a5 (ship)  [0x9]=1a6
  //   [0xa]=1a7  [0xb]=1a8 (ship)  [0xc]=1a9  [0xd]=1aa
  unsigned char resourceTypeEnabled19d[0xe];
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
  // Per-nation, per-tech research-status row (byte[techId]: 2 = researched, 1 = in
  // progress, 0 = not started). True base 0x268, stride 0x1d. The defaults initializer
  // sets techs 0..2 to 2 and zeroes the rest; readers index it dynamically by tech id
  // (0x5b0a20/0x5b0a90/0x5b12e0/0x5b192c). Specific tech ids gate named capabilities and
  // used to carry per-flag field names:
  //   [0x06] TMapMgr order gate (DAT_00696f0c)     [0x0b] intermediate fort (cap level 2)
  //   [0x0c] TMapMgr order gate (DAT_00696f0a)     [0x0f] engineer gate (0x277)
  //   [0x13] recruit tier (0x27b)                  [0x16] advanced fort (cap level 3)
  //   [0x17] TMapMgr order gate (DAT_00696f0b)     [0x18] secondary capability (0x280)
  // Fields formerly reached via orderCapRows277[nationTag - 1] (the apparent "previous
  // row", an artifact of the old +0xf phase) are just in-row bytes here.
  struct OrderCapRow {
    unsigned char techStatusByTechId[0x1d];
  };
  OrderCapRow orderCapRows277[7];
  // Per-nation selected-order-type row (true base 0x333, stride 0xe): one byte per
  // navy-order resource type (0..13), 1 = this type currently selected for the nation.
  // Init sets types [0..4] = 1; UpdateSelectionAndRecalculateScores (0x5b0500) clears
  // the same-group siblings (via GetResourceDescriptorWord20ByType) and sets the new one.
  struct CapRowB {
    unsigned char selectedByResourceType[0xe];
  };
  CapRowB capRowsB333[7];
  // Per-nation ability-activation row (byte[abilityId], ids 0..0x1d; true base 0x395,
  // tiling exactly between capRowsB333 and capRowsD467). ActivateSlotAndUpdateUI
  // (0x5b0340) sets [abilityId] on activation and clears the replaced slot's ability;
  // ResolveEraCapabilityFallbackSlot (0x5c35c0) probes candidate upgrades dynamically.
  // Defaults: ids 0..7 = 1 plus 0x18/0x1b = 1. Former per-flag names were specific ids:
  // [0x08] = recruit tier (0x39d gate), [0x10] = elite recruit (0x3a5 gate).
  struct MilitaryCapRow {
    unsigned char abilityActiveById[0x1e];
  };
  MilitaryCapRow abilityActiveRows395[7];
  // Per-nation table D (true base 0x467, stride 9); init-only.
  struct CapRowD {
    unsigned char flags[9]; // init: [0,1,2,4,7] = 1, rest 0
  };
  CapRowD capRowsD467[7];
  // Per-nation table E (true base 0x4a6, stride 0x3a = 0x1d shorts); init zeroes it. Ends
  // at the real 0x63c allocation size. Per-tech completion-year offset, added to the 0x717
  // base year by the tech-item completion-date line (0x5b12e0).
  struct CapRowE {
    short completionYearOffsetByTechId[0x1d];
  };
  CapRowE capRowsE4a6[7];

  void ConstructCityOrderCapabilityStateVtable();
  void InitializeCityOrderCapabilityStateDefaults();
  void GenerateRandomCapabilityPrioritySlots();
  void ApplyCityOrderCapabilityUnlockByTechId(int nTechId);
  int GetNationFortLevelCap(int nNationId);
  // True when both prerequisite techs of `techId` (from g_aTechItemPrerequisitePairs;
  // 0 = none, and status byte 0 is always 2) are researched for the nation. 0x5b0a20.
  bool AreTechItemPrerequisitePairCompleted(int techId, int nationSlot);
  // Writes the not-yet-researched prerequisites of `techId` for the nation: if the first
  // is done, missing1 = the second (0 if none) and missing2 = 0; otherwise missing1 = the
  // first and missing2 = the second if it is also unresearched. 0x5b0a90.
  void SelectMissingTechItemPrerequisitesFromPair(int techId, int nationSlot, int* missing1,
                                                  int* missing2);
  // Activates an ability in its slot group for a nation: marks it active, records it in
  // nationCapRows1e8[nation].slots[group], and for unit-order groups (1..8) reloads the
  // city's TUnitOrder cost profile; for other groups upgrades matching military units.
  // 0x5b0340, __thiscall, RET 0x8.
  void ActivateSlotAndUpdateUI(int abilityId, int nationSlot);
  // Reselects a nation's navy-order resource type: flips the capRowsB333 selection
  // bytes (clearing same-group types), retargets the city's unit-order slot for the
  // type's group, then reprocesses every matching primary navy-order node (prune +
  // admiral relink), posts the "orders changed" message when the active nation is
  // affected, and redistributes the freed score across the remaining owned nodes.
  // 0x5b0500, __thiscall, RET 0x8.
  void UpdateSelectionAndRecalculateScores(int resourceType, int nationSlot);

  ~TTechMgr() override;
};
