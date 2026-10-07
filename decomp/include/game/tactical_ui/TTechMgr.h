#pragma once

#include "game/nation_domain_types.h"
#include "compat.h"

#include "game/app/TObject.h"
#include "game/tactical_ui/TechPrerequisitePair.h"

// Global city-order capability table (singleton g_pTechMgr @ 0x006A43D8).
// VTABLE: IMPERIALISM 0x0066ad28
class TTechMgr : public TObject {
public:
  enum { kProductionOrderTechId = 0x13 };

  DECLARE_DYNCREATE(TTechMgr)
  TTechMgr();
  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;
  short prioritySlots[29];
  short capabilityValueByNationAndResource[7][23];
  unsigned char perTechUnlockFlag[29];
  unsigned char resourceTypeEnabled[14];
  unsigned char initFlags1ab[4]; // defaults initializer sets all four to 1
  unsigned char initFlags1af[4]; // set to 1
  unsigned char pad1b3[0x1c3 - 0x1b3];
  bool flag1c3; // set to 1
  unsigned char pad1c4[0x1c9 - 0x1c4];
  unsigned char initFlags1c9[9]; // defaults initializer sets bytes {0,1,2,4,7} = 1, rest 0
  // Paired capability selector shorts updated at specific unlock milestones.
  short techSelectorShort;
  short activeZoneIndex;
  struct NationCapRow {
    short slots[10];
  };
  NationCapRow nationCapRows1e8[kMajorNationCount];
  short marker262;
  TechPrerequisitePair activePrerequisitePair;
  struct OrderCapRow {
    unsigned char techStatusByTechId[29];
  };
  OrderCapRow orderCapRows277[7];
  struct CapRowB {
    unsigned char selectedByResourceType[14];
  };
  CapRowB capRowsB333[7];
  struct MilitaryCapRow {
    unsigned char abilityActiveById[30];
  };
  MilitaryCapRow abilityActiveRows[7];
  struct UniversityRecruitmentAvailabilityRow {
    unsigned char availableByCategory[9];
  };
  UniversityRecruitmentAvailabilityRow universityRecruitmentAvailabilityByNation[kMajorNationCount];
  struct CapRowE {
    short completionYearOffsetByTechId[29];
  };
  CapRowE capRowsE4a6[7];

  void ITechMgr();
  void GenerateTables();
  void CheckForAdvances();
  void ActivateAdvance(int techId, int forcedNationSlot);
  void UniversalActivation(int nTechId);
  void PurchaseTech(int slot, int nationIndex);
  void CancelPurchase(int slot, int nationIndex);
  // Stores value*4 into prioritySlots[index] (the "Tyer" turn-instruction handler)
  void SetAdvanceDate(int index, int value);
  int GetBestFort(int nNationId);
  bool HavePreReqs(int techId, int nationSlot);
  void GetPreReqs(int techId, int nationSlot, int* missingPrimaryTechId,
                  int* missingSecondaryTechId);
  void ActivateLandUnit(int abilityId, int nationSlot);
  void ActivateShip(int resourceType, int nationSlot);
  void GeneralActivation(int techId, int nationSlot);
  short GetNextNewAdvance(short nationSlot);

  ~TTechMgr() override;
};
ASSERT_SIZE(TTechMgr, 0x63c);

short GetEnabledIndustryCapabilitySlotByClass(short classId);
