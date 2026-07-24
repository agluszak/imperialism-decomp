#pragma once

#include "game/city/TProductionOrder.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TStream;
class TCity;

// Stored as a 16-bit value in TUnitOrder and its serialized cost profiles. The
// numeric value is also the population-strength divisor used by the armory UI.
enum eUnitOrderWorkforceMode {
  kLowSkillWorkforceMode = 1,
  kMediumSkillWorkforceMode = 2,
  kHighSkillWorkforceMode = 4
};

// VTABLE: IMPERIALISM 0x0064f8a0
class TUnitOrder : public TProductionOrder {
public:
  DECLARE_DYNCREATE(TUnitOrder)
  virtual ~TUnitOrder() override;                   // slot 0x01 (scalar deleting destructor)
  virtual void WriteTo(TStream* stream) override;   // slot 0x05 0x4b7850
  virtual void ReadFrom(TStream* stream) override;  // slot 0x06 0x4b7920
  virtual bool SetQuantity(short param_1) override; // slot 0x0b 0x4b7210
  virtual short MaxOrder() override;                // slot 0x0c 0x4b7080

  // Loads one g_aUnitOrderCostProfileByAbilityId row into the order's cost fields
  // (called by TTechMgr::ActivateSlotAndUpdateUI when an ability activates a slot).
  // 0x4b77e0, __thiscall, RET 0x1c.
  void SetOrderCostProfile(short resourceTypeIndex, short primaryInputResourceId,
                           short primaryInputPerUnit, short secondaryInputResourceId,
                           short secondaryInputPerUnit, short cashCostPerUnit, short workforceMode);
  virtual void Produce() override; // slot 0x0d 0x4b73b0
  virtual void FillOrderSheet(OrderSheet* orderSheet,
                              short quantity) override; // slot 0x10 0x4b7320
  virtual void InitializeCityRecruitmentOrderContext(
      TCity* city, short nEntryId, short nPrimaryInputResourceId, short nPrimaryInputPerUnit,
      short nSecondaryInputResourceId, short nSecondaryInputPerUnit, short nCashCostPerUnit,
      short nWorkforceMode, byte bSpecialistMode); // slot 0x11 0x4b6fe0
  // TUnitOrder adds 0x10 bytes (0x4c..0x5c) over TProductionOrder's 0x4c base. All are
  // written by the slot-0x11 init InitializeCityRecruitmentOrderContext (0x004b6fe0),
  // so the roles are that init's own named parameters (recruit/training recipe: two
  // input resources with per-unit rates, a cash cost, a workforce mode and a
  // specialist flag).
  short primaryInputResourceId;   // 0x4c — nPrimaryInputResourceId
  short secondaryInputResourceId; // 0x4e — nSecondaryInputResourceId
  short primaryInputPerUnit;      // 0x50 — nPrimaryInputPerUnit
  short secondaryInputPerUnit;    // 0x52 — nSecondaryInputPerUnit
  short cashCostPerUnit;          // 0x54 — nCashCostPerUnit
  short workforceMode;            // 0x56 — serialized eUnitOrderWorkforceMode value
  unsigned char specialistMode;   // 0x58 — bSpecialistMode
  unsigned char pad59[0x5c - 0x59];

  // NOOP: verified empty in original 0x004b6f22 (no standalone TUnitOrder::TUnitOrder body exists: construction is fully inlined into CreateObject 0x004b6f20; that address is its operator-new call site)
  TUnitOrder() {}
};

ASSERT_SIZE(TUnitOrder, 0x5c);
