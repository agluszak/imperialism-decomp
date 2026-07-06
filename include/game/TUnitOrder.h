#pragma once

#include "game/TProductionOrder.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TStream;

// TODO(manifest): describe TUnitOrder and its role. Base edge (TProductionOrder) recovered from RTTI CRuntimeClass chain: TUnitOrder -> TProductionOrder -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0064f8a0
class TUnitOrder : public TProductionOrder {
public:
  // === BEGIN GENERATED DECLS (TUnitOrder) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TUnitOrder)
  virtual ~TUnitOrder(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x4b7850
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x4b7920
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a InitializeBasicCityOrderContext inherited unchanged (0x4b4f70)
  virtual bool SetQuantity(short param_1) override; // slot 0x0b 0x4b7210
  virtual short MaxOrder() override;                // slot 0x0c 0x4b7080
  virtual undefined CommitIfPending() override;     // slot 0x0d 0x4b73b0
  // slot 0x0e ResetCityOrderItemDerivedStateNoop inherited unchanged (0x4b5140)
  // slot 0x0f Produce inherited unchanged (0x4b5180)
  virtual undefined FillOrderSheet() override; // slot 0x10 0x4b7320
  virtual void InitializeCityRecruitmentOrderContext(
      void* pCityState, short nEntryId, short nPrimaryInputResourceId, short nPrimaryInputPerUnit,
      short nSecondaryInputResourceId, short nSecondaryInputPerUnit, short nCashCostPerUnit,
      short nWorkforceMode, byte bSpecialistMode); // slot 0x11 0x4b6fe0
                                                   // === END GENERATED DECLS (TUnitOrder) ===
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
  short workforceMode;            // 0x56 — nWorkforceMode
  unsigned char specialistMode;   // 0x58 — bSpecialistMode
  unsigned char pad59[0x5c - 0x59];

  TUnitOrder();
};

ASSERT_SIZE(TUnitOrder, 0x5c);

