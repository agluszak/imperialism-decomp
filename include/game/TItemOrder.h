#pragma once

#include "game/TProductionOrder.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TStream;

// VTABLE: IMPERIALISM 0x0064f958
class TItemOrder : public TProductionOrder {
public:
  // === BEGIN GENERATED DECLS (TItemOrder) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TItemOrder)
  virtual ~TItemOrder() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x4b5670
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x4b5710
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a InitializeBasicCityOrderContext inherited unchanged (0x4b4f70)
  virtual bool SetQuantity(short param_1) override;                // slot 0x0b 0x4b53d0
  virtual short MaxOrder() override;                               // slot 0x0c 0x4b5310
  virtual undefined CommitIfPending() override;                    // slot 0x0d 0x4b5580
  virtual undefined ResetCityOrderItemDerivedStateNoop() override; // slot 0x0e 0x4b5620
  // slot 0x0f Produce inherited unchanged (0x4b5180)
  virtual void FillOrderSheet(OrderSheet* orderSheet,
                              short quantity) override; // slot 0x10 0x4b5510
  virtual undefined
  InitializeCityProductionState_Impl_At004b5290(int param_1, undefined2 param_2, undefined2 param_3,
                                                undefined2 param_4,
                                                undefined2 param_5); // slot 0x11 0x4b5290
  // === END GENERATED DECLS (TItemOrder) ===
  // TItemOrder is 0x54 bytes vs. TProductionOrder's 0x4c (RTTI), adding four shorts
  // (0x4c..0x54), all written by the slot-0x11 init
  // InitializeCityProductionState_Impl (0x004b5290). Unlike TUnitOrder (whose 0x4c is
  // an input-resource id), TItemOrder zeroes 0x4c at init and only fills 0x4e/0x50/0x52
  // from its params, so 0x4c is a runtime-derived field. Names hedged by offset.
  short field4c; // 0x4c — zeroed at init; SetQuantity (0x004b53d0) writes a derived value here
  short
      field4e; // 0x4e — init param_3; read by MaxOrder / CommitIfPending / FillOrderSheet as an input requirement
  short field50; // 0x50 — init param_4 (tested vs 0); read by the same cost/max calcs
  short
      buildingSlot; // 0x52 — building slot id (init param_5); read by TIndustryAmtBar / TIndustryCluster

  TItemOrder();
};

ASSERT_SIZE(TItemOrder, 0x54);
