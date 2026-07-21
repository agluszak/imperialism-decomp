#pragma once

#include "game/TProductionOrder.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064f620
class TPopGrowthOrder : public TProductionOrder {
public:
  DECLARE_DYNCREATE(TPopGrowthOrder)
  virtual ~TPopGrowthOrder() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x4b4fe0)
  // slot 0x06 ReadFrom inherited unchanged (0x4b5060)
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a IProductionOrder inherited unchanged (0x4b4f70)
  virtual bool SetQuantity(short param_1) override; // slot 0x0b 0x4b8230
  virtual short MaxOrder() override;                // slot 0x0c 0x4b81b0
  virtual void Produce() override;                  // slot 0x0d 0x4b82f0
  virtual void Restock() override;                  // slot 0x0e 0x4b8420
  // slot 0x0f ResetOrderSheet inherited unchanged (0x4b5180)
  virtual void FillOrderSheet(OrderSheet* orderSheet,
                              short quantity) override; // slot 0x10 0x4b8440
  // Field-initialization body for the manual-alloc construction path (mirrors
  // TCapacityOrder's ICapacityOrder at the analogous
  // sibling slot): sets quantityField04/cityField08/summaryField0c from `city`, zeroes
  // trackingSlots10/field3e/field40/accumulatedValue, and seeds resourceTypeIndex48 = 1.
  // No current caller in ported code (manual or autogen); kept as a virtual at its
  // existing slot rather than eliminated, since there is no evidence either way whether
  // the original dispatches it via vtable or a direct call, and this class has a prior
  // revert history from vtable-signature mistakes (bd imperialism-decomp-1uj.39).
  virtual void IPopGrowthOrder(TCity* city); // slot 0x11 0x4b8160, Mac-style second-phase init

  TPopGrowthOrder();
};
