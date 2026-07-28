#pragma once

#include "compat.h"

#include "game/city/TProductionOrder.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064f620
class TPopGrowthOrder : public TProductionOrder {
public:
  DECLARE_DYNCREATE(TPopGrowthOrder)
  virtual ~TPopGrowthOrder() override;               // slot 0x01 (scalar deleting destructor)
  virtual bool SetQuantity(short quantity) override; // slot 0x0b 0x4b8230
  virtual short MaxOrder() override;                 // slot 0x0c 0x4b81b0
  virtual void Produce() override;                   // slot 0x0d 0x4b82f0
  virtual void Restock() override;                   // slot 0x0e 0x4b8420
  virtual void FillOrderSheet(OrderSheet* orderSheet,
                              short quantity) override; // slot 0x10 0x4b8440
  // Field-initialization body for the manual-alloc construction path (mirrors
  // TCapacityOrder's ICapacityOrder at the analogous
  // sibling slot): sets quantity/ownerCity/productionSummary from `city`, zeroes
  // trackingSlots/reservedWorkforce/limitingConstraint/accumulatedValue, and seeds resourceTypeIndex = 1.
  // No current caller in ported code (manual or autogen); kept as a virtual at its
  // existing slot rather than eliminated, since there is no evidence either way whether
  // the original dispatches it via vtable or a direct call, and this class has a prior
  // revert history from vtable-signature mistakes (bd imperialism-decomp-1uj.39).
  virtual void IPopGrowthOrder(TCity* city); // slot 0x11 0x4b8160, Mac-style second-phase init

  // NOOP: verified empty in original 0x004b8112 (no standalone TPopGrowthOrder::TPopGrowthOrder body exists: construction is fully inlined into CreateObject 0x004b8110; that address is its operator-new call site)
  TPopGrowthOrder() {}
};
ASSERT_SIZE(TPopGrowthOrder, 0x4c);
