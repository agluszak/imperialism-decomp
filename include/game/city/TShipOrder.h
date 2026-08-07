#pragma once

#include "game/city/TProductionOrder.h"
#include "game/mfc.h"

class TCity;

// VTABLE: IMPERIALISM 0x0064f738
class TShipOrder : public TProductionOrder {
public:
  DECLARE_DYNCREATE(TShipOrder)
  // FUNCTION: IMPERIALISM 0x004b8510
  ~TShipOrder() override {} // slot 0x01 (scalar deleting destructor)

  bool SetQuantity(short quantity) override;                            // slot 0x0b 0x4b8800
  short MaxOrder() override;                                            // slot 0x0c 0x4b86d0
  void Produce() override;                                              // slot 0x0d 0x4b8970
  void FillOrderSheet(OrderSheet* orderSheet, short quantity) override; // slot 0x10 0x4b8b80
  virtual bool AutoCanMakeProduct();                                    // slot 0x11 0x4b85a0
  virtual bool CanMakeProduct();                                        // slot 0x12 0x4b8630
  virtual void LaunchShip();                                            // slot 0x13 0x4b89a0

  // Construction stores only the derived vptr; it does not clear tracking slots.
  // SYNTHETIC: IMPERIALISM 0x004b84c0
  // TShipOrder::TShipOrder
  TShipOrder() : TProductionOrder() {}

  // TShipOrder adds no fields of its own: `config/rtti_class_oracle.csv` gives
  // it the identical 0x4c object size as TProductionOrder, so every field
  // formerly modeled here (quantity, ownerCity, productionSummary,
  // trackingSlots, reservedWorkforce, limitingConstraint, field44, resourceTypeIndex, unknown4a)
  // is really TProductionOrder's own layout — see TProductionOrder.h.
};

ASSERT_SIZE(TShipOrder, 0x4c);
