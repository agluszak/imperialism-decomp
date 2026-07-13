#pragma once

#include "game/TProductionOrder.h"
#include "game/mfc.h"

class TCity;

// VTABLE: IMPERIALISM 0x0064f738
class TShipOrder : public TProductionOrder {
public:
  DECLARE_DYNCREATE(TShipOrder)
  ~TShipOrder() override;                          // slot 0x01 (scalar deleting destructor)

  bool SetQuantity(short quantity) override;                      // slot 0x0b 0x4b8800
  short MaxOrder() override;                                      // slot 0x0c 0x4b86d0
  undefined CommitIfPending() override;                           // slot 0x0d 0x4b8970
  void FillOrderSheet(void* orderSheet, short quantity) override; // slot 0x10 0x4b8b80
  virtual bool CanMakeFromCityStock();                            // slot 0x11 0x4b85a0
  virtual bool CanFillOrderSheet();                               // slot 0x12 0x4b8630
  virtual void CommitQueuedNavyOrdersAndUpdateTierByCapability(); // slot 0x13 0x4b89a0

  TShipOrder();

  // TShipOrder adds no fields of its own: `config/rtti_class_oracle.csv` gives
  // it the identical 0x4c object size as TProductionOrder, so every field
  // formerly modeled here (quantityField04, cityField08, summaryField0c,
  // trackingSlots10, field3e, field40, field44, resourceTypeIndex48, field4a)
  // is really TProductionOrder's own layout — see TProductionOrder.h.
};

ASSERT_SIZE(TShipOrder, 0x4c);
