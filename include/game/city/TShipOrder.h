#pragma once

#include "game/city/TProductionOrder.h"
#include "game/mfc.h"

class TCity;

// VTABLE: IMPERIALISM 0x0064f738
class TShipOrder : public TProductionOrder {
public:
  DECLARE_DYNCREATE(TShipOrder)
  ~TShipOrder() override; // slot 0x01 (scalar deleting destructor)

  bool SetQuantity(short quantity) override;                            // slot 0x0b 0x4b8800
  short MaxOrder() override;                                            // slot 0x0c 0x4b86d0
  void Produce() override;                                              // slot 0x0d 0x4b8970
  void FillOrderSheet(OrderSheet* orderSheet, short quantity) override; // slot 0x10 0x4b8b80
  virtual bool CanMakeFromCityStock();                                  // slot 0x11 0x4b85a0
  virtual bool CanFillOrderSheet();                                     // slot 0x12 0x4b8630
  virtual void CommitQueuedNavyOrdersAndUpdateTierByCapability();       // slot 0x13 0x4b89a0

  // CreateObject (0x004b8470) allocates 0x4c bytes and stores the vptr, nothing else --
  // the original does NOT clear the tracking slots at construction, and TProductionOrder's
  // ctor (0x004b4f00, 9 bytes) only stores a vptr, so the previous body's claim that the
  // base zero-inits these fields was wrong. The clear survives in the reset path below.
  TShipOrder() : TProductionOrder() {}

  // TShipOrder adds no fields of its own: `config/rtti_class_oracle.csv` gives
  // it the identical 0x4c object size as TProductionOrder, so every field
  // formerly modeled here (quantityField04, cityField08, summaryField0c,
  // trackingSlots10, field3e, field40, field44, resourceTypeIndex48, field4a)
  // is really TProductionOrder's own layout — see TProductionOrder.h.
};

ASSERT_SIZE(TShipOrder, 0x4c);
