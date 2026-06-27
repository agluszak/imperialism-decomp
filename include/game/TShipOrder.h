#pragma once

#include "game/TProductionOrder.h"
#include "game/mfc.h"

class TCity;

// TODO(manifest): describe TShipOrder and its role. Base edge (TProductionOrder)
// recovered from RTTI CRuntimeClass chain: TShipOrder -> TProductionOrder -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0064f738
class TShipOrder : public TProductionOrder {
public:
  CRuntimeClass* GetRuntimeClass() const override; // slot 0x00 0x4b84a0
  ~TShipOrder() override;                          // slot 0x01 (scalar deleting destructor)

  bool SetQuantity(short quantity) override;                      // slot 0x0b 0x4b8800
  short MaxOrder() override;                                      // slot 0x0c 0x4b86d0
  undefined CommitIfPending() override;                           // slot 0x0d 0x4b8970
  undefined FillOrderSheet() override;                            // slot 0x10 0x4b8b80
  virtual bool CanMakeFromCityStock();                            // slot 0x11 0x4b85a0
  virtual bool CanFillOrderSheet();                               // slot 0x12 0x4b8630
  virtual void CommitQueuedNavyOrdersAndUpdateTierByCapability(); // slot 0x13 0x4b89a0

  TShipOrder();

  short quantityField04;
  TCity* cityField08;
  void* summaryField0c;
  short trackingSlots10[0x17];
  short field3e;
  short field40;
  int field44;
  short resourceTypeIndex48;
  short field4a;
};

ASSERT_SIZE(TShipOrder, 0x4c);
