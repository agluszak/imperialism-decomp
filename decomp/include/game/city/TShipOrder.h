#pragma once

#include "game/city/TProductionOrder.h"
#include "game/mfc.h"

class TCity;

// VTABLE: IMPERIALISM 0x0064f738
class TShipOrder : public TProductionOrder {
public:
  DECLARE_DYNCREATE(TShipOrder)
  // FUNCTION: IMPERIALISM 0x004b8510
  ~TShipOrder() override {}

  bool SetQuantity(short quantity) override;
  short MaxOrder() override;
  void Produce() override;
  void FillOrderSheet(OrderSheet* orderSheet, short quantity) override;
  virtual bool AutoCanMakeProduct();
  virtual bool CanMakeProduct();
  virtual void LaunchShip();

  // Construction stores only the derived vptr; it does not clear tracking slots.
  TShipOrder() {}
};

ASSERT_SIZE(TShipOrder, 0x4c);
