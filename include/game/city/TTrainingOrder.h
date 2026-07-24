#pragma once

#include "compat.h"

#include "game/city/TProductionOrder.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064f798
class TTrainingOrder : public TProductionOrder {
public:
  DECLARE_DYNCREATE(TTrainingOrder)
  virtual ~TTrainingOrder() override;               // slot 0x01 (scalar deleting destructor)
  virtual bool SetQuantity(short param_1) override; // slot 0x0b 0x4b6cd0
  virtual short MaxOrder() override;                // slot 0x0c 0x4b6b90
  virtual void Produce() override;                  // slot 0x0d 0x4b6e30
  virtual void Restock() override;                  // slot 0x0e 0x4b6f00
  virtual void FillOrderSheet(OrderSheet* orderSheet,
                              short quantity) override;         // slot 0x10 0x4b6de0
  virtual void ITrainingOrder(TCity* city, short resourceType); // slot 0x11 0x4b6b20

  // NOOP: verified empty in original 0x004b6a62 (no standalone TTrainingOrder::TTrainingOrder body exists: construction is fully inlined into CreateObject 0x004b6a60; that address is its operator-new call site)
  TTrainingOrder() {}
};
ASSERT_SIZE(TTrainingOrder, 0x4c);
