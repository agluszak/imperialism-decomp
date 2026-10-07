#pragma once

#include "game/city/TProductionOrder.h"
#include "game/mfc.h"

class TStream;

// VTABLE: IMPERIALISM 0x0064f958
class TItemOrder : public TProductionOrder {
public:
  DECLARE_DYNCREATE(TItemOrder)
  // FUNCTION: IMPERIALISM 0x004b5270
  virtual ~TItemOrder() override {}
  virtual void WriteTo(TStream* stream) override;
  virtual void ReadFrom(TStream* stream) override;
  virtual bool SetQuantity(short quantity) override;
  virtual short MaxOrder() override;
  virtual void Produce() override;
  virtual void Restock() override;
  virtual void FillOrderSheet(OrderSheet* orderSheet, short quantity) override;
  virtual void IItemOrder(TCity* city, short outputResourceType, short primaryInputResourceId,
                          short secondaryInputResourceId, short productionSlot);
  short requestedQuantity;        // desired quantity retained across availability clamps
  short primaryInputResourceId;   // first stockByType / trackingSlots resource index
  short secondaryInputResourceId; // second resource index, or -1 for two units of primary
  short productionSlot;           // city productionAccum index

  TItemOrder() {
    quantity = 0;
  }
};

ASSERT_SIZE(TItemOrder, 0x54);
