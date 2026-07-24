#pragma once

#include "game/city/TProductionOrder.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TStream;

// VTABLE: IMPERIALISM 0x0064f958
class TItemOrder : public TProductionOrder {
public:
  DECLARE_DYNCREATE(TItemOrder)
  virtual ~TItemOrder() override;                   // slot 0x01 (scalar deleting destructor)
  virtual void WriteTo(TStream* stream) override;   // slot 0x05 0x4b5670
  virtual void ReadFrom(TStream* stream) override;  // slot 0x06 0x4b5710
  virtual bool SetQuantity(short param_1) override; // slot 0x0b 0x4b53d0
  virtual short MaxOrder() override;                // slot 0x0c 0x4b5310
  virtual void Produce() override;                  // slot 0x0d 0x4b5580
  virtual void Restock() override;                  // slot 0x0e 0x4b5620
  virtual void FillOrderSheet(OrderSheet* orderSheet,
                              short quantity) override; // slot 0x10 0x4b5510
  virtual void InitializeItemOrderContext(TCity* city, short outputResourceType,
                                          short primaryInputResourceId,
                                          short secondaryInputResourceId,
                                          short productionSlot); // slot 0x11 0x4b5290
  // TItemOrder is 0x54 bytes vs. TProductionOrder's 0x4c (RTTI). The slot-0x11
  // initializer and resource-indexed city-stock accesses recover all four added shorts.
  short requestedQuantity4c;      // desired quantity retained across availability clamps
  short primaryInputResourceId;   // first cityStockByType / trackingSlots resource index
  short secondaryInputResourceId; // second resource index, or -1 for two units of primary
  short productionSlot;           // city productionAccum1fc index

  // In-class inline: TItemOrder has no standalone ctor body -- CreateObject (0x004b51d0)
  // allocates 0x54 bytes, stores the derived vptr, then MOV word ptr [eax+4],0. That +4
  // store is quantityField04 (a TProductionOrder member, so it must be assigned in the
  // body, not a member-init-list entry); the previous empty body dropped it entirely.
  TItemOrder() {
    quantityField04 = 0;
  }
};

ASSERT_SIZE(TItemOrder, 0x54);
