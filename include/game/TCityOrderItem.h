#pragma once

#include "game/CObject.h"

class CArchive;

#define TCITYORDERITEM_VTABLE_SLOT(n) virtual void VTableSlot##n##_Provisional(void) {}

// Shared city production order-item protocol (Mac: Produce/FillOrderSheet family).
// Per-class fork vtables live in the 0x0064f714+ factory region; do not pin one
// mega-table address on this abstract base.
class TCityOrderItem : public CObject {
public:
  TCITYORDERITEM_VTABLE_SLOT(05);
  TCITYORDERITEM_VTABLE_SLOT(06);
  TCITYORDERITEM_VTABLE_SLOT(07);
  TCITYORDERITEM_VTABLE_SLOT(08);
  TCITYORDERITEM_VTABLE_SLOT(09);
  TCITYORDERITEM_VTABLE_SLOT(10);
  virtual short MaxOrder();
  virtual bool SetQuantity(short quantity);
  virtual void CommitIfPending();
  TCITYORDERITEM_VTABLE_SLOT(14);
  // slot 0x3c — clears the OrderSheet working buffers (Mac: Produce()).
  virtual void Produce(void* orderSheet);
  virtual void FillOrderSheet(void* orderSheet, short quantity);
  virtual bool CanMakeFromCityStock();
  virtual bool CanFillOrderSheet(void* orderSheet);
  virtual void ApplyCityProductionSlotDelta();
};
