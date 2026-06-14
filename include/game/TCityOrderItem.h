#pragma once

#include "game/CObject.h"

struct CArchive;

#define TCITYORDERITEM_VTABLE_SLOT(n) virtual void VTableSlot##n##_Provisional(void) {}

// Shared city production order-item base (Mac: common Produce/FillOrderSheet protocol).
// VTABLE: IMPERIALISM 0x0064fa18
class TCityOrderItem : public CObject {
public:
  virtual CRuntimeClass* GetRuntimeClass();
  virtual void Serialize(CArchive* ar);
  virtual void AssertValidOrSlot0c();
  virtual void DumpOrSlot10(int unused = 0);
  TCITYORDERITEM_VTABLE_SLOT(05);
  TCITYORDERITEM_VTABLE_SLOT(06);
  TCITYORDERITEM_VTABLE_SLOT(07);
  TCITYORDERITEM_VTABLE_SLOT(08);
  TCITYORDERITEM_VTABLE_SLOT(09);
  TCITYORDERITEM_VTABLE_SLOT(10);
  TCITYORDERITEM_VTABLE_SLOT(11);
  TCITYORDERITEM_VTABLE_SLOT(12);
  TCITYORDERITEM_VTABLE_SLOT(13);
  TCITYORDERITEM_VTABLE_SLOT(14);
  // slot 0x3c — clears the OrderSheet working buffers (Mac: Produce()).
  virtual void Produce(void* orderSheet);
};
