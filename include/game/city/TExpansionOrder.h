#pragma once

#include "compat.h"

#include "game/city/TItemOrder.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064f6d8
class TExpansionOrder : public TItemOrder {
public:
  DECLARE_DYNCREATE(TExpansionOrder)
  virtual ~TExpansionOrder() override;               // slot 0x01 (scalar deleting destructor)
  virtual bool SetQuantity(short quantity) override; // slot 0x0b 0x4b9260
  virtual short MaxOrder() override;                 // slot 0x0c 0x4b91f0
  virtual void Produce() override;                   // slot 0x0d 0x4b9090
  virtual void FillOrderSheet(OrderSheet* orderSheet,
                              short quantity) override; // slot 0x10 0x4b9360
  virtual void IExpansionOrder(TCity* city, short resourceType, short primaryInputResource,
                               short secondaryInputResource,
                               short productionSlot); // slot 0x12 0x4b9010

  // NOOP: verified empty in original 0x004b8f52 (no standalone TExpansionOrder::TExpansionOrder body exists: construction is fully inlined into CreateObject 0x004b8f50; that address is its operator-new call site)
  TExpansionOrder() {}
};
ASSERT_SIZE(TExpansionOrder, 0x54);

// SwapFirstTwoBytesInBuffer (0x4b9340) and WriteByteSwappedShortArrayToStream (0x4b94a0)
// are shared stream byte-order helpers, not expansion-order code: they live in
// game/core/stream_byteswap.h.
