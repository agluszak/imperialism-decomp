#pragma once

#include "game/TItemOrder.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064f6d8
class TExpansionOrder : public TItemOrder {
public:
  DECLARE_DYNCREATE(TExpansionOrder)
  virtual ~TExpansionOrder() override;              // slot 0x01 (scalar deleting destructor)
  virtual bool SetQuantity(short param_1) override; // slot 0x0b 0x4b9260
  virtual short MaxOrder() override;                // slot 0x0c 0x4b91f0
  virtual void Produce() override;                  // slot 0x0d 0x4b9090
  virtual void FillOrderSheet(OrderSheet* orderSheet,
                              short quantity) override; // slot 0x10 0x4b9360
  virtual void IExpansionOrder(TCity* city, short resourceType, short primaryInputResource,
                               short secondaryInputResource,
                               short productionSlot); // slot 0x12 0x4b9010

  TExpansionOrder();
};

// 0x4b9340: swaps the first two bytes of the buffer (byte-order swap helper).
void SwapFirstTwoBytesInBuffer(unsigned char* buffer);

class TStream;
// 0x4b94a0: writes `count` shorts to the stream, each byte-swapped, via the stream's
// WriteBytesSlot78 primitive.
void WriteWordArrayToOutputCallbackLE(TStream* stream, short* words, int count);
