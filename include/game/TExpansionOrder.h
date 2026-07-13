#pragma once

#include "game/TItemOrder.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064f6d8
class TExpansionOrder : public TItemOrder {
public:
  // === BEGIN GENERATED DECLS (TExpansionOrder) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TExpansionOrder)
  virtual ~TExpansionOrder() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x4b5670)
  // slot 0x06 ReadFrom inherited unchanged (0x4b5710)
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a InitializeBasicCityOrderContext inherited unchanged (0x4b4f70)
  virtual bool SetQuantity(short param_1) override; // slot 0x0b 0x4b9260
  virtual short MaxOrder() override;                // slot 0x0c 0x4b91f0
  virtual undefined CommitIfPending() override;     // slot 0x0d 0x4b9090
  // slot 0x0e ResetCityOrderItemDerivedStateNoop inherited unchanged (0x4b5620)
  // slot 0x0f Produce inherited unchanged (0x4b5180)
  virtual void FillOrderSheet(void* orderSheet, short quantity) override; // slot 0x10 0x4b9360
  // slot 0x11 InitializeCityProductionState_Impl_At004b5290 inherited unchanged (0x4b5290)
  virtual undefined
  InitializeCityProductionState_Impl_At004b9010(int param_1, undefined2 param_2, undefined2 param_3,
                                                undefined2 param_4,
                                                undefined2 param_5); // slot 0x12 0x4b9010
  // === END GENERATED DECLS (TExpansionOrder) ===

  TExpansionOrder();
};

// 0x4b9340: swaps the first two bytes of the buffer (byte-order swap helper).
void SwapFirstTwoBytesInBuffer(unsigned char* buffer);
