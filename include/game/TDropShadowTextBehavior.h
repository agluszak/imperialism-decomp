#pragma once

#include "game/TBehavior.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064eb60
class TDropShadowTextBehavior : public TBehavior {
public:
  // === BEGIN GENERATED DECLS (TDropShadowTextBehavior) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TDropShadowTextBehavior)
  virtual ~TDropShadowTextBehavior() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a OrphanTiny_SetDwordEcxOffset_8_00487280 inherited unchanged (0x487280)
  // slot 0x0b OrphanLeaf_NoCall_Ins02_004872a0 inherited unchanged (0x4872a0)
  // slot 0x0c CreateTDialogBehaviorInstance inherited unchanged (0x4872c0)
  void NoOpSlot34(undefined4 value) override; // slot 0x0d byte 0x34 0x4b1150
  // === END GENERATED DECLS (TDropShadowTextBehavior) ===
  // TBehavior's own slice ends exactly at 0x10 (ASSERT_SIZE); the ctor zeroes each of
  // these 4 bytes individually (not a single dword store), so modeled as 4 distinct
  // byte fields pending further evidence of their real semantics.
  unsigned char field10;
  unsigned char field11;
  unsigned char field12;
  unsigned char field13;

  TDropShadowTextBehavior();
};
