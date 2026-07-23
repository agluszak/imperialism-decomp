#pragma once

#include "game/ui_core/TBehavior.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064eb60
class TDropShadowTextBehavior : public TBehavior {
public:
  DECLARE_DYNCREATE(TDropShadowTextBehavior)
  virtual ~TDropShadowTextBehavior() override; // slot 0x01 (scalar deleting destructor)
  void Draw(RECT* bounds) override;            // slot 0x0d byte 0x34 0x4b1150
  // TBehavior's own slice ends exactly at 0x10 (ASSERT_SIZE); the ctor zeroes each of
  // these 4 bytes individually (not a single dword store), so modeled as 4 distinct
  // byte fields pending further evidence of their real semantics.
  unsigned char field10;
  unsigned char field11;
  unsigned char field12;
  unsigned char field13;

  TDropShadowTextBehavior();
};
