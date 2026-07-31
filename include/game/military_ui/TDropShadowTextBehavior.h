#pragma once

#include "compat.h"

#include "game/ui_core/TBehavior.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064eb60
class TDropShadowTextBehavior : public TBehavior {
public:
  DECLARE_DYNCREATE(TDropShadowTextBehavior)
  // FUNCTION: IMPERIALISM 0x004b1100
  virtual ~TDropShadowTextBehavior() override {} // slot 0x01 (scalar deleting destructor)
  void Draw(RECT* bounds) override;              // slot 0x0d byte 0x34 0x4b1150
  // Draw passes the complete +0x10 dword to SetQuickDrawColorAndPropagateIfChanged.
  COLORREF shadowColor10;

  TDropShadowTextBehavior();

  // Two-phase init (MacApp IViewClass idiom): stores the shadow colour and tags the
  // behaviour 'drop'. 0x004b1120, __thiscall.
  void IDropShadowTextBehavior(COLORREF shadowColor);
};

ASSERT_SIZE(TDropShadowTextBehavior, 0x14);
