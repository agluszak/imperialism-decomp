#pragma once

#include "game/core/CString.h"
#include "game/ui_core/TBehavior.h"
#include "game/gfx/quickdraw_regions.h"
#include "game/mfc.h"

class TView;

// VTABLE: IMPERIALISM 0x0064eb10
class TInfoBarBehavior : public TBehavior {
public:
  DECLARE_DYNCREATE(TInfoBarBehavior)
  virtual ~TInfoBarBehavior() override; // slot 0x01 (scalar deleting destructor)
  virtual void IInfoBarBehavior(CString text, TView* ownerView); // slot 0x0e 0x4b0e20
  virtual unsigned char DoSetCursor(CPoint* point,
                                    RgnHandle region); // slot 0x0f 0x4b0f50
  CString text;

  TInfoBarBehavior();

  CRect layoutRect;
};

ASSERT_SIZE(TInfoBarBehavior, 0x24);
