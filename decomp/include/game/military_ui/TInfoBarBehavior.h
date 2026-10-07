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
  virtual ~TInfoBarBehavior() override;
  virtual void IInfoBarBehavior(CString text, TView* ownerView);
  virtual bool DoSetCursor(CPoint* point, RgnHandle region);
  CString text;

  TInfoBarBehavior();

  CRect layoutRect;
};

ASSERT_SIZE(TInfoBarBehavior, 0x24);
