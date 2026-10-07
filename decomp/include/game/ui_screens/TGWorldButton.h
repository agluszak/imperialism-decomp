#pragma once

#include "compat.h"

#include "game/ui_core/TControl.h"
#include "game/mfc.h"

struct TQuickDrawSurfaceContext;

// VTABLE: IMPERIALISM 0x0065ff60
class TGWorldButton : public TControl {
public:
  DECLARE_DYNCREATE(TGWorldButton)
  virtual ~TGWorldButton() override;
  virtual void Draw(RECT* rectBuffer) override;
  virtual void HiliteState(unsigned char fEnabledState, bool fRefreshNow) override;

  TGWorldButton();
  void IGWorldButton(TView* panel, int* offsetLayout, int* sizeLayout,
                     short bitmapResourceId); // Mac oracle: IGWorldButton(..., short)

  short frameOffsetX;
  short pad86;
  TQuickDrawSurfaceContext* frameSurface;
};
ASSERT_SIZE(TGWorldButton, 0x8c);
