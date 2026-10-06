#pragma once

#include "compat.h"

#include "game/ui_core/TControl.h"
#include "game/mfc.h"

struct TQuickDrawSurfaceContext;

// VTABLE: IMPERIALISM 0x0065ff60
class TGWorldButton : public TControl {
public:
  DECLARE_DYNCREATE(TGWorldButton)
  virtual ~TGWorldButton() override;            // slot 0x01 (scalar deleting destructor)
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x572270
  virtual void HiliteState(unsigned char fEnabledState,
                           bool fRefreshNow) override; // slot 0x70 0x572200

  TGWorldButton();
  void IGWorldButton(TView* panel, int* offsetLayout, int* sizeLayout,
                     short bitmapResourceId); // Mac oracle: IGWorldButton(..., short)

  short frameOffsetX;
  short pad86;
  TQuickDrawSurfaceContext* frameSurface;
};
ASSERT_SIZE(TGWorldButton, 0x8c);
