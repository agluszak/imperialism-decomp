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
                           unsigned char fRefreshNow) override; // slot 0x70 0x572200

  TGWorldButton();
  void IGWorldButton(TView* panel, int* offsetLayout, int* sizeLayout,
                     short bitmapResourceId); // Mac oracle: IGWorldButton(..., short)

  // Source-strip column offset (in pixels): shifted by +/-frameWidth34 on each
  // HiliteState toggle to select the enabled/disabled frame
  // of a horizontal sprite strip. Zeroed by the ctor.
  short field84;
  short pad86;
  // Source surface holding the sprite strip; Draw blits the
  // {field84, 0, field84+frameWidth34, frameHeight38} slice from it.
  TQuickDrawSurfaceContext* field88;
};
ASSERT_SIZE(TGWorldButton, 0x8c);
