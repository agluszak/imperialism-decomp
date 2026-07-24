#pragma once

#include "compat.h"

#include "game/ui_core/TControl.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006561b0
class TFrameRadioView : public TControl {
public:
  DECLARE_DYNCREATE(TFrameRadioView)
  virtual ~TFrameRadioView() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x004fe060
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x4fdfc0
  virtual void HiliteState(unsigned char fEnabledState,
                           unsigned char fRefreshNow) override; // slot 0x70 0x4fe190

  // NOOP: verified empty in original 0x004fdf06 (no standalone TFrameRadioView::TFrameRadioView body exists: CreateObject 0x004fded0 inlines this default ctor, calling the TControl base ctor directly at that site)
  TFrameRadioView() {}
};
ASSERT_SIZE(TFrameRadioView, 0x84);
