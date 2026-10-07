#pragma once

#include "compat.h"

#include "game/ui_core/TControl.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006561b0
class TFrameRadioView : public TControl {
public:
  DECLARE_DYNCREATE(TFrameRadioView)
  virtual ~TFrameRadioView() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void Draw(RECT* rectBuffer) override;
  virtual void HiliteState(unsigned char fEnabledState, bool fRefreshNow) override;

  // NOOP: verified empty in original 0x004fdf06
  TFrameRadioView() {}
};
ASSERT_SIZE(TFrameRadioView, 0x84);
