#pragma once

#include "compat.h"

#include "game/ui_core/TPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0065d280
class TDisappearingButton : public TPicture {
public:
  DECLARE_DYNCREATE(TDisappearingButton)
  virtual ~TDisappearingButton() override;
  virtual void HiliteState(unsigned char fEnabledState, bool fRefreshNow) override;
  virtual void DrawImmediate();

  TDisappearingButton();
};
ASSERT_SIZE(TDisappearingButton, 0x90);
