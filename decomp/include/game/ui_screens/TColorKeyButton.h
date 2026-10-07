#pragma once

#include "compat.h"

#include "game/ui_screens/TColorKeyPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0065fd28
class TColorKeyButton : public TColorKeyPicture {
public:
  DECLARE_DYNCREATE(TColorKeyButton)
  virtual ~TColorKeyButton() override;
  virtual void HiliteState(unsigned char fEnabledState, bool fRefreshNow) override;
  virtual void DrawImmediate();

  TColorKeyButton();

  int field98;
};
ASSERT_SIZE(TColorKeyButton, 0x9c);
