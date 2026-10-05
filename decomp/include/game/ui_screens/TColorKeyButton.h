#pragma once

#include "compat.h"

#include "game/ui_screens/TColorKeyPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0065fd28
class TColorKeyButton : public TColorKeyPicture {
public:
  DECLARE_DYNCREATE(TColorKeyButton)
  virtual ~TColorKeyButton() override; // slot 0x01 (scalar deleting destructor)
  virtual void HiliteState(unsigned char fEnabledState,
                           bool fRefreshNow) override; // slot 0x70 0x571ff0
  virtual void DrawImmediate();                        // slot 0x74 0x572060

  TColorKeyButton();

  int field98;
};
ASSERT_SIZE(TColorKeyButton, 0x9c);
