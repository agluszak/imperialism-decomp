#pragma once

#include "game/ui_core/TPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0065d280
class TDisappearingButton : public TPicture {
public:
  DECLARE_DYNCREATE(TDisappearingButton)
  virtual ~TDisappearingButton() override; // slot 0x01 (scalar deleting destructor)
  virtual void HiliteState(unsigned char fEnabledState,
                           unsigned char fRefreshNow) override; // slot 0x70 0x568c40
  virtual void DrawImmediate();                                 // slot 0x73 0x568c90

  TDisappearingButton();
};
