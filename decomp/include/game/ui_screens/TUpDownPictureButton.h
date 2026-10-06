#pragma once

#include "game/ui_core/TPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0065f440
class TUpDownPictureButton : public TPicture {
public:
  DECLARE_DYNCREATE(TUpDownPictureButton)
  virtual ~TUpDownPictureButton() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoMouseCommand(CPoint& point, TToolboxEvent* event,
                              CPoint origin) override; // slot 0x47 0x5716b0
  virtual void HiliteState(unsigned char fEnabledState,
                           bool fRefreshNow) override; // slot 0x70 0x571620
  virtual void DrawImmediate();                        // slot 0x73 0x571690
  short glyph;
  short timingWord92;

  // FUNCTION: IMPERIALISM 0x005715a0
  TUpDownPictureButton() : TPicture(), timingWord92(7000) {}
};

ASSERT_SIZE(TUpDownPictureButton, 0x94);
