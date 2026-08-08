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
                           unsigned char fRefreshNow) override; // slot 0x70 0x571620
  virtual void DrawImmediate();                                 // slot 0x73 0x571690
  short glyph90;
  short timingWord92;

  // Inline so derived ctors (TCzechBox 0x571c20, TRadioPictureButton 0x5717c0)
  // reproduce the original's direct TPicture::TPicture call.
  // FUNCTION: IMPERIALISM 0x005715a0
  TUpDownPictureButton() : TPicture(), timingWord92(7000) {}
};

ASSERT_SIZE(TUpDownPictureButton, 0x94);
