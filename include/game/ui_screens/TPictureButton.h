#pragma once

#include "compat.h"
#include "game/ui_core/TPicture.h"

// VTABLE: IMPERIALISM 0x65e6f8
class TPictureButton : public TPicture {
public:
  DECLARE_DYNCREATE(TPictureButton)
  virtual ~TPictureButton() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoMouseCommand(CPoint& point, TToolboxEvent* event,
                              CPoint origin) override; // slot 0x47 0x570900
  virtual void HiliteState(unsigned char enabledState,
                           unsigned char refreshNow) override; // slot 0x70 0x570870
  virtual void DrawImmediate();                                // slot 0x73 0x5708c0
  short glyph90;
  short timingWord92;

  // Inline so derived ctors reproduce the original's direct TPicture::TPicture call
  // with the timingWord92 seed folded in (e.g. TOnOffRadioButton 0x5719f0).
  // FUNCTION: IMPERIALISM 0x005707f0
  TPictureButton() : TPicture(), timingWord92(7000) {}
};

ASSERT_SIZE(TPictureButton, 0x94);
