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
                           bool refreshNow) override; // slot 0x70 0x570870
  virtual void DrawImmediate();                       // slot 0x73 0x5708c0
  short glyph;
  short clickSoundId;

  // FUNCTION: IMPERIALISM 0x005707f0
  TPictureButton() : TPicture(), clickSoundId(7000) {}
};

ASSERT_SIZE(TPictureButton, 0x94);
