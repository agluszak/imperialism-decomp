#pragma once

#include "compat.h"
#include "game/TPicture.h"

// VTABLE: IMPERIALISM 0x65e6f8
class TPictureButton : public TPicture {
public:
  DECLARE_DYNCREATE(TPictureButton)
  virtual ~TPictureButton() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoMouseCommand(CPoint& point, TToolboxEvent* event,
                              CPoint origin) override; // slot 0x47 0x570900
  virtual void HiliteState(unsigned char enabledState,
                           unsigned char refreshNow) override; // slot 0x70 0x570870
  virtual bool DrawImmediate();                                // slot 0x73 0x5708c0
  short glyph90;
  short timingWord92;

  TPictureButton();
};

ASSERT_SIZE(TPictureButton, 0x94);
