#pragma once

#include "compat.h"
#include "game/ui_core/TPicture.h"

// VTABLE: IMPERIALISM 0x65e6f8
class TPictureButton : public TPicture {
public:
  DECLARE_DYNCREATE(TPictureButton)
  virtual ~TPictureButton() override;
  virtual void DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin) override;
  virtual void HiliteState(unsigned char enabledState, bool refreshNow) override;
  virtual void DrawImmediate();
  short glyph;
  short clickSoundId;

  // FUNCTION: IMPERIALISM 0x005707f0
  TPictureButton() : clickSoundId(7000) {}
};

ASSERT_SIZE(TPictureButton, 0x94);
