#pragma once

#include "game/ui_core/TPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0065f440
class TUpDownPictureButton : public TPicture {
public:
  DECLARE_DYNCREATE(TUpDownPictureButton)
  virtual ~TUpDownPictureButton() override;
  virtual void DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin) override;
  virtual void HiliteState(unsigned char fEnabledState, bool fRefreshNow) override;
  virtual void DrawImmediate();
  short glyph;
  short clickSoundId;

  // FUNCTION: IMPERIALISM 0x005715a0
  TUpDownPictureButton() : clickSoundId(7000) {}
};

ASSERT_SIZE(TUpDownPictureButton, 0x94);
