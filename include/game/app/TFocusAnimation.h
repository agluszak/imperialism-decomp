#pragma once

#include "compat.h"

#include "game/app/TAnimation.h"

class TView;

// Focus-animation helper object
// completion callback at slot 0x14 (index 5 of subclass, slot 13 in vtable).
// VTABLE: IMPERIALISM 0x0064c450
class TFocusAnimation : public TAnimation {
  DECLARE_DYNCREATE(TFocusAnimation)
public:
  // FUNCTION: IMPERIALISM 0x004a0080
  ~TFocusAnimation() override {}
  TFocusAnimation() : TAnimation(), enabledFlag(1) {}

  virtual void Tick() override;                             // slot 10 / 0x28 0x4a0140
  virtual void DrawNextFrame(POINT* unusedOffset) override; // slot 11 / 0x2c 0x4a0250
  virtual void IdleDraw();                                  // slot 13 / 0x34 0x4a0190
  virtual void ClipAndPaste();                              // slot 14 / 0x38 0x4a0280

  char enabledFlag; // 0x2c

  char padding2D[3];
};
ASSERT_SIZE(TFocusAnimation, 0x30);
