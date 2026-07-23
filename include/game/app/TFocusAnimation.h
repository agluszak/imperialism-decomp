#pragma once

#include "game/app/TAnimation.h"

class TView;

// Focus-animation helper object
// completion callback at slot 0x14 (index 5 of subclass, slot 13 in vtable).
// VTABLE: IMPERIALISM 0x0064c450
class TFocusAnimation : public TAnimation {
  DECLARE_DYNCREATE(TFocusAnimation)
public:
  TFocusAnimation();
  virtual void Tick() override;                       // slot 10 / 0x28 0x4a0140
  virtual void DrawNextFrame(POINT* offset) override; // slot 11 / 0x2c 0x4a0250
  virtual void IdleDraw();                            // slot 13 / 0x34 0x4a0190
  virtual void ClipAndPaste();                        // slot 14 / 0x38 0x4a0280

  // (The old ScopedRenderTarget/FieldNN/Source* cast-helper accessors are retired:
  // they mapped 1:1 onto the recovered TAnimation base fields -- ownerView04,
  // frameIndex08/frameCount0A/field0C, tickCounter10/ticksPerFrame14, registryTag18,
  // and screenRect1C used as the blit source rect.)

  char enabledFlag; // 0x2c

  char pad_2d[3];
};
