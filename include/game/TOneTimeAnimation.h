#pragma once

#include "compat.h"
#include "game/mfc.h"

class TView;

// One-shot tile-effect animation (explosions, sap blasts) pumped modally by
// TTacticalBattleView::RunOneTimeAnimationModalWaitAndInvalidateCityDialog (0x5a9170).
// Derives from the MFC CObject root: the factory at 0x0049fd20 installs the shared
// CObject runtime vtable (0x0066fec4), and TOneTimeAnimation adds no virtuals of its
// own; the animation fields begin at offset 0x4.
class TOneTimeAnimation : public CObject {
public:
  TView* scopedRenderTarget; // 0x04 — render-target view for the scoped QuickDraw context
  short currentFrame;        // 0x08
  short frameCount;          // 0x0a
  short effectId0C;          // 0x0c effect sprite id
  char pad_0e[2];
  int frameTick;      // 0x10
  int frameTickLimit; // 0x14
  int registryTag18;  // 0x18 UI transient-registry tag (the tile index)
  RECT targetRect;    // 0x1c
  char completeFlag;  // 0x2c

  // Field initializer invoked right after `new` (0x49fd60, __thiscall, ret 0x18).
  void ConstructTOneTimeAnimationBaseState(TView* view, RECT* rect, short frameCountArg,
                                           short effectId, int tickLimit, int registryTag);

  void AdvanceOneTimeAnimationFrameAndInvalidateTargetRect();
};
