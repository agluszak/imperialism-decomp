// TOneTimeAnimation scoped QuickDraw render/tick slice.

#include "decomp_types.h"
#include "game/TView.h"
#include "game/mfc.h"
#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"
#include "game/mfc.h"
#include "game/ui_widget_thunks.h"
#include <new>
#include "game/quickdraw_guards.h"

#include "game/TOneTimeAnimation.h"

// FUNCTION: IMPERIALISM 0x0049fd60
void TOneTimeAnimation::ConstructTOneTimeAnimationBaseState(TView* view, RECT* rect,
                                                            short frameCountArg, short effectId,
                                                            int tickLimit, int registryTag) {
  scopedRenderTarget = view;
  targetRect = *rect;
  frameCount = frameCountArg;
  effectId0C = effectId;
  frameTickLimit = tickLimit;
  registryTag18 = registryTag;
  currentFrame = 0;
  frameTick = 0;
  completeFlag = 0;
}

// FUNCTION: IMPERIALISM 0x0049fde0
void TOneTimeAnimation::AdvanceOneTimeAnimationFrameAndInvalidateTargetRect() {
  if (completeFlag == 0) {
    int nextTick = frameTick + 1;
    frameTick = nextTick;
    if (nextTick == frameTickLimit) {
      reinterpret_cast<TView*>(this)->InvalidateCityDialogRectRegion(&targetRect, 1);

      ScopedMapQuickDrawContextGuard quickDrawContext(scopedRenderTarget);
      scopedRenderTarget->Refresh();

      RECT renderRect;
      CopyRect(&renderRect, &targetRect);
      scopedRenderTarget->ApplyRectSlot110(&renderRect);

      frameTick = 0;
      if (currentFrame < frameCount - 1) {
        currentFrame = currentFrame + 1;
      } else {
        completeFlag = 1;
      }
    }
  }
}
