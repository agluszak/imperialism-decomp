// TOneTimeAnimation: a TAnimation subclass driving a one-shot tile effect through a scoped
// QuickDraw render/tick slice.

#include "game/app/TOneTimeAnimation.h"

#include "decomp_types.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/mfc.h"
#include "game/quickdraw_guards.h"
#include <new>

// SYNTHETIC: IMPERIALISM 0x0049fcc0
// TOneTimeAnimation::CreateObject

// SYNTHETIC: IMPERIALISM 0x0049fcf0
// TOneTimeAnimation::`scalar deleting destructor'

// Trivial virtual destructor. The whole TOneTimeAnimation -> TAnimation -> TObject -> CObject
// destructor chain is trivial, so MSVC collapses the per-level vtable resets to the single
// base-most write (`mov [ecx], 0x0066fec4; ret` at 0x49fd20). Ghidra mislabeled this address
// as CreateTOneTimeAnimationInstance; the scalar deleting destructor above calls it.

// SYNTHETIC: IMPERIALISM 0x0049fd40
// TOneTimeAnimation::GetRuntimeClass

IMPLEMENT_DYNCREATE(TOneTimeAnimation, TAnimation)

// FUNCTION: IMPERIALISM 0x0049fd60
void TOneTimeAnimation::InitializeOneTimeAnimation(TView* view, RECT* rect, short frameCountArg,
                                                   short effectId, int tickLimit, int registryTag) {
  ownerView = view;
  screenRect = *rect;
  frameCount = frameCountArg;
  frameResourceBaseId = effectId;
  ticksPerFrame = tickLimit;
  this->registryTag = registryTag;
  frameIndex = 0;
  ticksSinceFrameChange = 0;
  completeFlag = 0;
}

// FUNCTION: IMPERIALISM 0x0049fde0
void TOneTimeAnimation::Tick() {
  if (completeFlag == 0) {
    int nextTick = ticksSinceFrameChange + 1;
    ticksSinceFrameChange = nextTick;
    if (nextTick == ticksPerFrame) {
      ownerView->InvalidateCityDialogRectRegion(&screenRect, 1);

      ScopedMapQuickDrawContextGuard quickDrawContext(ownerView);
      ownerView->PrepareForDrawing();

      RECT renderRect;
      CopyRect(&renderRect, &screenRect);
      ownerView->Draw(&renderRect);

      ticksSinceFrameChange = 0;
      if (frameIndex < frameCount - 1) {
        frameIndex = frameIndex + 1;
      } else {
        completeFlag = 1;
      }
    }
  }
}
