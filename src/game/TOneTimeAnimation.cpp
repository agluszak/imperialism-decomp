// TOneTimeAnimation: a TAnimation subclass driving a one-shot tile effect through a scoped
// QuickDraw render/tick slice.

#include "game/TOneTimeAnimation.h"

#include "decomp_types.h"
#include "game/TView.h"
#include "game/UiRuntimeContext.h"
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
// FUNCTION: IMPERIALISM 0x0049fd20
TOneTimeAnimation::~TOneTimeAnimation() {}

// SYNTHETIC: IMPERIALISM 0x0049fd40
// TOneTimeAnimation::GetRuntimeClass

IMPLEMENT_DYNCREATE(TOneTimeAnimation, TAnimation)

// FUNCTION: IMPERIALISM 0x0049fd60
void TOneTimeAnimation::ConstructTOneTimeAnimationBaseState(TView* view, RECT* rect,
                                                            short frameCountArg, short effectId,
                                                            int tickLimit, int registryTag) {
  ownerView04 = view;
  screenRect1C = *rect;
  frameCount0A = frameCountArg;
  field0C = effectId;
  ticksPerFrame14 = tickLimit;
  registryTag18 = registryTag;
  frameIndex08 = 0;
  tickCounter10 = 0;
  completeFlag = 0;
}

// FUNCTION: IMPERIALISM 0x0049fde0
void TOneTimeAnimation::Tick() {
  if (completeFlag == 0) {
    int nextTick = tickCounter10 + 1;
    tickCounter10 = nextTick;
    if (nextTick == ticksPerFrame14) {
      ownerView04->InvalidateCityDialogRectRegion(&screenRect1C, 1);

      ScopedMapQuickDrawContextGuard quickDrawContext(ownerView04);
      ownerView04->PrepareForDrawing();

      RECT renderRect;
      CopyRect(&renderRect, &screenRect1C);
      ownerView04->ApplyRectSlot110(&renderRect);

      tickCounter10 = 0;
      if (frameIndex08 < frameCount0A - 1) {
        frameIndex08 = frameIndex08 + 1;
      } else {
        completeFlag = 1;
      }
    }
  }
}
