// TOneTimeAnimation scoped QuickDraw render/tick slice.

#include "decomp_types.h"
#include "game/generated/vcall_facades.h"
#include "game/ui_widget_shared.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

struct TOneTimeAnimationLayout {
  void* vftable;
  void* scopedRenderTarget;
  short currentFrame;
  short frameCount;
  short field0c;
  char pad_0e[2];
  int frameTick;
  int frameTickLimit;
  int field18;
  RECT targetRect;
  char completeFlag;
};

undefined4 thunk_InvalidateCityDialogRectRegion(void);

// FUNCTION: IMPERIALISM 0x0049fde0
void __fastcall
AdvanceOneTimeAnimationFrameAndInvalidateTargetRect(TOneTimeAnimationLayout* oneTimeAnimation,
                                                    int unusedEdx) {
  // ORIG_CALLCONV: __thiscall
  (void)unusedEdx;
  if (oneTimeAnimation->completeFlag == 0) {
    int nextTick = oneTimeAnimation->frameTick + 1;
    oneTimeAnimation->frameTick = nextTick;
    if (nextTick == oneTimeAnimation->frameTickLimit) {
      reinterpret_cast<void(__stdcall*)(int, int)>(thunk_InvalidateCityDialogRectRegion)(
          reinterpret_cast<int>(&oneTimeAnimation->targetRect), 1);

      ScopedMapQuickDrawContextGuard quickDrawContext(oneTimeAnimation->scopedRenderTarget);
      VCall_FocusAnimationView_RenderSlotF8(oneTimeAnimation->scopedRenderTarget);

      RECT renderRect;
      CopyRect(&renderRect, &oneTimeAnimation->targetRect);
      VCall_FocusAnimationView_ApplyRectSlot110(oneTimeAnimation->scopedRenderTarget,
                                                &renderRect.left);

      oneTimeAnimation->frameTick = 0;
      if (oneTimeAnimation->currentFrame < oneTimeAnimation->frameCount - 1) {
        oneTimeAnimation->currentFrame = oneTimeAnimation->currentFrame + 1;
      } else {
        oneTimeAnimation->completeFlag = 1;
      }
    }
  }
}
