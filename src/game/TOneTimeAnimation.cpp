// TOneTimeAnimation scoped QuickDraw render/tick slice.

#include "decomp_types.h"
#include "game/TView.h"
#include "game/CObject.h"
#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"
#include "game/win_rect.h"
#include "game/ui_widget_thunks.h"
#include <new>
#include "game/quickdraw_guards.h"
#include "game/generated/vcall_facades.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

// TOneTimeAnimation derives from the MFC CObject root: the factory at
// 0x0049fd20 installs the shared CObject runtime vtable (0x0066fec4) into the
// object, and TOneTimeAnimation adds no virtuals of its own. The CObject base
// supplies the vptr at offset 0; the animation fields begin at offset 0x4,
// matching the constructor at 0x0049fd60.
// Duplicate VTABLE annotation removed
class TOneTimeAnimation : public CObject {
public:
  void* scopedRenderTarget; // 0x04
  short currentFrame;       // 0x08
  short frameCount;         // 0x0a
  short field0c;            // 0x0c
  char pad_0e[2];
  int frameTick;      // 0x10
  int frameTickLimit; // 0x14
  int field18;        // 0x18
  RECT targetRect;    // 0x1c
  char completeFlag;  // 0x2c

  void AdvanceOneTimeAnimationFrameAndInvalidateTargetRect();
};

undefined4 thunk_InvalidateCityDialogRectRegion(void);

// FUNCTION: IMPERIALISM 0x0049fde0
void TOneTimeAnimation::AdvanceOneTimeAnimationFrameAndInvalidateTargetRect() {
  if (completeFlag == 0) {
    int nextTick = frameTick + 1;
    frameTick = nextTick;
    if (nextTick == frameTickLimit) {
      reinterpret_cast<void(__stdcall*)(int, int)>(thunk_InvalidateCityDialogRectRegion)(
          reinterpret_cast<int>(&targetRect), 1);

      ScopedMapQuickDrawContextGuard quickDrawContext(scopedRenderTarget);
      reinterpret_cast<TView*>(scopedRenderTarget)->Refresh();

      RECT renderRect;
      CopyRect(&renderRect, &targetRect);
      reinterpret_cast<TView*>(scopedRenderTarget)->ApplyRectSlot110(&renderRect.left);

      frameTick = 0;
      if (currentFrame < frameCount - 1) {
        currentFrame = currentFrame + 1;
      } else {
        completeFlag = 1;
      }
    }
  }
}
