// TFocusAnimation scoped QuickDraw render/tick slice.

#include "decomp_types.h"
#include "game/generated/vcall_facades.h"
#include "game/ui_widget_shared.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

struct TFocusAnimationLayout {
  void* vftable;
  void* scopedRenderTarget;
  short currentFrame;
  short frameCount;
  short field0c;
  char pad_0e[2];
  int frameTick;
  int frameTickLimit;
  int field18;
  int field1c;
  int field20;
  int field24;
  int field28;
  char enabledFlag;
};

// FUNCTION: IMPERIALISM 0x004a0190
void __fastcall DestructTFocusAnimationAndMaybeFree(TFocusAnimationLayout* focusAnimation,
                                                    int unusedEdx) {
  // ORIG_CALLCONV: __thiscall
  (void)unusedEdx;
  if (focusAnimation->enabledFlag != 0) {
    ScopedMapQuickDrawContextGuard quickDrawContext(focusAnimation->scopedRenderTarget);
    VCall_FocusAnimationView_RenderSlotF8(focusAnimation->scopedRenderTarget);

    int completionRecord[2];
    completionRecord[0] = 0;
    completionRecord[1] = 0;
    VCall_FocusAnimation_CallSlot2C(focusAnimation, completionRecord);
    VCall_FocusAnimationView_PostRenderSlotFC(focusAnimation->scopedRenderTarget);
  }
}
