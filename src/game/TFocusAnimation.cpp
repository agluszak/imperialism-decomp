// TFocusAnimation scoped QuickDraw render/tick slice.

#include "game/TFocusAnimation.h"

#include "game/TView.h"
#include "game/mfc.h"
#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"
#include "game/ui_widget_thunks.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

// FUNCTION: IMPERIALISM 0x004a0190
void TFocusAnimation::DestructTFocusAnimationAndMaybeFree() {
  if (enabledFlag != 0) {
    ScopedMapQuickDrawContextGuard quickDrawContext(scopedRenderTarget);
    reinterpret_cast<TView*>(scopedRenderTarget)->Refresh();

    int completionRecord[2];
    completionRecord[0] = 0;
    completionRecord[1] = 0;
    this->DispatchCompletionRecordSlot14(completionRecord);
    reinterpret_cast<TView*>(scopedRenderTarget)->PostRenderSlotFC();
  }
}
