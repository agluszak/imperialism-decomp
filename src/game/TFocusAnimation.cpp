// TFocusAnimation scoped QuickDraw render/tick slice.

#include "decomp_types.h"
#include "game/TView.h"
#include "game/mfc.h"
#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"
#include "game/mfc.h"
#include "game/ui_widget_thunks.h"
#include <new>
#include "game/quickdraw_guards.h"
#include "game/generated/vcall_facades.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

// TFocusAnimation derives from the MFC CObject root: the factory at 0x004a0080
// installs the shared CObject runtime vtable (0x0066fec4) and the class adds no
// virtuals of its own. CObject supplies the vptr at offset 0; the animation
// fields begin at offset 0x4.
// Duplicate VTABLE annotation removed
class TFocusAnimation : public CObject {
public:
  void* scopedRenderTarget; // 0x04
  short currentFrame;       // 0x08
  short frameCount;         // 0x0a
  short field0c;            // 0x0c
  char pad_0e[2];
  int frameTick;      // 0x10
  int frameTickLimit; // 0x14
  int field18;        // 0x18
  int field1c;        // 0x1c
  int field20;        // 0x20
  int field24;        // 0x24
  int field28;        // 0x28
  char enabledFlag;   // 0x2c

  void DestructTFocusAnimationAndMaybeFree();
};

// FUNCTION: IMPERIALISM 0x004a0190
void TFocusAnimation::DestructTFocusAnimationAndMaybeFree() {
  if (enabledFlag != 0) {
    ScopedMapQuickDrawContextGuard quickDrawContext(scopedRenderTarget);
    reinterpret_cast<TView*>(scopedRenderTarget)->Refresh();

    int completionRecord[2];
    completionRecord[0] = 0;
    completionRecord[1] = 0;
    VCall_FocusAnimation_CallSlot2C(this, completionRecord);
    reinterpret_cast<TView*>(scopedRenderTarget)->PostRenderSlotFC();
  }
}
