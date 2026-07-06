#include "game/TPlacard.h"
#include "game/mfc.h"
#include "game/TControl.h"
#include "game/ui_invalidation_guard.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_widget_thunks.h"
// SYNTHETIC: IMPERIALISM 0x0058b960
// TPlacard::CreateObject
// SYNTHETIC: IMPERIALISM 0x0058b9f0
// TPlacard::GetRuntimeClass

IMPLEMENT_DYNCREATE(TPlacard, TPicture)

// FUNCTION: IMPERIALISM 0x0058ba10
TPlacard::TPlacard() : TPicture() {
  this->glyph90 = 0;
}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x0058ba40
// TPlacard::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x0058bab0
void TPlacard::NoOpUiLifecycleHook(int arg) {
  TView::NoOpUiLifecycleHook(arg);
  if (glyph90 == 0) {
    SetState(0, 1);
    return;
  }
  SetState(1, 1);
}

// FUNCTION: IMPERIALISM 0x0058bb50
bool TPlacard::IsSelected(short value, bool refreshNow) {
  if (value != glyph90) {
    if (value == 0) {
      SetState(0, refreshNow);
    } else if (glyph90 == 0) {
      SetState(1, refreshNow);
    }
    glyph90 = value;
    if (refreshNow) {
      RECT rect;
      rect.top = field38 - 0xc;
      rect.left = static_cast<short>((field34 / 2) - 10);
      rect.right = rect.left + 0x14;
      rect.bottom = field38 - 1;
      InvalidateCityDialogRectRegion(&rect, 1);
    }
  }
  return glyph90 != 0;
}

// FUNCTION: IMPERIALISM 0x0058bc60
void TPlacard::ApplyRectSlot110(RECT* rectBuffer) {
  (void)rectBuffer;
  TPicture::ApplyRectSlot110(nullptr);
  reinterpret_cast<void(__cdecl*)(int, int)>(ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor)(0,
                                                                                                10);
  if (glyph90 < 10) {
    SetQuickDrawTextOriginWithContextOffset(field34 / 2 - 2, 0);
  } else if (glyph90 < 100) {
    SetQuickDrawTextOriginWithContextOffset(field34 / 2 - 6, 0);
  } else {
    SetQuickDrawTextOriginWithContextOffset(field34 / 2 - 10, 0);
  }
  RefreshControl();
}

TPlacard::~TPlacard() {}
