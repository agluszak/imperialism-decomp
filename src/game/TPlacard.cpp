#include "game/TPlacard.h"
#include "game/CRuntimeClass.h"
#include "game/TControl.h"
#include "game/trade_quickdraw.h"
#include "game/ui_widget_thunks.h"

CRuntimeClass g_pClassDescTPlacard = {nullptr, 0, 0, nullptr, nullptr};

// FUNCTION: IMPERIALISM 0x0058b960
void* __cdecl CreateTPlacardInstance(void) {
  return new TPlacard();
}

// FUNCTION: IMPERIALISM 0x0058b9f0
CRuntimeClass* TPlacard::GetRuntimeClass() {
  return &g_pClassDescTPlacard;
}

// FUNCTION: IMPERIALISM 0x0058ba10
TPlacard::TPlacard() : TPictureButton() {
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

// FUNCTION: IMPERIALISM 0x0058bc60
void TPlacard::ApplyRectSlot110(RECT* rectBuffer) {
  (void)rectBuffer;
  TPictureResourceEntryBase::ApplyRectSlot110(nullptr);
  reinterpret_cast<void(__cdecl*)(int, int)>(ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor)(0,
                                                                                                 10);
  if (glyph90 < 10) {
    SetQuickDrawTextOrigin(field34 / 2 - 2, 0);
  } else if (glyph90 < 100) {
    SetQuickDrawTextOrigin(field34 / 2 - 6, 0);
  } else {
    SetQuickDrawTextOrigin(field34 / 2 - 10, 0);
  }
  RefreshControl();
}

TPlacard::~TPlacard() {}
