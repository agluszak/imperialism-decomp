#include "game/TWarningView.h"
#include "game/mfc.h"
#include "game/TControl.h"

extern "C" {
// GLOBAL: IMPERIALISM 0x00663178
CRuntimeClass g_pClassDescTWarningView = {nullptr, 0, 0, nullptr, nullptr};
}

void FreeHeapBufferIfNotNull(undefined4 ptr_value);

// FUNCTION: IMPERIALISM 0x00592860
TWarningView* __cdecl CreateTWarningViewInstance(void) {
  return new TWarningView();
}

// FUNCTION: IMPERIALISM 0x005928e0
CRuntimeClass* TWarningView::GetRuntimeClass() const {
  return &g_pClassDescTWarningView;
}

// FUNCTION: IMPERIALISM 0x00592900
TWarningView::TWarningView() : TPictureResourceEntryBase() {}

// Destructors are compiler-generated (implicit) from real inheritance.

// SYNTHETIC: IMPERIALISM 0x00592930
// TWarningView::`scalar deleting destructor'
TWarningView::~TWarningView() {}

// FUNCTION: IMPERIALISM 0x00592980
void TWarningView::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0x22 && event != 0) {
    unsigned int controlTag =
        *reinterpret_cast<unsigned int*>(reinterpret_cast<char*>(event) + 0x1c);
    if (controlTag >= 0x70696331 && controlTag <= 0x70696335) {
      TControl::HandleEvent(commandId, sourceHandler, event);
      return;
    }
  }
  TControl::HandleEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x00592a70
void TWarningView::NoOpUiLifecycleHook(int arg) {
  (void)arg;
  TView* titlePanel = QueryOwnerContextPanel();
  if (titlePanel == 0) {
    return;
  }
  TView* titleControl =
      reinterpret_cast<TView*>(titlePanel->ResolveControlByTag(0x7469746c)); // 'titl'
  if (titleControl != 0) {
    titleControl->RefreshControl();
  }
}
