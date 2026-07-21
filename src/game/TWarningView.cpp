#include "game/TWarningView.h"
#include "game/mfc.h"
#include "game/TControl.h"

// SYNTHETIC: IMPERIALISM 0x00592860
// TWarningView::CreateObject
// SYNTHETIC: IMPERIALISM 0x005928e0
// TWarningView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TWarningView, TPicture)

// FUNCTION: IMPERIALISM 0x00592900
TWarningView::TWarningView() : TPicture() {}

// Destructors are compiler-generated (implicit) from real inheritance.

// SYNTHETIC: IMPERIALISM 0x00592930
// TWarningView::`scalar deleting destructor'
TWarningView::~TWarningView() {}

// FUNCTION: IMPERIALISM 0x00592980
void TWarningView::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0x22 && event != 0) {
    unsigned int controlTag =
        *reinterpret_cast<unsigned int*>(reinterpret_cast<char*>(event) + 0x1c);
    if (controlTag >= 0x70696331 && controlTag <= 0x70696335) {
      TControl::DoEvent(commandId, sourceHandler, event);
      return;
    }
  }
  TControl::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x00592a70
void TWarningView::DoPostCreate(int arg) {
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
