#include "game/ui_widgets/TWarningView.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_widgets.h"
#include "game/mfc.h"
#include "game/ui_core/TControl.h"

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
// FUNCTION: IMPERIALISM 0x00592960
TWarningView::~TWarningView() {}

// FUNCTION: IMPERIALISM 0x00592980
void TWarningView::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0x22 && event != 0) {
    unsigned int controlTag =
        *reinterpret_cast<unsigned int*>(reinterpret_cast<char*>(event) + 0x1c);
    if (controlTag >= kControlTagPic1 && controlTag <= kControlTagPic5) {
      TControl::DoEvent(commandId, sourceHandler, event);
      return;
    }
  }
  TControl::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x00592a70
void TWarningView::DoPostCreate(int arg) {
  (void)arg;
  TView* titlePanel = GetRootView();
  if (titlePanel == 0) {
    return;
  }
  TView* titleControl =
      reinterpret_cast<TView*>(titlePanel->ResolveControlByTag(kControlTagTitl)); // 'titl'
  if (titleControl != 0) {
    titleControl->RefreshControl();
  }
}
