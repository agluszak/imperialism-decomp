#include "game/ui_widgets/TWarningView.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_widgets.h"
#include "game/mfc.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/TControl.h"
#include "game/ui_screens/TSimMgr.h"

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
  if (commandId == 0x22) {
    unsigned int controlTag = sourceHandler->controlTag;
    switch (controlTag) {
    case kControlTagPic1:
      g_pSimMgr->EnterOptionalPhase(0x68);
      break;
    case kControlTagPic1 + 1:
      g_pSimMgr->EnterOptionalPhase(0x67);
      break;
    case kControlTagPic1 + 2:
      g_pSimMgr->EnterOptionalPhase(0x6a);
      break;
    case kControlTagPic1 + 3:
      g_pSimMgr->EnterOptionalPhase(0x69);
      break;
    case kControlTagPic5:
      g_pSimMgr->EnterOptionalPhase(5);
      break;
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
  TView* titleControl = titlePanel->ResolveControlByTag(kControlTagTitl); // 'titl'
  if (titleControl != 0) {
    titleControl->RefreshControl();
  }
}
