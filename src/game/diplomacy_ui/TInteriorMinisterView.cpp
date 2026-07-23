#include "game/diplomacy_ui/TInteriorMinisterView.h"
#include "game/ui_tags_common.h"

#include "game/gfx/TAmbitApplication.h"
#include "game/ui_core/TEventHandler.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TWindow.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
// SYNTHETIC: IMPERIALISM 0x004f35e0
// TInteriorMinisterView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004f3670
// TInteriorMinisterView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TInteriorMinisterView, TMinisterView)

// The original inlines TMinisterView(TView(), field60(0)) directly here (same
// ctor-inlining divergence already established for TForeignMinisterView).
// FUNCTION: IMPERIALISM 0x004f3690
TInteriorMinisterView::TInteriorMinisterView() : TMinisterView() {}

// SYNTHETIC: IMPERIALISM 0x004f36c0
// TInteriorMinisterView::`scalar deleting destructor'
TInteriorMinisterView::~TInteriorMinisterView() {}

// FUNCTION: IMPERIALISM 0x004f3710
void TInteriorMinisterView::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  unsigned int tag = sourceHandler->controlTag;
  if (commandId == 0xa) {
    if (tag == kControlTagBack) {
      CloseBooks();
      return;
    } else if (tag == kControlTagOkay) {
      CloseBooks();
      TWindow* owner = GetWindow();
      g_pGlobalUiRootController->CloseAndFreeWindow(owner);
      return;
    }
  } else if (commandId == 0x14) {
    if (tag == kControlTagRecc) {
      OpenBook(kTurnEventInteriorMinisterRecommendationBook);
    } else if (tag == kControlTagTran) {
      if (g_pSimMgr->field14 == 0) {
        TWindow* owner = GetWindow();
        g_pGlobalUiRootController->CloseAndFreeWindow(owner);
      }
    } else if (tag == kControlTagTrea) {
      OpenBook(kTurnEventTreasuriesBook);
    }
    return;
  }
  TEventHandler::DoEvent(commandId, sourceHandler, event);
}
