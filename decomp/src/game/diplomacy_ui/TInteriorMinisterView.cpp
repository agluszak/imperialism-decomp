#include "game/diplomacy_ui/TInteriorMinisterView.h"
#include "game/ui_tags_common.h"

#include "game/gfx/TAmbitApplication.h"
#include "game/ui_core/TEventHandler.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TWindow.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"

IMPLEMENT_DYNCREATE(TInteriorMinisterView, TMinisterView)

// FUNCTION: IMPERIALISM 0x004f3690
TInteriorMinisterView::TInteriorMinisterView() {}

// FUNCTION: IMPERIALISM 0x004f36f0
TInteriorMinisterView::~TInteriorMinisterView() {}

// FUNCTION: IMPERIALISM 0x004f3710
void TInteriorMinisterView::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId != 0xa && commandId != 0x14) {
    TEventHandler::DoEvent(commandId, sourceHandler, event);
    return;
  }
  unsigned int tag = sourceHandler->controlTag;
  if (commandId == 0xa) {
    if (tag == kControlTagBack) {
      CloseBooks();
      return;
    } else if (tag == kControlTagOkay) {
      CloseBooks();
      TWindow* owner = GetWindow();
      g_pAmbitApplication->CloseAndFreeWindow(owner);
      return;
    }
  } else if (commandId == 0x14) {
    if (tag == kControlTagRecc) {
      OpenBook(kTurnEventInteriorMinisterRecommendationBook);
    } else if (tag == kControlTagTran) {
      if (g_pSimMgr->field14 == 0) {
        TWindow* owner = GetWindow();
        g_pAmbitApplication->CloseAndFreeWindow(owner);
      }
    } else if (tag == kControlTagTrea) {
      OpenBook(kTurnEventTreasuriesBook);
    }
    return;
  }
  TEventHandler::DoEvent(commandId, sourceHandler, event);
}
