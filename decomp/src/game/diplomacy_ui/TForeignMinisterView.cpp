#include "game/diplomacy_ui/TForeignMinisterView.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_diplomacy.h"

#include "game/gfx/TAmbitApplication.h"
#include "game/ui_core/TEventHandler.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TWindow.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"

IMPLEMENT_DYNCREATE(TForeignMinisterView, TMinisterView)

// FUNCTION: IMPERIALISM 0x004f2fd0
TForeignMinisterView::TForeignMinisterView() : TMinisterView() {}

// FUNCTION: IMPERIALISM 0x004f3030
TForeignMinisterView::~TForeignMinisterView() {}

// FUNCTION: IMPERIALISM 0x004f3050
void TForeignMinisterView::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
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
    switch (tag) {
    case kControlTagExpo:
      OpenBook(kTurnEventExportsBook);
      break;
    case kControlTagDeal:
      OpenBook(kTurnEventMiniDealBook);
      break;
    case kControlTagMerc:
      OpenBook(kTurnEventMerchantMarineBook);
      break;
    case kControlTagGlob:
      ShowWorldMap();
      break;
    case kControlTagPric:
      OpenBook(kTurnEventPriceHistoryBook);
      break;
    case kControlTagRecc:
      OpenBook(kTurnEventForeignMinisterRecommendationBook);
      break;
    default:
      break;
    }
    return;
  }
  TEventHandler::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x004f31d0
void TForeignMinisterView::ShowWorldMap() {
  if (g_pSimMgr->field14 == 0) {
    TWindow* owner = GetWindow();
    CloseBooks();
    g_pAmbitApplication->CloseAndFreeWindow(owner);
  }
}

// FUNCTION: IMPERIALISM 0x004f3220
void TForeignMinisterView::ShowWorldExports() {}
