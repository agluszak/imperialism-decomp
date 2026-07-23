#include "game/diplomacy_ui/TForeignMinisterView.h"

#include "game/gfx/TAmbitApplication.h"
#include "game/ui_core/TEventHandler.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TWindow.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/ui_control_tags.h"
// SYNTHETIC: IMPERIALISM 0x004f2f20
// TForeignMinisterView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004f2fb0
// TForeignMinisterView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TForeignMinisterView, TMinisterView)

// The original inlines TMinisterView(TView(), field60(0)) directly here (only TView's
// own base ctor stays out-of-line); the recompile emits a call to TMinisterView's real
// ctor instead, which is the accepted architectural shape until ctor-inlining is
// modeled (same divergence pattern as TEscortMission(TZone*)/TNavyMission(TZone*)).
// FUNCTION: IMPERIALISM 0x004f2fd0
TForeignMinisterView::TForeignMinisterView() : TMinisterView() {}

// SYNTHETIC: IMPERIALISM 0x004f3000
// TForeignMinisterView::`scalar deleting destructor'
TForeignMinisterView::~TForeignMinisterView() {}

// FUNCTION: IMPERIALISM 0x004f3050
void TForeignMinisterView::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
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
    g_pGlobalUiRootController->CloseAndFreeWindow(owner);
  }
}

// FUNCTION: IMPERIALISM 0x004f3220
void TForeignMinisterView::ShowWorldExports() {}
