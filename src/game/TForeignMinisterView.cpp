#include "game/TForeignMinisterView.h"

#include "game/TAmbitApplication.h"
#include "game/TEventHandler.h"
#include "game/TSimMgr.h"
#include "game/TWindow.h"
#include "game/global_data_tables.h"
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
void TForeignMinisterView::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  unsigned int tag = sourceHandler->controlTag;
  if (commandId == 0xa) {
    if (tag == kControlTagBack) {
      CloseBooks();
      return;
    } else if (tag == kControlTagOkay) {
      CloseBooks();
      TWindow* owner = static_cast<TWindow*>(OwnerPanel());
      g_pGlobalUiRootController->CloseAndFreeWindow(owner);
      return;
    }
  } else if (commandId == 0x14) {
    switch (tag) {
    case kControlTagExpo:
      OpenBook(0x2300);
      break;
    case kControlTagDeal:
      OpenBook(0x22f6);
      break;
    case kControlTagMerc:
      OpenBook(0x22ec);
      break;
    case kControlTagGlob:
      ShowWorldMap();
      break;
    case kControlTagPric:
      OpenBook(0x231e);
      break;
    case kControlTagRecc:
      OpenBook(0x22e2);
      break;
    default:
      break;
    }
    return;
  }
  TEventHandler::HandleEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x004f31d0
void TForeignMinisterView::ShowWorldMap() {
  if (g_pSimMgr->field14 == 0) {
    TWindow* owner = static_cast<TWindow*>(OwnerPanel());
    CloseBooks();
    g_pGlobalUiRootController->CloseAndFreeWindow(owner);
  }
}

// FUNCTION: IMPERIALISM 0x004f3220
void TForeignMinisterView::ShowWorldExports() {}
