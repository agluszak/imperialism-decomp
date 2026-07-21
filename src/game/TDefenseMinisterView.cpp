#include "game/TDefenseMinisterView.h"

#include "game/TAmbitApplication.h"
#include "game/TArmyMgr.h"
#include "game/TEventHandler.h"
#include "game/TSimMgr.h"
#include "game/TViewMgr.h"
#include "game/TWindow.h"
#include "game/global_data_tables.h"
#include "game/ui_control_tags.h"
// SYNTHETIC: IMPERIALISM 0x004f3240
// TDefenseMinisterView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004f32d0
// TDefenseMinisterView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TDefenseMinisterView, TMinisterView)

// The original inlines TMinisterView(TView(), field60(0)) directly here (same
// ctor-inlining divergence already established for TForeignMinisterView).
// FUNCTION: IMPERIALISM 0x004f32f0
TDefenseMinisterView::TDefenseMinisterView() : TMinisterView() {}

// SYNTHETIC: IMPERIALISM 0x004f3320
// TDefenseMinisterView::`scalar deleting destructor'
TDefenseMinisterView::~TDefenseMinisterView() {}

// FUNCTION: IMPERIALISM 0x004f3370
void TDefenseMinisterView::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  unsigned int tag = sourceHandler->controlTag;
  if (commandId == 0xa) {
    if (tag == kControlTagBack) {
      CloseBooks();
      return;
    } else if (tag == kControlTagOkay) {
      CloseBooks();
      TWindow* owner = static_cast<TWindow*>(GetWindow());
      g_pGlobalUiRootController->CloseAndFreeWindow(owner);
      return;
    }
  } else if (commandId == 0x14) {
    if (tag == kControlTagCann) {
      short activeNationId = g_pSimMgr->GetActiveNationId();
      if (g_pMapContextActionManager->ScanMapContextActionEntriesForCodeMatch(activeNationId)) {
        if (g_pSimMgr->field14 == 0) {
          TWindow* owner = static_cast<TWindow*>(GetWindow());
          g_pGlobalUiRootController->CloseAndFreeWindow(owner);
          g_pSimMgr->EnterOptionalPhase(0x65);
        }
      } else {
        CString message;
        g_pSimMgr->GetString(0x273d, 0x12, &message);
        g_pUiRuntimeContext->ModalMessage(message, g_ptDiplomacyNoticeModalMessage, 1, 0);
      }
    } else if (tag == kControlTagRecc) {
      OpenBook(0x258a);
    }
    return;
  }
  TEventHandler::DoEvent(commandId, sourceHandler, event);
}
