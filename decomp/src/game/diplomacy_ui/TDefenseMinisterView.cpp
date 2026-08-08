#include "game/diplomacy_ui/TDefenseMinisterView.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_diplomacy.h"

#include "game/gfx/TAmbitApplication.h"
#include "game/military/TArmyMgr.h"
#include "game/ui_core/TEventHandler.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_core/TWindow.h"
#include "game/globals/global_types.h"
#include "game/globals/diplomacy_ui_globals.h"
#include "game/globals/shared_globals.h"
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
// FUNCTION: IMPERIALISM 0x004f3350
TDefenseMinisterView::~TDefenseMinisterView() {}

// FUNCTION: IMPERIALISM 0x004f3370
void TDefenseMinisterView::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
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
    if (tag == kControlTagCann) {
      short activeNationId = g_pSimMgr->GetActiveNationId();
      if (g_pMapContextActionManager->ScanMapContextActionEntriesForCodeMatch(activeNationId)) {
        if (g_pSimMgr->field14 == 0) {
          TWindow* owner = GetWindow();
          g_pAmbitApplication->CloseAndFreeWindow(owner);
          g_pSimMgr->EnterOptionalPhase(0x65);
        }
      } else {
        CString message;
        g_pSimMgr->GetString(0x273d, 0x12, &message);
        g_pViewMgr->ModalMessage(message, g_ptDiplomacyNoticeModalMessage, 1, 0);
      }
    } else if (tag == kControlTagRecc) {
      OpenBook(kTurnEventDefenseMinisterRecommendationBook);
    }
    return;
  }
  TEventHandler::DoEvent(commandId, sourceHandler, event);
}
