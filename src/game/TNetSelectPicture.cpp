#include "game/TNetSelectPicture.h"

#include "game/TCluster.h"
#include "game/TControl.h"
#include "game/TMultiplayerMgr.h"
#include "game/global_data_tables.h"
#include "game/ui_control_tags.h"
#include "game/ui_invalidation_guard.h"

// SYNTHETIC: IMPERIALISM 0x0045ae10
// TNetSelectPicture::`scalar deleting destructor'
TNetSelectPicture::~TNetSelectPicture() {}
// SYNTHETIC: IMPERIALISM 0x00576900
// TNetSelectPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x00576980
// TNetSelectPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TNetSelectPicture, TNoHilitePicture)

// FUNCTION: IMPERIALISM 0x005769a0
void TNetSelectPicture::DoPostCreate(int arg) {
  TView::DoPostCreate(arg);
}

// FUNCTION: IMPERIALISM 0x005769c0
void TNetSelectPicture::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (g_SetupScreensAssertFlag_006A4264 == 0) {
    TemporarilyClearAndRestoreUiInvalidationFlag(g_szSetupScreensSourcePath_00698AB8, 0x2e6);
  }
  if (commandId == 0x14 || commandId == 0xa || commandId == 0x22) {
    if (sourceHandler->controlTag == kControlTagCncl) {
      g_pGameFlowState->ResetGameFlowStateAndPostTurnEvent5DC();
    } else if (sourceHandler->controlTag == kControlTagOkay) {
      TCluster* protControl = static_cast<TCluster*>(ResolveControlByTag(kControlTagProt));
      protControl->AssertValid();
      int selectedProtocolTag = protControl->GetSelectedChildTag();
      TView* protocolOption = ResolveControlByTag(selectedProtocolTag);
      g_pGameFlowState->ValidateGameFlowNameAndSelectionContext(protocolOption->controlValue3c, 1);
    }
  }
  TControl::HandleEvent(commandId, sourceHandler, event);
}
