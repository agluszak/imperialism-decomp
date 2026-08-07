#include "game/ui_screens/TNetSelectPicture.h"
#include "game/ui_tags_common.h"

#include "game/ui_core/TCluster.h"
#include "game/ui_core/TControl.h"
#include "game/net/TMultiplayerMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_screens_globals.h"
#include "game/gfx/ui_invalidation_guard.h"

// SYNTHETIC: IMPERIALISM 0x0045ae10
// TNetSelectPicture::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x0045ae40
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
void TNetSelectPicture::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
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
  TControl::DoEvent(commandId, sourceHandler, event);
}
