#include "game/ui_screens/TNetGameSelectPicture.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_screens.h"

#include "game/ui_core/TCluster.h"
#include "game/ui_core/TControl.h"
#include "game/net/TMultiplayerMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"

// FUNCTION: IMPERIALISM 0x00576b50
TNetGameSelectPicture::~TNetGameSelectPicture() {}

IMPLEMENT_DYNCREATE(TNetGameSelectPicture, TNoHilitePicture)

// FUNCTION: IMPERIALISM 0x00576b90
void TNetGameSelectPicture::DoPostCreate(int arg) {
  TView::DoPostCreate(arg);
  g_pGameFlowState->InitializeRuntimeSelectionCredentialsFromProviderAndConnect(this);
}

// FUNCTION: IMPERIALISM 0x00576bc0
void TNetGameSelectPicture::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0x14 || commandId == 0xa || commandId == 0x22) {
    if (sourceHandler->controlTag == kControlTagCncl) {
      g_pGameFlowState->ResetSessionAndShowMainMenu();
    } else if (sourceHandler->controlTag == kControlTagHost) {
      g_pGameFlowState->Host();
    } else if (sourceHandler->controlTag == kControlTagJoin) {
      TCluster* gameControl = static_cast<TCluster*>(FindSubView(kControlTagGame));
      gameControl->AssertValid();
      int selectedGameTag = gameControl->GetCurrentChoice();
      TView* selectedGameOption = FindSubView(selectedGameTag);
      g_pGameFlowState->ApplyJoinGameSelectionAndShowNetworkGameOptions(
          selectedGameOption->controlValue);
    }
  }
  TControl::DoEvent(commandId, sourceHandler, event);
}
