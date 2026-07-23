#include "game/TNetGameSelectPicture.h"

#include "game/TCluster.h"
#include "game/TControl.h"
#include "game/TMultiplayerMgr.h"
#include "game/global_data_tables.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_screens.h"

// SYNTHETIC: IMPERIALISM 0x00576b20
// TNetGameSelectPicture::`scalar deleting destructor'
TNetGameSelectPicture::~TNetGameSelectPicture() {}
// SYNTHETIC: IMPERIALISM 0x00576aa0
// TNetGameSelectPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x00576b70
// TNetGameSelectPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TNetGameSelectPicture, TNoHilitePicture)

TNetGameSelectPicture::TNetGameSelectPicture() {}

// FUNCTION: IMPERIALISM 0x00576b90
void TNetGameSelectPicture::DoPostCreate(int arg) {
  TView::DoPostCreate(arg);
  g_pGameFlowState->InitializeRuntimeSelectionCredentialsFromProviderAndConnect(this);
}

// FUNCTION: IMPERIALISM 0x00576bc0
void TNetGameSelectPicture::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0x14 || commandId == 0xa || commandId == 0x22) {
    if (sourceHandler->controlTag == kControlTagCncl) {
      g_pGameFlowState->ResetGameFlowStateAndPostTurnEvent5DCAlt();
    } else if (sourceHandler->controlTag == kControlTagHost) {
      g_pGameFlowState->AssignStringAtB4FromB0AndResetState40();
    } else if (sourceHandler->controlTag == kControlTagJoin) {
      TCluster* gameControl = static_cast<TCluster*>(ResolveControlByTag(kControlTagGame));
      gameControl->AssertValid();
      int selectedGameTag = gameControl->GetSelectedChildTag();
      TView* selectedGameOption = ResolveControlByTag(selectedGameTag);
      g_pGameFlowState->ApplyJoinGameSelectionAndPostTurnEvent5E4(
          selectedGameOption->controlValue3c);
    }
  }
  TControl::DoEvent(commandId, sourceHandler, event);
}
