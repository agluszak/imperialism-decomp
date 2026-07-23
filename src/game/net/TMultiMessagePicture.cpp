#include "game/net/TMultiMessagePicture.h"
#include "game/multiplayer_session_tags.h"
#include "game/ui_tags_common.h"

#include "game/ui_screens/CString.h"
#include "game/gfx/TAmbitApplication.h"
#include "game/ui_screens/TCzechBox.h"
#include "game/ui_core/TEditText.h"
#include "game/net/TMultiplayerMgr.h"
#include "game/ui_core/TWindow.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"

// SYNTHETIC: IMPERIALISM 0x0044fb10
// TMultiMessagePicture::`scalar deleting destructor'
TMultiMessagePicture::~TMultiMessagePicture() {}
// SYNTHETIC: IMPERIALISM 0x0054ec20
// TMultiMessagePicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x0054eca0
// TMultiMessagePicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMultiMessagePicture, TPicture)

TMultiMessagePicture::TMultiMessagePicture() {}

// FUNCTION: IMPERIALISM 0x0054ecc0
void TMultiMessagePicture::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId != 0x14 && commandId != 0xa && commandId != 0x22) {
    return;
  }

  unsigned int tag = sourceHandler->controlTag;
  if (tag != kControlTagCanc && tag != kControlTagCncl) { // 'canc', 'cncl'
    if (tag != kControlTagOkay) {                         // 'okay'
      TControl::DoEvent(commandId, sourceHandler, event);
      return;
    }

    TEditText* messageControl =
        static_cast<TEditText*>(ResolveControlByTag(kSessionTagMesg)); // 'mesg'
    messageControl->AssertValid();
    CString message;
    messageControl->GetCurrentText(&message);

    unsigned int recipientMask = 0;
    for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
      TCzechBox* nationBox =
          static_cast<TCzechBox*>(ResolveControlByTag(kSessionTagBox0 + nationSlot)); // 'box0'..
      nationBox->AssertValid();
      if (nationBox->IsEnabled() != 0 && nationBox->IsOn() != 0) {
        recipientMask |= 1 << nationSlot;
      }
    }
    g_pGameFlowState->CreateAndSendTurnEvent0C_Text256AndTwoFlags(
        &message, static_cast<unsigned char>(recipientMask),
        static_cast<unsigned char>(FindActiveNationSlotIndexInGameFlowList()));
  }

  g_pGlobalUiRootController->CloseAndFreeWindow(GetWindow());
}
