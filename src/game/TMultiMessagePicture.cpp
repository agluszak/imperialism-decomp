#include "game/TMultiMessagePicture.h"

#include "game/CString.h"
#include "game/TAmbitApplication.h"
#include "game/TCzechBox.h"
#include "game/TEditText.h"
#include "game/TMultiplayerMgr.h"
#include "game/TWindow.h"
#include "game/global_data_tables.h"

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
  if (tag != 0x63616e63 && tag != 0x636e636c) { // 'canc', 'cncl'
    if (tag != 0x6f6b6179) {                    // 'okay'
      TControl::DoEvent(commandId, sourceHandler, event);
      return;
    }

    TEditText* messageControl = static_cast<TEditText*>(ResolveControlByTag(0x6d657367)); // 'mesg'
    messageControl->AssertValid();
    CString message;
    messageControl->GetCurrentText(&message);

    unsigned int recipientMask = 0;
    for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
      TCzechBox* nationBox =
          static_cast<TCzechBox*>(ResolveControlByTag(0x626f7830 + nationSlot)); // 'box0'..
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
