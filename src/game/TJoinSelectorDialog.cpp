#include "game/TJoinSelectorDialog.h"

#include "game/CMcWindow.h"
#include "game/TEditText.h"
#include "game/TLanguageMgr.h"
#include "game/TMultiplayerMgr.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_control_tags.h"
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x0044fab0
// TJoinSelectorDialog::`scalar deleting destructor'
TJoinSelectorDialog::~TJoinSelectorDialog() {}
// SYNTHETIC: IMPERIALISM 0x0054e690
// TJoinSelectorDialog::CreateObject

// SYNTHETIC: IMPERIALISM 0x0054e710
// TJoinSelectorDialog::GetRuntimeClass

IMPLEMENT_DYNCREATE(TJoinSelectorDialog, TNoHilitePicture)

TJoinSelectorDialog::TJoinSelectorDialog() {}

// FUNCTION: IMPERIALISM 0x0054e730
void TJoinSelectorDialog::NoOpUiLifecycleHook(int arg) {
  TView::NoOpUiLifecycleHook(arg);

  TStaticText* tnamControl = static_cast<TStaticText*>(ResolveControlByTag(kControlTagTnam));
  tnamControl->AssertValid();
  TEditText* nameControl = static_cast<TEditText*>(ResolveControlByTag(kControlTagName));
  nameControl->AssertValid();
  TStaticText* tgamControl = static_cast<TStaticText*>(ResolveControlByTag(kControlTagTgam));
  tgamControl->AssertValid();
  TStaticText* gameControl = static_cast<TStaticText*>(ResolveControlByTag(kControlTagGame));
  gameControl->AssertValid();

  ConfigureUiControlStyleValueAndCaptionFromStringResource(tnamControl, 0, 0xc, 0x2b6b, -2, 0x2742,
                                                           4);
  ConfigureUiControlStyleValueAndCaptionFromStringResource(tgamControl, 0, 0xc, 0x2b6b, -2, 0x2742,
                                                           5);

  CString normalizedPlayerName =
      g_pLanguageMgr->NormalizeRuntimeCredentialNameToken(&g_pGameFlowState->playerNameString);
  ApplyControlThemeStyleAndOptionalCaption(nameControl, 0, 0xc, 0x2b6b, 1, normalizedPlayerName);
  nameControl->field_9c = 0xc;
  if (nameControl->field_94 != nullptr) {
    nameControl->field_94->SendMessage(0xc5, nameControl->field_9c, 0);
  }

  gameControl->field90 = 0x2b6b;
  gameControl->field92 = 2;
}

// FUNCTION: IMPERIALISM 0x0054e9a0
void TJoinSelectorDialog::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if ((commandId == 0x14 || commandId == 0xa || commandId == 0x22 || commandId == 0xd) &&
      (sourceHandler->controlTag == kControlTagCanc ||
       sourceHandler->controlTag == kControlTagCncl ||
       sourceHandler->controlTag == kControlTagOkay)) {
    static_cast<TControl*>(OwnerPanel())
        ->SetTextStyleAndMaybeRefresh(
            reinterpret_cast<TUiTextStyleDescriptor*>(sourceHandler->controlTag), 1);
  }
  TControl::HandleEvent(commandId, sourceHandler, event);
}
