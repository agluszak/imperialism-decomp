#include "game/net/TJoinSelectorDialog.h"
#include "game/multiplayer_session_tags.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_screens.h"
#include "game/ui_core/TWindow.h"

#include "game/ui_core/CMcEditWindow.h"
#include "game/ui_core/TEditText.h"
#include "game/ui_core/TLanguageMgr.h"
#include "game/net/TMultiplayerMgr.h"
#include "game/ui_screens/TRadioText.h"
#include "game/ui_screens/TRadioTextCluster.h"
#include "game/net/TWNetSessionManager.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x0044fab0
// TJoinSelectorDialog::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x0044fb40
TJoinSelectorDialog::~TJoinSelectorDialog() {}
// SYNTHETIC: IMPERIALISM 0x0054e690
// TJoinSelectorDialog::CreateObject

// SYNTHETIC: IMPERIALISM 0x0054e710
// TJoinSelectorDialog::GetRuntimeClass

IMPLEMENT_DYNCREATE(TJoinSelectorDialog, TNoHilitePicture)

// FUNCTION: IMPERIALISM 0x0054e730
void TJoinSelectorDialog::DoPostCreate(int arg) {
  TView::DoPostCreate(arg);

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
  nameControl->maxCharacterCount = 0xc;
  if (nameControl->editWindow != nullptr) {
    nameControl->editWindow->SendMessage(0xc5, nameControl->maxCharacterCount, 0);
  }

  gameControl->textAlignmentCode = 0x2b6b;
  gameControl->textOptionFlags = 2;
}

// FUNCTION: IMPERIALISM 0x0054e8e0
void TJoinSelectorDialog::AddJoinableGameOptionEntry(const char* label,
                                                     RuntimeSelectionRecord* record) {
  TRadioTextCluster* gameControl =
      static_cast<TRadioTextCluster*>(ResolveControlByTag(kControlTagGame));
  gameControl->AssertValid();
  unsigned long recordTag = (unsigned long)record;
  TRadioText* item = gameControl->AddItem(recordTag, (int)record, label, 0x12, -1);
  ApplyUiTextStyleAndThemeFlags(item, 0, 0xc, 0x2b6b, 0x2b6c);
  item->SetTextAlignmentAndMaybeRefresh(-2, 0);
  gameControl->SetSelectedTextOptionByTag((int)record, false);
}

// FUNCTION: IMPERIALISM 0x0054e970
RuntimeSelectionRecord* TJoinSelectorDialog::GetSelectedJoinableGame() {
  TRadioTextCluster* gameControl =
      static_cast<TRadioTextCluster*>(ResolveControlByTag(kControlTagGame));
  gameControl->AssertValid();
  return (RuntimeSelectionRecord*)gameControl->selectedTag88;
}

// FUNCTION: IMPERIALISM 0x0054e9a0
void TJoinSelectorDialog::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if ((commandId == 0x14 || commandId == 0xa || commandId == 0x22 || commandId == 0xd) &&
      (sourceHandler->controlTag == kControlTagCanc ||
       sourceHandler->controlTag == kControlTagCncl ||
       sourceHandler->controlTag == kControlTagOkay)) {
    GetWindow()->Dismiss(sourceHandler->controlTag, 1);
  }
  TControl::DoEvent(commandId, sourceHandler, event);
}
