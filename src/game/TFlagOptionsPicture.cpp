#include "game/TFlagOptionsPicture.h"

#include "game/CString.h"
#include "game/ImperialismApp.h"
#include "game/TAmbitApplication.h"
#include "game/TControl.h"
#include "game/TDropShadowText.h"
#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/TMultiplayerMgr.h"
#include "game/TSimMgr.h"
#include "game/TViewMgr.h"
#include "game/TWindow.h"
#include "game/global_data_tables.h"
#include "game/ui_control_tags.h"
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x0043da10
// TFlagOptionsPicture::`scalar deleting destructor'
TFlagOptionsPicture::~TFlagOptionsPicture() {}
// SYNTHETIC: IMPERIALISM 0x0056b210
// TFlagOptionsPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x0056b290
// TFlagOptionsPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TFlagOptionsPicture, TPicture)

TFlagOptionsPicture::TFlagOptionsPicture() {}

// FUNCTION: IMPERIALISM 0x0056b2b0
void TFlagOptionsPicture::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xa) {
    CString text;
    unsigned int tag = sourceHandler->controlTag;
    if (tag == kControlTagGowy) {
      TWindow* owner = static_cast<TWindow*>(OwnerPanel());
      owner->Dismiss(tag, 0);
    } else if (tag == kControlTagCred) {
      TWindow* owner = static_cast<TWindow*>(OwnerPanel());
      owner->Dismiss(kControlTagOkay, 0);
      g_pSimMgr->EnterOptionalPhase(0x71);
    } else if (tag == kControlTagNewg || tag == kControlTagQuit) {
      if (g_pUiRuntimeContext->DispatchGameStateEventIfLocalizedPromptAccepted(tag)) {
        TWindow* owner = static_cast<TWindow*>(OwnerPanel());
        owner->Dismiss(tag, 0);
        if (g_pSimMgr->multiplayerSessionRole == 1) {
          int saveResult = 0;
          if (g_pGameFlowState->fieldF4 != 0) {
            saveResult = g_pGameFlowState->TrySaveGameAndMaybeShowFailureDialog(0xa1, nullptr, 0);
          }
          g_pGameFlowState->DispatchTaggedGameStateEvent1F20(tag, saveResult, -3);
        } else if (tag == kControlTagQuit) {
          PostWmCloseToMainThreadWindow();
        } else {
          g_pGlobalUiRootController->CreateAndQueueTurnEventPacketTagGWEN();
        }
      }
    } else if (tag == kControlTagLoad) {
      if (g_pSimMgr->multiplayerSessionRole != 0) {
        g_pUiRuntimeContext->ShowLocalizedUiPromptByGroupAndIndex(0x2737, 0x34, 0, 0);
      } else {
        TWindow* owner = static_cast<TWindow*>(OwnerPanel());
        owner->Dismiss(tag, 0);
        g_pSimMgr->EnterOptionalPhase(0x70);
      }
    } else if (tag == kControlTagPref) {
      TWindow* owner = static_cast<TWindow*>(OwnerPanel());
      owner->Dismiss(tag, 0);
      g_pSimMgr->EnterOptionalPhase(0x6b);
    } else if (tag == kControlTagSave) {
      TWindow* owner = static_cast<TWindow*>(OwnerPanel());
      owner->Dismiss(tag, 0);
      if (g_pSimMgr->multiplayerSessionRole == 2) {
        g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&text, 0x2742, 0x13);
        g_pUiRuntimeContext->ModalMessage(text, g_ptQueryFloaterModalMessage, 0, 0);
      } else {
        g_pSimMgr->EnterOptionalPhase(0x6f);
      }
    } else {
      TControl::HandleEvent(commandId, sourceHandler, event);
    }
  } else {
    TControl::HandleEvent(commandId, sourceHandler, event);
  }
}

// FUNCTION: IMPERIALISM 0x0056b640
void TFlagOptionsPicture::DoPostCreate(int arg) {
  TPicture::DoPostCreate(arg);

  CString text;
  for (int i = 0; i < 8; ++i) {
    g_pSimMgr->GetString(0x2743, static_cast<short>(i), &text);
    TDropShadowText* control =
        static_cast<TDropShadowText*>(ResolveControlByTag(kControlTagTxt0 + i));
    control->QueryStepValue();
    if (i == 0) {
      ApplyUiTextStyleAndThemeFlags(control, 0, 0xc, 0x2b6c, 0x2b6a);
    } else {
      ApplyUiTextStyleAndThemeFlags(control, 0, 0xe, 0x2b6b, 0x2b6c);
    }
    control->SetTextAlignmentAndMaybeRefresh(i > 1 ? -2 : 1, 0);
    control->SetTextAndMaybeRefresh(&text, 0);
  }
}
