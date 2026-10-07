#include "game/ui_screens/TGameSetupMultiplayerPicture.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_screens.h"

#include "game/CSubViewIterator.h"
#include "game/ImperialismApp.h"
#include "game/gfx/TAmbitApplication.h"
#include "game/assets/TAssetMgr.h"
#include "game/ui_core/TControl.h"
#include "game/ui_widgets/TDropShadowText.h"
#include "game/ui_widgets/TInfoBarText.h"
#include "game/gfx/TResourceMgr.h"
#include "game/net/TMultiplayerMgr.h"
#include "game/ui_screens/TRadioTextCluster.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TViewMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/military/mapped_flavor_text.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

IMPLEMENT_DYNCREATE(TGameSetupMultiplayerPicture, TNoHilitePicture)

// FUNCTION: IMPERIALISM 0x00575f30
TGameSetupMultiplayerPicture::TGameSetupMultiplayerPicture() {}

// FUNCTION: IMPERIALISM 0x00575f90
TGameSetupMultiplayerPicture::~TGameSetupMultiplayerPicture() {}

// FUNCTION: IMPERIALISM 0x00575fb0
void TGameSetupMultiplayerPicture::DoPostCreate(int arg) {
  TView::DoPostCreate(arg);

  TRadioTextCluster* protControl = static_cast<TRadioTextCluster*>(FindSubView(kControlTagProt));
  protControl->AssertValid();
  protControl->selectedColorCode = 0x4c;
  protControl->unselectedColorCode = 0x4d;

  if (g_pGameFlowState->InitializeProtocolList(this)) {
    CSubViewIterator iter(protControl);
    TView* child = iter.FirstSubView();
    if (iter.MoreSubViews()) {
      do {
        child->AssertValid();
        ApplyUiTextStyleAndThemeFlags(static_cast<TDropShadowText*>(child), 0, 0xc, 0x2b6c, 0x2b6a);
        child = iter.NextSubView();
      } while (iter.MoreSubViews());
    }
  } else {
    g_pGameFlowState->CancelProtocolSelect();
  }

  TInfoBarText* cursControl = static_cast<TInfoBarText*>(FindSubView(kControlTagCurs));
  cursControl->AssertValid();
  TextStyle styleDescriptor;
  styleDescriptor.fontFamily = 0;
  styleDescriptor.fontStyleFlags = 0;
  styleDescriptor.fontSize = 0;
  styleDescriptor.textColor = 0;
  BuildUiTextStyleDescriptor(&styleDescriptor, 0, 0xe, 0x2b6c);
  cursControl->SetTextStyle(styleDescriptor, true);
  cursControl->InitializeMapHintTextStyleAndThemeFlags(0x2b6b, 0x2b6c);
  cursControl->SetJustification(1, false);

  ApplySharedStringToGlobalControlTag(CString(g_szEmptyString), kControlTagMain);
  SetTaggedStringAndApply(0x2737, 0x1f, kControlTagRand);
  SetTaggedStringAndApply(0x2737, 0x20, kControlTagScen);
  SetTaggedStringAndApply(0x2737, 0x21, kControlTagLoad);
  SetTaggedStringAndApply(0x2737, 0x22, kControlTagMult);
  SetTaggedStringAndApply(0x2737, 0x23, kControlTagJoin);
  SetTaggedStringAndApply(0x2737, 0x24, kControlTagProt);

  if (g_pAssetMgr->AreThereStrayClientSaves()) {
    TControl* spitControl = static_cast<TControl*>(FindSubView(kControlTagSpit));
    spitControl->AssertValid();
    spitControl->ViewEnable(1, 0);
    SetControlString(0x2759, 7, spitControl);
  }
}

// FUNCTION: IMPERIALISM 0x00576230
void TGameSetupMultiplayerPicture::DoEvent(int commandId, TEventHandler* sourceHandler,
                                           TEvent* event) {
  if (commandId == 0x14 || commandId == 0xa || commandId == 0x22 || commandId == 0xd) {
    unsigned int tag = sourceHandler->controlTag;

    if (tag == kControlTagLoad || tag == kControlTagJoin || tag == kControlTagRand ||
        tag == kControlTagScen) {
      TRadioTextCluster* protControl =
          static_cast<TRadioTextCluster*>(FindSubView(kControlTagProt));
      protControl->AssertValid();
      TView* selectedProtocolControl = protControl->FindSubView(protControl->selectedTag);
      selectedProtocolControl->AssertValid();

      bool isNotJoin = (tag != kControlTagJoin);
      int protocolValue = selectedProtocolControl->controlValue;
      bool accepted =
          g_pGameFlowState->ValidateGameFlowNameAndSelectionContext(protocolValue, isNotJoin);
      if (!accepted) {
        CString errorMsg;
        g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&errorMsg, 0x2737, 0x28);
        g_pViewMgr->ModalMessage(errorMsg, g_ptGameSetupModalMessage, 0, 0);
        g_pGameFlowState->ResetGameFlowStateAndShowMainMenu();
        return;
      }

      g_pImperialismApp->WriteProfileInt("Settings", "DefaultProtocol",
                                         selectedProtocolControl->controlTag);
    }

    // Second dispatch: the actual per-tag action.
    unsigned int actionTag = sourceHandler->controlTag;
    if (actionTag == kControlTagLoad) {
      g_pGameFlowState->scenarioSelectionTag = kControlTagLoad;
      if (g_pGameFlowState->PrepareGameName()) {
        g_pSimMgr->multiplayerSessionRole = kSessionRoleHost;
        g_nSaveFormatVersion = -2;
        g_pAmbitApplication->PostTurnEventCodeMessage(EncodeTurnEventCode(kTurnEventLoadSave));
      }
    } else if (actionTag == kControlTagJoin) {
      g_bMultiplayerScenarioSetupActive = false;
      g_pSimMgr->multiplayerSessionRole = kSessionRoleClient;
      g_pGameFlowState->SelectGameAndShowOptions(0);
    } else if (actionTag == kControlTagRand) {
      g_pGameFlowState->scenarioSelectionTag = kControlTagRand;
      if (g_pGameFlowState->PrepareGameName()) {
        g_pSimMgr->multiplayerSessionRole = kSessionRoleHost;
        g_pAmbitApplication->PostTurnEventCodeMessage(
            EncodeTurnEventCode(kTurnEventRandomGameSetup));
      }
    } else if (actionTag == kControlTagMult) {
      g_pGameFlowState->ResetGameFlowStateAndShowMainMenu();
    } else if (actionTag == kControlTagScen) {
      g_pGameFlowState->scenarioSelectionTag = kControlTagScn0; // 'scn0'
      if (g_pGameFlowState->PrepareGameName()) {
        g_pSimMgr->multiplayerSessionRole = kSessionRoleHost;
        g_pAmbitApplication->PostTurnEventCodeMessage(
            EncodeTurnEventCode(kTurnEventScenarioGameSetup));
      }
    } else if (actionTag == kControlTagSpit) {
      if (g_pAssetMgr->AreThereStrayClientSaves() &&
          g_pViewMgr->ShowLocalizedUiPromptByGroupAndIndex(0x2759, 8, 0, 1)) {
        int deletedCount = g_pAssetMgr->DeleteStrayClientSaves();

        CString message;
        g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&message, 0x2759, 9);
        CString formattedMessage;
        scanBracketExpressions(g_pSimMgr, &formattedMessage, static_cast<LPCSTR>(message),
                               deletedCount);
        g_pViewMgr->ModalMessage(formattedMessage, g_ptGameSetupModalMessage, 0, 0);

        TView* spitControl = FindSubView(kControlTagSpit);
        spitControl->AssertValid();
        spitControl->ViewEnable(0, 0);
        SetControlHoverHelpText(CString(g_szEmptyString), spitControl);
      }
    }
  }
  TControl::DoEvent(commandId, sourceHandler, event);
}
