#include "game/TGameSetupMultiplayerPicture.h"

#include "game/CSubViewIterator.h"
#include "game/ImperialismApp.h"
#include "game/TAmbitApplication.h"
#include "game/TAssetMgr.h"
#include "game/TControl.h"
#include "game/TDropShadowText.h"
#include "game/TInfoBarText.h"
#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/TMultiplayerMgr.h"
#include "game/TRadioTextCluster.h"
#include "game/TSimMgr.h"
#include "game/TViewMgr.h"
#include "game/global_data_tables.h"
#include "game/mapped_flavor_text.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_control_tags.h"
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x00575e90
// TGameSetupMultiplayerPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x00575f10
// TGameSetupMultiplayerPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TGameSetupMultiplayerPicture, TNoHilitePicture)

// FUNCTION: IMPERIALISM 0x00575f30
TGameSetupMultiplayerPicture::TGameSetupMultiplayerPicture() {}

// SYNTHETIC: IMPERIALISM 0x00575f60
// TGameSetupMultiplayerPicture::`scalar deleting destructor'
TGameSetupMultiplayerPicture::~TGameSetupMultiplayerPicture() {}

// FUNCTION: IMPERIALISM 0x00575fb0
void TGameSetupMultiplayerPicture::DoPostCreate(int arg) {
  TView::DoPostCreate(arg);

  TRadioTextCluster* protControl =
      static_cast<TRadioTextCluster*>(ResolveControlByTag(kControlTagProt));
  protControl->AssertValid();
  protControl->word8C = 0x4c;
  protControl->word8E = 0x4d;

  if (g_pGameFlowState->InitializeProtocolOptionControlFromProvider(this)) {
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
    g_pGameFlowState->ResetDiplomacyRuntimeSelectionAndSetModeNada();
  }

  TInfoBarText* cursControl = static_cast<TInfoBarText*>(ResolveControlByTag(kControlTagCurs));
  cursControl->AssertValid();
  TUiTextStyleDescriptor styleDescriptor;
  styleDescriptor.fontFamily = 0;
  styleDescriptor.fontStyleFlags = 0;
  styleDescriptor.fontSize = 0;
  styleDescriptor.textColor = 0;
  BuildUiTextStyleDescriptor(&styleDescriptor, 0, 0xe, 0x2b6c);
  cursControl->ApplyTextStyleDescriptorAndMaybeRefresh(&styleDescriptor, 1);
  cursControl->InitializeMapHintTextStyleAndThemeFlags(0x2b6b, 0x2b6c);
  cursControl->SetTextAlignmentAndMaybeRefresh(1, 0);

  ApplySharedStringToGlobalControlTag(CString(g_szEmptyString), kControlTagMain);
  LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(0x2737, 0x1f, kControlTagRand);
  LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(0x2737, 0x20, kControlTagScen);
  LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(0x2737, 0x21, kControlTagLoad);
  LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(0x2737, 0x22, kControlTagMult);
  LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(0x2737, 0x23, kControlTagJoin);
  LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(0x2737, 0x24, kControlTagProt);

  if (g_pUiViewManager->HasPendingClientSaveFile()) {
    TControl* spitControl = static_cast<TControl*>(ResolveControlByTag(kControlTagSpit));
    spitControl->AssertValid();
    spitControl->SetState(1, 0);
    LoadUiStringByGroupAndIndexToControlObject(0x2759, 7, spitControl);
  }
}

// Multiplayer setup dialog dispatcher. Only commandId 0x14/0x0a/0x22/0x0d (button-
// activation codes) are handled; anything else forwards straight to the base class.
//
// Note on 'load'/'rand'/'scen' (retry confirm loop): the retail binary's own
// confirmation-dialog retry loop here is dead code -- its guard (ReturnTrueStub,
// 0x408594) unconditionally returns 1, so the loop body never runs. Omitted below,
// matching TGameSetupPicture::HandleEvent's identical precedent.
// FUNCTION: IMPERIALISM 0x00576230
void TGameSetupMultiplayerPicture::HandleEvent(int commandId, TEventHandler* sourceHandler,
                                               TEvent* event) {
  if (commandId == 0x14 || commandId == 0xa || commandId == 0x22 || commandId == 0xd) {
    unsigned int tag = static_cast<unsigned int>(sourceHandler->controlTag);

    if (tag == kControlTagJoin) {
      TRadioTextCluster* protControl =
          static_cast<TRadioTextCluster*>(ResolveControlByTag(kControlTagProt));
      protControl->AssertValid();
      TView* selectedProtocolControl = protControl->ResolveControlByTag(protControl->selectedTag88);
      selectedProtocolControl->AssertValid();

      bool isNotJoin = (tag != kControlTagJoin);
      int protocolValue = selectedProtocolControl->controlValue3c;
      unsigned char accepted =
          g_pGameFlowState->ValidateGameFlowNameAndSelectionContext(protocolValue, isNotJoin);
      if (!accepted) {
        CString errorMsg;
        g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&errorMsg, 0x2737, 0x28);
        g_pUiRuntimeContext->DispatchLocalizedUiMessageWithTemplateA13A0(
            errorMsg, &g_cstrGameSetupMessageStore, 0, 0);
        g_pGameFlowState->ResetGameFlowStateAndPostTurnEvent5DC();
        return;
      }

      g_pImperialismApp->WriteProfileInt("Settings", "DefaultProtocol",
                                         selectedProtocolControl->controlTag);
    }

    // Second dispatch: the actual per-tag action.
    unsigned int actionTag = static_cast<unsigned int>(sourceHandler->controlTag);
    if (actionTag == kControlTagLoad) {
      g_pGameFlowState->scenarioSelectionTag = kControlTagLoad;
      if (g_pGameFlowState->ValidateAndPrepareGameFlowNameForDispatch()) {
        g_pSimMgr->field44 = 1;
        g_nSaveFormatVersion = -2;
        g_pGlobalUiRootController->PostTurnEventCodeMessage2420(0x5de);
      }
    } else if (actionTag == kControlTagJoin) {
      g_bMultiplayerScenarioSetupActive = 0;
      g_pSimMgr->field44 = 2;
      g_pGameFlowState->ApplyJoinGameSelectionAndPostTurnEvent5E4(0);
    } else if (actionTag == kControlTagRand) {
      g_pGameFlowState->scenarioSelectionTag = kControlTagRand;
      if (g_pGameFlowState->ValidateAndPrepareGameFlowNameForDispatch()) {
        g_pSimMgr->field44 = 1;
        g_pGlobalUiRootController->PostTurnEventCodeMessage2420(0x5dd);
      }
    } else if (actionTag == kControlTagMult) {
      g_pGameFlowState->ResetGameFlowStateAndPostTurnEvent5DC();
    } else if (actionTag == kControlTagScen) {
      g_pGameFlowState->scenarioSelectionTag = 0x73636e30; // 'scn0'
      if (g_pGameFlowState->ValidateAndPrepareGameFlowNameForDispatch()) {
        g_pSimMgr->field44 = 1;
        g_pGlobalUiRootController->PostTurnEventCodeMessage2420(0x5df);
      }
    } else if (actionTag == kControlTagSpit) {
      if (g_pUiViewManager->HasPendingClientSaveFile() &&
          g_pUiRuntimeContext->ShowLocalizedUiPromptByGroupAndIndex(0x2759, 8, 0, 1)) {
        int deletedCount = g_pUiViewManager->DeleteLegacyCliSaveImpFiles();

        CString message;
        g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&message, 0x2759, 9);
        CString formattedMessage;
        scanBracketExpressions(g_pSimMgr, &formattedMessage, static_cast<LPCSTR>(message),
                               deletedCount);
        g_pUiRuntimeContext->DispatchLocalizedUiMessageWithTemplateA13A0(
            formattedMessage, &g_cstrGameSetupMessageStore, 0, 0);

        TView* spitControl = ResolveControlByTag(kControlTagSpit);
        spitControl->AssertValid();
        spitControl->SetState(0, 0);
        SetControlHoverHelpText(CString(g_szEmptyString), spitControl);
      }
    }
  }
  TControl::HandleEvent(commandId, sourceHandler, event);
}
