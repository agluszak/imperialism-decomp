#include "game/TGameSetupMultiplayerPicture.h"

#include "game/CSubViewIterator.h"
#include "game/TAssetMgr.h"
#include "game/TControl.h"
#include "game/TDropShadowText.h"
#include "game/TInfoBarText.h"
#include "game/TMultiplayerMgr.h"
#include "game/TRadioTextCluster.h"
#include "game/global_data_tables.h"
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
void TGameSetupMultiplayerPicture::NoOpUiLifecycleHook(int arg) {
  TView::NoOpUiLifecycleHook(arg);

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
  cursControl->SetTextThemeCodeAndMaybeRefresh(1, 0);

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

// FUNCTION: IMPERIALISM 0x00576230
void TGameSetupMultiplayerPicture::HandleEvent(int commandId, TEventHandler* sourceHandler,
                                               TEvent* event) {}
