#include "game/navy_ui/TGamePreferencesPicture.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_military.h"

#include "game/ui_screens/CString.h"
#include "game/ImperialismApp.h"
#include "game/gfx/TAmbitApplication.h"
#include "game/ui_core/TControl.h"
#include "game/ui_screens/TCzechBox.h"
#include "game/ui_widgets/TDeluxeText.h"
#include "game/ui_widgets/TDropShadowText.h"
#include "game/ui_core/TEventHandler.h"
#include "game/ui_screens/TRadioTextCluster.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_widgets/TSoundPlayer.h"
#include "game/ui_screens/TTwoPicSlider.h"
#include "game/ui_core/TViewMgr.h"
#include "game/gfx/TDisplayMgr.h"
#include "game/gfx/TModuleLibraryCacheTableStateB.h"
#include "game/assets/TAssetMgr.h"
#include "game/ui_core/THelpMgr.h"
#include "game/ui_widgets/TInfoBarText.h"
#include "game/ui_text_label_helpers_decls.h"
#include "game/globals/navy_ui_globals.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"

// FUNCTION: IMPERIALISM 0x0043d960
TGamePreferencesPicture::TGamePreferencesPicture() {}
// SYNTHETIC: IMPERIALISM 0x0043da70
// TGamePreferencesPicture::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x0043db40
TGamePreferencesPicture::~TGamePreferencesPicture() {}
// SYNTHETIC: IMPERIALISM 0x0056a510
// TGamePreferencesPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x0056a590
// TGamePreferencesPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TGamePreferencesPicture, TPicture)

// Builds the game-preferences screen state: seeds the shared 'main' ticker text and
// the cursor hint panel, loads the okay/quer captions, wires the five 'opta'..'opte'
// preference checkboxes (enabled per g_anGamePreferenceIndexByRow and multiplayer
// role) with their 'txta'.. labels, initializes the music/sound TTwoPicSliders from
// preferenceValues[3]/[2], lazily creates g_pHelpMgr, and preloads the
// auto-resolution yes/no radio cluster from the "AutoRes" profile setting.
// FUNCTION: IMPERIALISM 0x0056a5b0
void TGamePreferencesPicture::DoPostCreate(int arg) {
  TView* activeDialog = g_pDisplayMgr->activeDialog;
  CString text;
  this->TView::DoPostCreate(arg);

  g_pCursorControlPanel =
      static_cast<TInfoBarText*>(activeDialog->ResolveControlByTag(kControlTagCurs));
  g_pCursorControlPanel->AssertValid();
  g_pCursorControlPanel->InitializeMapHintTextStyleAndThemeFlags(0x2b6c, 0x2b67);

  ApplySharedStringToGlobalControlTag(CString(g_pGamePreferencesSharedText_0065DDC8),
                                      kControlTagMain);

  LoadUiStringByGroupAndIndexToControlObject(0x2743, 0x25, ResolveControlByTag(kControlTagOkay));
  LoadUiStringByGroupAndIndexToControlObject(0x2730, 3, ResolveControlByTag(kControlTagQuer));

  for (int row = 0; row < 5; ++row) {
    int prefIndex = g_anGamePreferenceIndexByRow[row];
    TCzechBox* checkbox = static_cast<TCzechBox*>(ResolveControlByTag(kControlTagOpta + row));
    if (checkbox == 0) {
      // No checkbox on this screen variant: the label alone, always enabled, showing
      // the "on" caption.
      TDeluxeText* label = static_cast<TDeluxeText*>(ResolveControlByTag(kControlTagTxta + row));
      label->AssertValid();
      label->SetEnabled(1, 0);
      g_pSimMgr->GetString(0x2743, static_cast<short>(row * 2 + 0x10), &text);
      label->SetTextStyle(0, 0xc, 0x38);
      label->SetTextAlignmentAndMaybeRefresh(1, 0);
      label->UpdateTextEntrySharedString(&text);
      label->CenterVertically(0);
      continue;
    }

    char enabled = prefIndex != -1;
    if (g_pGameFlowState != 0 && g_pSimMgr->multiplayerSessionRole != 0 && prefIndex == 0) {
      enabled = 0;
    }
    TDeluxeText* label = static_cast<TDeluxeText*>(ResolveControlByTag(kControlTagTxta + row));
    label->AssertValid();
    label->SetEnabled(enabled, 0);
    checkbox = static_cast<TCzechBox*>(ResolveControlByTag(kControlTagOpta + row));
    checkbox->AssertValid();
    checkbox->SetEnabled(enabled, 0);
    // The TView-level state, dispatched through slot 0x2a (TCzechBox's own two-byte
    // SetState overload at slot 0x75 hides it on the derived type).
    static_cast<TView*>(checkbox)->SetState(enabled, 0);
    LoadUiStringByGroupAndIndexToControlObject(0x2743, static_cast<short>(row + 0x26), checkbox);
    if (enabled != 0) {
      checkbox->SetState(static_cast<unsigned char>(g_pSimMgr->preferenceValues[prefIndex]),
                         static_cast<unsigned char>(0));
      unsigned char isOn = checkbox->IsOn();
      g_pSimMgr->GetString(0x2743, static_cast<short>(row * 2 + 0x10 + (isOn ? 0 : 1)), &text);
      TDeluxeText* caption = static_cast<TDeluxeText*>(ResolveControlByTag(kControlTagTxta + row));
      caption->AssertValid();
      caption->SetTextStyle(0, 0xc, 0x38);
      label->SetTextAlignmentAndMaybeRefresh(1, 0);
      caption->UpdateTextEntrySharedStringAndMaybeNotify(&text, 0);
      caption->CenterVertically(0);
    }
  }

  originalSoundVolumePercent = g_pSimMgr->preferenceValues[3];
  TTwoPicSlider* musicSlider = static_cast<TTwoPicSlider*>(ResolveControlByTag(kControlTagMusi));
  musicSlider->AssertValid();
  musicSlider->InitializePictureSurfaces(0x1036);
  short musicSpan = static_cast<short>(musicSlider->frameHeight38 - 0xc);
  short musicSplit = static_cast<short>(g_pSimMgr->preferenceValues[3] * musicSpan / 0xff);
  musicSlider->splitPosition = static_cast<short>((musicSplit == 0) ? 0 : musicSplit + 0xc);
  musicSlider->mode = 1;
  LoadUiStringByGroupAndIndexToControlObject(0x2743, 0x27, musicSlider);

  TTwoPicSlider* soundSlider = static_cast<TTwoPicSlider*>(ResolveControlByTag(kControlTagSoun));
  soundSlider->AssertValid();
  soundSlider->InitializePictureSurfaces(0x1038);
  short soundSpan = static_cast<short>(soundSlider->frameHeight38 - 0xc);
  short soundSplit = static_cast<short>(g_pSimMgr->preferenceValues[2] * soundSpan / 100);
  soundSlider->splitPosition = static_cast<short>((soundSplit == 0) ? 0 : soundSplit + 0xc);
  soundSlider->mode = 2;
  LoadUiStringByGroupAndIndexToControlObject(0x2743, 0x26, soundSlider);

  if (g_pHelpMgr == 0) {
    g_pHelpMgr = new THelpMgr();
    g_pHelpMgr->InitializeHelpManagerIndexArrayAndState();
  }

  TView* autoResPrompt = ResolveControlByTag(kControlTagTpca);
  autoResPrompt->AssertValid();
  TRadioTextCluster* autoResCluster =
      static_cast<TRadioTextCluster*>(ResolveControlByTag(kControlTagOpca));
  autoResCluster->AssertValid();
  autoResPrompt->SetEnabled(1, 0);

  CString promptText;
  g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&promptText, 0x2763, 0x18);
  TDeluxeText* promptLabel = static_cast<TDeluxeText*>(autoResPrompt);
  promptLabel->SetTextStyle(0, 0xc, 0x38);
  promptLabel->SetTextAlignmentAndMaybeRefresh(1, 0);
  promptLabel->UpdateTextEntrySharedStringAndMaybeNotify(&promptText, 0);
  promptLabel->CenterVertically(0);

  TDropShadowText* yesOption = static_cast<TDropShadowText*>(ResolveControlByTag(kControlTagYess));
  yesOption->AssertValid();
  g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&promptText, 0x2763, 0x16);
  yesOption->SetTextAndMaybeRefresh(&promptText, 0);
  ApplyUiTextStyleAndThemeFlags(yesOption, 0, 0xc, 0x2b6a, 0x2b6c);

  TDropShadowText* noOption = static_cast<TDropShadowText*>(ResolveControlByTag(kControlTagNooo));
  noOption->AssertValid();
  g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&promptText, 0x2763, 0x17);
  noOption->SetTextAndMaybeRefresh(&promptText, 0);
  ApplyUiTextStyleAndThemeFlags(noOption, 0, 0xc, 0x2b6a, 0x2b6c);

  autoResCluster->frameThemeCode90 = 0x2b6c;
  autoResCluster->itemInset92 = 2;
  autoResCluster->SetEnabled(1, 0);
  autoResCluster->SetState(1, 0);

  int autoResEnabled = 0;
  g_pUiViewManager->LoadSettingValueByKeyIntoOut(&autoResEnabled,
                                                 g_pGamePreferencesAutoResKey_0065DDCC, 1);
  autoResCluster->SetSelectedTextOptionByTag(
      autoResEnabled != 0 ? kControlTagYess : kControlTagNooo, false);
}

// FUNCTION: IMPERIALISM 0x0056ae10
void TGamePreferencesPicture::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xa) {
    unsigned int tag = sourceHandler->controlTag;
    if (tag == kControlTagCanc) {
      g_pSfxPlaybackSystem->SetMasterVolumeFromPercent(
          static_cast<short>(originalSoundVolumePercent));
      g_pSimMgr->preferenceValues[3] = static_cast<short>(originalSoundVolumePercent);
      g_pSfxPlaybackSystem->ScaleAndApplyAuxOutputVolume(g_pSimMgr->preferenceValues[3]);
      if (g_pSimMgr->mode == 1) {
        g_pGlobalUiRootController->PostTurnEventCodeMessage2420(
            EncodeTurnEventCode(kTurnEventMainMenu));
      } else {
        g_pSimMgr->StartNextPhase();
      }
    } else if (tag == kControlTagOkay) {
      for (int i = 0; i < 5; ++i) {
        TCzechBox* checkbox = static_cast<TCzechBox*>(ResolveControlByTag(kControlTagOpta + i));
        if (checkbox != nullptr) {
          checkbox->AssertValid();
          g_pSimMgr->preferenceValues[i] = checkbox->IsOn();
        }
      }

      TTwoPicSlider* musicSlider =
          static_cast<TTwoPicSlider*>(ResolveControlByTag(kControlTagMusi));
      musicSlider->AssertValid();
      short musicPosition = musicSlider->splitPosition;
      if (musicPosition < 0xc) {
        musicPosition = 0;
      } else {
        musicPosition -= 0xc;
      }
      g_pSimMgr->preferenceValues[3] = static_cast<short>(
          (musicPosition * 0xff) / static_cast<short>(musicSlider->frameHeight38 - 0xc));

      TTwoPicSlider* soundSlider =
          static_cast<TTwoPicSlider*>(ResolveControlByTag(kControlTagSoun));
      soundSlider->AssertValid();
      short soundPosition = soundSlider->splitPosition;
      if (soundPosition < 0xc) {
        soundPosition = 0;
      } else {
        soundPosition -= 0xc;
      }
      g_pSimMgr->preferenceValues[2] = static_cast<short>(
          (soundPosition * 100) / static_cast<short>(soundSlider->frameHeight38 - 0xc));

      g_pSfxPlaybackSystem->ScaleAndApplyAuxOutputVolume(g_pSimMgr->preferenceValues[3]);
      if (g_pSimMgr->mode == 1 || g_pSimMgr->mode == 3) {
        g_pGlobalUiRootController->PostTurnEventCodeMessage2420(
            EncodeTurnEventCode(kTurnEventMainMenu));
      } else {
        g_pSimMgr->StartNextPhase();
      }

      TRadioTextCluster* autoResolutionCluster =
          static_cast<TRadioTextCluster*>(ResolveControlByTag(kControlTagOpca));
      autoResolutionCluster->AssertValid();
      bool autoResolve = autoResolutionCluster->selectedTag88 == kControlTagYess; // 'yess'
      if (!g_pImperialismApp->ApplyAutoResolutionModeAndPersist(autoResolve)) {
        g_pUiRuntimeContext->ShowLocalizedUiPromptByGroupAndIndex(0x2763, 7, 2, 0);
      }
    } else {
      TControl::DoEvent(commandId, sourceHandler, event);
    }
  } else {
    TControl::DoEvent(commandId, sourceHandler, event);
  }

  if (commandId == 4) {
    unsigned int tag = sourceHandler->controlTag;
    if (tag >= kControlTagOpta && tag <= kControlTagOpta + 0x19) {
      unsigned int idx = tag - kControlTagOpta;
      sourceHandler->AssertValid();
      bool checked = static_cast<TCzechBox*>(sourceHandler)->IsOn() != 0;
      CString text;
      g_pSimMgr->GetString(0x2743, static_cast<short>((checked ? 0 : 1) + idx * 2 + 0x10), &text);
      TDeluxeText* tooltip = static_cast<TDeluxeText*>(ResolveControlByTag(kControlTagTxta + idx));
      tooltip->AssertValid();
      tooltip->UpdateTextEntrySharedStringAndMaybeNotify(&text, 1);
      tooltip->CenterVertically(1);
    }
  }
}
