#include "game/navy_ui/TGamePreferencesPicture.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_military.h"

#include "game/ui_screens/CString.h"
#include "game/ImperialismApp.h"
#include "game/gfx/TAmbitApplication.h"
#include "game/ui_core/TControl.h"
#include "game/ui_screens/TCzechBox.h"
#include "game/ui_widgets/TDeluxeText.h"
#include "game/ui_core/TEventHandler.h"
#include "game/ui_screens/TRadioTextCluster.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_widgets/TSoundPlayer.h"
#include "game/ui_screens/TTwoPicSlider.h"
#include "game/ui_core/TViewMgr.h"
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

// FUNCTION: IMPERIALISM 0x0056a5b0
void TGamePreferencesPicture::DoPostCreate(int arg) {}

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
