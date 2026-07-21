#include "game/TGamePreferencesPicture.h"

#include "game/CString.h"
#include "game/ImperialismApp.h"
#include "game/TAmbitApplication.h"
#include "game/TControl.h"
#include "game/TCzechBox.h"
#include "game/TDeluxeText.h"
#include "game/TEventHandler.h"
#include "game/TSimMgr.h"
#include "game/TSoundPlayer.h"
#include "game/TViewMgr.h"
#include "game/global_data_tables.h"
#include "game/ui_control_tags.h"
// SYNTHETIC: IMPERIALISM 0x0043da70
// TGamePreferencesPicture::`scalar deleting destructor'
TGamePreferencesPicture::~TGamePreferencesPicture() {}
// SYNTHETIC: IMPERIALISM 0x0056a510
// TGamePreferencesPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x0056a590
// TGamePreferencesPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TGamePreferencesPicture, TPicture)

TGamePreferencesPicture::TGamePreferencesPicture() {}

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
        g_pGlobalUiRootController->PostTurnEventCodeMessage2420(0x5dc);
      } else {
        g_pSimMgr->StartNextPhase();
      }
    } else if (tag == kControlTagOkay) {
      for (int i = 0; i < 5; ++i) {
        TCzechBox* checkbox = static_cast<TCzechBox*>(ResolveControlByTag(kControlTagOpta + i));
        if (checkbox != nullptr) {
          checkbox->AssertValid();
          g_pSimMgr->preferenceValues[i] = checkbox->GetCheckedStateByte();
        }
      }

      // TODO: the original also reads two scrollbar-style controls here ('musi'/'soun')
      // and derives preferenceValues[3]/[2] as percentages:
      //   percent = max(0, current - 0xc) * scale / (maxPos - 0xc)   (scale = 0xff/100)
      // reading `current` at the control's own +0x38 and `maxPos` at +0x90 (raw field
      // reads in the disassembly, no accessor call). Neither offset matches any
      // TView-family class recovered so far and no construction site was found tying a
      // concrete class to the 'musi'/'soun' tags -- left unmodeled rather than guessing
      // a type, per the type-modeling guardrail.

      g_pSfxPlaybackSystem->ScaleAndApplyAuxOutputVolume(g_pSimMgr->preferenceValues[3]);
      if (g_pSimMgr->mode == 1 || g_pSimMgr->mode == 3) {
        g_pGlobalUiRootController->PostTurnEventCodeMessage2420(0x5dc);
      } else {
        g_pSimMgr->StartNextPhase();
      }

      // TODO: the original also resolves the 'opca' auto-resolution checkbox here and
      // reads its own +0x88 field, comparing it against the FourCC 'yess':
      //   TView* opca = ResolveControlByTag(kControlTagOpca);
      //   opca->AssertValid();
      //   bool autoResolve = *(int*)((char*)opca + 0x88) == 0x79657373; // 'yess'
      // +0x88 doesn't match TCzechBox's own checkedStateByte94 (+0x94) or any other
      // recovered class at this tag -- left unmodeled rather than guessing a type.
      bool autoResolve = false;
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
      bool checked = static_cast<TCzechBox*>(sourceHandler)->GetCheckedStateByte() != 0;
      CString text;
      g_pSimMgr->GetString(0x2743, static_cast<short>((checked ? 0 : 1) + idx * 2 + 0x10), &text);
      TDeluxeText* tooltip = static_cast<TDeluxeText*>(ResolveControlByTag(kControlTagTxta + idx));
      tooltip->AssertValid();
      tooltip->UpdateTextEntrySharedStringAndMaybeNotify(&text, 1);
      tooltip->RecenterTextFromMeasuredWidthAndMaybeInvalidate(1);
    }
  }
}
