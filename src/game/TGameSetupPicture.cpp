#include "game/TGameSetupPicture.h"

#include "game/ImperialismApp.h"
#include "game/TApplication.h"
#include "game/TSoundPlayer.h"
#include "game/global_data_tables.h"
#include "game/ui_control_tags.h"

// SYNTHETIC: IMPERIALISM 0x005757c0
// TGameSetupPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x00575840
// TGameSetupPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TGameSetupPicture, TNoHilitePicture)

// FUNCTION: IMPERIALISM 0x00575860
TGameSetupPicture::TGameSetupPicture() : TNoHilitePicture() {}

// SYNTHETIC: IMPERIALISM 0x00575890
// TGameSetupPicture::`scalar deleting destructor'
TGameSetupPicture::~TGameSetupPicture() {}

// FUNCTION: IMPERIALISM 0x005758e0
void TGameSetupPicture::NoOpUiLifecycleHook(int arg) {
}

// Main-menu button dispatcher. Only commandId 0x14/0x0a/0x22 (button-activation
// codes) are handled; anything else forwards straight to the base class. The
// source control's FourCC tag (TEventHandler::controlTag) selects the branch.
//
// TODO(bd 1uj.57.9 follow-up): three branches are intentionally incomplete --
// - 'mult': EnsureGameFlowStateAndPostTurnEvent5E5 (0x544540) constructs/inits
//   g_pGameFlowState (TMultiplayerMgr, via a Config::InitDefaults-shaped ctor and
//   a vtable slot 0x94 call) and posts turn event 0x5e5; unported pending its own
//   investigation.
// - 'rand': the shift-key + debug-flag (byte @ 0x6a42dc, unclaimed global) gate
//   selects between a full TOcean/TMapMgr bootstrap (a 0x1950-tile init loop) and
//   a lighter path that calls an unclaimed TSimMgr method (0x581ae0,
//   SetSelectedIndex6AAndTriggerRefresh) and TAssetMgr::
//   NoOpRuntimeUiCallback_005df3f0(1) before posting turn event 0x5dd or 0x3c0.
// - 'load'/'scen': the retail binary's own confirmation-dialog retry loop here is
//   dead code -- its guard (0x408594, unconditionally `return 1;`) always reports
//   "accepted", so the loop body (format + show a confirm messagebox via
//   TViewMgr::DispatchLocalizedUiMessageWithTemplateA13A0) never runs. Omitted
//   below since it can never execute; only the loop's post-condition is kept.
// FUNCTION: IMPERIALISM 0x00575900
void TGameSetupPicture::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId != 0x14 && commandId != 0xa && commandId != 0x22) {
    TNoHilitePicture::HandleEvent(commandId, sourceHandler, event);
    return;
  }

  unsigned int controlTag = static_cast<unsigned int>(sourceHandler->controlTag);
  short postEventCode = -1;

  if (controlTag == kControlTagHigh) {
    g_pSfxPlaybackSystem->PlaySoundEffect(0x1b58, 0, 1);
    postEventCode = 0x5e0;
  } else if (controlTag == 0x636e636c /* 'cncl' */) {
    postEventCode = 0x5dc;
  } else if (controlTag == kControlTagLoad) {
    g_pSfxPlaybackSystem->PlaySoundEffect(0x1b58, 0, 1);
    g_nSaveFormatVersion = -2;
    postEventCode = 0x5de;
  } else if (controlTag == kControlTagMult) {
    g_pSfxPlaybackSystem->PlaySoundEffect(0x1b58, 0, 1);
    // falls straight to the base-class forward below (no PostTurnEventCodeMessage2420
    // on this path in the original either) -- see TODO above.
  } else if (controlTag == kControlTagQuit) {
    PostWmCloseToMainThreadWindow();
    // no PostTurnEventCodeMessage2420 on this path (matches the original).
  } else if (controlTag == kControlTagPref) {
    postEventCode = 0x1036;
  } else if (controlTag == kControlTagRand) {
    // see TODO above -- neither the cheat-gate nor the normal path is ported yet.
  } else if (controlTag == kControlTagScen) {
    g_pSfxPlaybackSystem->PlaySoundEffect(0x1b58, 0, 1);
    postEventCode = 0x5df;
  } else {
    TNoHilitePicture::HandleEvent(commandId, sourceHandler, event);
    return;
  }

  if (postEventCode >= 0) {
    g_pGlobalUiRootController->PostTurnEventCodeMessage2420(postEventCode);
  }
  TNoHilitePicture::HandleEvent(commandId, sourceHandler, event);
}
