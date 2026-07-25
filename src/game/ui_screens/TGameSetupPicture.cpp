#include "game/gfx/TAmbitApplication.h"
#include "game/ui_tags_common.h"
#include "game/ui_screens/TGameSetupPicture.h"

#include "game/ImperialismApp.h"
#include "game/ui_core/TApplication.h"
#include "game/assets/TAssetMgr.h"
#include "game/map/TMapMgr.h"
#include "game/net/TMultiplayerMgr.h"
#include "game/navy/TOcean.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_widgets/TSoundPlayer.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"

// SYNTHETIC: IMPERIALISM 0x005757c0
// TGameSetupPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x00575840
// TGameSetupPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TGameSetupPicture, TNoHilitePicture)

// FUNCTION: IMPERIALISM 0x00575860
TGameSetupPicture::TGameSetupPicture() : TNoHilitePicture() {}

// SYNTHETIC: IMPERIALISM 0x00575890
// TGameSetupPicture::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x005758c0
TGameSetupPicture::~TGameSetupPicture() {}

// FUNCTION: IMPERIALISM 0x005758e0
void TGameSetupPicture::DoPostCreate(int arg) {
  TView::DoPostCreate(arg);
}

// Main-menu button dispatcher. Only commandId 0x14/0x0a/0x22 (button-activation
// codes) are handled; anything else forwards straight to the base class. The
// source control's FourCC tag (TEventHandler::controlTag) selects the branch.
//
// Note on 'load'/'scen'/'rand' (normal path): the retail binary's own confirmation-
// dialog retry loop here is dead code -- its guard (0x408594, unconditionally
// `return 1;`) always reports "accepted", so the loop body (format + show a confirm
// messagebox via TViewMgr::ModalMessage) never runs.
// Omitted below since it can never execute; only the loop's post-condition is kept.
// FUNCTION: IMPERIALISM 0x00575900
void TGameSetupPicture::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId != 0x14 && commandId != 0xa && commandId != 0x22) {
    TNoHilitePicture::DoEvent(commandId, sourceHandler, event);
    return;
  }

  unsigned int controlTag = static_cast<unsigned int>(sourceHandler->controlTag);
  TurnEventCodeStorage postEventCode = -1;

  if (controlTag == kControlTagHigh) {
    g_pSfxPlaybackSystem->PlaySoundEffect(0x1b58, 0, 1);
    postEventCode = EncodeTurnEventCode(kTurnEventHighScores);
  } else if (controlTag == kControlTagCncl) {
    postEventCode = EncodeTurnEventCode(kTurnEventMainMenu);
  } else if (controlTag == kControlTagLoad) {
    g_pSfxPlaybackSystem->PlaySoundEffect(0x1b58, 0, 1);
    g_nSaveFormatVersion = -2;
    postEventCode = EncodeTurnEventCode(kTurnEventLoadSave);
  } else if (controlTag == kControlTagMult) {
    g_pSfxPlaybackSystem->PlaySoundEffect(0x1b58, 0, 1);
    // TMultiplayerMgr::EnsureGameFlowStateAndPostTurnEvent5E5 already posts turn
    // event 0x5e5 itself -- falls straight to the base-class forward below (matches
    // the original, no PostTurnEventCodeMessage2420 call here). Safe to call through
    // a null g_pGameFlowState: the method is non-virtual and checks `this` before
    // touching any member.
    g_pGameFlowState->EnsureGameFlowStateAndPostTurnEvent5E5();
  } else if (controlTag == kControlTagQuit) {
    g_pGlobalUiRootController->PostWmCloseToMainThreadWindow();
    // no PostTurnEventCodeMessage2420 on this path (matches the original).
  } else if (controlTag == kControlTagPref) {
    postEventCode = EncodeTurnEventCode(kTurnEventGamePreferences);
  } else if (controlTag == kControlTagRand) {
    short shiftState = static_cast<short>(GetAsyncKeyState(VK_SHIFT));
    if ((shiftState & 0x8000) != 0 && g_bRandomMapDeveloperCheatFlag != 0) {
      // Developer cheat path: bypass the setup screens and instantly bootstrap a
      // fresh random map.
      g_pSfxPlaybackSystem->PlaySoundEffect(0x232c, 0, 1);
      if (g_pGameFlowState == 0) {
        if (g_pActiveMapOrderContext != 0) {
          g_pActiveMapOrderContext->Free();
          g_pActiveMapOrderContext = 0;
        }
        g_pActiveMapOrderContext = new TOcean();
        // The zone-graph BFS distance cache is invalidated whenever the map order
        // context is rebuilt. The original CALLs the shared helper here (0x00575be0);
        // inlining its two global writes was a modelling error. Cited by its real
        // address, 0x005621b0 -- 0x004043d1 is only the ILT thunk in front of it.
        ResetPortZoneGlobalContextCounters();
        if (g_pGameFlowState != 0) {
          g_pGameFlowState->Free();
          g_pGameFlowState = 0;
        }
        g_pGlobalMapState = new TMapMgr();
        g_pGlobalMapState->IMapMgr();
      }
      g_pSimMgr->RebuildGlobalOrderManagersAndCapabilityState(1);
      g_pGlobalMapState->AllocateAndResetTerrainAndCityScoreTables();
      g_pGlobalMapState->LoadPoliticalMapRegionSubtypeTableFromResourceStream();
      for (short tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
        g_pGlobalMapState->AssignPictToTile(tileIndex);
        g_pGlobalMapState->UpdateTileNeighborBorderInfluenceCounters(tileIndex, 0);
      }
      postEventCode = EncodeTurnEventCode(kTurnEventMapEditor);
    } else {
      g_pSfxPlaybackSystem->PlaySoundEffect(0x1b58, 0, 1);
      g_pSimMgr->SetSelectedIndex6AAndTriggerRefresh(0);
      g_pUiViewManager->OpenFilesFor(1);
      postEventCode = EncodeTurnEventCode(kTurnEventRandomGameSetup);
    }
  } else if (controlTag == kControlTagScen) {
    g_pSfxPlaybackSystem->PlaySoundEffect(0x1b58, 0, 1);
    postEventCode = EncodeTurnEventCode(kTurnEventScenarioGameSetup);
  } else {
    TNoHilitePicture::DoEvent(commandId, sourceHandler, event);
    return;
  }

  if (postEventCode >= 0) {
    g_pGlobalUiRootController->PostTurnEventCodeMessage2420(postEventCode);
  }
  TNoHilitePicture::DoEvent(commandId, sourceHandler, event);
}
