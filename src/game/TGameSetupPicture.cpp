#include "game/TAmbitApplication.h"
#include "game/TGameSetupPicture.h"

#include "game/ImperialismApp.h"
#include "game/TApplication.h"
#include "game/TAssetMgr.h"
#include "game/TMapMgr.h"
#include "game/TMultiplayerMgr.h"
#include "game/TOcean.h"
#include "game/TSimMgr.h"
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
// messagebox via TViewMgr::DispatchLocalizedUiMessageWithTemplateA13A0) never runs.
// Omitted below since it can never execute; only the loop's post-condition is kept.
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
    // TMultiplayerMgr::EnsureGameFlowStateAndPostTurnEvent5E5 already posts turn
    // event 0x5e5 itself -- falls straight to the base-class forward below (matches
    // the original, no PostTurnEventCodeMessage2420 call here). Safe to call through
    // a null g_pGameFlowState: the method is non-virtual and checks `this` before
    // touching any member.
    g_pGameFlowState->EnsureGameFlowStateAndPostTurnEvent5E5();
  } else if (controlTag == kControlTagQuit) {
    PostWmCloseToMainThreadWindow();
    // no PostTurnEventCodeMessage2420 on this path (matches the original).
  } else if (controlTag == kControlTagPref) {
    postEventCode = 0x1036;
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
        // ResetPortZoneGlobalContextCounters (0x4043d1): the zone-graph BFS distance
        // cache is invalidated whenever the map order context is rebuilt.
        g_nMapActionContextCount = 0;
        g_nMapActionContextDistanceCacheSizedFor = -1;
        if (g_pGameFlowState != 0) {
          g_pGameFlowState->Free();
          g_pGameFlowState = 0;
        }
        g_pGlobalMapState = new TMapMgr();
        g_pGlobalMapState->InitializeGlobalMapState();
      }
      g_pSimMgr->RebuildGlobalOrderManagersAndCapabilityState(1);
      g_pGlobalMapState->AllocateAndResetTerrainAndCityScoreTables();
      g_pGlobalMapState->LoadPoliticalMapRegionSubtypeTableFromResourceStream();
      for (short tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
        g_pGlobalMapState->UpdateMapTileAdjacencyMasksAndVariantForTile(tileIndex);
        g_pGlobalMapState->UpdateTileNeighborBorderInfluenceCounters(tileIndex, 0);
      }
      postEventCode = 0x3c0;
    } else {
      g_pSfxPlaybackSystem->PlaySoundEffect(0x1b58, 0, 1);
      g_pSimMgr->SetSelectedIndex6AAndTriggerRefresh(0);
      g_pUiViewManager->NoOpRuntimeUiCallback_005df3f0(1);
      postEventCode = 0x5dd;
    }
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
