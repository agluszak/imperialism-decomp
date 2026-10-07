#include "game/map_domain_types.h"
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
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"

IMPLEMENT_DYNCREATE(TGameSetupPicture, TNoHilitePicture)

// FUNCTION: IMPERIALISM 0x00575860
TGameSetupPicture::TGameSetupPicture() : TNoHilitePicture() {}

// FUNCTION: IMPERIALISM 0x005758c0
TGameSetupPicture::~TGameSetupPicture() {}

// FUNCTION: IMPERIALISM 0x005758e0
void TGameSetupPicture::DoPostCreate(int arg) {
  TView::DoPostCreate(arg);
}

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
    g_pGameFlowState->EnsureGameFlowStateAndShowMultiplayerSetup();
  } else if (controlTag == kControlTagQuit) {
    g_pAmbitApplication->PostWmCloseToMainThreadWindow();
    // no PostTurnEventCodeMessage on this path (matches the original).
  } else if (controlTag == kControlTagPref) {
    postEventCode = EncodeTurnEventCode(kTurnEventGamePreferences);
  } else if (controlTag == kControlTagRand) {
    short shiftState = static_cast<short>(GetAsyncKeyState(VK_SHIFT));
    if ((shiftState & 0x8000) != 0 && g_bRandomMapDeveloperCheatFlag) {
      g_pSfxPlaybackSystem->PlaySoundEffect(0x232c, 0, 1);
      if (g_pGameFlowState == 0) {
        if (g_pActiveMapOrderContext != 0) {
          g_pActiveMapOrderContext->Free();
          g_pActiveMapOrderContext = 0;
        }
        g_pActiveMapOrderContext = new TOcean();
        ResetPortZoneGlobalContextCounters();
        if (g_pGameFlowState != 0) {
          g_pGameFlowState->Free();
          g_pGameFlowState = 0;
        }
        g_pGlobalMapState = new TMapMgr();
        g_pGlobalMapState->IMapMgr();
      }
      g_pSimMgr->CreateSimObjects(true);
      g_pGlobalMapState->AllocateAndResetTerrainAndCityScoreTables();
      g_pGlobalMapState->LoadPoliticalMapRegionSubtypeTableFromResourceStream();
      for (short tileIndex = 0; tileIndex < kStrategicTileCount; ++tileIndex) {
        g_pGlobalMapState->AssignPictToTile(tileIndex);
        g_pGlobalMapState->UpdateTileNeighborBorderInfluenceCounters(tileIndex, 0);
      }
      postEventCode = EncodeTurnEventCode(kTurnEventMapEditor);
    } else {
      g_pSfxPlaybackSystem->PlaySoundEffect(0x1b58, 0, 1);
      g_pSimMgr->SelectMapArtSet(0);
      g_pAssetMgr->OpenFilesFor(1);
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
    g_pAmbitApplication->PostTurnEventCodeMessage(postEventCode);
  }
  TNoHilitePicture::DoEvent(commandId, sourceHandler, event);
}
