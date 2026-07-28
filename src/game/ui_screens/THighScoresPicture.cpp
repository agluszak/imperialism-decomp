#include "game/gfx/TAmbitApplication.h"
#include "game/ui_screens/THighScoresPicture.h"

#include "game/ui_core/TApplication.h"
#include "game/assets/TAssetMgr.h"
#include "game/ui_widgets/TSoundPlayer.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/ui_text_label_helpers_decls.h"
#include "game/ui_core/quickdraw_rendering.h"

#include <stdio.h>
#include <string.h>

// FUNCTION: IMPERIALISM 0x0045ada0
void THighScoresPicture::Hilite() {}

// SYNTHETIC: IMPERIALISM 0x0045adc0
// THighScoresPicture::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x0045adf0
THighScoresPicture::~THighScoresPicture() {}
// SYNTHETIC: IMPERIALISM 0x00575280
// THighScoresPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x00575300
// THighScoresPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(THighScoresPicture, TNoHilitePicture)

// FUNCTION: IMPERIALISM 0x00575320
void THighScoresPicture::DoPostCreate(int arg) {
  TNoHilitePicture::DoPostCreate(arg);

  g_pSfxPlaybackSystem->ResetDualAudioCuePools();
  g_pSfxPlaybackSystem->PushCueToDualAudioCuePools(0xb);
  g_pSfxPlaybackSystem->SelectAndScheduleRandomAudioCue();

  CString path;
  AssignScoresDatPathToSharedString(&path);
  FILE* file = fopen(path, "rb");
  if (file == 0) {
    memset(scoreValues94, 0, sizeof(scoreValues94));
  } else {
    for (int i = 0; i < 10; ++i) {
      if (fread(&scoreValues94[i], 4, 1, file) == 0) {
        scoreValues94[i] = 0;
      }
      fread(scoreNamesBc[i], 0x20, 1, file);
    }
    fclose(file);
  }
}

// Draws the high-scores table: for each positive score row, the rank number ("N. "),
// the player name, and the score value, each drawn twice (shadow pass in black at
// +1,+1, then the themed foreground color).
// FUNCTION: IMPERIALISM 0x00575460
void THighScoresPicture::Draw(RECT* rectBuffer) {
  TPicture::Draw(rectBuffer);
  COLORREF foregroundColor = 0;
  CString lineText;
  CString unusedText;
  ResolveUiThemeColor(0x2b68, &foregroundColor);
  COLORREF secondaryColor = 0;
  ResolveUiThemeColor(0x2b67, &secondaryColor);
  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0x18, 0x2b68);

  int rank = 0;
  int y = 100;
  const int* scoreValue = scoreValues94;
  const char (*scoreName)[0x20] = scoreNamesBc;
  do {
    if (*scoreValue < 1) {
      break;
    }
    ++rank;
    lineText.Format(g_szDecimalFormat, rank);
    lineText += s_szRankDotSeparator_00698ab4;
    SetQuickDrawColorAndSyncGlobals(0);
    SetQuickDrawTextOriginWithContextOffset(0x97, static_cast<short>(y + 1));
    DrawTextWithCachedQuickDrawStyleState(&lineText);
    SetQuickDrawColorAndSyncGlobals(foregroundColor);
    SetQuickDrawTextOriginWithContextOffset(0x96, static_cast<short>(y));
    DrawTextWithCachedQuickDrawStyleState(&lineText);

    lineText = CString(*scoreName);
    SetQuickDrawColorAndSyncGlobals(0);
    SetQuickDrawTextOriginWithContextOffset(0xbf, static_cast<short>(y + 1));
    DrawTextWithCachedQuickDrawStyleState(&lineText);
    SetQuickDrawColorAndSyncGlobals(foregroundColor);
    SetQuickDrawTextOriginWithContextOffset(0xbe, static_cast<short>(y));
    DrawTextWithCachedQuickDrawStyleState(&lineText);

    lineText.Format(g_szDecimalFormat, *scoreValue);
    SetQuickDrawColorAndSyncGlobals(0);
    SetQuickDrawTextOriginWithContextOffset(0x1af, static_cast<short>(y + 1));
    DrawTextWithCachedQuickDrawStyleState(&lineText);
    SetQuickDrawColorAndSyncGlobals(foregroundColor);
    SetQuickDrawTextOriginWithContextOffset(0x1ae, static_cast<short>(y));
    DrawTextWithCachedQuickDrawStyleState(&lineText);

    y += 0x20;
    ++scoreValue;
    ++scoreName;
  } while (rank < 10);
  (void)secondaryColor;
  (void)unusedText;
}

// FUNCTION: IMPERIALISM 0x00575770
void THighScoresPicture::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  (void)sourceHandler;
  (void)event;
  if (commandId == 0xa) {
    g_pGlobalUiRootController->PostTurnEventCodeMessage2420(
        EncodeTurnEventCode(kTurnEventMainMenu));
    g_pSfxPlaybackSystem->ResetDualAudioCuePools();
    g_pSfxPlaybackSystem->PushCueToDualAudioCuePools(0xb);
    g_pSfxPlaybackSystem->SelectAndScheduleRandomAudioCue();
  }
}
