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

// FUNCTION: IMPERIALISM 0x0045adf0
THighScoresPicture::~THighScoresPicture() {}

IMPLEMENT_DYNCREATE(THighScoresPicture, TNoHilitePicture)

// FUNCTION: IMPERIALISM 0x00575320
void THighScoresPicture::DoPostCreate(int arg) {
  TNoHilitePicture::DoPostCreate(arg);

  g_pSfxPlaybackSystem->ResetPlayList();
  g_pSfxPlaybackSystem->AddToPlayList(0xb);
  g_pSfxPlaybackSystem->PlayRandomTrack();

  CString path;
  AssignScoresDatPathToSharedString(&path);
  FILE* file = fopen(path, "rb");
  if (file == 0) {
    memset(scoreValues, 0, sizeof(scoreValues));
  } else {
    for (int i = 0; i < 10; ++i) {
      if (fread(&scoreValues[i], 4, 1, file) == 0) {
        scoreValues[i] = 0;
      }
      fread(scoreNames[i], 0x20, 1, file);
    }
    fclose(file);
  }
}

// FUNCTION: IMPERIALISM 0x00575460
void THighScoresPicture::Draw(RECT* rectBuffer) {
  TPicture::Draw(rectBuffer);
  COLORREF foregroundColor = 0;
  CString lineText;
  CString unusedText;
  ResolveUiThemeColor(0x2b68, &foregroundColor);
  COLORREF secondaryColor = 0;
  ResolveUiThemeColor(0x2b67, &secondaryColor);
  ApplyTextStyle(0, 0x18, 0x2b68);

  int rank = 0;
  int y = 100;
  const int* scoreValue = scoreValues;
  const char (*scoreName)[0x20] = scoreNames;
  do {
    if (*scoreValue < 1) {
      break;
    }
    ++rank;
    lineText.Format(g_szDecimalFormat, rank);
    lineText += s_szRankDotSeparator;
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
  if (commandId == 0xa) {
    g_pAmbitApplication->PostTurnEventCodeMessage(EncodeTurnEventCode(kTurnEventMainMenu));
    g_pSfxPlaybackSystem->ResetPlayList();
    g_pSfxPlaybackSystem->AddToPlayList(0xb);
    g_pSfxPlaybackSystem->PlayRandomTrack();
  }
}
