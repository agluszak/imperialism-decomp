#include "game/TGameScorePicture.h"

#include "game/TControl.h"
#include "game/TCountry.h"
#include "game/TDropShadowText.h"
#include "game/TGreatPower.h"
#include "game/TSimMgr.h"
#include "game/TSoundPlayer.h"
#include "game/global_data_tables.h"
#include "game/mapped_flavor_text.h"
#include "game/ui_control_tags.h"
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x0045afb0
// TGameScorePicture::`scalar deleting destructor'
TGameScorePicture::~TGameScorePicture() {}
// SYNTHETIC: IMPERIALISM 0x0057b000
// TGameScorePicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x0057b080
// TGameScorePicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TGameScorePicture, TNoHilitePicture)

// FUNCTION: IMPERIALISM 0x0045af80
TGameScorePicture::TGameScorePicture() {}

// FUNCTION: IMPERIALISM 0x0057b0a0
void TGameScorePicture::DoPostCreate(int arg) {
  TNoHilitePicture::DoPostCreate(arg);

  CString templateText;
  CString argumentText;
  CString displayText;
  TextStyle scoreStyle = {0, 0, 0, 0};
  COLORREF shadowColor = 0;

  g_pSfxPlaybackSystem->ResetDualAudioCuePools();
  g_pSfxPlaybackSystem->PushCueToDualAudioCuePools(11);
  g_pSfxPlaybackSystem->SelectAndScheduleRandomAudioCue();

  BuildUiTextStyleDescriptor(&scoreStyle, 0, 14, 0x2b68);
  ResolveUiThemeColor(0x2b6a, &shadowColor);

  g_apNationStates[g_pSimMgr->GetActiveNationId()]->GenerateGameScore();

  for (int row = 0; row < 12; ++row) {
    TDropShadowText* label =
        static_cast<TDropShadowText*>(ResolveControlByTag(0x73637261u + row)); // 'scra'..
    label->AssertValid();
    if (row == 11) {
      BuildUiTextStyleDescriptor(&scoreStyle, 0, 18, 0x2b68);
    }
    label->InstallTextStyle(scoreStyle, 1);
    label->shadowColor94 = shadowColor;

    g_pSimMgr->GetString(0x2761, static_cast<short>(row + 2), &displayText);
    if (row == 10) {
      templateText = displayText;
      g_pSimMgr->GetString(0x2737, static_cast<short>(g_pSimMgr->difficultyLevel + 13),
                           &argumentText);
      scanBracketExpressions(g_pSimMgr, &displayText, static_cast<LPCSTR>(templateText),
                             static_cast<LPCSTR>(argumentText));
    }
    label->SetTextAndMaybeRefresh(&displayText, 1);

    TDropShadowText* value =
        static_cast<TDropShadowText*>(ResolveControlByTag(0x6e756d61u + row)); // 'numa'..
    value->AssertValid();
    value->InstallTextStyle(scoreStyle, 1);
    value->shadowColor94 = shadowColor;

    if (row == 10) {
      int difficultyPercent =
          g_apNationStates[g_pSimMgr->GetActiveNationId()]->gameScoreDifficultyPercent958;
      if (difficultyPercent % 10 > 0) {
        FormatFloatToLocalizedSharedString(static_cast<float>(difficultyPercent) * 0.1f,
                                           &displayText);
      } else {
        displayText.Format(g_szDecimalFormat, difficultyPercent / 10);
      }
      displayText = g_szLowercaseX + displayText;
    } else {
      displayText.Format(g_szDecimalFormat,
                         g_apNationStates[g_pSimMgr->GetActiveNationId()]->gameScoreRows930[row]);
    }
    value->SetTextAndMaybeRefresh(&displayText, 1);
  }

  TDropShadowText* victory =
      static_cast<TDropShadowText*>(ResolveControlByTag(0x76696374u)); // 'vict'
  victory->AssertValid();
  g_pSimMgr->GetString(0x2761, 0, &templateText);
  g_apNationStates[g_pSimMgr->GetActiveNationId()]->FormatOverlayTerrainLabelText(&argumentText);
  scanBracketExpressions(g_pSimMgr, &displayText, static_cast<LPCSTR>(templateText),
                         static_cast<LPCSTR>(argumentText));
  victory->SetTextAndMaybeRefresh(&displayText, 1);
  InitializeUiTextStyleDescriptor(&scoreStyle, 0, 24, 0x2b68, 1);
  victory->InstallTextStyle(scoreStyle, 1);
  victory->shadowColor94 = shadowColor;

  TDropShadowText* pointsFor =
      static_cast<TDropShadowText*>(ResolveControlByTag(0x70746672u)); // 'ptfr'
  pointsFor->AssertValid();
  g_pSimMgr->GetString(0x2761, 1, &displayText);
  pointsFor->SetTextAndMaybeRefresh(&displayText, 1);
  BuildUiTextStyleDescriptor(&scoreStyle, 0, 14, 0x2b68);
  pointsFor->InstallTextStyle(scoreStyle, 1);
  pointsFor->shadowColor94 = shadowColor;
}

// FUNCTION: IMPERIALISM 0x0057b620
void TGameScorePicture::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  TControl::DoEvent(commandId, sourceHandler, event);
  if (commandId == 0xa && sourceHandler->controlTag == kTagDone) {
    ReinitializeGameFlowAndPostTurnEventCode(kTurnEventHighScores);
  }
}
