#include "game/diplomacy_ui/TCouncilView.h"
#include "game/ui_tags_city.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_diplomacy.h"

#include "game/app/TAnimator.h"
#include "game/ui_core/TControl.h"
#include "game/city_ui/TCountry.h"
#include "game/app/TCouncilTickerAnimation.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/ui_widgets/TDropShadowText.h"
#include "game/TEvent.h"
#include "game/ui_core/TEventHandler.h"
#include "game/nation/TGreatPower.h"
#include "game/map/TMapMgr.h"
#include "game/ui_core/TPicture.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_widgets/TSoundPlayer.h"
#include "game/ui_core/TStaticText.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/diplomacy_ui_globals.h"
#include "game/globals/shared_globals.h"
#include "game/military/mapped_flavor_text.h"
#include "game/mfc.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_core/ScopedMapQuickDrawContext.h"
#include "game/ui_text_label_helpers_decls.h"

namespace {
const short kCouncilCoatOfArmsPictureBase = 0x1105;
const short kCouncilTickerIntervalMapMode = 0x2710;
const unsigned int kEndControlTagReselect = kControlTagRestartCaps;  // mode 0x17
const unsigned int kEndControlTagReselectAlt = kControlTagScoreCaps; // mode 0x16

} // namespace

// FUNCTION: IMPERIALISM 0x00430630
TCouncilView::TCouncilView() : TDiplomacyMapView() {}

// FUNCTION: IMPERIALISM 0x00430690
TCouncilView::~TCouncilView() {}

IMPLEMENT_DYNCREATE(TCouncilView, TDiplomacyMapView)

// FUNCTION: IMPERIALISM 0x004fba70
void TCouncilView::DoPostCreate(int arg) {
  this->TView::DoPostCreate(arg);

  interactionMode = 5;
  tickerSlots[0] = 0;
  tickerSlots[1] = 0;
  tickerSlots[2] = 0;
  tickerSlots[3] = 0;
  tickerSlots[4] = 0;
  tickerSlots[5] = 0;
  tickerSlots[6] = 0;
  tickerSlots[7] = 0;
  tickerSlots[8] = 0;
  tickerSlots[9] = 0;

  this->BuildDiplomacyNationOverlayGeometryAndHitMasks();

  TDropShadowText* titleControl =
      static_cast<TDropShadowText*>(this->ResolveControlByTag(kControlTagTitl));
  titleControl->AssertValid();
  ApplyUiTextStyleAndThemeFlags(titleControl, 0, 0x10, 0x2b6c, 0x2b67);
  titleControl->SetJustification(-2, false);

  if (g_pSimMgr->mode == kGamePhaseCouncilDefeat || g_pSimMgr->mode == kGamePhaseCouncilVictory) {
    CString terrainLabel;
    g_apTerrainTypeDescriptorTable[g_pDiplomacyTurnStateManager->lastProcessedNationSlot]
        ->FormatOverlayTerrainLabelText(&terrainLabel);
    CString titleTemplate;
    g_pSimMgr->GetString(0x275d, 3, &titleTemplate);
    CString finalTitle;
    scanBracketExpressions(g_pSimMgr, &finalTitle, static_cast<LPCSTR>(titleTemplate),
                           static_cast<LPCSTR>(terrainLabel));
    titleControl->SetTextAndMaybeRefresh(&finalTitle, false);
    DisplayStats();

    if (g_pDiplomacyTurnStateManager->lastProcessedNationSlot == g_pSimMgr->GetPlayerCountry()) {
      g_pSfxPlaybackSystem->PlaySoundEffect(0x1f43, 0, 1);
    } else {
      g_pSfxPlaybackSystem->PlaySoundEffect(0x1f44, 0, 1);
    }
  } else {
    CString titleText;
    g_pSimMgr->GetString(0x2733, 0x5e, &titleText);
    titleControl->SetTextAndMaybeRefresh(&titleText, false);

    ApplySharedStringToGlobalControlTag(CString(g_szEmptyString), kControlTagMain);

    TView* endControl = this->ResolveControlByTag(kControlTagEnd);
    LoadUiStringByGroupAndIndexToControlObject(0x2746, 6, endControl);

    TView* querControl = this->ResolveControlByTag(kControlTagQuer);
    LoadUiStringByGroupAndIndexToControlObject(0x2730, 3, querControl);
  }
}

// FUNCTION: IMPERIALISM 0x004fbd60
void TCouncilView::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 10) {
    if (sourceHandler->controlTag == kControlTagStar) { // "star"
      this->StartVoting();
      return;
    }
  } else if (commandId == 0x14) {
    unsigned int tag = sourceHandler->controlTag;
    int tagIndex = 0;
    unsigned int* tagTable = g_aDiplomacyActionTopicTabTags;
    do {
      if (tag == *tagTable) {
        break;
      }
      tagTable += 1;
      tagIndex += 1;
    } while (tagTable < g_aDiplomacyActionTopicTabTags + 6);
    if (tagIndex < 6) {
      this->ChangeSelectedActionTopic(tagIndex);
      return;
    }
  } else {
    TControl::DoEvent(commandId, sourceHandler, event);
  }
}

// FUNCTION: IMPERIALISM 0x004fbdf0
void TCouncilView::DisplayStats() {
  CString text;
  TextStyle style;
  BuildUiTextStyleDescriptor(&style, 0, 0xc, 0x2b6a);

  NationSlot sourceNation = g_pDiplomacyTurnStateManager->congressLeadership.chairmanNationSlot;
  NationSlot targetNation = g_pDiplomacyTurnStateManager->congressLeadership.counterpartNationSlot;
  short categoryCounts[8];
  for (int i = 0; i < 8; ++i) {
    categoryCounts[i] = 0;
  }
  for (int record = 0; record < kProvinceCount; ++record) {
    if (g_pDiplomacyTurnStateManager->pendingPolicyCodeMatrix[record] == -1) {
      continue;
    }
    short ownerCode = g_pGlobalMapState->cityScoreTable[record].ownerNationCode;
    int category;
    if (ownerCode >= 7) {
      TCountry* country = g_apTerrainTypeDescriptorTable[ownerCode];
      if (country->IsColonyOf(sourceNation) || country->IsColonyOf(targetNation)) {
        category = 1;
      } else {
        category = 3;
      }
    } else {
      if (ownerCode == sourceNation || ownerCode == targetNation) {
        category = 0;
      } else {
        category = 2;
      }
    }
    if (g_pDiplomacyTurnStateManager->pendingPolicyCodeMatrix[record] == targetNation) {
      category += 4;
    }
    ++categoryCounts[category];
  }

  for (int row = 0; row < 4; ++row) {
    TStaticText* titleLabel = static_cast<TStaticText*>(
        this->ResolveControlByTag(IMPERIALISM_FOURCC('t', 't', 'l', '0') + row));
    titleLabel->AssertValid();
    titleLabel->SetTextWithStrListID(0x2733, static_cast<short>(0x5a + row), true);
    titleLabel->InstallTextStyle(style, 0);
    titleLabel->SetJustification(1, false);
    titleLabel->Show(1, 0);

    TStaticText* majorField = static_cast<TStaticText*>(
        this->ResolveControlByTag(IMPERIALISM_FOURCC('n', 'u', 'm', '0') + row));
    majorField->AssertValid();
    text.Format(g_szDecimalFormat, categoryCounts[row]);
    majorField->SetTextAndMaybeRefresh(&text, true);
    majorField->InstallTextStyle(style, 0);
    majorField->SetJustification(-1, false);
    majorField->Show(1, 1);

    TStaticText* minorField = static_cast<TStaticText*>(
        this->ResolveControlByTag(IMPERIALISM_FOURCC('n', 'u', 'm', '4') + row));
    minorField->AssertValid();
    text.Format(g_szDecimalFormat, categoryCounts[row + 4]);
    minorField->SetTextAndMaybeRefresh(&text, true);
    minorField->InstallTextStyle(style, 0);
    minorField->Show(1, 1);
  }

  CString scoreText;
  BuildUiTextStyleDescriptor(&style, 0, 0x18, 0x2b68);

  COLORREF scoreShadowColor;
  ResolveUiThemeColor(0x2b6a, &scoreShadowColor);

  TDropShadowText* sourceScore =
      static_cast<TDropShadowText*>(ResolveControlByTag(IMPERIALISM_FOURCC('s', 'c', 'o', '0')));
  sourceScore->AssertValid();
  scoreText.Format(g_szDecimalFormat,
                   g_pDiplomacyTurnStateManager->congressSupport.chairmanSupportCount);
  sourceScore->SetTextAndMaybeRefresh(&scoreText, true);
  sourceScore->InstallTextStyle(style, 0);
  sourceScore->shadowColor = scoreShadowColor;
  sourceScore->Show(1, 1);

  TDropShadowText* targetScore =
      static_cast<TDropShadowText*>(ResolveControlByTag(IMPERIALISM_FOURCC('s', 'c', 'o', '1')));
  targetScore->AssertValid();
  scoreText.Format(g_szDecimalFormat,
                   g_pDiplomacyTurnStateManager->congressSupport.counterpartSupportCount);
  targetScore->SetTextAndMaybeRefresh(&scoreText, true);
  targetScore->InstallTextStyle(style, 0);
  targetScore->shadowColor = scoreShadowColor;
  targetScore->Show(1, 1);
}

// FUNCTION: IMPERIALISM 0x004fc2e0
void TCouncilView::StartVoting() {
  CString candidateName;

  TextStyle councilTextStyle;
  councilTextStyle.textColor = 0;
  BuildUiTextStyleDescriptor(&councilTextStyle, 0, 0xe, 0x2b6a);

  councilNationCount = 0;

  TStaticText* can0 = static_cast<TStaticText*>(ResolveControlByTag(kControlTagCan0));
  can0->AssertValid();
  g_apNationStates[g_pDiplomacyTurnStateManager->congressLeadership.chairmanNationSlot]->GetName(
      &candidateName);
  can0->SetTextAndMaybeRefresh(&candidateName, true);
  can0->InstallTextStyle(councilTextStyle, 0);

  TStaticText* can1 = static_cast<TStaticText*>(ResolveControlByTag(kControlTagCan1));
  can1->AssertValid();
  g_apNationStates[g_pDiplomacyTurnStateManager->congressLeadership.counterpartNationSlot]->GetName(
      &candidateName);
  can1->SetTextAndMaybeRefresh(&candidateName, true);
  can1->InstallTextStyle(councilTextStyle, 0);

  TPicture* coat0 = static_cast<TPicture*>(ResolveControlByTag(kControlTagCoa0));
  coat0->AssertValid();
  coat0->SetPictureRsrcID(
      static_cast<short>(g_pDiplomacyTurnStateManager->congressLeadership.chairmanNationSlot +
                         kCouncilCoatOfArmsPictureBase),
      1);
  TPicture* coat1 = static_cast<TPicture*>(ResolveControlByTag(kControlTagCoa1));
  coat1->AssertValid();
  coat1->SetPictureRsrcID(
      static_cast<short>(g_pDiplomacyTurnStateManager->congressLeadership.counterpartNationSlot +
                         kCouncilCoatOfArmsPictureBase),
      1);

  const short phase = static_cast<short>(g_pSimMgr->mode);
  if (phase == kGamePhaseCouncilVictory || phase == kGamePhaseCouncilDefeat) {
    for (int provinceIndex = 0; provinceIndex < kProvinceCount; ++provinceIndex) {
      if (g_pGlobalMapState->cityScoreTable[provinceIndex].ownerNationCode != -1) {
        tileHasOwnerFlags[provinceIndex] = true;
      }
    }
    visibleVoteTier = kCouncilTickerIntervalMapMode;

    TControl* endControl = static_cast<TControl*>(ResolveControlByTag(kControlTagEnd));
    if (endControl != NULL) {
      endControl->AssertValid();
      endControl->controlTag =
          (phase == kGamePhaseCouncilDefeat) ? kEndControlTagReselect : kEndControlTagReselectAlt;
    }
    return;
  }

  short maxPendingTier = councilNationCount;
  for (int tierIndex = 0; tierIndex < kDiplomacyPairMatrixEntries; ++tierIndex) {
    const short tierValue = g_pDiplomacyTurnStateManager->pendingPolicyTierMatrix[tierIndex];
    if (tierValue != -1 && maxPendingTier < tierValue) {
      maxPendingTier = tierValue;
    }
  }
  councilNationCount = maxPendingTier;
  visibleVoteTier = 0;

  TCouncilTickerAnimation* tickerAnimation = new TCouncilTickerAnimation();
  if (tickerAnimation != NULL) {
    tickerAnimation->InitializeCouncilTicker(this, 2);
    if (g_pUiAnimator != NULL) {
      g_pUiAnimator->AddAnimation(tickerAnimation);
    }
  }

  SetCursor(g_pViewMgr->turnEventCursors[26]);

  TControl* endControl = static_cast<TControl*>(ResolveControlByTag(kControlTagEnd));
  if (endControl != NULL) {
    endControl->AssertValid();
    endControl->ViewEnable(0, 0);
  }
}

// FUNCTION: IMPERIALISM 0x004fc630
void TCouncilView::NextTick() {
  CString unusedMsg; // constructed/destructed; never populated in the observed binary
  ++visibleVoteTier;

  for (int idx = 0; idx < kDiplomacyPairMatrixEntries; ++idx) {
    short tier = g_pDiplomacyTurnStateManager->pendingPolicyTierMatrix[idx];
    if (tier != -1 && (tier == visibleVoteTier || tier == visibleVoteTier - 1)) {
      RECT* tileRect = &tileMarkerRects[idx];
      RECT inflated = {tileRect->left - 1, tileRect->top - 1, tileRect->right + 2,
                       tileRect->bottom + 2};
      InvalidateCityDialogRectRegion(&inflated, 1);
    }
  }

  {
    ScopedMapQuickDrawContext quickDraw(this);
    PrepareForDrawing();
    DrawVoteNuggets();
    RECT rect = {0, 0, frameWidth, 300};
    ValidateControlRectIfWindowActive(&rect);
  }

  bool unusedFlag = false; // never set true in the observed binary
  if (unusedFlag) {
    g_pSfxPlaybackSystem->PlaySoundEffect(0x1f41, 0, 1);
  }

  if (visibleVoteTier == councilNationCount + 2) {
    SetCursor(LoadCursorA(NULL, IDC_ARROW));
    TView* endControlTarget = ResolveControlByTag(kControlTagEnd);
    endControlTarget->AssertValid();
    endControlTarget->ViewEnable(1, 0);

    if (g_pDiplomacyTurnStateManager->lastProcessedNationSlot == -1) {
      g_pSfxPlaybackSystem->PlaySoundEffect(0x1f42, 0, 1);
    } else {
      bool allowAdvance = false;
      short activeNation = g_pSimMgr->GetPlayerCountry();
      if (g_pDiplomacyTurnStateManager->lastProcessedNationSlot == activeNation &&
          g_pSimMgr->multiplayerSessionRole == kSessionRoleStandalone) {
        short tick = g_pSimMgr->GetEconomicTurn();
        unsigned char* phaseTable = g_pSimMgr->councilByDecade;
        if (phaseTable[tick / 40] != 2) {
          allowAdvance = !g_pViewMgr->ShowLocalizedUiPromptByGroupAndIndex(0x275d, 7, 0, 1);
        }
      }
      if (!allowAdvance) {
        g_pSimMgr->StartNextPhase();
        return;
      }
      g_pDiplomacyTurnStateManager->lastProcessedNationSlot = -1;
      g_pSimMgr->turnStateCode = kGamePhaseAdvanceSeason;
      g_pSfxPlaybackSystem->PlaySoundEffect(0x1f42, 0, 1);
    }
    DisplayStats();
  }
}

// FUNCTION: IMPERIALISM 0x004fc950
void TCouncilView::HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* point,
                                                                       RgnHandle hitArg) {
  TView::HandleCursorHoverSelectionByChildHitTestAndFallback(point, hitArg);
  if ((int)visibleVoteTier < councilNationCount + 2) {
    SetCursor(g_pViewMgr->turnEventCursors[26]);
  }
}
