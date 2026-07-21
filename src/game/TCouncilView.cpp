#include "game/TCouncilView.h"

#include "game/TAnimator.h"
#include "game/TControl.h"
#include "game/TCountry.h"
#include "game/TCouncilTickerAnimation.h"
#include "game/TDiplomacyMgr.h"
#include "game/TDropShadowText.h"
#include "game/TEvent.h"
#include "game/TEventHandler.h"
#include "game/TGreatPower.h"
#include "game/TMapMgr.h"
#include "game/TPicture.h"
#include "game/TSimMgr.h"
#include "game/TSoundPlayer.h"
#include "game/TStaticText.h"
#include "game/TView.h"
#include "game/TViewMgr.h"
#include "game/global_data_tables.h"
#include "game/mapped_flavor_text.h"
#include "game/mfc.h"
#include "game/quickdraw_rendering.h"
#include "game/ScopedMapQuickDrawContext.h"
#include "game/ui_control_tags.h"
#include "game/ui_text_label_helpers_decls.h"

namespace {
const short kCouncilCoatOfArmsPictureBase = 0x1105;
const short kCouncilTickerIntervalMapMode = 0x2710;
const unsigned int kEndControlTagReselect = 0x52655374u;    // mode 0x17
const unsigned int kEndControlTagReselectAlt = 0x53636f72u; // mode 0x16

void ApplyCouncilCandidateTextStyle(TStaticText* textControl, const TUiTextStyleDescriptor* style) {
  textControl->SetTextStyleAndMaybeRefresh(const_cast<TUiTextStyleDescriptor*>(style), 0);
}

void RefreshCouncilCandidateNameText(TView* hostPanel, unsigned int controlTag, short nationSlot) {
  TControl* control = static_cast<TControl*>(hostPanel->ResolveControlByTag(controlTag));
  if (control == nullptr) {
    return;
  }
  control->AssertValid();

  TGreatPower* nation = g_apNationStates[nationSlot];
  if (nation == nullptr) {
    return;
  }

  CString labelText;
  nation->LoadNationDisplayNameSharedRefFromField8(&labelText);
  TStaticText* textControl = static_cast<TStaticText*>(control);
  textControl->SetTextAndMaybeRefresh(&labelText, 1);
}

void RefreshCouncilCoatOfArmsPicture(TView* hostPanel, unsigned int controlTag, short nationSlot) {
  TControl* control = static_cast<TControl*>(hostPanel->ResolveControlByTag(controlTag));
  if (control == nullptr) {
    return;
  }
  control->AssertValid();
  const short pictureId = static_cast<short>(nationSlot + kCouncilCoatOfArmsPictureBase);
  static_cast<TPicture*>(control)->SetPictureResourceIdAndRefresh(pictureId, 1);
}
} // namespace

// SYNTHETIC: IMPERIALISM 0x00430660
// TCouncilView::`scalar deleting destructor'
TCouncilView::~TCouncilView() {}

// SYNTHETIC: IMPERIALISM 0x004fb9d0
// TCouncilView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004fba50
// TCouncilView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TCouncilView, TDiplomacyMapView)

TCouncilView::TCouncilView() : TDiplomacyMapView() {}

// slot 0x37 — lifecycle-hook override: rebuilds the council nation-overlay geometry and
// labels (the base impl is a no-op, hence the inherited slot name).
// FUNCTION: IMPERIALISM 0x004fba70
void TCouncilView::DoPostCreate(int arg) {
  // Calls the (literally no-op) base-class slot 0x37 impl non-virtually, matching the
  // ground truth's fixed-address (not vtable) call to 0x48ab70.
  this->TView::DoPostCreate(arg);

  interactionModeAt94 = 5;
  tickerSlots24ca[0] = 0;
  tickerSlots24ca[1] = 0;
  tickerSlots24ca[2] = 0;
  tickerSlots24ca[3] = 0;
  tickerSlots24ca[4] = 0;
  tickerSlots24ca[5] = 0;
  tickerSlots24ca[6] = 0;
  tickerSlots24ca[7] = 0;
  tickerSlots24ca[8] = 0;
  tickerSlots24ca[9] = 0;

  this->BuildDiplomacyNationOverlayGeometryAndHitMasks();

  TDropShadowText* titleControl =
      static_cast<TDropShadowText*>(this->ResolveControlByTag(kControlTagTitl));
  titleControl->AssertValid();
  ApplyUiTextStyleAndThemeFlags(titleControl, 0, 0x10, 0x2b6c, 0x2b67);
  titleControl->SetTextAlignmentAndMaybeRefresh(-2, 0);

  if (g_pSimMgr->mode == 0x17 || g_pSimMgr->mode == 0x16) {
    // Map-interaction mode: title shows "<terrain/country name>" expanded through the
    // localized "[0]" template, plus a self-vs-other SFX cue for the highlighted nation.
    CString terrainLabel;
    g_apTerrainTypeDescriptorTable[g_pDiplomacyTurnStateManager->lastProcessedNationSlot78e]
        ->FormatOverlayTerrainLabelText(&terrainLabel);
    CString titleTemplate;
    g_pSimMgr->GetString(0x275d, 3, &titleTemplate);
    CString finalTitle;
    scanBracketExpressions(g_pSimMgr, &finalTitle, static_cast<LPCSTR>(titleTemplate),
                           static_cast<LPCSTR>(terrainLabel));
    titleControl->SetTextAndMaybeRefresh(&finalTitle, 0);

    if (g_pDiplomacyTurnStateManager->lastProcessedNationSlot78e ==
        g_pSimMgr->GetActiveNationId()) {
      g_pSfxPlaybackSystem->PlaySoundEffect(0x1f43, 0, 1);
    } else {
      g_pSfxPlaybackSystem->PlaySoundEffect(0x1f44, 0, 1);
    }
  } else {
    // Normal council mode: static council-panel title, then clear/reload the "main"
    // ticker panel and the "end"/"quer" council-action button captions.
    CString titleText;
    g_pSimMgr->GetString(0x2733, 0x5e, &titleText);
    titleControl->SetTextAndMaybeRefresh(&titleText, 0);

    ApplySharedStringToGlobalControlTag(CString(g_szEmptyString), kControlTagMain);

    TView* endControl = this->ResolveControlByTag(kControlTagEnd);
    LoadUiStringByGroupAndIndexToControlObject(0x2746, 6, endControl);

    TView* querControl = this->ResolveControlByTag(kControlTagQuer);
    LoadUiStringByGroupAndIndexToControlObject(0x2730, 3, querControl);
  }
}

// slot 0x0f — HandleEvent override: routes council-control events by the source
// handler's 4-char control tag; everything else falls through to TControl::HandleEvent.
// FUNCTION: IMPERIALISM 0x004fbd60
void TCouncilView::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 10) {
    if (sourceHandler->controlTag == 0x73746172) { // "star"
      // Rebuild council controls + restart the vote ticker. 0x4fc2e0's receiver is a
      // TCouncilView (verified: it writes councilNationCount24c8/visibleVoteTier528 and resolves its
      // own controls via the TView vtable), so it is owned by this class, not the small
      // TCouncilTickerAnimation it was previously attributed to.
      this->InitializeDiplomacyCouncilViewControlsAndTicker();
      return;
    }
  } else if (commandId == 0x14) {
    unsigned int tag = sourceHandler->controlTag;
    int tagIndex = 0;
    unsigned int* tagTable = g_councilControlTagTable;
    do {
      if (tag == *tagTable) {
        break;
      }
      tagTable += 1;
      tagIndex += 1;
    } while (tagTable < g_councilControlTagTable + 6);
    if (tagIndex < 6) {
      this->ChangeSelectedActionTopic(tagIndex);
      return;
    }
  } else {
    TControl::HandleEvent(commandId, sourceHandler, event);
  }
}

// Receiver confirmed to be TCouncilView (writes councilNationCount24c8 / visibleVoteTier528; resolves
// its own controls via the TView vtable). NOTE: still 24.80% -- the original inlines the
// candidate/coat-of-arms/text-style helpers (and a leading CString ctor) rather than calling
// them out of line as below; a faithful match needs those inlined. TODO: inline helpers.
// FUNCTION: IMPERIALISM 0x004fc2e0
void TCouncilView::InitializeDiplomacyCouncilViewControlsAndTicker() {
  TCouncilView* hostPanel = this;

  TUiTextStyleDescriptor councilTextStyle;
  councilTextStyle.fontFamily = 0;
  councilTextStyle.fontStyleFlags = 0;
  councilTextStyle.fontSize = 0;
  councilTextStyle.textColor = 0;
  BuildUiTextStyleDescriptor(&councilTextStyle, 0, 0xe, 0x2b6a);

  councilNationCount24c8 = 0;

  RefreshCouncilCandidateNameText(hostPanel, kControlTagCan0,
                                  g_pDiplomacyTurnStateManager->selectedSourceNationSlot784);
  TControl* can0Control = static_cast<TControl*>(hostPanel->ResolveControlByTag(kControlTagCan0));
  if (can0Control != nullptr) {
    ApplyCouncilCandidateTextStyle(static_cast<TStaticText*>(can0Control), &councilTextStyle);
  }

  RefreshCouncilCandidateNameText(hostPanel, kControlTagCan1,
                                  g_pDiplomacyTurnStateManager->selectedTargetNationSlot786);
  TControl* can1Control = static_cast<TControl*>(hostPanel->ResolveControlByTag(kControlTagCan1));
  if (can1Control != nullptr) {
    ApplyCouncilCandidateTextStyle(static_cast<TStaticText*>(can1Control), &councilTextStyle);
  }

  RefreshCouncilCoatOfArmsPicture(hostPanel, kControlTagCoa0,
                                  g_pDiplomacyTurnStateManager->selectedSourceNationSlot784);
  RefreshCouncilCoatOfArmsPicture(hostPanel, kControlTagCoa1,
                                  g_pDiplomacyTurnStateManager->selectedTargetNationSlot786);

  const short localizationMode = static_cast<short>(g_pSimMgr->mode);
  if (localizationMode == 0x16 || localizationMode == 0x17) {
    const char* tileRecordBytes = reinterpret_cast<const char*>(g_pGlobalMapState->cityScoreTable);
    int flagIndex = 0;
    for (int tileOffset = 0; tileOffset < 0xfc00; tileOffset += 0xa8) {
      if (tileRecordBytes[tileOffset] != -1) {
        tileHasOwnerFlags52C[flagIndex] = true;
      }
      ++flagIndex;
    }
    visibleVoteTier528 = kCouncilTickerIntervalMapMode;

    TControl* endControl = static_cast<TControl*>(hostPanel->ResolveControlByTag(kControlTagEnd));
    if (endControl != nullptr) {
      endControl->AssertValid();
      endControl->controlTag =
          (localizationMode == 0x17) ? kEndControlTagReselect : kEndControlTagReselectAlt;
    }
    return;
  }

  short maxPendingTier = councilNationCount24c8;
  for (int tierIndex = 0; tierIndex < kDiplomacyPairMatrixEntries; ++tierIndex) {
    const short tierValue = g_pDiplomacyTurnStateManager->pendingPolicyTierMatrix484[tierIndex];
    if (tierValue != -1 && maxPendingTier < tierValue) {
      maxPendingTier = tierValue;
    }
  }
  councilNationCount24c8 = maxPendingTier;
  visibleVoteTier528 = 0;

  TCouncilTickerAnimation* tickerAnimation = new TCouncilTickerAnimation();
  if (tickerAnimation != nullptr) {
    tickerAnimation->ConstructTCouncilTickerAnimationBaseState(hostPanel, 2);
    if (g_pUiAnimator != nullptr) {
      g_pUiAnimator->AddObjectToUiTransientRegistry(tickerAnimation);
    }
  }

  SetCursor(static_cast<HCURSOR>(g_pUiRuntimeContext->cursorTable[26]));

  TControl* endControl = static_cast<TControl*>(hostPanel->ResolveControlByTag(kControlTagEnd));
  if (endControl != nullptr) {
    endControl->AssertValid();
    endControl->SetState(0, 0);
  }
}

// FUNCTION: IMPERIALISM 0x004fc630
void TCouncilView::AdvanceCivilianTerrainSelectionStep() {
  CString unusedMsg; // constructed/destructed; never populated in the observed binary
  ++visibleVoteTier528;

  for (int idx = 0; idx < kDiplomacyPairMatrixEntries; ++idx) {
    short tier = g_pDiplomacyTurnStateManager->pendingPolicyTierMatrix484[idx];
    if (tier != -1 && (tier == visibleVoteTier528 || tier == visibleVoteTier528 - 1)) {
      RECT* tileRect = &tileMarkerRects6AC[idx];
      RECT inflated = {tileRect->left - 1, tileRect->top - 1, tileRect->right + 2,
                       tileRect->bottom + 2};
      InvalidateCityDialogRectRegion(&inflated, 1);
    }
  }

  {
    ScopedMapQuickDrawContextGuard quickDraw(this);
    PrepareForDrawing();
    DrawVoteNuggets();
    RECT rect = {0, 0, frameWidth34, 300};
    ValidateControlRectIfWindowActive(&rect);
  }

  bool unusedFlag = false; // never set true in the observed binary
  if (unusedFlag) {
    g_pSfxPlaybackSystem->PlaySoundEffect(0x1f41, 0, 1);
  }

  if (visibleVoteTier528 == councilNationCount24c8 + 2) {
    SetCursor(LoadCursorA(nullptr, IDC_ARROW));
    TView* endControlTarget = ResolveControlByTag(0x656e6420);
    endControlTarget->AssertValid();
    endControlTarget->SetState(1, 0);

    if (g_pDiplomacyTurnStateManager->lastProcessedNationSlot78e == -1) {
      g_pSfxPlaybackSystem->PlaySoundEffect(0x1f42, 0, 1);
    } else {
      bool allowAdvance = false;
      short activeNation = g_pSimMgr->GetActiveNationId();
      if (g_pDiplomacyTurnStateManager->lastProcessedNationSlot78e == activeNation &&
          g_pSimMgr->multiplayerSessionRole == 0) {
        short tick = g_pSimMgr->GetEconomicTurn();
        unsigned char* phaseTable = &g_pSimMgr->field6e;
        if (phaseTable[tick / 40] != 2) {
          allowAdvance =
              g_pUiRuntimeContext->ShowLocalizedUiPromptByGroupAndIndex(0x275d, 7, 0, 1) == 0;
        }
      }
      if (!allowAdvance) {
        g_pSimMgr->StartNextPhase();
      } else {
        g_pDiplomacyTurnStateManager->lastProcessedNationSlot78e = -1;
        g_pSimMgr->turnStateCode = 0x10;
        g_pSfxPlaybackSystem->PlaySoundEffect(0x1f42, 0, 1);
      }
    }
    // 0x4fbdf0 (1005 bytes) -- rebuilds the diplomacy-map hint-overlay text: classifies
    // every diplomacy-matrix entry against the two selected nations into 8 buckets over a
    // TMapMgr-side per-region table, then formats 5 named number controls ('num0'..'num4')
    // plus a conditional 'scr0' summary control via CString::Format. Return value unused.
    // Deliberately not ported here (UI hint-text/formatting construction, not game logic);
    // the matrix/state mutations above are unaffected by this omission.
  }
}

// slot 0x35 — cursor-hover override: base hit test, then force the pointer cursor while
// hovering the council nation strip.
// FUNCTION: IMPERIALISM 0x004fc950
void TCouncilView::HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* point,
                                                                       RgnHandle hitArg) {
  TView::HandleCursorHoverSelectionByChildHitTestAndFallback(point, hitArg);
  if ((int)visibleVoteTier528 < councilNationCount24c8 + 2) {
    SetCursor((HCURSOR)g_pUiRuntimeContext->cursorTable[26]);
  }
}
