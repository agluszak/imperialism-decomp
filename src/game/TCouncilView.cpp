#include "game/TCouncilView.h"

#include "game/TAnimator.h"
#include "game/TControl.h"
#include "game/TCouncilTickerAnimation.h"
#include "game/TDiplomacyMgr.h"
#include "game/TEvent.h"
#include "game/TEventHandler.h"
#include "game/TGreatPower.h"
#include "game/TMapMgr.h"
#include "game/TPicture.h"
#include "game/TSimMgr.h"
#include "game/TStaticText.h"
#include "game/TView.h"
#include "game/TViewMgr.h"
#include "game/global_data_tables.h"
#include "game/mfc.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_control_tags.h"

// Free-function region-invalidate wrapper (ILT target 0x004f6d90); the base class
// TDiplomacyMapView calls it through this same thunk-cast at four sites.
undefined4 thunk_WrapperFor_InvalidateCityDialogRectRegion_At004f6d90(void);

namespace {
const short kCouncilCoatOfArmsPictureBase = 0x1105;
const short kCouncilTickerIntervalMapMode = 0x2710;
const unsigned int kEndControlTagReselect = 0x52655374u;    // mode 0x17
const unsigned int kEndControlTagReselectAlt = 0x53636f72u; // mode 0x16

void ApplyCouncilCandidateTextStyle(TStaticText* textControl,
                                    const TControlPictureRectState* style) {
  textControl->SetCityProductionDialogPictureRectAndMaybeRefresh(
      const_cast<TControlPictureRectState*>(style), 0);
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
  textControl->AssignTextSharedRefIfChangedAndMaybeInvalidate(&labelText, 1);
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
void TCouncilView::NoOpUiLifecycleHook(int arg) {
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
  // TODO(partial 0x4fba70): the original then builds the council title/label CStrings
  // from the localization table (special-casing language ids 0x16/0x17 with an SFX cue),
  // positions the nation overlays, and pushes them through the picture virtuals.
}

// slot 0x0f — HandleEvent override: routes council-control events by the source
// handler's 4-char control tag; everything else falls through to TControl::HandleEvent.
// FUNCTION: IMPERIALISM 0x004fbd60
void TCouncilView::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 10) {
    if (sourceHandler->controlTag == 0x73746172) { // "star"
      // Rebuild council controls + restart the vote ticker. 0x4fc2e0's receiver is a
      // TCouncilView (verified: it writes councilNationCount24c8/field528 and resolves its
      // own controls via the TView vtable), so it is owned by this class, not the small
      // TCouncilTickerAnimation it was previously attributed to.
      this->InitializeDiplomacyCouncilViewControlsAndTicker();
      return;
    }
  } else if (commandId == 0x14) {
    unsigned int tag = sourceHandler->controlTag;
    int tagIndex = 0;
    int* tagTable = g_councilControlTagTable;
    do {
      if (tag == *tagTable) {
        break;
      }
      tagTable += 1;
      tagIndex += 1;
    } while (reinterpret_cast<int>(tagTable) < reinterpret_cast<int>(g_councilControlTagTable + 6));
    if (tagIndex < 6) {
      reinterpret_cast<void(__stdcall*)(int)>(
          thunk_WrapperFor_InvalidateCityDialogRectRegion_At004f6d90)(tagIndex);
      return;
    }
  } else {
    TControl::HandleEvent(commandId, sourceHandler, event);
  }
}

// Receiver confirmed to be TCouncilView (writes councilNationCount24c8 / field528; resolves
// its own controls via the TView vtable). NOTE: still 24.80% -- the original inlines the
// candidate/coat-of-arms/text-style helpers (and a leading CString ctor) rather than calling
// them out of line as below; a faithful match needs those inlined. TODO: inline helpers.
// FUNCTION: IMPERIALISM 0x004fc2e0
void TCouncilView::InitializeDiplomacyCouncilViewControlsAndTicker() {
  TView* hostPanel = this;
  char* panelState = reinterpret_cast<char*>(this);

  TControlPictureRectState councilTextStyle;
  councilTextStyle.mode = 0;
  councilTextStyle.flag2 = 0;
  councilTextStyle.pointSize = 0;
  councilTextStyle.styleRef6 = 0;
  BuildUiTextStyleDescriptor(&councilTextStyle, 0, 0xe, 0x2b6a);

  *reinterpret_cast<short*>(panelState + 0x24c8) = 0;

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
        panelState[0x52c + flagIndex] = 1;
      }
      ++flagIndex;
    }
    *reinterpret_cast<short*>(panelState + 0x528) = kCouncilTickerIntervalMapMode;

    TControl* endControl = static_cast<TControl*>(hostPanel->ResolveControlByTag(kControlTagEnd));
    if (endControl != nullptr) {
      endControl->AssertValid();
      *reinterpret_cast<unsigned int*>(reinterpret_cast<char*>(endControl) + 0x1c) =
          (localizationMode == 0x17) ? kEndControlTagReselect : kEndControlTagReselectAlt;
    }
    return;
  }

  short maxPendingTier = *reinterpret_cast<short*>(panelState + 0x24c8);
  for (int tierIndex = 0; tierIndex < kDiplomacyPairMatrixEntries; ++tierIndex) {
    const short tierValue = g_pDiplomacyTurnStateManager->pendingPolicyTierMatrix484[tierIndex];
    if (tierValue != -1 && maxPendingTier < tierValue) {
      maxPendingTier = tierValue;
    }
  }
  *reinterpret_cast<short*>(panelState + 0x24c8) = maxPendingTier;
  *reinterpret_cast<short*>(panelState + 0x528) = 0;

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

// slot 0x35 — cursor-hover override: base hit test, then force the pointer cursor while
// hovering the council nation strip.
// FUNCTION: IMPERIALISM 0x004fc950
void TCouncilView::HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* point,
                                                                       RgnHandle hitArg) {
  TView::HandleCursorHoverSelectionByChildHitTestAndFallback(point, hitArg);
  if ((int)field528 < councilNationCount24c8 + 2) {
    SetCursor((HCURSOR)g_pUiRuntimeContext->cursorTable[26]);
  }
}
