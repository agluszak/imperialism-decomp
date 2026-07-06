#include "game/TCouncilView.h"

#include "game/TControl.h"
#include "game/TEvent.h"
#include "game/TEventHandler.h"
#include "game/TViewMgr.h"
#include "game/global_data_tables.h"
#include "game/mfc.h"

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
      // TODO(partial 0x4fbd60): kicks the council ticker/controls rebuild (0x4fc2e0,
      // csv: InitializeDiplomacyCouncilViewControlsAndTicker) — port once that body's
      // receiver attribution is verified.
      return;
    }
  } else if (commandId == 0x14) {
    int tagIndex = 0;
    while (tagIndex < 6 && sourceHandler->controlTag != g_councilControlTagTable[tagIndex]) {
      ++tagIndex;
    }
    if (tagIndex < 6) {
      // TODO(partial 0x4fbd60): invalidates the matched council region
      // (0x4f6d90, csv: WrapperFor_InvalidateCityDialogRectRegion_At004f6d90).
      return;
    }
  } else {
    TControl::HandleEvent(commandId, sourceHandler, event);
  }
}

// slot 0x35 — cursor-hover override: base hit test, then force the pointer cursor while
// hovering the council nation strip.
// FUNCTION: IMPERIALISM 0x004fc950
void TCouncilView::HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* point, int hitArg) {
  TView::HandleCursorHoverSelectionByChildHitTestAndFallback(point, hitArg);
  if ((int)field528 < councilNationCount24c8 + 2) {
    SetCursor((HCURSOR)g_pUiRuntimeContext->cursorTable[26]);
  }
}
