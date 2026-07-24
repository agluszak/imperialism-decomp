#include "game/diplomacy_ui/TGrantsView.h"
#include "game/ui_tags_diplomacy.h"

#include "game/diplomacy_ui/TDiplomacyMapView.h"
#include "game/ui_core/TEventHandler.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_core/TCluster.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/globals/prelude.h"
#include "game/globals/diplomacy_ui_globals.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

// FUNCTION: IMPERIALISM 0x004303a0
TGrantsView::TGrantsView() {
  diplomacyMapView60 = 0;
}

// SYNTHETIC: IMPERIALISM 0x004303d0
// TGrantsView::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00430400
TGrantsView::~TGrantsView() {}
// SYNTHETIC: IMPERIALISM 0x004f7fd0
// TGrantsView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004f8060
// TGrantsView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TGrantsView, TPanelView)

// FUNCTION: IMPERIALISM 0x004f8080
void TGrantsView::DoPostCreate(int arg) {
  CString hoverText;
  TView::DoPostCreate(arg);
  diplomacyMapView60 = static_cast<TDiplomacyMapView*>(ownerContext);

  for (int grantSlot = 0; grantSlot < 8; ++grantSlot) {
    TView* grantControl = ResolveControlByTag(kControlTagDoc0 + grantSlot); // 'doc0'..
    g_pSimMgr->GetString(0x2733, static_cast<short>(grantSlot + 0x3e), &hoverText);
    SetControlHoverHelpText(hoverText, grantControl);
  }
  hoverText = g_szEmptyString;
  SetControlHoverHelpText(hoverText, this);
}

// Draws the grants/aid table's 7 category headers (column index 3 is reserved for
// the row-label column, drawn separately below) plus a "Total" row summing this
// nation's active diplomacy grants. Every label/value is drawn twice (theme 0x2b68
// color at +1,+1 then theme 0x2b6b color at +0,+0) -- a drop-shadow idiom shared with
// TDiplomacyMapView's legend labels.
// FUNCTION: IMPERIALISM 0x004f81c0
void TGrantsView::Draw(RECT* rectBuffer) {
  (void)rectBuffer;
  CString labelText;
  CString sumText;

  short baseX = static_cast<short>(0x48 - ownerLocalX);
  short baseY = static_cast<short>(0x16f - ownerLocalY);

  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xe, 0x2b68);

  COLORREF styleShadow = 0;
  COLORREF styleForeground = 0;
  ResolveUiThemeColor(0x2b6b, &styleShadow);
  ResolveUiThemeColor(0x2b68, &styleForeground);

  g_pSimMgr->GetString(0x2733, 0x21, &labelText);
  SetQuickDrawColorAndSyncGlobals(styleForeground);
  SetQuickDrawTextOriginWithContextOffset(baseX + 1, baseY + 1);
  DrawTextWithCachedQuickDrawStyleState(&labelText);
  SetQuickDrawColorAndSyncGlobals(styleShadow);
  SetQuickDrawTextOriginWithContextOffset(baseX, baseY);
  DrawTextWithCachedQuickDrawStyleState(&labelText);

  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xc, 0x2b68);

  // Y (row) and X (column) position tables for the 8 category slots; slot 3 (the
  // row-label column, x=0x48/y=0x16f -- same as baseX/baseY above) is skipped in the
  // loop below and reused for the "Total" row's y position instead.
  static const short kGrantColumnY[8] = {0x16f, 0x180, 0x180, 0x187, 0x1d5, 0x1d5, 0x1d5, 0x1d5};
  static const short kGrantColumnX[8] = {0xe7, 0x14d, 0x1f1, 0x48, 0x5e, 0xe8, 0x173, 0x1f7};

  for (int i = 0; i < 8; ++i) {
    if (i == 3) {
      continue;
    }
    g_pSimMgr->GetString(0x2733, static_cast<short>(0x22 + i), &labelText);
    short y = static_cast<short>(kGrantColumnY[i] - ownerLocalY);
    short x = static_cast<short>(kGrantColumnX[i] - ownerLocalX);
    SetQuickDrawColorAndSyncGlobals(styleForeground);
    SetQuickDrawTextOriginWithContextOffset(x + 1, y + 1);
    DrawTextWithCachedQuickDrawStyleState(&labelText);
    SetQuickDrawColorAndSyncGlobals(styleShadow);
    SetQuickDrawTextOriginWithContextOffset(x, y);
    DrawTextWithCachedQuickDrawStyleState(&labelText);
  }

  g_pSimMgr->GetString(0x2733, 0x25, &labelText);
  TGreatPower* activeNation = g_apNationStates[g_pSimMgr->GetActiveNationId()];
  int grantSum = activeNation->SumDiplomacyGrantEntriesMaskedToValueBits();
  g_pSimMgr->NumToCurrency(grantSum, &sumText);
  labelText += s_szSpaceSeparator_00695794 + sumText;

  short totalY = static_cast<short>(kGrantColumnY[3] - ownerLocalY);
  SetQuickDrawColorAndSyncGlobals(styleForeground);
  SetQuickDrawTextOriginWithContextOffset(baseX + 1, totalY + 1);
  DrawTextWithCachedQuickDrawStyleState(&labelText);
  SetQuickDrawColorAndSyncGlobals(styleShadow);
  SetQuickDrawTextOriginWithContextOffset(baseX, totalY);
  DrawTextWithCachedQuickDrawStyleState(&labelText);

  SetQuickDrawFillColor(0);
}

// FUNCTION: IMPERIALISM 0x004f85d0
void TGrantsView::Setup() {
  TCluster* documentCluster =
      static_cast<TCluster*>(ResolveControlByTag(kControlTagDocs)); // 'docs'
  SetControlHoverHelpText(CString(g_pDiplomacyPanelEmptyText_00654ec8), documentCluster);
  documentCluster->SetSelectedChildTagAndRefresh(kControlTagDoc0); // 'doc0'
  diplomacyMapView60->selectedGrantRowC0 = 0;
  diplomacyMapView60->actionCodeBC = kDipActionOneTimeGrant;
}

// FUNCTION: IMPERIALISM 0x004f8650
void TGrantsView::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xc) {
    short tagOffset = static_cast<short>(sourceHandler->controlTag - 0x6330);
    TDiplomacyMapView* mapView = diplomacyMapView60;
    if (tagOffset & 1) {
      mapView->actionCodeBC = kDipActionRecurringGrant;
    } else {
      mapView->actionCodeBC = kDipActionOneTimeGrant;
    }
    mapView = diplomacyMapView60;
    mapView->selectedGrantRowC0 = static_cast<short>(tagOffset / 2);
  }
  TEventHandler::DoEvent(commandId, sourceHandler, event);
}
