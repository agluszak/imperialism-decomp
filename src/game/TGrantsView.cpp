#include "game/TGrantsView.h"

#include "game/TDiplomacyMapView.h"
#include "game/TEventHandler.h"
#include "game/TGreatPower.h"
#include "game/TSimMgr.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x004303d0
// TGrantsView::`scalar deleting destructor'
TGrantsView::~TGrantsView() {}
// SYNTHETIC: IMPERIALISM 0x004f7fd0
// TGrantsView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004f8060
// TGrantsView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TGrantsView, TPanelView)

TGrantsView::TGrantsView() {}

// FUNCTION: IMPERIALISM 0x004f8080
void TGrantsView::NoOpUiLifecycleHook(int arg) {}

// Draws the grants/aid table's 7 category headers (column index 3 is reserved for
// the row-label column, drawn separately below) plus a "Total" row summing this
// nation's active diplomacy grants. Every label/value is drawn twice (theme 0x2b68
// color at +1,+1 then theme 0x2b6b color at +0,+0) -- a drop-shadow idiom shared with
// TDiplomacyMapView's legend labels.
// FUNCTION: IMPERIALISM 0x004f81c0
void TGrantsView::ApplyRectSlot110(RECT* rectBuffer) {
  (void)rectBuffer;
  CString labelText;
  CString sumText;

  short baseX = static_cast<short>(0x48 - ownerLocalX);
  short baseY = static_cast<short>(0x16f - ownerLocalY);

  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xe, 0x2b68);

  int styleShadow = 0;
  int styleForeground = 0;
  MapUiThemeCodeToStyleFlags(0x2b6b, &styleShadow);
  MapUiThemeCodeToStyleFlags(0x2b68, &styleForeground);

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
  g_pSimMgr->FormatIntegerString(grantSum, &sumText);
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
undefined TGrantsView::OrphanRetStub_00430550() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004f8650
void TGrantsView::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xc) {
    short tagOffset = static_cast<short>(sourceHandler->controlTag - 0x6330);
    TDiplomacyMapView* mapView = static_cast<TDiplomacyMapView*>(m_panelData);
    if (tagOffset & 1) {
      mapView->actionCodeBC = 8;
    } else {
      mapView->actionCodeBC = 7;
    }
    mapView = static_cast<TDiplomacyMapView*>(m_panelData);
    mapView->selectedGrantRowC0 = static_cast<short>(tagOffset / 2);
  }
  TEventHandler::HandleEvent(commandId, sourceHandler, event);
}
