#include "game/TTreatiesView.h"

#include "game/TDiplomacyMapView.h"
#include "game/TEventHandler.h"
#include "game/TCluster.h"
#include "game/TSimMgr.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_control_tags.h"
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x00430350
// TTreatiesView::`scalar deleting destructor'
TTreatiesView::~TTreatiesView() {}
// SYNTHETIC: IMPERIALISM 0x004f7a10
// TTreatiesView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004f7aa0
// TTreatiesView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTreatiesView, TPanelView)

TTreatiesView::TTreatiesView() {}

// FUNCTION: IMPERIALISM 0x004f7ac0
void TTreatiesView::DoPostCreate(int arg) {
  TPanelView::DoPostCreate(arg);
  CString text;
  for (int i = 0; i < 7; ++i) {
    TView* control = ResolveControlByTag(kControlTagScr0 + i);
    g_pSimMgr->GetString(0x2733, static_cast<short>(0x37 + i), &text);
    SetControlHoverHelpText(text, control);
  }
  text = CString(g_szEmptyString);
  SetControlHoverHelpText(text, this);
}

// Draws the treaties screen's header label plus 7 horizontally-centered nation
// labels, each in a theme-0x2b68 color at +1,+1 then a theme-0x2b6b color at +0,+0
// (the same drop-shadow idiom as TGrantsView::ApplyRectSlot110 and
// TCouncilPanelView::ApplyRectSlot110).
// FUNCTION: IMPERIALISM 0x004f7c00
void TTreatiesView::ApplyRectSlot110(RECT* rectBuffer) {
  (void)rectBuffer;
  CString labelText;
  // Constructed and destroyed here (EH state tracked) but never touched in the body
  // -- a dead local in the original, kept for the exact EH/codegen shape (same
  // pattern as TDiplomacyMapView::ApplyRectSlot110's unusedScratch).
  CString unusedScratch;

  InitializeUiTextStyleDescriptorAndApplyQuickDraw(0, 0xe, 0x2b68, 1);

  int styleShadow = 0;
  int styleForeground = 0;
  MapUiThemeCodeToStyleFlags(0x2b6b, &styleShadow);
  MapUiThemeCodeToStyleFlags(0x2b68, &styleForeground);

  g_pSimMgr->GetString(0x2733, 0x20, &labelText);
  short headerX = static_cast<short>(0x48 - ownerLocalX);
  short headerY = static_cast<short>(0x16f - ownerLocalY);
  SetQuickDrawColorAndSyncGlobals(styleForeground);
  SetQuickDrawTextOriginWithContextOffset(headerX + 1, headerY + 1);
  DrawTextWithCachedQuickDrawStyleState(&labelText);
  SetQuickDrawColorAndSyncGlobals(styleShadow);
  SetQuickDrawTextOriginWithContextOffset(headerX, headerY);
  DrawTextWithCachedQuickDrawStyleState(&labelText);

  // Smaller point size (0xa vs the header's 0xe) for the per-row nation labels.
  InitializeUiTextStyleDescriptorAndApplyQuickDraw(0, 0xa, 0x2b68, 1);

  static const short kTreatyRowY[7] = {0x1a1, 0x1d4, 0x1a1, 0x1d4, 0x1d4, 0x1d4, 0x1a1};
  static const short kTreatyRowCenterX[7] = {0x83, 0x83, 0x144, 0x113, 0x17e, 0x1eb, 0x1bb};

  for (int i = 0; i < 7; ++i) {
    g_pSimMgr->GetString(0x2733, static_cast<short>(i + 6), &labelText);
    short y = static_cast<short>(kTreatyRowY[i] - ownerLocalY);
    short width = MeasureTextExtentWithCachedQuickDrawStyle(&labelText);
    short x = static_cast<short>(kTreatyRowCenterX[i] - width / 2 - ownerLocalX);
    SetQuickDrawColorAndSyncGlobals(styleForeground);
    SetQuickDrawTextOriginWithContextOffset(x + 1, y + 1);
    DrawTextWithCachedQuickDrawStyleState(&labelText);
    SetQuickDrawColorAndSyncGlobals(styleShadow);
    SetQuickDrawTextOriginWithContextOffset(x, y);
    DrawTextWithCachedQuickDrawStyleState(&labelText);
  }

  SetQuickDrawFillColor(0);
}

// FUNCTION: IMPERIALISM 0x004f7f10
void TTreatiesView::Setup() {
  TCluster* scrollCluster = static_cast<TCluster*>(ResolveControlByTag(0x7363726f)); // 'scro'
  SetControlHoverHelpText(CString(g_pDiplomacyPanelEmptyText_00654ec8), scrollCluster);
  scrollCluster->SetSelectedChildTagAndRefresh(0x73637235); // 'scr5'
  diplomacyMapView60->actionCodeBC = 0xe;
}

// FUNCTION: IMPERIALISM 0x004f7f80
void TTreatiesView::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xc) {
    unsigned int tag = sourceHandler->controlTag;
    TDiplomacyMapView* mapView = diplomacyMapView60;
    if (tag < kControlTagScr0 + 5) {
      mapView->actionCodeBC = (tag - kControlTagScr0) + 2;
    } else {
      mapView->actionCodeBC = (tag - kControlTagScr0) + 9;
    }
  }
  TEventHandler::HandleEvent(commandId, sourceHandler, event);
}
