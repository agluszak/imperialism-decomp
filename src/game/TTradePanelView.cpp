#include "game/TTradePanelView.h"

#include "game/CString.h"
#include "game/TCluster.h"
#include "game/TDiplomacyMapView.h"
#include "game/TSimMgr.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x00430450
// TTradePanelView::`scalar deleting destructor'
TTradePanelView::~TTradePanelView() {}
// SYNTHETIC: IMPERIALISM 0x004f86d0
// TTradePanelView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004f8760
// TTradePanelView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTradePanelView, TPanelView)

TTradePanelView::TTradePanelView() {}

// FUNCTION: IMPERIALISM 0x004f8780
void TTradePanelView::DoPostCreate(int arg) {}

// Row-label geometry (6 commodity rows) and column-header geometry (3 headers), read
// from raw stack literals in the original (0x4f8940). The exact per-slot stack layout
// wasn't fully disentangled (Ghidra folds these into several overlapping scalar/array
// locals); the values themselves are read directly from the instruction stream and the
// draw order (foreground offset (+1,+1), then shadow at the base position) is verified
// against every other call site.
namespace {
const short kTradePanelRowY[6] = {0x1b7, 0x184, 0x1b7, 0x184, 0x1b7, 0x184};
const short kTradePanelRowX[6] = {0x52, 0x83, 0xb6, 0xea, 0x11d, 0x14c};
const short kTradePanelColumnY[3] = {0xd5, 0x1b5, 0x212};
const short kTradePanelColumnX[3] = {0x1b7, 0x184, 0x1ce};
} // namespace

// FUNCTION: IMPERIALISM 0x004f8940
void TTradePanelView::Draw(RECT* rectBuffer) {
  CString strA;
  CString strB; // constructed/destroyed only in the original; never otherwise touched.

  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xe, 0x2b68);
  COLORREF shadowStyle;
  COLORREF foregroundStyle;
  ResolveUiThemeColor(0x2b6b, &shadowStyle);
  ResolveUiThemeColor(0x2b68, &foregroundStyle);

  g_pSimMgr->GetString(0x2733, 0x2a, &strA);
  short baseX = static_cast<short>(0x48 - ownerLocalX);
  short baseY = static_cast<short>(0x16f - ownerLocalY);
  SetQuickDrawColorAndSyncGlobals(foregroundStyle);
  SetQuickDrawTextOriginWithContextOffset(baseX + 1, baseY + 1);
  DrawTextWithCachedQuickDrawStyleState(&strA);
  SetQuickDrawColorAndSyncGlobals(shadowStyle);
  SetQuickDrawTextOriginWithContextOffset(baseX, baseY);
  DrawTextWithCachedQuickDrawStyleState(&strA);

  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xc, 0x2b68);

  for (int i = 0; i < 6; ++i) {
    g_pSimMgr->GetString(0x2733, i + 0x2b, &strA);
    short rowX = static_cast<short>(kTradePanelRowX[i] - ownerLocalX);
    short rowY = static_cast<short>(kTradePanelRowY[i] - ownerLocalY);
    SetQuickDrawColorAndSyncGlobals(foregroundStyle);
    SetQuickDrawTextOriginWithContextOffset(rowX + 1, rowY + 1);
    DrawTextWithCachedQuickDrawStyleState(&strA);
    SetQuickDrawColorAndSyncGlobals(shadowStyle);
    SetQuickDrawTextOriginWithContextOffset(rowX, rowY);
    DrawTextWithCachedQuickDrawStyleState(&strA);
  }

  for (int j = 0; j < 3; ++j) {
    g_pSimMgr->GetString(0x2733, j + 0x31, &strA);
    short measuredWidth = MeasureTextExtentWithCachedQuickDrawStyle(&strA);
    short colY = static_cast<short>(kTradePanelColumnY[j] - ownerLocalY);
    short colX = static_cast<short>(kTradePanelColumnX[j] - measuredWidth / 2 - ownerLocalX);
    SetQuickDrawColorAndSyncGlobals(foregroundStyle);
    SetQuickDrawTextOriginWithContextOffset(colX + 1, colY + 1);
    DrawTextWithCachedQuickDrawStyleState(&strA);
    SetQuickDrawColorAndSyncGlobals(shadowStyle);
    SetQuickDrawTextOriginWithContextOffset(colX, colY);
    DrawTextWithCachedQuickDrawStyleState(&strA);
  }

  SetQuickDrawFillColor(0);
}

// FUNCTION: IMPERIALISM 0x004f8d50
void TTradePanelView::Setup() {
  TCluster* tradeCluster = static_cast<TCluster*>(ResolveControlByTag(0x636c7573)); // 'clus'
  SetControlHoverHelpText(CString(g_pDiplomacyPanelEmptyText_00654ec8), tradeCluster);
  tradeCluster->SetSelectedChildTagAndRefresh(0x74726161); // 'traa'
  diplomacyMapView60->selectedGrantRowC0 = 0;
  diplomacyMapView60->actionCodeBC = kDipActionTradeSubsidy;
}

// FUNCTION: IMPERIALISM 0x004f8dd0
void TTradePanelView::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xc) {
    if (sourceHandler->controlTag == 0x6c696e6b) { // 'link'
      diplomacyMapView60->actionCodeBC = kDipActionLinkTradePolicy;
    } else {
      int tradeRow = sourceHandler->controlTag - 0x74726161; // 'traa'
      diplomacyMapView60->selectedGrantRowC0 = static_cast<short>(tradeRow);
      short threshold = g_awDiplomacyTradePolicyIconValueTable[tradeRow];
      if (threshold == 300) {
        diplomacyMapView60->actionCodeBC = kDipActionBoycott;
      } else if (threshold < 0x60) {
        diplomacyMapView60->actionCodeBC = kDipActionTradeSubsidy;
      } else {
        diplomacyMapView60->actionCodeBC = kDipActionTradePolicy;
      }
    }
  }
  TEventHandler::DoEvent(commandId, sourceHandler, event);
}
