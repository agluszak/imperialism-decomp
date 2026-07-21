#include "game/TScoreGraph.h"
#include "game/TWindow.h"

#include "game/TDiplomacyMgr.h"
#include "game/TGreatPower.h"
#include "game/TInfoBarText.h"
#include "game/TViewMgr.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_control_tags.h"
#include "game/ui_text_label_helpers_decls.h"
// SYNTHETIC: IMPERIALISM 0x004fe240
// TScoreGraph::`scalar deleting destructor'
TScoreGraph::~TScoreGraph() {}
// SYNTHETIC: IMPERIALISM 0x004fe1d0
// TScoreGraph::CreateObject

// SYNTHETIC: IMPERIALISM 0x004fe290
// TScoreGraph::GetRuntimeClass

IMPLEMENT_DYNCREATE(TScoreGraph, TView)

TScoreGraph::TScoreGraph() {}

// FUNCTION: IMPERIALISM 0x004fe2b0
void TScoreGraph::DoPostCreate(int arg) {
  TView::DoPostCreate(arg);
  g_pDiplomacyTurnStateManager->RecomputeNationComparativePowerMetrics();

  for (int i = 0; i < 7; ++i) {
    TView* tabControl = ownerContext->ResolveControlByTag(kControlTagTab0 + i);
    tabControl->AssertValid();
    LoadUiStringByGroupAndIndexToControlObject(0x2757, static_cast<short>(i + 9), tabControl);
  }

  SetControlHoverHelpText(CString(g_szEmptyString), ownerContext);

  TView* owner = GetWindow();
  g_pCursorControlPanel = static_cast<TInfoBarText*>(owner->ResolveControlByTag(kControlTagCurs));
  g_pCursorControlPanel->AssertValid();
  g_pCursorControlPanel->InitializeMapHintTextStyleAndThemeFlags(0x2b6c, 0x2b67);
}

// For each of the 7 great powers with a live terrain descriptor, draws a stacked
// horizontal bar of its 4 comparativePowerRows1824 components (army, avg relation,
// territory+tech, commodity) in the great power's legend colors (slots 3-6), a black
// border rect behind it, and the nation's name to the right. Row Y for the next nation
// carries over as (this row's total bar width + 0x34) -- ported verbatim from the
// original, including that apparent quirk.
// FUNCTION: IMPERIALISM 0x004fe390
void TScoreGraph::Draw(RECT* rectBuffer) {
  (void)rectBuffer;
  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xc, 0x2b67);

  int rowY = 0;
  for (int nationIndex = 0; nationIndex < 7; ++nationIndex) {
    if (g_apTerrainTypeDescriptorTable[nationIndex] == nullptr) {
      continue;
    }

    int total = 0;
    for (int component = 0; component < 4; ++component) {
      total += g_pDiplomacyTurnStateManager->comparativePowerRows1824[nationIndex][component];
    }

    SetQuickDrawFillColor(0);
    RECT bgRect;
    bgRect.top = rowY + 2;
    bgRect.right = static_cast<short>(total) + 2;
    bgRect.bottom = rowY + 0x26;
    bgRect.left = 2;
    FillRectWithQuickDrawBrushAndContextOffset(&bgRect);

    int segX = 0;
    RECT segRect;
    for (int segComponent = 0; segComponent < 4; ++segComponent) {
      segRect.left = static_cast<short>(segX);
      int segValue =
          g_pDiplomacyTurnStateManager->comparativePowerRows1824[nationIndex][segComponent];
      segRect.right = static_cast<short>(segValue) + segRect.left;
      segRect.bottom = rowY + 0x24;
      segRect.top = rowY;
      g_pUiRuntimeContext->ApplyLegendSplitSlot34(segComponent + 3);
      FillRectWithQuickDrawBrushAndContextOffset(&segRect);
      segX += segValue;
    }

    CString label;
    g_apNationStates[nationIndex]->FormatOverlayTerrainLabelText(&label);
    SetQuickDrawFillColor(0);
    SetQuickDrawTextOriginWithContextOffset(0, static_cast<short>(segX) + 0x30);
    DrawTextWithCachedQuickDrawStyleState(&label);
    rowY = segX + 0x34;
  }
}
