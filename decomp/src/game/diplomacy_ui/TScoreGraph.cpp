#include "game/diplomacy_ui/TScoreGraph.h"
#include "game/ui_tags_common.h"
#include "game/ui_core/TWindow.h"

#include "game/military_ui/TDiplomacyMgr.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_widgets/TInfoBarText.h"
#include "game/ui_core/TViewMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"
// FUNCTION: IMPERIALISM 0x004fe270
TScoreGraph::~TScoreGraph() {}

IMPLEMENT_DYNCREATE(TScoreGraph, TView)

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

// FUNCTION: IMPERIALISM 0x004fe390
void TScoreGraph::Draw(RECT* rectBuffer) {
  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xc, 0x2b67);

  int rowY = 0;
  for (int nationIndex = 0; nationIndex < 7; ++nationIndex) {
    if (g_apTerrainTypeDescriptorTable[nationIndex] == nullptr) {
      continue;
    }

    int total = 0;
    for (int component = 0; component < 4; ++component) {
      total += g_pDiplomacyTurnStateManager->comparativePowerRows[nationIndex][component];
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
      int segValue = g_pDiplomacyTurnStateManager->comparativePowerRows[nationIndex][segComponent];
      segRect.right = static_cast<short>(segValue) + segRect.left;
      segRect.bottom = rowY + 0x24;
      segRect.top = rowY;
      g_pViewMgr->SetForeColor(static_cast<short>(segComponent + 3));
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
