#include "game/ui_widgets/TTradeScreenPicture.h"

#include "game/gfx/TDisplayMgr.h"
#include "game/nation/TGreatPower.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/ui_widgets/TTradeMgr.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_widgets_globals.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x005ba680
// TTradeScreenPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x005ba700
// TTradeScreenPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTradeScreenPicture, TPicture)

// FUNCTION: IMPERIALISM 0x005ba720
TTradeScreenPicture::TTradeScreenPicture() {}

// SYNTHETIC: IMPERIALISM 0x005ba750
// TTradeScreenPicture::`scalar deleting destructor'
TTradeScreenPicture::~TTradeScreenPicture() {}

// Repaints the trade-screen commodity summary block. In map-blit mode (kTurnEventTradeOverview/kTurnEventIndustryOverview) it just
// blits the passed rect; otherwise it draws, for each of the 17 commodity rows, the current
// diplomacy value (right cell) and the proposal weight (middle cell) via the cached
// QuickDraw text state.
// FUNCTION: IMPERIALISM 0x005ba7a0
void TTradeScreenPicture::Draw(RECT* rectBuffer) {
  RECT localRect;
  localRect.left = rectBuffer->left;
  localRect.top = rectBuffer->top;
  localRect.right = rectBuffer->right;
  localRect.bottom = rectBuffer->bottom;

  short screenMode = g_pDisplayMgr->clipSnapshotEvent;
  if (screenMode == kTurnEventTradeOverview || screenMode == kTurnEventIndustryOverview) {
    BlitRectWithOptionalTransparency(&g_pPrimaryRenderSurfaceContext->blitSurface,
                                     &g_pActiveQuickDrawSurfaceContext->blitSurface, &localRect,
                                     &localRect, 0, 0);
    return;
  }

  TPicture::Draw(rectBuffer);
  InitializeUiTextStyleDescriptorAndApplyQuickDraw(0, 0xe, 0x2b68, 2);

  int i = 0;
  const unsigned int* tagPtr = g_tradeCommodityRowTagTable;
  do {
    CString cellText;
    TView* ctrl = this->ResolveControlByTag(*tagPtr);
    if (ctrl == nullptr) {
      MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
      TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUTradeViews_0069AA94, 0xbf);
    }

    // Entries 6 (" 6sr") and 12 (" 5am") are group terminators, skipped unless a production
    // order is active.
    if ((tagPtr != &g_tradeCommodityRowTagTable[6] && tagPtr != &g_tradeCommodityRowTagTable[12]) ||
        g_pCityOrderCapabilityState->perTechUnlockFlag180[TTechMgr::kProductionOrderTechId] != 0) {
      RECT cellRect;

      // Right cell: the active nation's diplomacy value for this commodity.
      cellRect.top = ctrl->ownerLocalY + 3;
      cellRect.bottom = cellRect.top + 0xe;
      cellRect.left = ctrl->ownerLocalX + 0x11a;
      cellRect.right = cellRect.left + 0x12;
      short diploValue =
          g_apNationStates[g_pSimMgr->GetActiveNationId()]->GetDiplomacyExternalStateByTarget(
              static_cast<short>(i));
      if (diploValue == 0) {
        cellText = CString("--");
      } else {
        cellText.Format(
            g_szDecimalFormat,
            static_cast<int>(
                g_apNationStates[g_pSimMgr->GetActiveNationId()]->GetDiplomacyExternalStateByTarget(
                    static_cast<short>(i))));
      }
      cellRect.top -= 5;
      cellRect.bottom -= 5;
      RenderTradeScreenCommoditySummaryRows_Impl(&cellText, &cellRect, -1, 0);

      // Middle cell: the proposal weight for this commodity, formatted as an integer.
      cellRect.top = ctrl->ownerLocalY + 3;
      cellRect.bottom = cellRect.top + 0xe;
      cellRect.left = ctrl->ownerLocalX + 0xc8;
      cellRect.right = cellRect.left + 0x26;
      short weight =
          g_pNationInteractionStateManager->QueryProposalWeightSlot4C(static_cast<short>(i));
      g_pSimMgr->NumToCurrency(weight, &cellText);
      cellRect.top -= 5;
      cellRect.bottom -= 5;
      RenderTradeScreenCommoditySummaryRows_Impl(&cellText, &cellRect, -1, 0);
    }
    ++i;
    ++tagPtr;
  } while (tagPtr < &g_tradeCommodityRowTagTable[17]);
}
