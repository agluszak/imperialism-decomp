#include "game/ui_widgets/TIndustryCluster.h"
#include "game/ui_core/TNumberText.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_widgets.h"
#include "game/ui_core/TWindow.h"
#include "game/ui_widgets/TRailCluster.h"
#include "game/ui_widgets/TShipyardCluster.h"
#include "game/ui_widgets/TTradeCluster.h"

#include "game/ui_widgets/TAmtBar.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TPicture.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_widgets_globals.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/nation/TGreatPower.h"

#include "decomp_types.h"
#include "game/ui_widgets/TTraderAmtBar.h"
#include "game/ui_core/TViewMgr.h"
#include "game/quickdraw_guards.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/mfc.h"
#include <new>

namespace {

const int kScenarioRecordTags[] = {
    kControlTagRs0Sp, kControlTagRs1Sp, kControlTagRs2Sp, kControlTagRs3Sp, kControlTagRs4Sp,
    kControlTagRs5Sp, kControlTagRs6Sp, kControlTagMa0Sp, kControlTagMa1Sp, kControlTagMa2Sp,
    kControlTagMa3Sp, kControlTagMa4Sp, kControlTagMa5Sp, kControlTagGd0Sp, kControlTagGd1Sp,
    kControlTagGd2Sp, kControlTagGd3Sp,
};

} // namespace

// FUNCTION: IMPERIALISM 0x0058aef0
TTraderAmtBar::TTraderAmtBar() : TAmtBar() {}

// SYNTHETIC: IMPERIALISM 0x0058ae30
// TTraderAmtBar::CreateObject
// SYNTHETIC: IMPERIALISM 0x0058aed0
// TTraderAmtBar::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTraderAmtBar, TAmtBar)

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x0058af30
// TTraderAmtBar::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x0058af80
void TTraderAmtBar::DoPostCreate(int arg) {
  (void)arg;
  TGreatPower* nationState = g_apNationStates[g_pSimMgr->GetActiveNationId()];
  int scenarioTag = this->ownerContext->controlTag;

  short recordIndex = 0;
  while (recordIndex < 0x11) {
    if (kScenarioRecordTags[recordIndex] == scenarioTag) {
      break;
    }
    recordIndex = (short)(recordIndex + 1);
  }

  short merchantCapacity = nationState != 0 ? nationState->merchantCapacity : 0;
  if (merchantCapacity == 0) {
    stepOrCurrentValue = 0;
  } else {
    short currentValue = nationState->GetStockpile(recordIndex);
    stepOrCurrentValue =
        (short)((((int)merchantCapacity - (int)currentValue) * this->frameWidth34) /
                (int)merchantCapacity);
  }

  short gaugeValue = 0;
  if (nationState != 0) {
    gaugeValue = nationState->GetTradeOffersFor(recordIndex);
  }
  if (merchantCapacity == 0) {
    rangeOrMaxValue = 0;
  } else {
    rangeOrMaxValue = (short)((this->frameHeight38 * (int)gaugeValue) / (int)merchantCapacity);
  }

  auxValueA = merchantCapacity;
  auxValueB = 0x37;
  TView::DoPostCreate(arg);
}

// FUNCTION: IMPERIALISM 0x0058b040
void TTraderAmtBar::UpdateFromScaleOrRatio(int scaleValue, int ratioValue) {
  this->frameWidth34 = scaleValue;
  this->frameHeight38 = ratioValue;
}

// FUNCTION: IMPERIALISM 0x0058b070
short TTraderAmtBar::ApplyMoveClamp(int baseValue, short requestedValue) {
  short result = static_cast<short>(baseValue);
  if (requestedValue > 0) {
    // 0x0058b083-0x0058b091 inlines the active-nation lookup; 0x0058b09f divides
    // frameWidth34 (+0x34), not frameHeight38, and the original guards the IDIV with
    // nothing -- there is no merchantCapacity != 0 test in the binary.
    TGreatPower* nationState = g_apNationStates[g_pSimMgr->GetActiveNationId()];
    short merchantCapacity = nationState->merchantCapacity;
    if ((int)requestedValue < (static_cast<int>(this->frameWidth34) / (int)merchantCapacity)) {
      if (this->ownerContext->ResolveControlByTag(kControlTagSell) != 0) {
        result = 1;
      }
    }
  }
  return result;
}

// FUNCTION: IMPERIALISM 0x0058b0f0
void TTraderAmtBar::RenderPrimarySurfaceOverlayPanelWithClipCache() {
  CTemporaryRegion surface;
  TAmtBar* control = this;
  GetClip(surface.tempRgn);

  if (control != 0 && control->IsActionable() != 0) {
    control->PrepareForDrawing();
    if (control->IsActionable() != 0) {
      CRect boundsRect(0, 0, 0, 0);
      control->QueryBounds(&boundsRect);
      control->ApplyBounds(&boundsRect, 1);
      control->QueryBounds(&boundsRect);
      CPoint translatedOrigin(g_nOverlayClipCacheParamX, g_nOverlayClipCacheParamY);
      control->TranslatePointToParentChain4E(&translatedOrigin);

      short styleValueAt60 = rangeOrMaxValue;
      if (styleValueAt60 > 0) {
        short styleValueAt66 = auxValueB;
        SetQuickDrawTextOriginWithContextOffset(0, 0);
        g_pViewMgr->ApplyLegendSplitSlot34(styleValueAt66);
        SetQuickDrawPenSizeAndMarkDirty(1, 5);
        DrawCenteredGuideLineOnMapDc((short)(styleValueAt60 - 1), 0);
        ResetQuickDrawStrokeState();
      }

      SetClip(surface.tempRgn);
      TWindow* owner = control->GetWindow();
      if (owner != 0) {
        owner->ForceRedraw();
      }
    }
  }
}
