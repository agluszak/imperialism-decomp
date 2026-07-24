#include "game/ui_widgets/TIndustryCluster.h"
#include "game/ui_core/TNumberText.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_widgets.h"
#include "game/ui_core/TWindow.h"
#include "game/ui_widgets/TRailCluster.h"
#include "game/ui_widgets/TShipyardCluster.h"
#include "game/ui_widgets/TTradeCluster.h"

#include "game/ui_widgets/TAmtBar.h"
#include "game/ui_core/TPicture.h"
#include "game/globals/prelude.h"
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
  TGreatPower* nationState = GetActiveNationState();
  int scenarioTag = *reinterpret_cast<int*>(reinterpret_cast<char*>(this->ownerContext) + 0x1c);

  short recordIndex = 0;
  while (recordIndex < 0x11) {
    if (kScenarioRecordTags[recordIndex] == scenarioTag) {
      break;
    }
    recordIndex = (short)(recordIndex + 1);
  }

  short tradeCapacity = nationState != 0 ? nationState->tradeCapacity : 0;
  if (tradeCapacity == 0) {
    stepOrCurrentValue = 0;
  } else {
    short currentValue = nationState->GetDiplomacyExternalStateByTarget(recordIndex);
    stepOrCurrentValue = (short)((((int)tradeCapacity - (int)currentValue) * this->frameWidth34) /
                                 (int)tradeCapacity);
  }

  short gaugeValue = 0;
  if (nationState != 0) {
    gaugeValue = nationState->QueryNationMetricBySlot7C(recordIndex);
  }
  if (tradeCapacity == 0) {
    rangeOrMaxValue = 0;
  } else {
    rangeOrMaxValue = (short)((this->frameHeight38 * (int)gaugeValue) / (int)tradeCapacity);
  }

  auxValueA = tradeCapacity;
  auxValueB = 0x37;
  TView::DoPostCreate(arg);
}

// FUNCTION: IMPERIALISM 0x0058b040
void TTraderAmtBar::UpdateFromScaleOrRatio(int scaleValue, int ratioValue) {
  this->frameWidth34 = scaleValue;
  this->frameHeight38 = ratioValue;
}

// FUNCTION: IMPERIALISM 0x0058b070
short TTraderAmtBar::ApplyMoveClamp(int baseValue, int requestedValue) {
  short priorResult = static_cast<short>(baseValue);
  short requested = static_cast<short>(requestedValue);
  short result = priorResult;
  if (requestedValue > 0) {
    TGreatPower* nationState = GetActiveNationState();
    short tradeCapacity = nationState->tradeCapacity;
    if (tradeCapacity != 0) {
      if ((int)requestedValue < (this->frameHeight38 / (int)tradeCapacity)) {
        TNumberText* sellControl =
            static_cast<TNumberText*>(this->ownerContext->ResolveControlByTag(kControlTagSell));
        if (sellControl != 0) {
          result = 1;
        }
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
        g_pUiRuntimeContext->ApplyLegendSplitSlot34(styleValueAt66);
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
