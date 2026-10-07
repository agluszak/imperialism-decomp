#include "game/ui_widgets/TAmtBar.h"
#include "game/ui_core/TNumberText.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_widgets.h"
#include "game/city_ui/TBuildingView.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_widgets/TIndustryCluster.h"
#include "game/ui_widgets/TRailAmtBar.h"
#include "game/ui_widgets/TShipyardCluster.h"
#include "game/ui_widgets/TTradeCluster.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/nation_globals.h"
#include "game/globals/ui_widgets_globals.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/city/TCity.h"
#include "game/nation/TGreatPower.h"
#include "game/city/TProductionOrder.h"
#include "game/mfc.h"
#include "game/ui_core/TViewMgr.h"
#include "game/quickdraw_guards.h"
#include "game/ui_core/quickdraw_rendering.h"
#include <new>

#include "game/ui_widgets/TRailCluster.h"
#include "game/ui_core/TView.h"

const int kAssertLineRatioA = 0xd1d;

IMPLEMENT_DYNCREATE(TRailCluster, TAmtBarCluster)

// FUNCTION: IMPERIALISM 0x00589720
TRailCluster::TRailCluster() : TAmtBarCluster() {
  this->selectedMetricOrder = 0;
  this->selectedMetricStep = 0;
}

// FUNCTION: IMPERIALISM 0x00589790
TRailCluster::~TRailCluster() {}

// FUNCTION: IMPERIALISM 0x005897b0
void TRailCluster::DoPostCreate(int styleSeed) {
  short recordIndex = styleSeed;
  short activeNationId = g_pSimMgr->GetPlayerCountry();
  TGreatPower* activeNationState = g_apNationStates[activeNationId];
  TCity* city = activeNationState == 0 ? 0 : activeNationState->GetCityState();

  unsigned int summaryTag = controlTag;
  TPopulationMgr* population = city->productionSummary;
  if (summaryTag < kControlTagPopv) {
    if (summaryTag == kSummaryTagPopu) {
      recordIndex = 0x3c;
      selectedMetricStep = 1;
      selectedMetricValue = static_cast<short>(city->GetBuildingType(0x0f));
    } else if (summaryTag == kSummaryTagFood) {
      TLaborPool* labor = population->productionSlots;
      recordIndex = 7;
      selectedMetricStep = 2;
      selectedMetricValue =
          static_cast<short>(((labor->highSkillCount * 2 + labor->mediumSkillCount) * 2 +
                              population->powerPlantOutput + labor->lowSkillCount) /
                             2);
    }
  } else if (summaryTag < kControlTagProg) {
    if (summaryTag == kSummaryTagProf) {
      recordIndex = 0x18;
      selectedMetricStep = 1;
      selectedMetricValue = population->baselineSlots->mediumSkillCount;
    } else if (summaryTag == kSummaryTagPowe) {
      recordIndex = 0x34;
      selectedMetricStep = 6;
      selectedMetricValue = 999;
    }
  } else if (summaryTag == kSummaryTagRail) {
    TLaborPool* labor = population->productionSlots;
    recordIndex = 0x33;
    selectedMetricStep = 1;
    selectedMetricValue =
        static_cast<short>(((labor->highSkillCount * 2 + labor->mediumSkillCount) * 2 +
                            labor->lowSkillCount + population->powerPlantOutput) /
                           2);
  } else if (summaryTag == kSummaryTagTrai) {
    recordIndex = 0x17;
    selectedMetricStep = 1;
    selectedMetricValue = population->baselineSlots->lowSkillCount;
  }

  selectedMetricOrder = city->orderSlots[recordIndex];
  TAmtBarCluster::DoPostCreate(styleSeed);
  SetMoveAmount(selectedMetricOrder->quantity, true);
}

// FUNCTION: IMPERIALISM 0x005899c0
void TRailCluster::SetMoveAmount(short amount) {
  SetMoveAmount(amount, false);
}

// FUNCTION: IMPERIALISM 0x005899f0
void TRailCluster::SetMoveAmount(short dragValue, bool updateFlag) {
  short step = selectedMetricStep;
  short quantizedDragValue = ((step / 2 + dragValue) / step) * step;
  TProductionOrder* selectedOrder = selectedMetricOrder;
  short previousValue = selectedOrder->quantity;
  if (selectedOrder != 0) {
    selectedOrder->SetQuantity(quantizedDragValue);
  }

  if ((static_cast<char>(updateFlag) == 0) && (selectedOrder->quantity == previousValue)) {
    return;
  }

  TNumberText* moveControl = static_cast<TNumberText*>(FindSubView(kControlTagMove));
  if (moveControl == 0) {
    FailNilPointerInUSmallViews(0xcf2);
  }

  moveControl->SetControlValue(static_cast<int>(selectedOrder->quantity), 0);

  CRect moveBoundsRect;
  RECT moveInvalidRect;
  moveControl->GetFrame(&moveBoundsRect);
  OffsetRect(&moveBoundsRect, ownerLocalX, ownerLocalY);
  CopyRect(&moveInvalidRect, &moveBoundsRect);
  ownerContext->InvalidateCityDialogRectRegion(&moveInvalidRect, 1);

  TAmtBar* barControl = static_cast<TAmtBar*>(FindSubView(kControlTagBar));
  if (barControl == 0) {
    FailNilPointerInUSmallViews(0xcf9);
  }

  float barScale = 9999.0f;
  if (barControl->auxValueA != 0) {
    barScale =
        static_cast<float>(barControl->frameWidth) / static_cast<float>(barControl->auxValueA);
  }

  if (selectedOrder->quantity == selectedMetricValue) {
    barControl->auxValueB = 0x34;
  } else {
    barControl->auxValueB = 0x3a;
  }

  short scaledMoveAmount = static_cast<int>(static_cast<float>(selectedOrder->quantity) * barScale);
  short scaledMaximum = static_cast<int>(static_cast<float>(selectedOrder->MaxOrder()) * barScale);
  barControl->SetAmt(scaledMoveAmount, scaledMaximum);

  CPoint moveControlPosition;
  moveControlPosition.x = barControl->ownerLocalX + scaledMoveAmount - 2;
  moveControlPosition.y = barControl->ownerLocalY + barControl->frameHeight;
  moveControl->Locate(moveControlPosition, true);
  moveControl->GetFrame(&moveBoundsRect);
  OffsetRect(&moveBoundsRect, ownerLocalX, ownerLocalY);
  CopyRect(&moveInvalidRect, &moveBoundsRect);
  ownerContext->InvalidateCityDialogRectRegion(&moveInvalidRect, 1);

  static_cast<TBuildingView*>(ownerContext)->UpdateFields();
}

// FUNCTION: IMPERIALISM 0x00589d10
void TRailCluster::UpdateMax() {
  TRailAmtBar* barControl = static_cast<TRailAmtBar*>(FindSubView(kControlTagBar));
  if (barControl == 0) {
    FailNilPointerWithAssert(s_SourcePathUSmallViews, kAssertLineRatioA);
  }

  if (barControl->auxValueA != 0) {
    barControl->DrawMax((selectedMetricOrder->MaxOrder() * barControl->frameWidth) /
                        barControl->auxValueA);
  }
}

// FUNCTION: IMPERIALISM 0x00589da0
void TRailCluster::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 100) {
    TNumberText* moveControl = static_cast<TNumberText*>(FindSubView(kControlTagMove));
    if (moveControl == 0) {
      FailNilPointerInUSmallViews(0xcf2);
    }
    int moveValue = moveControl->UpdateControlCachedIntFromWindowText();
    SetMoveAmount(static_cast<short>(moveValue + 1));
    return;
  }
  if (commandId != 0x65) {
    TAmtBarCluster::DoEvent(commandId, sourceHandler, event);
    return;
  }
  TNumberText* moveControl = static_cast<TNumberText*>(FindSubView(kControlTagMove));
  if (moveControl == 0) {
    FailNilPointerInUSmallViews(0xcf2);
  }
  int moveValue = moveControl->UpdateControlCachedIntFromWindowText();
  SetMoveAmount(static_cast<short>(moveValue - 1));
}
