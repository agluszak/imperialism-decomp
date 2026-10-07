#include "game/ui_widgets/TIndustryCluster.h"
#include "game/ui_core/TNumberText.h"
#include "game/ui_tags_common.h"
#include "game/ui_screens/TSimMgr.h"

#include "game/ui_widgets/TIndustryAmtBar.h"
#include "game/city_ui/TBuildingView.h"
#include "game/ui_core/TView.h"
#include "game/nation/TGreatPower.h"
#include "game/city/TCity.h"
#include "game/city/TItemOrder.h"
#include "game/city/TProductionOrder.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/nation_globals.h"
#include "game/globals/ui_widgets_globals.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/ui_core/TViewMgr.h"
#include "game/mfc.h"
#include "game/quickdraw_guards.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/GameAssert.h"

#include <new>

const int kAssertLineRatioB = 0xb73;

IMPLEMENT_DYNCREATE(TIndustryCluster, TAmtBarCluster)

// FUNCTION: IMPERIALISM 0x00588af0
TIndustryCluster::TIndustryCluster()
    : TAmtBarCluster(), selectedMetricOrder(0), selectedMetricValue(0), selectedMetricStep(0) {}

// FUNCTION: IMPERIALISM 0x00588b50
TIndustryCluster::~TIndustryCluster() {}

// FUNCTION: IMPERIALISM 0x00588b70
void TIndustryCluster::DoPostCreate(int styleSeed) {
  short tagIndex = 0;
  short activeNationId = g_pSimMgr->GetPlayerCountry();
  TGreatPower* activeNationState = g_apNationStates[activeNationId];
  TCity* province = activeNationState == 0 ? 0 : activeNationState->GetCityState();

  int mappedSummaryTag = g_pTradeSummarySelectionMap[0];
  while (mappedSummaryTag != this->controlTag) {
    tagIndex = (short)(tagIndex + 1);
    mappedSummaryTag = g_pTradeSummarySelectionMap[tagIndex];
  }

  TProductionOrder* selectedMetricRecord = province->orderSlots[tagIndex];
  this->selectedMetricOrder = selectedMetricRecord;
  this->selectedMetricValue = static_cast<short>(activeNationState->GetCityState()->GetBuildingType(
      static_cast<TItemOrder*>(selectedMetricRecord)->productionSlot));

  TAmtBarCluster::DoPostCreate(styleSeed);
  this->SetMoveAmount(selectedMetricRecord->quantity, true);
}

// FUNCTION: IMPERIALISM 0x00588c30
void TIndustryCluster::SetMoveAmount(short amount) {
  this->SetMoveAmount(amount, false);
}

// FUNCTION: IMPERIALISM 0x00588c60
void TIndustryCluster::SetMoveAmount(short dragValue, bool updateControls) {
  TProductionOrder* selectedOrder = this->selectedMetricOrder;
  short previousValue = selectedOrder->quantity;
  if (selectedOrder != 0) {
    selectedOrder->SetQuantity(dragValue);
  }

  if ((!updateControls) && (selectedOrder->quantity == previousValue)) {
    return;
  }

  TNumberText* moveControl = static_cast<TNumberText*>(this->ResolveControlByTag(kControlTagMove));
  if (moveControl == 0) {
    FailNilPointerInUSmallViews(0xb42);
  }

  moveControl->SetControlValue((int)selectedOrder->quantity, 0);

  CRect moveBoundsRect;
  RECT moveInvalidRect;
  moveControl->QueryBounds(&moveBoundsRect);
  OffsetRect(&moveBoundsRect, this->ownerLocalX, this->ownerLocalY);
  CopyRect(&moveInvalidRect, &moveBoundsRect);
  this->ownerContext->InvalidateCityDialogRectRegion(&moveInvalidRect, 1);

  TAmtBar* barControl = static_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagBar));
  if (barControl == 0) {
    FailNilPointerInUSmallViews(0xb49);
  }

  float barScale = 9999.0f;
  if (barControl->auxValueA != 0) {
    barScale =
        static_cast<float>(barControl->frameWidth) / static_cast<float>(barControl->auxValueA);
  }

  if (selectedOrder->quantity == this->selectedMetricValue) {
    barControl->auxValueB = 0x34;
  } else {
    barControl->auxValueB = 0x3a;
  }

  int scaledMoveAmount = static_cast<int>(static_cast<float>(selectedOrder->quantity) * barScale);
  int scaledMaximum = static_cast<int>(static_cast<float>(selectedOrder->MaxOrder()) * barScale);
  barControl->SetAmt(static_cast<short>(scaledMoveAmount), static_cast<short>(scaledMaximum));

  CPoint moveControlPosition;
  moveControlPosition.x = barControl->ownerLocalX + static_cast<short>(scaledMoveAmount) - 2;
  moveControlPosition.y = barControl->ownerLocalY + barControl->frameHeight;
  moveControl->Locate(moveControlPosition, true);
  moveControl->QueryBounds(&moveBoundsRect);
  OffsetRect(&moveBoundsRect, this->ownerLocalX, this->ownerLocalY);
  CopyRect(&moveInvalidRect, &moveBoundsRect);
  this->ownerContext->InvalidateCityDialogRectRegion(&moveInvalidRect, 1);

  static_cast<TBuildingView*>(this->ownerContext)->UpdateFields();
}

// FUNCTION: IMPERIALISM 0x00588f60
void TIndustryCluster::UpdateMax() {
  TIndustryAmtBar* barControl = static_cast<TIndustryAmtBar*>(ResolveControlByTag(kControlTagBar));
  if (barControl == 0) {
    FailNilPointerWithAssert(s_SourcePathUSmallViews, kAssertLineRatioB);
  }

  if (barControl->auxValueA != 0) {
    barControl->DrawMax(static_cast<short>(
        (selectedMetricOrder->MaxOrder() * barControl->frameWidth) / barControl->auxValueA));
  }
}

// FUNCTION: IMPERIALISM 0x00588ff0
void TIndustryCluster::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 100) {
    TNumberText* moveControl =
        static_cast<TNumberText*>(this->ResolveControlByTag(kControlTagMove));
    if (moveControl == 0) {
      GAME_FAIL_NIL_POINTER();
    }
    int moveValue = moveControl->UpdateControlCachedIntFromWindowText();
    this->SetMoveAmount(static_cast<short>(moveValue + 1));
    return;
  }
  if (commandId != 0x65) {
    TAmtBarCluster::DoEvent(commandId, sourceHandler, event);
    return;
  }
  TNumberText* moveControl = static_cast<TNumberText*>(this->ResolveControlByTag(kControlTagMove));
  if (moveControl == 0) {
    GAME_FAIL_NIL_POINTER();
  }
  int moveValue = moveControl->UpdateControlCachedIntFromWindowText();
  this->SetMoveAmount(static_cast<short>(moveValue - 1));
}
