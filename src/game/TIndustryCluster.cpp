#include "game/TIndustryCluster.h"
#include "game/TSimMgr.h"

#include "game/TAmtBar.h"
#include "game/TView.h"
#include "game/TGreatPower.h"
#include "game/TCity.h"
#include "game/TItemOrder.h"
#include "game/TProductionOrder.h"
#include "game/global_data_tables.h"
#include "game/ui_control_tags.h"
#include "game/ui_invalidation_guard.h"
#include "game/UiRuntimeContext.h"
#include "game/mfc.h"
#include "game/quickdraw_guards.h"
#include "game/quickdraw_rendering.h"
#include "game/GameAssert.h"

#include <new>

#include "game/mfc.h"

const int kAssertLineRatioB = 0xb73;

static __inline void UpdateTradeBarFromSelectedMetricRatio(TIndustryCluster* context,
                                                           int assertLine) {
  TAmtBar* barControl = reinterpret_cast<TAmtBar*>(
      reinterpret_cast<TView*>(context)->ResolveControlByTag(kControlTagBar));
  if (barControl == 0) {
    FailNilPointerInUSmallViews(assertLine);
  }

  TAmtBar* barLayout = reinterpret_cast<TAmtBar*>(barControl);
  if (barLayout->auxValueA != 0) {
    int ratioValue = ((int)context->selectedMetricOrder->MaxOrder() * barLayout->frameWidth34) /
                     (int)barLayout->auxValueA;
    barControl->SetBarMetricRatio(ratioValue);
  }
}

// SYNTHETIC: IMPERIALISM 0x00588a30
// TIndustryCluster::CreateObject

// SYNTHETIC: IMPERIALISM 0x00588ad0
// TIndustryCluster::GetRuntimeClass

IMPLEMENT_DYNCREATE(TIndustryCluster, TAmtBarCluster)

// FUNCTION: IMPERIALISM 0x00588af0
TIndustryCluster::TIndustryCluster()
    : TAmtBarCluster(), selectedMetricOrder(0), selectedMetricValue(0), selectedMetricStep(0) {}

// SYNTHETIC: IMPERIALISM 0x00588b20
// TIndustryCluster::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00588b70
void TIndustryCluster::DoPostCreate(int styleSeed) {
  short tagIndex = 0;
  short activeNationId = g_pSimMgr->GetActiveNationId();
  TGreatPower* activeNationState = GetNationStateBySlot(activeNationId);
  TCity* province = activeNationState == 0 ? 0 : activeNationState->GetCityState();

  int mappedSummaryTag = GetTradeSummarySelectionTagByIndex(0);
  while (mappedSummaryTag != this->controlTag) {
    tagIndex = (short)(tagIndex + 1);
    mappedSummaryTag = GetTradeSummarySelectionTagByIndex(tagIndex);
  }

  TProductionOrder* selectedMetricRecord = province->tradeCommodityRecordPtrs[tagIndex];
  this->selectedMetricOrder = selectedMetricRecord;
  // `productionSlot` only exists on TItemOrder-sized (0x54-byte) objects; safe
  // here because tagIndex is bounded to the 23-entry g_pTradeSummarySelectionMap
  // table (0x696108), which never selects the TTrainingOrder slots
  // (0x17/0x18) sharing this band.
  this->selectedMetricValue = static_cast<short>(activeNationState->GetCityState()->GetBuildingType(
      static_cast<TItemOrder*>(selectedMetricRecord)->productionSlot));

  TAmtBarCluster::DoPostCreate(styleSeed);
  this->SetMoveAmount(selectedMetricRecord->quantityField04, 1);
}

// FUNCTION: IMPERIALISM 0x00588c30
void TIndustryCluster::SetMoveAmount(short amount) {
  this->SetMoveAmount(amount, 0);
}

// FUNCTION: IMPERIALISM 0x00588c60
void TIndustryCluster::SetMoveAmount(short dragValue, unsigned char updateControls) {
  TProductionOrder* selectedOrder = this->selectedMetricOrder;
  short previousValue = selectedOrder->quantityField04;
  if (selectedOrder != 0) {
    selectedOrder->SetQuantity(dragValue);
  }

  if ((updateControls == 0) && (selectedOrder->quantityField04 == previousValue)) {
    return;
  }

  TAmtBar* moveControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagMove));
  if (moveControl == 0) {
    FailNilPointerInUSmallViews(0xb42);
  }

  moveControl->SetControlValueSlot1E4((int)selectedOrder->quantityField04, 0);

  CRect moveBoundsRect;
  RECT moveInvalidRect;
  moveControl->QueryBounds(&moveBoundsRect);
  OffsetRect(&moveBoundsRect, this->ownerLocalX, this->ownerLocalY);
  CopyRect(&moveInvalidRect, &moveBoundsRect);
  reinterpret_cast<TView*>(this)->InvalidateCityDialogRectRegion(&moveInvalidRect, 1);

  TAmtBar* barControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagBar));
  if (barControl == 0) {
    FailNilPointerInUSmallViews(0xb49);
  }

  float barScale = 9999.0f;
  if (barControl->frameWidth34 != 0) {
    barScale = (float)barControl->frameHeight38 / (float)barControl->frameWidth34;
  }

  if (selectedOrder->quantityField04 == this->selectedMetricValue) {
    barControl->auxValueB = 0x34;
  } else {
    barControl->auxValueB = 0x3a;
  }

  int scaledMetric = (int)((float)selectedOrder->MaxOrder() * barScale);
  int scaledRange = (int)((float)selectedOrder->quantityField04 * barScale);
  barControl->SetBarMetric(scaledMetric, scaledRange);
  this->UpdateMax();
}

// FUNCTION: IMPERIALISM 0x00588f60
void TIndustryCluster::UpdateMax() {
  UpdateTradeBarFromSelectedMetricRatio(this, kAssertLineRatioB);
}

// FUNCTION: IMPERIALISM 0x00588ff0
void TIndustryCluster::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 100) {
    TAmtBar* moveControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagMove));
    if (moveControl == 0) {
      GAME_FAIL_NIL_POINTER();
    }
    int moveValue = moveControl->QueryValue();
    this->SetMoveAmount(static_cast<short>(moveValue + 1));
    return;
  }
  if (commandId != 0x65) {
    TAmtBarCluster::DoEvent(commandId, sourceHandler, event);
    return;
  }
  TAmtBar* moveControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagMove));
  if (moveControl == 0) {
    GAME_FAIL_NIL_POINTER();
  }
  int moveValue = moveControl->QueryValue();
  this->SetMoveAmount(static_cast<short>(moveValue - 1));
}

TIndustryCluster::~TIndustryCluster() {}
