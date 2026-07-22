#include "game/TAmtBar.h"
#include "game/TSimMgr.h"
#include "game/TIndustryCluster.h"
#include "game/TShipyardCluster.h"
#include "game/TTradeCluster.h"
#include "game/global_data_tables.h"
#include "game/ui_invalidation_guard.h"
#include "game/TCity.h"
#include "game/TGreatPower.h"
#include "game/TProductionOrder.h"
#include "game/mfc.h"
#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_control_tags.h"
#include <new>

#include "game/TRailCluster.h"
#include "game/TView.h"

#include "game/mfc.h"

const int kAssertLineRatioA = 0xd1d;

static __inline void UpdateTradeBarFromSelectedMetricRatio(TRailCluster* context, int assertLine) {
  void* owner = context;
  TAmtBar* barControl = reinterpret_cast<TAmtBar*>(
      reinterpret_cast<TView*>(owner)->ResolveControlByTag(kControlTagBar));
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

// SYNTHETIC: IMPERIALISM 0x00589660
// TRailCluster::CreateObject

// SYNTHETIC: IMPERIALISM 0x00589700
// TRailCluster::GetRuntimeClass

IMPLEMENT_DYNCREATE(TRailCluster, TAmtBarCluster)

// FUNCTION: IMPERIALISM 0x00589720
TRailCluster::TRailCluster() : TAmtBarCluster() {
  this->selectedMetricOrder = 0;
  this->selectedMetricStep = 0;
}

// SYNTHETIC: IMPERIALISM 0x00589760
// TRailCluster::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x005897b0
void TRailCluster::DoPostCreate(int styleSeed) {
  short recordIndex = static_cast<short>(styleSeed);
  short activeNationId = g_pSimMgr->GetActiveNationId();
  TGreatPower* activeNationState = GetNationStateBySlot(activeNationId);
  TCity* city = activeNationState == 0 ? 0 : activeNationState->GetCityState();

  unsigned int summaryTag = (unsigned int)this->controlTag;
  TPopulationMgr* population = city->productionSummary1d8;
  if (summaryTag < 0x706f7076) {
    if (summaryTag == kSummaryTagPopu) {
      recordIndex = 0x3c;
      this->selectedMetricStep = 1;
      this->selectedMetricValue = static_cast<short>(city->GetBuildingType(0x0f));
      goto LABEL_12;
    }
    if (summaryTag == kSummaryTagFood) {
      TLaborPool* labor = population->productionSlots14;
      recordIndex = 7;
      this->selectedMetricStep = 2;
      this->selectedMetricValue =
          static_cast<short>(((labor->highSkillCount08 * 2 + labor->mediumSkillCount06) * 2 +
                              population->extraAt1e + labor->lowSkillCount04) /
                             2);
      goto LABEL_12;
    }
  } else if (summaryTag < 0x70726f67) {
    if (summaryTag == kSummaryTagProf) {
      recordIndex = 0x18;
      this->selectedMetricStep = 1;
      this->selectedMetricValue = population->baselineSlots10->mediumSkillCount06;
      goto LABEL_12;
    }
    if (summaryTag == kSummaryTagPowe) {
      recordIndex = 0x34;
      this->selectedMetricStep = 6;
      this->selectedMetricValue = 999;
      goto LABEL_12;
    }
  } else {
    if (summaryTag == kSummaryTagRail) {
      TLaborPool* labor = population->productionSlots14;
      recordIndex = 0x33;
      this->selectedMetricStep = 1;
      this->selectedMetricValue =
          static_cast<short>(((labor->highSkillCount08 * 2 + labor->mediumSkillCount06) * 2 +
                              labor->lowSkillCount04 + population->extraAt1e) /
                             2);
      goto LABEL_12;
    }
    if (summaryTag == kSummaryTagIart) {
      recordIndex = 0x17;
      this->selectedMetricStep = 1;
      this->selectedMetricValue = population->baselineSlots10->lowSkillCount04;
      goto LABEL_12;
    }
  }
LABEL_12:
  this->selectedMetricOrder = city->orderSlotsE4[recordIndex];
  TAmtBarCluster::DoPostCreate(styleSeed);
  this->SetMoveAmount(this->selectedMetricOrder->quantityField04, 1);
}

// FUNCTION: IMPERIALISM 0x005899c0
void TRailCluster::SetMoveAmount(short amount) {
  this->SetMoveAmount(amount, 0);
}

// FUNCTION: IMPERIALISM 0x005899f0
void TRailCluster::SetMoveAmount(short dragValue, unsigned char updateFlag) {
  short step = this->selectedMetricStep;
  int quantizedDragValue = ((((int)step / 2) + (int)(short)dragValue) / (int)step) * (int)step;
  TProductionOrder* selectedOrder = this->selectedMetricOrder;
  short previousValue = selectedOrder->quantityField04;
  if (selectedOrder != 0) {
    selectedOrder->SetQuantity(static_cast<short>(quantizedDragValue));
  }

  if (((char)updateFlag == 0) && (selectedOrder->quantityField04 == previousValue)) {
    return;
  }

  TAmtBar* moveControl = reinterpret_cast<TAmtBar*>(
      reinterpret_cast<TView*>(this)->ResolveControlByTag(kControlTagMove));
  if (moveControl == 0) {
    FailNilPointerInUSmallViews(0xcf2);
  }

  moveControl->SetControlValueSlot1E4((int)selectedOrder->quantityField04, 0);

  CRect moveBoundsRect;
  RECT moveInvalidRect;
  moveControl->QueryBounds(&moveBoundsRect);
  OffsetRect(&moveBoundsRect, this->ownerLocalX, this->ownerLocalY);
  CopyRect(&moveInvalidRect, &moveBoundsRect);
  reinterpret_cast<TView*>(this)->InvalidateCityDialogRectRegion(&moveInvalidRect, 1);

  TAmtBar* barControl = reinterpret_cast<TAmtBar*>(
      reinterpret_cast<TView*>(this)->ResolveControlByTag(kControlTagBar));
  if (barControl == 0) {
    FailNilPointerInUSmallViews(0xcf9);
  }

  TAmtBar* barLayout = reinterpret_cast<TAmtBar*>(barControl);
  TAmtBar* barAmount = reinterpret_cast<TAmtBar*>(barControl);
  float barScale = 9999.0f;
  if (barLayout->auxValueA != 0) {
    barScale = (float)barLayout->frameWidth34 / (float)barLayout->auxValueA;
  }

  if (selectedOrder->quantityField04 == selectedMetricValue) {
    barAmount->auxValueB = 0x34;
  } else {
    barAmount->auxValueB = 0x3a;
  }

  int scaledMetric = (int)((float)selectedOrder->MaxOrder() * barScale);
  int scaledRange = (int)((float)selectedOrder->quantityField04 * barScale);
  barControl->SetBarMetric(scaledMetric, scaledRange);
  this->UpdateMax();
}

// FUNCTION: IMPERIALISM 0x00589d10
void TRailCluster::UpdateMax() {
  UpdateTradeBarFromSelectedMetricRatio(this, kAssertLineRatioA);
}

// FUNCTION: IMPERIALISM 0x00589da0
void TRailCluster::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 100) {
    TAmtBar* moveControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagMove));
    if (moveControl == 0) {
      FailNilPointerInUSmallViews(0xcf2);
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
    FailNilPointerInUSmallViews(0xcf2);
  }
  int moveValue = moveControl->QueryValue();
  this->SetMoveAmount(static_cast<short>(moveValue - 1));
}

TRailCluster::~TRailCluster() {}
