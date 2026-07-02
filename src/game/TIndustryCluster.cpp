#include "game/TIndustryCluster.h"
#include "game/TSimMgr.h"

#include "game/TAmtBar.h"
#include "game/TUberCluster.h"
#include "game/TView.h"
#include "game/TGreatPower.h"
#include "game/TCity.h"
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

static __inline short ReadControlValueFieldPlus4(TAmtBar* control) {
  return *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 4);
}

static __inline void UpdateTradeBarFromSelectedMetricRatio(TIndustryCluster* context,
                                                           int assertLine) {
  TAmtBar* barControl = reinterpret_cast<TAmtBar*>(
      reinterpret_cast<TView*>(context)->ResolveControlByTag(kControlTagBar));
  if (barControl == 0) {
    FailNilPointerInUSmallViews(assertLine);
  }

  TAmtBar* barLayout = reinterpret_cast<TAmtBar*>(barControl);
  if (barLayout->auxValueA != 0) {
    int ratioValue = ((int)context->selectedMetricControl->QueryStepValue() * barLayout->field34) /
                     (int)barLayout->auxValueA;
    barControl->SetBarMetricRatio(ratioValue);
  }
}

// FUNCTION: IMPERIALISM 0x00588a30
TIndustryCluster* __cdecl CreateTradeMoveStepControlPanel(void) {
  return new TIndustryCluster();
}

// SYNTHETIC: IMPERIALISM 0x00588ad0
// TIndustryCluster::GetRuntimeClass

IMPLEMENT_DYNCREATE(TIndustryCluster, TUberCluster)

// FUNCTION: IMPERIALISM 0x00588af0
TIndustryCluster::TIndustryCluster()
    : TUberCluster(), selectedMetricControl(0), selectedMetricValue(0), selectedMetricStep(0) {}

// SYNTHETIC: IMPERIALISM 0x00588b20
// TIndustryCluster::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00588b70
void TIndustryCluster::NoOpUiLifecycleHook(int styleSeed) {
  short tagIndex = 0;
  short activeNationId = g_pLocalizationTable->GetActiveNationId();
  TGreatPower* activeNationState = GetNationStateBySlot(activeNationId);
  TCity* cityState = activeNationState == 0 ? 0 : activeNationState->GetCityState();

  int mappedSummaryTag = GetTradeSummarySelectionTagByIndex(0);
  while (mappedSummaryTag != this->controlTag) {
    tagIndex = (short)(tagIndex + 1);
    mappedSummaryTag = GetTradeSummarySelectionTagByIndex(tagIndex);
  }

  TradeCommodityMetricRecord* selectedMetricRecord = reinterpret_cast<TradeCommodityMetricRecord*>(
      *reinterpret_cast<int*>(reinterpret_cast<char*>(cityState) + (int)tagIndex * 4 + 0xe4));
  this->selectedMetricControl = reinterpret_cast<TAmtBar*>(selectedMetricRecord);
  this->selectedMetricValue =
      static_cast<short>(activeNationState->GetCityState()->GetBuildingProductionValueBySlot(
          *reinterpret_cast<short*>(reinterpret_cast<char*>(selectedMetricRecord) + 0x52)));

  this->InitializeTradeMoveAndBarControls(styleSeed);
  this->NotifyControlSelectionChange(reinterpret_cast<void*>(*reinterpret_cast<short*>(
                                         reinterpret_cast<char*>(selectedMetricRecord) + 4)),
                                     1);
}

// FUNCTION: IMPERIALISM 0x00588c30
void TIndustryCluster::ApplyMoveValue(int value) {
  this->NotifyControlSelectionChange(reinterpret_cast<void*>(value), 0);
}

// FUNCTION: IMPERIALISM 0x00588c60
int TIndustryCluster::NotifyControlSelectionChange(void* dragValuePtr, int updateFlag) {
  int dragValue = (int)dragValuePtr;
  TAmtBar* selectedControl = this->selectedMetricControl;
  short previousValue = ReadControlValueFieldPlus4(selectedControl);
  if (selectedControl != 0) {
    selectedControl->SetControlValue(dragValue);
  }

  if (((char)updateFlag == 0) && (ReadControlValueFieldPlus4(selectedControl) == previousValue)) {
    return 0;
  }

  TAmtBar* moveControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagMove));
  if (moveControl == 0) {
    FailNilPointerInUSmallViews(0xb42);
  }

  moveControl->SetControlValueSlot1E4((int)ReadControlValueFieldPlus4(selectedControl), 0);

  RECT moveBoundsRect;
  RECT moveInvalidRect;
  moveControl->QueryBounds(&moveBoundsRect);
  OffsetRect(&moveBoundsRect, this->ownerOffsetX, this->ownerOffsetY);
  CopyRect(&moveInvalidRect, &moveBoundsRect);
  reinterpret_cast<TView*>(this)->InvalidateCityDialogRectRegion(&moveInvalidRect, 1);

  TAmtBar* barControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagBar));
  if (barControl == 0) {
    FailNilPointerInUSmallViews(0xb49);
  }

  float barScale = 9999.0f;
  if (barControl->field34 != 0) {
    barScale = (float)barControl->field38 / (float)barControl->field34;
  }

  if (ReadControlValueFieldPlus4(selectedControl) == this->selectedMetricValue) {
    barControl->auxValueB = 0x34;
  } else {
    barControl->auxValueB = 0x3a;
  }

  int scaledMetric = (int)((float)selectedControl->QueryValue() * barScale);
  int scaledRange = (int)((float)ReadControlValueFieldPlus4(selectedControl) * barScale);
  barControl->SetBarMetric(scaledMetric, scaledRange);
  this->GetControlFlag(0, 0);
  return 0;
}

// FUNCTION: IMPERIALISM 0x00588f60
int TIndustryCluster::GetControlFlag(int arg1, int arg2) {
  UpdateTradeBarFromSelectedMetricRatio(this, kAssertLineRatioB);
  return 0;
}

// FUNCTION: IMPERIALISM 0x00588ff0
void TIndustryCluster::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 100) {
    TAmtBar* moveControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagMove));
    if (moveControl == 0) {
      GAME_FAIL_NIL_POINTER();
    }
    int moveValue = moveControl->QueryValue();
    this->ApplyMoveValue(moveValue + 1);
    return;
  }
  if (commandId != 0x65) {
    this->HandleTradeMoveControlAdjustment(commandId, sourceHandler, reinterpret_cast<int>(event));
    return;
  }
  TAmtBar* moveControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagMove));
  if (moveControl == 0) {
    GAME_FAIL_NIL_POINTER();
  }
  int moveValue = moveControl->QueryValue();
  this->ApplyMoveValue(moveValue - 1);
}

TIndustryCluster::~TIndustryCluster() {}
