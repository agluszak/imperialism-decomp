#include "game/TIndustryCluster.h"

#include "game/TAmtBar.h"
#include "game/TUberCluster.h"
#include "game/TView.h"
#include "game/TGreatPower.h"
#include "game/TCity.h"
#include "game/trade_quickdraw.h"
#include "game/ui_widget_thunks.h"
#include "game/win_rect.h"
#include "game/quickdraw_guards.h"
#include "game/GameAssert.h"

#include <new>

#include "game/CRuntimeClass.h"

extern "C" {
// GLOBAL: IMPERIALISM 0x00662f98
CRuntimeClass g_pClassDescTIndustryCluster = {0};
}

undefined4 thunk_InvalidateCityDialogRectRegion(void);

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
  TIndustryCluster* cluster =
      reinterpret_cast<TIndustryCluster*>(AllocateWithFallbackHandler(sizeof(TIndustryCluster)));
  if (cluster != 0) {
    new (cluster) TIndustryCluster();
  }
  return cluster;
}

// FUNCTION: IMPERIALISM 0x00588ad0
CRuntimeClass* TIndustryCluster::GetRuntimeClass() {
  return &g_pClassDescTIndustryCluster;
}

// FUNCTION: IMPERIALISM 0x00588af0
TIndustryCluster::TIndustryCluster()
    : TUberCluster(), selectedMetricControl(0), selectedMetricValue(0), selectedMetricStep(0) {}

// SYNTHETIC: IMPERIALISM 0x00588b20

// TIndustryCluster::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00588b70
void TIndustryCluster::SyncTradeCommoditySelectionWithActiveNationAndInitControls(int styleSeed) {
  short tagIndex = 0;
  short activeNationId = thunk_GetActiveNationId();
  TGreatPower* activeNationState = GetNationStateBySlot(activeNationId);
  NationCityTradeState* cityState =
      activeNationState == 0 ? 0 : activeNationState->GetCityState();

  int mappedSummaryTag = GetTradeSummarySelectionTagByIndex(0);
  while (mappedSummaryTag != this->controlTag) {
    tagIndex = (short)(tagIndex + 1);
    mappedSummaryTag = GetTradeSummarySelectionTagByIndex(tagIndex);
  }

  TradeCommodityMetricRecord* selectedMetricRecord = reinterpret_cast<TradeCommodityMetricRecord*>(
      *reinterpret_cast<int*>(reinterpret_cast<char*>(cityState) + (int)tagIndex * 4 + 0xe4));
  this->selectedMetricControl = reinterpret_cast<TAmtBar*>(selectedMetricRecord);
  this->selectedMetricValue = static_cast<short>(reinterpret_cast<TCity*>(cityState)
                                                    ->GetBuildingProductionValueBySlot(
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
  reinterpret_cast<void(__stdcall*)(int, int)>(thunk_InvalidateCityDialogRectRegion)(
      (int)&moveInvalidRect, 1);

  TAmtBar* barControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagBar));
  if (barControl == 0) {
    FailNilPointerInUSmallViews(0xb49);
  }

  TradeMoveControlState* barLayout = reinterpret_cast<TradeMoveControlState*>(barControl);
  TAmtBar* barAmount = reinterpret_cast<TAmtBar*>(barControl);
  float barScale = 9999.0f;
  if (barLayout->barStepsRaw != 0) {
    barScale = (float)barLayout->barRangeRaw / (float)barLayout->barStepsRaw;
  }

  if (ReadControlValueFieldPlus4(selectedControl) == this->selectedMetricValue) {
    barAmount->auxValueB = 0x34;
  } else {
    barAmount->auxValueB = 0x3a;
  }

  int scaledMetric = (int)((float)selectedControl->QueryValue() * barScale);
  int scaledRange = (int)((float)ReadControlValueFieldPlus4(selectedControl) * barScale);
  barControl->SetBarMetric(scaledMetric, scaledRange);
  reinterpret_cast<TUberCluster*>(this->ownerContext)->GetControlFlag(0, 0);
  return 0;
}

// FUNCTION: IMPERIALISM 0x00588f60
int TIndustryCluster::GetControlFlag(int arg1, int arg2) {
  UpdateTradeBarFromSelectedMetricRatio(this, kAssertLineRatioB);
  return 0;
}
