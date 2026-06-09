#include "game/TAmtBar.h"
#include "game/TIndustryCluster.h"
#include "game/TShipyardCluster.h"
#include "game/TTradeCluster.h"
#include "game/trade_quickdraw.h"
#include "game/TradeCommodityMetricRecord.h"
#include "game/NationState.h"
#include "game/ui_widget_thunks.h"
#include "game/win_rect.h"
#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"
#include <new>

#include "game/TRailCluster.h"
#include "game/TView.h"
#include "game/TUberCluster.h"

undefined4 thunk_InvalidateCityDialogRectRegion(void);

const int kAssertLineRatioA = 0xd1d;

static __inline short ReadControlValueFieldPlus4(TAmtBar* control) {
  return *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 4);
}

static __inline void UpdateTradeBarFromSelectedMetricRatio(TRailCluster* context, int assertLine) {
  void* owner = context;
  TAmtBar* barControl = reinterpret_cast<TAmtBar*>(
      reinterpret_cast<TView*>(owner)->ResolveControlByTag(kControlTagBar));
  if (barControl == 0) {
    FailNilPointerInUSmallViews(assertLine);
  }

  TAmtBar* barLayout = reinterpret_cast<TAmtBar*>(barControl);
  if (barLayout->auxValueA != 0) {
    int ratioValue =
        ((int)context->selectedMetricControl->QueryStepValue() * barLayout->field34) /
        (int)barLayout->auxValueA;
    barControl->SetBarMetricRatio(ratioValue);
  }
}

// FUNCTION: IMPERIALISM 0x00589660
TRailCluster* __cdecl CreateTradeMoveScaledControlPanel(void) {
  TRailCluster* cluster =
      reinterpret_cast<TRailCluster*>(AllocateWithFallbackHandler(sizeof(TRailCluster)));
  if (cluster != 0) {
    new (cluster) TRailCluster();
  }
  return cluster;
}

// FUNCTION: IMPERIALISM 0x00589700
void* __cdecl GetTRailClusterClassNamePointer(void) {
  return reinterpret_cast<void*>(0x00662fc8);
}

// FUNCTION: IMPERIALISM 0x00589720
TRailCluster::TRailCluster() : TUberCluster() {
  this->selectedMetricControl = 0;
  this->selectedMetricStep = 0;
}

// SYNTHETIC: IMPERIALISM 0x00589760
// TRailCluster::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x005897b0
void TRailCluster::SelectTradeCommodityPresetBySummaryTagAndInitControls(short recordIndex) {
  short activeNationId = thunk_GetActiveNationId();
  NationState* activeNationState = GetNationStateBySlot(activeNationId);
  NationCityTradeState* cityState = activeNationState == 0 ? 0 : activeNationState->cityState;

  unsigned int summaryTag = (unsigned int)this->controlTag;
  int scenarioDescriptor = *reinterpret_cast<int*>(reinterpret_cast<char*>(cityState) + 0x1d8);
  if (summaryTag < 0x706f7076) {
    if (summaryTag == kSummaryTagPopu) {
      recordIndex = 0x3c;
      this->selectedMetricStep = 1;
      this->selectedMetricValue = QueryNationMetricBySlot(activeNationState, 2) +
                                  (short)ReadIntAt(scenarioDescriptor + 0x24) -
                                  (short)ReadIntAt(scenarioDescriptor + 0x10);
      goto LABEL_12;
    }
    if (summaryTag == kSummaryTagProf) {
      recordIndex = 0x3e;
      this->selectedMetricStep = 0;
      this->selectedMetricValue = QueryNationMetricBySlot(activeNationState, 4) +
                                  (short)ReadIntAt(scenarioDescriptor + 0x30) -
                                  (short)ReadIntAt(scenarioDescriptor + 0x1c);
      goto LABEL_12;
    }
    if (summaryTag == kSummaryTagFood) {
      recordIndex = 0x38;
      this->selectedMetricStep = 1;
      this->selectedMetricValue = QueryNationMetricBySlot(activeNationState, 0) +
                                  (short)ReadIntAt(scenarioDescriptor + 0x18) -
                                  (short)ReadIntAt(scenarioDescriptor + 4);
      goto LABEL_12;
    }
  } else {
    if (summaryTag == kSummaryTagPowe) {
      recordIndex = 0x3f;
      this->selectedMetricStep = 0;
      this->selectedMetricValue = QueryNationMetricBySlot(activeNationState, 5) +
                                  (short)ReadIntAt(scenarioDescriptor + 0x34) -
                                  (short)ReadIntAt(scenarioDescriptor + 0x20);
      goto LABEL_12;
    }
    if (summaryTag == kSummaryTagRail) {
      recordIndex = 0x39;
      this->selectedMetricStep = 0;
      this->selectedMetricValue = QueryNationMetricBySlot(activeNationState, 6) +
                                  (short)ReadIntAt(scenarioDescriptor + 0x2c) -
                                  (short)ReadIntAt(scenarioDescriptor + 0x14);
      goto LABEL_12;
    }
    if (summaryTag == kSummaryTagIart) {
      recordIndex = 0x3a;
      this->selectedMetricStep = 0;
      this->selectedMetricValue = QueryNationMetricBySlot(activeNationState, 1) +
                                  (short)ReadIntAt(scenarioDescriptor + 0x1c) -
                                  (short)ReadIntAt(scenarioDescriptor + 8);
      goto LABEL_12;
    }
  }
  if (cityState != 0) {
    this->selectedMetricStep = cityState->tradeCommodityRecordPtrs[recordIndex]->buyQuantityStepRaw;
    this->selectedMetricValue =
        cityState->tradeCommodityRecordPtrs[recordIndex]->shortAt6 -
        cityState->tradeCommodityRecordPtrs[recordIndex]->buyQuantityStepRaw;
  }
LABEL_12:
  if (this->selectedMetricValue < 0) {
    this->selectedMetricValue = 0;
  }
}

// FUNCTION: IMPERIALISM 0x005899c0
void TRailCluster::ApplyMoveValue(int value) {
  reinterpret_cast<TUberCluster*>(reinterpret_cast<TRailCluster*>(this))
      ->NotifyControlSelectionChange(reinterpret_cast<void*>(value), 0);
}

// FUNCTION: IMPERIALISM 0x005899f0
int TRailCluster::NotifyControlSelectionChange(void* dragValuePtr, int updateFlag) {
  int dragValue = (int)dragValuePtr;
  TRailCluster* ctx = reinterpret_cast<TRailCluster*>(this);
  // ORIG_CALLCONV: __thiscall
  short step = ctx->selectedMetricStep;
  int quantizedDragValue = ((((int)step / 2) + (int)(short)dragValue) / (int)step) * (int)step;
  TAmtBar* selectedControl = ctx->selectedMetricControl;
  short previousValue = ReadControlValueFieldPlus4(selectedControl);
  if (selectedControl != 0) {
    selectedControl->SetControlValue(quantizedDragValue);
  }

  if (((char)updateFlag == 0) && (ReadControlValueFieldPlus4(selectedControl) == previousValue)) {
    return 0;
  }

  TAmtBar* moveControl =
      reinterpret_cast<TAmtBar*>(reinterpret_cast<TView*>(this)->ResolveControlByTag(kControlTagMove));
  if (moveControl == 0) {
    FailNilPointerInUSmallViews(0xcf2);
  }

  moveControl->SetControlValueSlot1E4((int)ReadControlValueFieldPlus4(selectedControl), 0);

  RECT moveBoundsRect;
  RECT moveInvalidRect;
  moveControl->QueryBounds(reinterpret_cast<int*>(&moveBoundsRect));
  OffsetRect(&moveBoundsRect, ctx->ownerOffsetX, ctx->ownerOffsetY);
  CopyRect(&moveInvalidRect, &moveBoundsRect);
  reinterpret_cast<void(__stdcall*)(int, int)>(thunk_InvalidateCityDialogRectRegion)(
      (int)&moveInvalidRect, 1);

  TAmtBar* barControl =
      reinterpret_cast<TAmtBar*>(reinterpret_cast<TView*>(this)->ResolveControlByTag(kControlTagBar));
  if (barControl == 0) {
    FailNilPointerInUSmallViews(0xcf9);
  }

  TAmtBar* barLayout = reinterpret_cast<TAmtBar*>(barControl);
  TAmtBar* barAmount = reinterpret_cast<TAmtBar*>(barControl);
  float barScale = 9999.0f;
  if (barLayout->auxValueA != 0) {
    barScale = (float)barLayout->field34 / (float)barLayout->auxValueA;
  }

  if (ReadControlValueFieldPlus4(selectedControl) == selectedMetricValue) {
    barAmount->auxValueB = 0x34;
  } else {
    barAmount->auxValueB = 0x3a;
  }

  int scaledMetric = (int)((float)selectedControl->QueryValue() * barScale);
  int scaledRange = (int)((float)ReadControlValueFieldPlus4(selectedControl) * barScale);
  barControl->SetBarMetric(scaledMetric, scaledRange);
  reinterpret_cast<TUberCluster*>(ctx->ownerContext)->GetControlFlag(0, 0);
  return 0;
}

// FUNCTION: IMPERIALISM 0x00589d10
int TRailCluster::GetControlFlag(int arg1, int arg2) {
  UpdateTradeBarFromSelectedMetricRatio(reinterpret_cast<TRailCluster*>(this), kAssertLineRatioA);
  return 0;
}
