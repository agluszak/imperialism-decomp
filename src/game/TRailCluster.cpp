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
TRailCluster::~TRailCluster() {}

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
