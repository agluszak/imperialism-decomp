#include "game/TAmtBar.h"
#include "game/TSimMgr.h"
#include "game/TIndustryCluster.h"
#include "game/TShipyardCluster.h"
#include "game/TTradeCluster.h"
#include "game/global_data_tables.h"
#include "game/ui_invalidation_guard.h"
#include "game/TCity.h"
#include "game/TGreatPower.h"
#include "game/mfc.h"
#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_control_tags.h"
#include <new>

#include "game/TRailCluster.h"
#include "game/TView.h"
#include "game/TUberCluster.h"

#include "game/mfc.h"

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
        ((int)context->selectedMetricControl->GetNextHandler() * barLayout->frameWidth34) /
        (int)barLayout->auxValueA;
    barControl->SetBarMetricRatio(ratioValue);
  }
}

// SYNTHETIC: IMPERIALISM 0x00589660
// TRailCluster::CreateObject

// SYNTHETIC: IMPERIALISM 0x00589700
// TRailCluster::GetRuntimeClass

IMPLEMENT_DYNCREATE(TRailCluster, TUberCluster)

// FUNCTION: IMPERIALISM 0x00589720
TRailCluster::TRailCluster() : TUberCluster() {
  this->selectedMetricControl = 0;
  this->selectedMetricStep = 0;
}

// SYNTHETIC: IMPERIALISM 0x00589760
// TRailCluster::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x005897b0
void TRailCluster::DoPostCreate(int styleSeed) {
  short recordIndex = static_cast<short>(styleSeed);
  short activeNationId = g_pSimMgr->GetActiveNationId();
  TGreatPower* activeNationState = GetNationStateBySlot(activeNationId);
  TCity* cityState = activeNationState == 0 ? 0 : activeNationState->GetCityState();

  unsigned int summaryTag = (unsigned int)this->controlTag;
  TPopulationMgr* scenarioDescriptor = cityState->productionSummary1d8;
  if (summaryTag < 0x706f7076) {
    if (summaryTag == kSummaryTagPopu) {
      recordIndex = 0x3c;
      this->selectedMetricStep = 1;
      this->selectedMetricValue = QueryNationMetricBySlot(activeNationState, 2) +
                                  scenarioDescriptor->productionSlots14->valueAt8 -
                                  scenarioDescriptor->productionSlots14->valueAt4;
      goto LABEL_12;
    }
    if (summaryTag == kSummaryTagProf) {
      recordIndex = 0x3e;
      this->selectedMetricStep = 0;
      this->selectedMetricValue = QueryNationMetricBySlot(activeNationState, 4) +
                                  scenarioDescriptor->extraAt1e - scenarioDescriptor->stockLevel1c;
      goto LABEL_12;
    }
    if (summaryTag == kSummaryTagFood) {
      recordIndex = 0x38;
      this->selectedMetricStep = 1;
      this->selectedMetricValue = QueryNationMetricBySlot(activeNationState, 0) +
                                  scenarioDescriptor->productionSlots14->valueAt6 -
                                  scenarioDescriptor->productionSlots14->valueAt4;
      goto LABEL_12;
    }
  } else {
    if (summaryTag == kSummaryTagPowe) {
      recordIndex = 0x3f;
      this->selectedMetricStep = 0;
      this->selectedMetricValue =
          QueryNationMetricBySlot(activeNationState, 5) +
          *reinterpret_cast<int*>(reinterpret_cast<char*>(scenarioDescriptor) + 0x34) -
          *reinterpret_cast<int*>(reinterpret_cast<char*>(scenarioDescriptor) + 0x20);
      goto LABEL_12;
    }
    if (summaryTag == kSummaryTagRail) {
      recordIndex = 0x39;
      this->selectedMetricStep = 0;
      this->selectedMetricValue =
          QueryNationMetricBySlot(activeNationState, 6) +
          *reinterpret_cast<int*>(reinterpret_cast<char*>(scenarioDescriptor) + 0x2c) -
          *reinterpret_cast<int*>(reinterpret_cast<char*>(scenarioDescriptor) + 0x14);
      goto LABEL_12;
    }
    if (summaryTag == kSummaryTagIart) {
      recordIndex = 0x3a;
      this->selectedMetricStep = 0;
      this->selectedMetricValue = QueryNationMetricBySlot(activeNationState, 1) +
                                  scenarioDescriptor->stockLevel1c -
                                  scenarioDescriptor->productionSlots14->valueAt4;
      goto LABEL_12;
    }
  }
  // No commodity-record read here: the real disassembly (0x005897b0) falls
  // through to the shared tail with `recordIndex` left at its initial value
  // (the incoming `styleSeed` argument) and does NOT touch
  // selectedMetricStep/selectedMetricValue in this branch — they simply keep
  // whatever the caller/ctor already set. The previous body here read
  // `buyQuantityStepRaw`/`shortAt6` off the facade at made-up offsets that
  // never matched any real TProductionOrder field or this function's actual
  // instructions; removed rather than reinventing conflicting base fields.
LABEL_12:
  if (this->selectedMetricValue < 0) {
    this->selectedMetricValue = 0;
  }
}

// FUNCTION: IMPERIALISM 0x005899c0
void TRailCluster::SetMoveAmount(short amount) {
  this->SetMoveAmount(amount, 0);
}

// FUNCTION: IMPERIALISM 0x005899f0
void TRailCluster::SetMoveAmount(short dragValue, unsigned char updateFlag) {
  TRailCluster* ctx = reinterpret_cast<TRailCluster*>(this);
  // ORIG_CALLCONV: __thiscall
  short step = ctx->selectedMetricStep;
  int quantizedDragValue = ((((int)step / 2) + (int)(short)dragValue) / (int)step) * (int)step;
  TAmtBar* selectedControl = ctx->selectedMetricControl;
  short previousValue = ReadControlValueFieldPlus4(selectedControl);
  if (selectedControl != 0) {
    selectedControl->SetEnable(static_cast<unsigned char>(quantizedDragValue));
  }

  if (((char)updateFlag == 0) && (ReadControlValueFieldPlus4(selectedControl) == previousValue)) {
    return;
  }

  TAmtBar* moveControl = reinterpret_cast<TAmtBar*>(
      reinterpret_cast<TView*>(this)->ResolveControlByTag(kControlTagMove));
  if (moveControl == 0) {
    FailNilPointerInUSmallViews(0xcf2);
  }

  moveControl->SetControlValueSlot1E4((int)ReadControlValueFieldPlus4(selectedControl), 0);

  CRect moveBoundsRect;
  RECT moveInvalidRect;
  moveControl->QueryBounds(&moveBoundsRect);
  OffsetRect(&moveBoundsRect, ctx->ownerLocalX, ctx->ownerLocalY);
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

  if (ReadControlValueFieldPlus4(selectedControl) == selectedMetricValue) {
    barAmount->auxValueB = 0x34;
  } else {
    barAmount->auxValueB = 0x3a;
  }

  int scaledMetric = (int)((float)selectedControl->QueryValue() * barScale);
  int scaledRange = (int)((float)ReadControlValueFieldPlus4(selectedControl) * barScale);
  barControl->SetBarMetric(scaledMetric, scaledRange);
  ctx->UpdateMax();
}

// FUNCTION: IMPERIALISM 0x00589d10
void TRailCluster::UpdateMax() {
  UpdateTradeBarFromSelectedMetricRatio(reinterpret_cast<TRailCluster*>(this), kAssertLineRatioA);
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
    this->HandleTradeMoveControlAdjustment(commandId, sourceHandler, reinterpret_cast<int>(event));
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
