#include "game/TSimMgr.h"
#include "game/TShipyardCluster.h"

#include "game/TAmtBar.h"
#include "game/TBuildingView.h"
#include "game/TView.h"
#include "game/TGreatPower.h"
#include "game/TCity.h"
#include "game/global_data_tables.h"
#include "game/ui_control_tags.h"
#include "game/ui_invalidation_guard.h"
#include "game/quickdraw_rendering.h"
#include "game/UiRuntimeContext.h"
#include "game/mfc.h"
#include "game/quickdraw_guards.h"
#include "game/GameAssert.h"

#include <new>

#include "game/mfc.h"

// SYNTHETIC: IMPERIALISM 0x0058a4d0
// TShipyardCluster::CreateObject

// SYNTHETIC: IMPERIALISM 0x0058a570
// TShipyardCluster::GetRuntimeClass

IMPLEMENT_DYNCREATE(TShipyardCluster, TAmtBarCluster)

// FUNCTION: IMPERIALISM 0x0058a590
TShipyardCluster::TShipyardCluster()
    : TAmtBarCluster(), selectedMetricOrder(0), selectedMetricValue(0), selectedMetricStep(0) {}

// SYNTHETIC: IMPERIALISM 0x0058a5c0
// TShipyardCluster::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x0058a610
void TShipyardCluster::DoPostCreate(int styleSeed) {
  TGreatPower* nationState = g_apNationStates[g_pSimMgr->GetActiveNationId()];
  TCity* province = nationState == 0 ? 0 : nationState->GetCityState();
  selectedMetricOrder = province->shipOrderSlots[0];
  selectedMetricValue = 999;
  TAmtBarCluster::DoPostCreate(styleSeed);
  this->SetMoveAmount(0);
}

// FUNCTION: IMPERIALISM 0x0058a690
void TShipyardCluster::SetMoveAmount(short amount) {
  TAmtBar* moveControl = static_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagMove));
  if (moveControl == 0) {
    GAME_FAIL_NIL_POINTER();
  }

  moveControl->SetControlValueSlot1E4(0, 0);

  RECT invalidateRect;
  CRect moveRect;
  moveControl->QueryBounds(&moveRect);
  OffsetRect(&moveRect, this->ownerLocalX, this->ownerLocalY);
  CopyRect(&invalidateRect, &moveRect);
  this->ownerContext->InvalidateCityDialogRectRegion(&invalidateRect, 1);

  TAmtBar* barControl = static_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagBar));
  if (barControl == 0) {
    GAME_FAIL_NIL_POINTER();
  }

  if (selectedMetricValue == 0) {
    barControl->auxValueB = 0x34;
  } else {
    barControl->auxValueB = 0x3a;
  }
  barControl->SetBarMetric(0, 0);

  int moveControlPosition[2];
  moveControlPosition[0] = barControl->ownerLocalX - 2;
  moveControlPosition[1] = barControl->ownerLocalY + barControl->frameHeight38;
  moveControl->CaptureLayoutF0(moveControlPosition, 1);
  moveControl->QueryBounds(&moveRect);
  OffsetRect(&moveRect, this->ownerLocalX, this->ownerLocalY);
  CopyRect(&invalidateRect, &moveRect);
  this->ownerContext->InvalidateCityDialogRectRegion(&invalidateRect, 1);

  TAmtBar* turnControl = static_cast<TAmtBar*>(this->ownerContext->ResolveControlByTag(0x7475726e));
  if (turnControl != 0) {
    turnControl->SetControlValueSlot1E4(0, 0);
    turnControl->QueryBounds(&moveRect);
    CopyRect(&invalidateRect, &moveRect);
    this->ownerContext->InvalidateCityDialogRectRegion(&invalidateRect, 1);
  }

  static_cast<TBuildingView*>(this->ownerContext)->UpdateFields();
  (void)amount;
}

// FUNCTION: IMPERIALISM 0x0058a940
void TShipyardCluster::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  TAmtBar* sourceControl = reinterpret_cast<TAmtBar*>(sourceHandler);
  int eventExtra = reinterpret_cast<int>(event);
  if (commandId == 10) {
    if (sourceControl->controlTag == (int)kControlTagRght) {
      TAmtBar* moveControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagMove));
      if (moveControl == 0) {
        GAME_FAIL_NIL_POINTER();
      }
      int moveValue = moveControl->QueryValue();
      this->SetMoveAmount(static_cast<short>(moveValue + 1));
      return;
    }
    if (sourceControl->controlTag != (int)kControlTagLeft) {
      TAmtBarCluster::DoEvent(commandId, static_cast<TEventHandler*>(sourceControl),
                              reinterpret_cast<TEvent*>(eventExtra));
      return;
    }
    TAmtBar* moveControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagMove));
    if (moveControl == 0) {
      GAME_FAIL_NIL_POINTER();
    }
    int moveValue = moveControl->QueryValue();
    if ((short)moveValue != 0) {
      this->SetMoveAmount(static_cast<short>(moveValue - 1));
      return;
    }
  } else {
    TAmtBarCluster::DoEvent(commandId, static_cast<TEventHandler*>(sourceControl),
                            reinterpret_cast<TEvent*>(eventExtra));
  }
}

TShipyardCluster::~TShipyardCluster() {}
