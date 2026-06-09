#include "game/TShipyardCluster.h"

#include "game/TAmtBar.h"
#include "game/TUberCluster.h"
#include "game/TView.h"
#include "game/NationState.h"
#include "game/trade_quickdraw.h"
#include "game/ui_widget_thunks.h"
#include "game/win_rect.h"
#include "game/quickdraw_guards.h"
#include "game/GameAssert.h"

#include <new>

undefined4 thunk_InvalidateCityDialogRectRegion(void);

static __inline NationCityTradeState* GetNationCityStateBySlot(short slotId) {
  TGreatPower* nationState = GetNationStateBySlot(slotId);
  if (nationState == 0) {
    return 0;
  }
  return nationState->GetCityState();
}

// FUNCTION: IMPERIALISM 0x0058a4d0
TShipyardCluster* __cdecl CreateTradeMoveArrowControlPanel(void) {
  TShipyardCluster* cluster =
      reinterpret_cast<TShipyardCluster*>(AllocateWithFallbackHandler(sizeof(TShipyardCluster)));
  if (cluster != 0) {
    new (cluster) TShipyardCluster();
  }
  return cluster;
}

// FUNCTION: IMPERIALISM 0x0058a570
void* __cdecl GetTShipyardClusterClassNamePointer(void) {
  return reinterpret_cast<void*>(0x00662ff8);
}

// FUNCTION: IMPERIALISM 0x0058a590
TShipyardCluster::TShipyardCluster() : TUberCluster(), field_88(0), field_8c(0), field_8e(0) {}

// SYNTHETIC: IMPERIALISM 0x0058a5c0
// TShipyardCluster::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x0058a610
void TShipyardCluster::SelectTradeSpecialCommodityAndInitializeControls() {
  NationCityTradeState* cityState = GetNationCityStateBySlot(thunk_GetActiveNationId());
  field_88 = cityState != 0 ? (int)cityState->specialCommodityRecordAt190 : 0;
  field_8c = 999;
  this->InitializeTradeMoveAndBarControls();
  this->ApplyMoveValue(0);
}

// FUNCTION: IMPERIALISM 0x0058a690
void TShipyardCluster::ApplyMoveValue(int value) {
  TAmtBar* moveControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagMove));
  if (moveControl == 0) {
    GAME_FAIL_NIL_POINTER();
  }

  moveControl->SetControlValueSlot1E4(0, 0);

  RECT invalidateRect;
  RECT moveRect;
  moveControl->QueryBounds(reinterpret_cast<int*>(&moveRect));
  OffsetRect(&moveRect, this->ownerOffsetX, this->ownerOffsetY);
  CopyRect(&invalidateRect, &moveRect);
  reinterpret_cast<void(__stdcall*)(int, int)>(thunk_InvalidateCityDialogRectRegion)(
      (int)&invalidateRect, 1);

  TAmtBar* barControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagBar));
  if (barControl == 0) {
    GAME_FAIL_NIL_POINTER();
  }

  barControl->auxValueB = (field_8c == 0) ? 0x34 : 0x3a;
  barControl->SetBarMetric(0, 0);

  moveControl->CaptureLayoutF0(reinterpret_cast<int*>(&moveRect), 1);
  OffsetRect(&moveRect, this->ownerOffsetX, this->ownerOffsetY);
  CopyRect(&invalidateRect, &moveRect);
  reinterpret_cast<void(__stdcall*)(int, int)>(thunk_InvalidateCityDialogRectRegion)(
      (int)&invalidateRect, 1);

  TAmtBar* turnControl =
      reinterpret_cast<TAmtBar*>(this->ownerContext->ResolveControlByTag(0x7475726e));
  if (turnControl != 0) {
    turnControl->SetControlValueSlot1E4(0, 0);
    turnControl->QueryBounds(reinterpret_cast<int*>(&moveRect));
    CopyRect(&invalidateRect, &moveRect);
    reinterpret_cast<void(__stdcall*)(int, int)>(thunk_InvalidateCityDialogRectRegion)(
        (int)&invalidateRect, 1);
  }

  reinterpret_cast<TUberCluster*>(this->ownerContext)->GetControlFlag(0, 0);
}

// FUNCTION: IMPERIALISM 0x0058a940
void TShipyardCluster::HandleTradeMoveArrowControlEvent(int commandId, TAmtBar* sourceControl,
                                                        int eventExtra) {
  if (commandId == 10) {
    if (sourceControl->controlTag == (int)kControlTagRght) {
      TAmtBar* moveControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagMove));
      if (moveControl == 0) {
        GAME_FAIL_NIL_POINTER();
      }
      int moveValue = moveControl->QueryValue();
      this->ApplyMoveValue(moveValue + 1);
      return;
    }
    if (sourceControl->controlTag != (int)kControlTagLeft) {
      this->HandleTradeMoveControlAdjustment(commandId, sourceControl, eventExtra);
      return;
    }
    TAmtBar* moveControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagMove));
    if (moveControl == 0) {
      GAME_FAIL_NIL_POINTER();
    }
    int moveValue = moveControl->QueryValue();
    if ((short)moveValue != 0) {
      this->ApplyMoveValue(moveValue - 1);
      return;
    }
  } else {
    this->HandleTradeMoveControlAdjustment(commandId, sourceControl, eventExtra);
  }
}
