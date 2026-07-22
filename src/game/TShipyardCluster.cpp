#include "game/TIndustryCluster.h"
#include "game/TSimMgr.h"
#include "game/TShipyardCluster.h"

#include "game/TAmtBar.h"
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

static __inline TCity* GetNationCityStateBySlot(short slotId) {
  TGreatPower* nationState = GetNationStateBySlot(slotId);
  if (nationState == 0) {
    return 0;
  }
  return nationState->GetCityState();
}

// SYNTHETIC: IMPERIALISM 0x0058a4d0
// TShipyardCluster::CreateObject

// SYNTHETIC: IMPERIALISM 0x0058a570
// TShipyardCluster::GetRuntimeClass

IMPLEMENT_DYNCREATE(TShipyardCluster, TAmtBarCluster)

// FUNCTION: IMPERIALISM 0x0058a590
TShipyardCluster::TShipyardCluster() : TAmtBarCluster(), field_88(0), field_8c(0), field_8e(0) {}

// SYNTHETIC: IMPERIALISM 0x0058a5c0
// TShipyardCluster::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x0058a610
void TShipyardCluster::DoPostCreate(int styleSeed) {
  TCity* cityState = GetNationCityStateBySlot(g_pSimMgr->GetActiveNationId());
  field_88 = cityState != 0 ? (int)cityState->shipOrderSlots[0] : 0;
  field_8c = 999;
  TAmtBarCluster::DoPostCreate(styleSeed);
  this->SetMoveAmount(0);
}

// FUNCTION: IMPERIALISM 0x0058a690
void TShipyardCluster::SetMoveAmount(short amount) {
  TAmtBar* moveControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagMove));
  if (moveControl == 0) {
    GAME_FAIL_NIL_POINTER();
  }

  moveControl->SetControlValueSlot1E4(0, 0);

  RECT invalidateRect;
  CRect moveRect;
  moveControl->QueryBounds(&moveRect);
  OffsetRect(&moveRect, this->ownerLocalX, this->ownerLocalY);
  CopyRect(&invalidateRect, &moveRect);
  reinterpret_cast<TView*>(this)->InvalidateCityDialogRectRegion(&invalidateRect, 1);

  TAmtBar* barControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagBar));
  if (barControl == 0) {
    GAME_FAIL_NIL_POINTER();
  }

  barControl->auxValueB = (field_8c == 0) ? 0x34 : 0x3a;
  barControl->SetBarMetric(0, 0);

  moveControl->CaptureLayoutF0(reinterpret_cast<int*>(&moveRect), 1);
  OffsetRect(&moveRect, this->ownerLocalX, this->ownerLocalY);
  CopyRect(&invalidateRect, &moveRect);
  reinterpret_cast<TView*>(this)->InvalidateCityDialogRectRegion(&invalidateRect, 1);

  TAmtBar* turnControl =
      reinterpret_cast<TAmtBar*>(this->ownerContext->ResolveControlByTag(0x7475726e));
  if (turnControl != 0) {
    turnControl->SetControlValueSlot1E4(0, 0);
    turnControl->QueryBounds(&moveRect);
    CopyRect(&invalidateRect, &moveRect);
    reinterpret_cast<TView*>(this)->InvalidateCityDialogRectRegion(&invalidateRect, 1);
  }

  static_cast<TIndustryCluster*>(this->ownerContext)->UpdateMax();
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
