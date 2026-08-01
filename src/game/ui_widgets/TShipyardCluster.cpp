#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TNumberText.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_widgets.h"
#include "game/ui_widgets/TShipyardCluster.h"

#include "game/ui_widgets/TAmtBar.h"
#include "game/city_ui/TBuildingView.h"
#include "game/city/TShipOrder.h"
#include "game/ui_core/TView.h"
#include "game/nation/TGreatPower.h"
#include "game/city/TCity.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_core/TViewMgr.h"
#include "game/mfc.h"
#include "game/quickdraw_guards.h"
#include "game/GameAssert.h"

#include <new>

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

// FUNCTION: IMPERIALISM 0x0058a5f0
TShipyardCluster::~TShipyardCluster() {}

// FUNCTION: IMPERIALISM 0x0058a610
void TShipyardCluster::DoPostCreate(int styleSeed) {
  TGreatPower* nationState = g_apNationStates[g_pSimMgr->GetActiveNationId()];
  TCity* province = nationState == 0 ? 0 : nationState->GetCityState();
  selectedMetricOrder = province->shipOrderSlots190[0];
  selectedMetricValue = 999;
  TAmtBarCluster::DoPostCreate(styleSeed);
  this->SetMoveAmount(0);
}

// FUNCTION: IMPERIALISM 0x0058a690
void TShipyardCluster::SetMoveAmount(short amount) {
  TNumberText* moveControl = static_cast<TNumberText*>(this->ResolveControlByTag(kControlTagMove));
  if (moveControl == 0) {
    GAME_FAIL_NIL_POINTER();
  }

  moveControl->SetControlValue(0, 0);

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

  CPoint moveControlPosition;
  moveControlPosition.x = barControl->ownerLocalX - 2;
  moveControlPosition.y = barControl->ownerLocalY + barControl->frameHeight38;
  moveControl->Locate(moveControlPosition, 1);
  moveControl->QueryBounds(&moveRect);
  OffsetRect(&moveRect, this->ownerLocalX, this->ownerLocalY);
  CopyRect(&invalidateRect, &moveRect);
  this->ownerContext->InvalidateCityDialogRectRegion(&invalidateRect, 1);

  TNumberText* turnControl =
      static_cast<TNumberText*>(this->ownerContext->ResolveControlByTag(kControlTagTurn));
  if (turnControl != 0) {
    turnControl->SetControlValue(0, 0);
    turnControl->QueryBounds(&moveRect);
    CopyRect(&invalidateRect, &moveRect);
    this->ownerContext->InvalidateCityDialogRectRegion(&invalidateRect, 1);
  }

  static_cast<TBuildingView*>(this->ownerContext)->UpdateFields();
  (void)amount;
}

// FUNCTION: IMPERIALISM 0x0058a940
void TShipyardCluster::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 10) {
    if (sourceHandler->controlTag == (int)kControlTagRght) {
      TNumberText* moveControl =
          static_cast<TNumberText*>(this->ResolveControlByTag(kControlTagMove));
      if (moveControl == 0) {
        GAME_FAIL_NIL_POINTER();
      }
      int moveValue = moveControl->UpdateControlCachedIntFromWindowText();
      this->SetMoveAmount(static_cast<short>(moveValue + 1));
      return;
    }
    if (sourceHandler->controlTag != (int)kControlTagLeft) {
      TAmtBarCluster::DoEvent(commandId, sourceHandler, event);
      return;
    }
    TNumberText* moveControl =
        static_cast<TNumberText*>(this->ResolveControlByTag(kControlTagMove));
    if (moveControl == 0) {
      GAME_FAIL_NIL_POINTER();
    }
    int moveValue = moveControl->UpdateControlCachedIntFromWindowText();
    if ((short)moveValue != 0) {
      this->SetMoveAmount(static_cast<short>(moveValue - 1));
      return;
    }
  } else {
    TAmtBarCluster::DoEvent(commandId, sourceHandler, event);
  }
}
