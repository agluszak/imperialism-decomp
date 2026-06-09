#include "game/TIndustryCluster.h"
#include "game/TRailCluster.h"
#include "game/TShipyardCluster.h"
#include "game/TTradeCluster.h"
#include "game/trade_quickdraw.h"
#include "game/TGreatPower.h"
#include "game/win_rect.h"
#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"

#include "game/ui_widget_thunks.h"
extern void FailNilPointerInUSmallViews(int line);
extern const int kAssertLineMoveBarInitNil;
undefined4 thunk_BuildUiTextStyleDescriptor(void);
undefined4 thunk_DispatchPanelControlEvent(void);
#include "game/TAmtBar.h"
#include "game/ui_widget_thunks.h"
#include "game/TUberCluster.h"
#include "game/ui_widget_thunks.h"

#include <new>

// FUNCTION: IMPERIALISM 0x00571460
TUberCluster::TUberCluster() : TCluster() {}

// FUNCTION: IMPERIALISM 0x00571490
TUberCluster::~TUberCluster() {}

int TUberCluster::vmethod_0115() {
  return 0;
}
void TUberCluster::ApplyMoveValue(int value) {}
int TUberCluster::NotifyControlSelectionChange(void* boundEntry, int arg2) {
  return 0;
}
int TUberCluster::GetControlFlag(int arg1, int arg2) {
  return 0;
}
int TUberCluster::GetBoolSlot1DC() {
  return 0;
}
void TUberCluster::DoControlAction() {}
void TUberCluster::SetTradeBidControlBitmap() {}
void TUberCluster::SetTradeOfferControlBitmap() {}
void TUberCluster::SetTradeOfferSecondaryBitmap() {}

// FUNCTION: IMPERIALISM 0x00586d60
void TUberCluster::InitializeTradeMoveAndBarControls(unsigned int styleSeed) {
  TAmtBar* moveControl =
      reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagMove));
  unsigned int styleDescriptor = styleSeed & 0xffff0000U;
  if (moveControl != 0) {
    reinterpret_cast<void(__cdecl*)(int, unsigned int*, int, int)>(thunk_BuildUiTextStyleDescriptor)(
        0, &styleDescriptor, 0xa, 0x2b67);
    moveControl->ApplyStyleDescriptor(&styleDescriptor, 0);
    moveControl->SetStyleState(-2, 0);
  }

  TAmtBar* barControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagBar));
  if (barControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineMoveBarInitNil);
  }
  barControl->vmethod_0055(styleDescriptor);
  this->thunk_NoOpUiLifecycleHook();
}

// FUNCTION: IMPERIALISM 0x005713c0
TUberCluster* __cdecl CreateTUberClusterInstance(void) {
  TUberCluster* cluster =
      reinterpret_cast<TUberCluster*>(AllocateWithFallbackHandler(sizeof(TUberCluster)));
  if (cluster != 0) {
    new (cluster) TUberCluster();
  }
  return cluster;
}

// FUNCTION: IMPERIALISM 0x00571440
void* __cdecl GetTUberClusterClassNamePointer(void) {
  return reinterpret_cast<void*>(0x0065e5b0);
}

// FUNCTION: IMPERIALISM 0x00586e70
void TUberCluster::HandleTradeMoveControlAdjustment(int commandId, void* eventArg, int eventExtra) {
  // ORIG_CALLCONV: __thiscall
  int normalizedCommand = commandId - 100;

  if (normalizedCommand == 0) {
    TControl* moveControl = this->ResolveControlByTag(0x6d6f7665); // kControlTagMove
    if (moveControl == 0) {
      FailNilPointerInUSmallViews(0x749); // kAssertLineMoveAdjustMove
    }
    short moveValue = reinterpret_cast<TAmtBar*>(moveControl)->QueryValue();

    TControl* availableControl = this->ResolveControlByTag(0x61766169); // kControlTagAvai
    if (availableControl == 0) {
      FailNilPointerInUSmallViews(0x74d); // kAssertLineMoveAdjustAvai
    }
    short availableValue = (short)(reinterpret_cast<TAmtBar*>(availableControl)->QueryValue());
    if (moveValue < availableValue) {
      this->ApplyMoveValue(moveValue + 1);
    }
  } else if (normalizedCommand == 1) {
    TControl* moveControl = this->ResolveControlByTag(0x6d6f7665); // kControlTagMove
    if (moveControl == 0) {
      FailNilPointerInUSmallViews(0x759); // kAssertLineMoveAdjustMoveMinus
    }
    int moveValue = reinterpret_cast<TAmtBar*>(moveControl)->QueryValue();
    if ((short)moveValue != 0) {
      this->ApplyMoveValue(moveValue - 1);
    }
  }
  reinterpret_cast<void(__fastcall*)(void*, int, void*, int)>(thunk_DispatchPanelControlEvent)(
      this, commandId, eventArg, eventExtra);
}
