#include "game/NationState.h"
#include "game/TAmtBar.h"
#include "game/TAmtBarCluster.h"
#include "game/GameAssert.h"
#include "game/UiRuntimeContext.h"
#include "game/trade_quickdraw.h"

struct NationState;

extern const int kTradeSellPropagationTags[17];
extern const int kControlTagBar;
extern NationState* GetNationStateBySlot(short slot);
extern short QueryNationMetricBySlot(NationState* state, short metricSlot);
extern int QueryUiScreenModeRaw(UiRuntimeContext* context);
extern void __fastcall HandleTradeMoveControlAdjustment(void* context, int commandId,
                                                        void* eventArg, int eventExtra);
extern void FailNilPointerInUSmallViews(int line);

const int kAssertLineTradeSellIncSell = 0x816;
const int kAssertLineTradeSellIncCap = 0x81d;

extern "C" {
char g_pClassDescTAmtBarCluster = 0;
}

// FUNCTION: IMPERIALISM 0x00586c40
TAmtBarCluster* TAmtBarCluster::CreateInstance() {
  return new TAmtBarCluster();
}

// FUNCTION: IMPERIALISM 0x00586cc0
void* TAmtBarCluster::GetClassNamePointer() {
  return &g_pClassDescTAmtBarCluster;
}

// FUNCTION: IMPERIALISM 0x00586ce0
TAmtBarCluster::TAmtBarCluster() : TUberCluster() {}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x00586d10
// TAmtBarCluster::`scalar deleting destructor'

// QueryValue() reads vtable slot 0x1E8, which is populated only on the concrete
// trade-control classes (TAmtBar, ...) and is NULL on others (e.g. this cluster's
// own vtable). It is therefore not a uniform TControl virtual, so the controls it
// is called on are accessed through the TradeControl dispatch view. Controls that
// only use real TControl/TView virtuals (SetEnabled@0xA4, SetState@0xA8,
// GetControlFlag, DoControlAction) are kept as plain TControl*.
// FUNCTION: IMPERIALISM 0x005873e0
void TAmtBarCluster::HandleTradeSellControlCommand(int commandId, void* eventArg, int eventExtra) {
  TView* ownerPanel = this->OwnerPanel();

  switch (commandId) {
  case 100: {
    if (this->GetBoolSlot1DC() != '\0') {
      TAmtBar* sellControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagSell));
      if (sellControl == 0) {
        FailNilPointerInUSmallViews(kAssertLineTradeSellIncSell);
      }

      int sellValue = sellControl->QueryValue();
      short activeNationSlot = thunk_GetActiveNationId();
      NationState* activeNationState = GetNationStateBySlot(activeNationSlot);
      short maxByNationMetric = 0;
      if (activeNationState != 0) {
        maxByNationMetric = QueryNationMetricBySlot(activeNationState, metricSlotAt88);
      }

      TAmtBar* capacityControl =
          reinterpret_cast<TAmtBar*>(ownerPanel->ResolveControlByTag(0x6d436170));
      if (capacityControl == 0) {
        FailNilPointerInUSmallViews(kAssertLineTradeSellIncCap);
      }

      if ((int)maxByNationMetric < sellValue) {
        int capacityValue = capacityControl->QueryValue();
        if ((int)maxByNationMetric < capacityValue) {
          sellControl->SetEnabled(maxByNationMetric + 1 != 0, 1);
          this->ApplyMoveValue(maxByNationMetric + 1);
          return;
        }
      }
    }
    break;
  }
  case 0x65: {
    TAmtBar* sellControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagSell));
    if (sellControl == 0) {
      GAME_FAIL_NIL_POINTER();
      break;
    }
    int sellValue = sellControl->QueryValue();
    if (1 < sellValue) {
      this->ApplyMoveValue(sellValue - 1);
      return;
    }
    break;
  }
  case 0x67:
    g_pUiRuntimeContext->ApplyUiRuntimeSlot68(-1);
    if (QueryUiScreenModeRaw(g_pUiRuntimeContext) == 3) {
      for (int i = 0;
           i < (int)(sizeof(kTradeSellPropagationTags) / sizeof(kTradeSellPropagationTags[0]));
           ++i) {
        TControl* rowControl = ownerPanel->ResolveControlByTag(kTradeSellPropagationTags[i]);
        if (rowControl != 0 &&
            reinterpret_cast<TUberCluster*>(rowControl)->GetControlFlag() == '\0') {
          reinterpret_cast<TUberCluster*>(rowControl)->DoControlAction();
        }
      }
      return;
    }
    break;
  case 0x68:
    g_pUiRuntimeContext->ApplyUiRuntimeSlot68(1);
    if (QueryUiScreenModeRaw(g_pUiRuntimeContext) == 4) {
      for (int i = 0;
           i < (int)(sizeof(kTradeSellPropagationTags) / sizeof(kTradeSellPropagationTags[0]));
           ++i) {
        TControl* rowControl = ownerPanel->ResolveControlByTag(kTradeSellPropagationTags[i]);
        if (rowControl != 0 &&
            reinterpret_cast<TUberCluster*>(rowControl)->GetControlFlag() == '\0') {
          reinterpret_cast<TUberCluster*>(rowControl)->DoControlAction();
        }
      }
      return;
    }
    break;
  case 0x69: {
    short activeNationSlot = thunk_GetActiveNationId();
    NationState* activeNationState = GetNationStateBySlot(activeNationSlot);
    short maxByNationMetric = 0;
    if (activeNationState != 0) {
      maxByNationMetric = QueryNationMetricBySlot(activeNationState, metricSlotAt88);
    }

    TAmtBar* capacityControl =
        reinterpret_cast<TAmtBar*>(ownerPanel->ResolveControlByTag(0x6d436170));
    if (capacityControl == 0) {
      GAME_FAIL_NIL_POINTER();
    }
    short cappedValue = (short)capacityControl->QueryValue();
    int applyValue = (int)maxByNationMetric;
    if ((int)cappedValue <= (int)maxByNationMetric) {
      applyValue = (int)cappedValue;
    }

    TControl* sellControl = this->ResolveControlByTag(kControlTagSell);
    sellControl->SetEnabled(1, 1);

    TControl* barControl = this->ResolveControlByTag(kControlTagBar);
    if (barControl == 0) {
      GAME_FAIL_NIL_POINTER();
    }
    barControl->SetState(1, 0);
    this->ApplyMoveValue(applyValue);
    return;
  }
  case 0x6a: {
    TControl* sellControl = this->ResolveControlByTag(kControlTagSell);
    sellControl->SetEnabled(0, 1);

    TControl* barControl = this->ResolveControlByTag(kControlTagBar);
    if (barControl == 0) {
      GAME_FAIL_NIL_POINTER();
    }
    barControl->SetState(0, 1);
    this->ApplyMoveValue(0);
    return;
  }
  default:
    this->HandleTradeMoveControlAdjustment(commandId, eventArg, eventExtra);
    return;
  }

  this->HandleTradeMoveControlAdjustment(commandId, eventArg, eventExtra);
}

// FUNCTION: IMPERIALISM 0x00588ff0
void TAmtBarCluster::HandleTradeMoveStepCommand(int commandId, void* eventArg, int eventExtra) {
  // ORIG_CALLCONV: __thiscall

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
    this->HandleTradeMoveControlAdjustment(commandId, eventArg, eventExtra);
    return;
  }
  TAmtBar* moveControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagMove));
  if (moveControl == 0) {
    GAME_FAIL_NIL_POINTER();
  }
  int moveValue = moveControl->QueryValue();
  this->ApplyMoveValue(moveValue - 1);
}
