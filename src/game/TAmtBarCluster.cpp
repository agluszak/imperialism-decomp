#include "game/TAmtBarCluster.h"
#include "game/GameAssert.h"
#include "game/TradeControl.h"
#include <new>
#include "game/UiRuntimeContext.h"
#include "game/trade_quickdraw.h"
#include "game/ui_widget_shared.h"

struct NationState;

extern const int kTradeSellPropagationTags[17];
extern const int kControlTagBar;
extern NationState* GetNationStateBySlot(short slot);
extern short QueryNationMetricBySlot(NationState* state, short metricSlot);
extern int QueryUiScreenModeRaw(UiRuntimeContext* context);
extern void __fastcall HandleTradeMoveControlAdjustment(void* context, int commandId, void* eventArg, int eventExtra);
extern void FailNilPointerInUSmallViews(int line);

const int kAssertLineTradeSellIncSell = 0x816;
const int kAssertLineTradeSellIncCap = 0x81d;

extern "C" {
char g_pClassDescTAmtBarCluster = 0;
char g_vtblTAmtBarCluster = 0;
}

undefined4 thunk_DestructEngineerDialogBaseState(void);

// FUNCTION: IMPERIALISM 0x00586c40
TAmtBarCluster* TAmtBarCluster::CreateInstance() {
  return new TAmtBarCluster();
}

// FUNCTION: IMPERIALISM 0x00586cc0
void* TAmtBarCluster::GetClassNamePointer() {
  return reinterpret_cast<void*>(&g_pClassDescTAmtBarCluster);
}

// FUNCTION: IMPERIALISM 0x00586ce0
TAmtBarCluster::TAmtBarCluster() : TUberCluster() {
}

// FUNCTION: IMPERIALISM 0x00586d10
void* TAmtBarCluster::DestructAndMaybeFree(int freeSelfFlag) {
  thunk_DestructEngineerDialogBaseState();
  if ((freeSelfFlag & 1) != 0) {
    // FreeHeapBufferIfNotNull
  }
  return this;
}

// FUNCTION: IMPERIALISM 0x00586e30
void TAmtBarCluster::HandleTradeSellControlCommand(int commandId, void* eventArg, int eventExtra) {
  void* ownerPanel = this->OwnerPanel();

  switch (commandId) {
  case 100: {
    if (this->GetBoolSlot1DC() != '\0') {
      TControl* sellControl = this->ResolveControlByTag(kControlTagSell);
      if (sellControl == 0) {
        FailNilPointerInUSmallViews(kAssertLineTradeSellIncSell);
      }

      int sellValue = reinterpret_cast<TradeControl*>(sellControl)->QueryValue();
      short activeNationSlot = QueryActiveNationId();
      NationState* activeNationState = GetNationStateBySlot(activeNationSlot);
      short maxByNationMetric = 0;
      if (activeNationState != 0) {
        maxByNationMetric = QueryNationMetricBySlot(activeNationState, metricSlotAt88);
      }

      TControl* capacityControl = reinterpret_cast<TView*>(ownerPanel)->ResolveControlByTag(0x6d436170);
      if (capacityControl == 0) {
        FailNilPointerInUSmallViews(kAssertLineTradeSellIncCap);
      }

      if ((int)maxByNationMetric < sellValue) {
        int capacityValue = reinterpret_cast<TradeControl*>(capacityControl)->QueryValue();
        if ((int)maxByNationMetric < capacityValue) {
          this->ApplyMoveValue(maxByNationMetric + 1);
        } else {
          this->ApplyMoveValue(maxByNationMetric);
          return;
        }
      }
    }
    break;
  }
  case 0x65: {
    TControl* sellControl = this->ResolveControlByTag(kControlTagSell);
    if (sellControl == 0) {
      GAME_FAIL_NIL_POINTER();
      break;
    }
    int sellValue = reinterpret_cast<TradeControl*>(sellControl)->QueryValue();
    if (1 < sellValue) {
      this->ApplyMoveValue(sellValue - 1);
      return;
    }
    break;
  }
  case 0x67:
    g_pUiRuntimeContext->ApplyUiRuntimeSlot68(-1);
    if (QueryUiScreenModeRaw(g_pUiRuntimeContext) == 3) {
      for (int i = 0; i < 6; ++i) { // kTradeSellPropagationTags
        TControl* rowControl = reinterpret_cast<TView*>(ownerPanel)->ResolveControlByTag(kTradeSellPropagationTags[i]);
        if (rowControl != 0 && rowControl->GetControlFlag() == '\0') {
          rowControl->DoControlAction();
        }
      }
      return;
    }
    break;
  case 0x68:
    g_pUiRuntimeContext->ApplyUiRuntimeSlot68(1);
    if (QueryUiScreenModeRaw(g_pUiRuntimeContext) == 4) {
      for (int i = 0; i < 6; ++i) { // kTradeSellPropagationTags
        TControl* rowControl = reinterpret_cast<TView*>(ownerPanel)->ResolveControlByTag(kTradeSellPropagationTags[i]);
        if (rowControl != 0 && rowControl->GetControlFlag() == '\0') {
          rowControl->DoControlAction();
        }
      }
      return;
    }
    break;
  case 0x69: {
    short activeNationSlot = QueryActiveNationId();
    NationState* activeNationState = GetNationStateBySlot(activeNationSlot);
    short maxByNationMetric = 0;
    if (activeNationState != 0) {
      maxByNationMetric = QueryNationMetricBySlot(activeNationState, metricSlotAt88);
    }

    TControl* capacityControl = reinterpret_cast<TView*>(ownerPanel)->ResolveControlByTag(0x6d436170);
    if (capacityControl == 0) {
      GAME_FAIL_NIL_POINTER();
    }
    short cappedValue = (short)reinterpret_cast<TradeControl*>(capacityControl)->QueryValue();
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
    HandleTradeMoveControlAdjustment(reinterpret_cast<TradeControl*>(this), commandId, eventArg, eventExtra);
    return;
  }

  HandleTradeMoveControlAdjustment(reinterpret_cast<TradeControl*>(this), commandId, eventArg, eventExtra);
}
