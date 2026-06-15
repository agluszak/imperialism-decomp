#include "game/TGreatPower.h"
#include "game/TAmtBar.h"
#include "game/TAmtBarCluster.h"
#include "game/GameAssert.h"
#include "game/UiRuntimeContext.h"
#include "game/trade_quickdraw.h"
#include "game/CRuntimeClass.h"

struct TGreatPower;

extern const int kTradeSellPropagationTags[17];
extern const int kControlTagBar;
extern TGreatPower* GetNationStateBySlot(short slot);
extern short QueryNationMetricBySlot(TGreatPower* state, short metricSlot);
extern int QueryUiScreenModeRaw(UiRuntimeContext* context);
extern void __fastcall HandleTradeMoveControlAdjustment(void* context, int commandId,
                                                        void* eventArg, int eventExtra);
extern void FailNilPointerInUSmallViews(int line);

const int kAssertLineTradeSellIncSell = 0x816;
const int kAssertLineTradeSellIncCap = 0x81d;

extern "C" {
CRuntimeClass g_pClassDescTAmtBarCluster = {nullptr, 0, 0, nullptr, nullptr};
}

// FUNCTION: IMPERIALISM 0x00586c40
TAmtBarCluster* TAmtBarCluster::CreateInstance() {
  return new TAmtBarCluster();
}

// FUNCTION: IMPERIALISM 0x00586cc0
CRuntimeClass* TAmtBarCluster::GetRuntimeClass() {
  return &g_pClassDescTAmtBarCluster;
}

// FUNCTION: IMPERIALISM 0x00586ce0
TAmtBarCluster::TAmtBarCluster() : TUberCluster() {}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x00586d10
// TAmtBarCluster::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00586ff0
void __cdecl OrphanRetStub_00586ff0(void) {}

// QueryValue() reads vtable slot 0x1E8, which is populated only on the concrete
// trade-control classes (TAmtBar, ...) and is NULL on others (e.g. this cluster's
// own vtable). It is therefore not a uniform TControl virtual, so the controls it
// is called on are accessed through the TradeControl dispatch view. Controls that
// only use real TControl/TView virtuals (SetEnabled@0xA4, SetState@0xA8,
// GetControlFlag, DoControlAction) are kept as plain TControl*.

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
