#include "game/TAmtBar.h"
#include "game/TIndustryCluster.h"
#include "game/TRailCluster.h"
#include "game/TShipyardCluster.h"
#include "game/TTradeCluster.h"
#include "game/trade_quickdraw.h"
#include "game/TGreatPower.h"
#include "game/ui_widget_thunks.h"
#include "game/win_rect.h"
#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"
#include <new>

#include "game/TCluster.h"

// FUNCTION: IMPERIALISM 0x00491400
TCluster::TCluster() {
  this->hasCommandTagResource = 5;
  this->field84 = 0x20202020;
}

// SYNTHETIC: IMPERIALISM 0x00491480
// TCluster::`scalar deleting destructor'

#include "decomp_types.h"

undefined4 thunk_DispatchPanelControlEvent(void);

void TCluster::DispatchPanelControlEvent(int eventClass, void* eventPayload, int eventFlags) {
  reinterpret_cast<void(__fastcall*)(void*, int, int, void*, int)>(thunk_DispatchPanelControlEvent)(
      this, 0, eventClass, eventPayload, eventFlags);
}

int TCluster::GetField84() {
  return this->field84;
}
void TCluster::SetControlClassAndRefresh(int classState, int refreshFlag) {}
