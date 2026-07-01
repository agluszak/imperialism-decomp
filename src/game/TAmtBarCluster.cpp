#include "game/TGreatPower.h"
#include "game/TAmtBar.h"
#include "game/TAmtBarCluster.h"
#include "game/GameAssert.h"
#include "game/UiRuntimeContext.h"
#include "game/global_data_tables.h"
#include "game/ui_control_tags.h"
#include "game/quickdraw_rendering.h"
#include "game/mfc.h"
#include "game/ui_invalidation_guard.h"

const int kAssertLineTradeSellIncSell = 0x816;
const int kAssertLineTradeSellIncCap = 0x81d;

// FUNCTION: IMPERIALISM 0x00586c40
TAmtBarCluster* TAmtBarCluster::CreateInstance() {
  return new TAmtBarCluster();
}
// SYNTHETIC: IMPERIALISM 0x00586cc0
// TAmtBarCluster::GetRuntimeClass

IMPLEMENT_DYNCREATE(TAmtBarCluster, TUberCluster)

// FUNCTION: IMPERIALISM 0x00586ce0
TAmtBarCluster::TAmtBarCluster() : TUberCluster() {}

// SYNTHETIC: IMPERIALISM 0x00586d10
// TAmtBarCluster::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00586d60
void TAmtBarCluster::NoOpUiLifecycleHook(int styleSeed) {
  this->InitializeTradeMoveAndBarControls(styleSeed);
}

// FUNCTION: IMPERIALISM 0x00586e70
void TAmtBarCluster::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  this->HandleTradeMoveControlAdjustment(commandId, sourceHandler, reinterpret_cast<int>(event));
}

// FUNCTION: IMPERIALISM 0x00586ff0
void TAmtBarCluster::ApplyMoveValue(int value) {
  (void)value;
}

TAmtBarCluster::~TAmtBarCluster() {}
