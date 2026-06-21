#include "game/TGreatPower.h"
#include "game/TAmtBar.h"
#include "game/TAmtBarCluster.h"
#include "game/GameAssert.h"
#include "game/UiRuntimeContext.h"
#include "game/trade_quickdraw.h"
#include "game/mfc.h"

struct TGreatPower;

extern const int kTradeSellPropagationTags[17];
extern const int kControlTagBar;
extern TGreatPower* GetNationStateBySlot(short slot);
extern short QueryNationMetricBySlot(TGreatPower* state, short metricSlot);
extern int QueryUiScreenModeRaw(UiRuntimeContext* context);
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
CRuntimeClass* TAmtBarCluster::GetRuntimeClass() const {
  return &g_pClassDescTAmtBarCluster;
}



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


undefined TAmtBarCluster::OrphanRetStub_00586ff0(void) { return 0;}

TAmtBarCluster::~TAmtBarCluster() {}
