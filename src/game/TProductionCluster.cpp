#include "game/TIndustryCluster.h"
#include "game/TRailCluster.h"
#include "game/TShipyardCluster.h"
#include "game/TTradeCluster.h"
#include "game/TGreatPower.h"
#include "game/mfc.h"
#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"

#include "game/TAmtBar.h"
#include "game/TProductionCluster.h"

#include "game/GameAssert.h"
#include "game/ui_invalidation_guard.h"
#include "game/quickdraw_rendering.h"

#include <new>

#include "game/mfc.h"

// SYNTHETIC: IMPERIALISM 0x00586840
// TProductionCluster::CreateObject
// SYNTHETIC: IMPERIALISM 0x00586900
// TProductionCluster::GetRuntimeClass

IMPLEMENT_DYNCREATE(TProductionCluster, TUberCluster)

// FUNCTION: IMPERIALISM 0x00586920
TProductionCluster::TProductionCluster()
    : TUberCluster(), field88(0), laborRate8c(0), stockpileRate8e(0), currentStockpile90(0),
      maximumStockpile94(0) {}

// SYNTHETIC: IMPERIALISM 0x00586970
// TProductionCluster::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x005869c0
void TProductionCluster::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  TAmtBar* valueControl = static_cast<TAmtBar*>(this->ResolveControlByTag(0x76616c75));
  if (valueControl == 0) {
    GAME_FAIL_NIL_POINTER();
  }
  this->TCluster::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x00586a60
void TProductionCluster::SetLaborRate(short laborRate) {
  laborRate8c = laborRate;
}

// FUNCTION: IMPERIALISM 0x00586a80
void TProductionCluster::SetStockpiles(short* current, short* maximum) {
  currentStockpile90 = current;
  maximumStockpile94 = maximum;
}

// FUNCTION: IMPERIALISM 0x00586ab0
void TProductionCluster::SetStockpileRate(short stockpileRate) {
  stockpileRate8e = stockpileRate;
}

TProductionCluster::~TProductionCluster() {}
