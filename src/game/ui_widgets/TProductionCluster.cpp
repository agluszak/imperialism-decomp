#include "game/ui_widgets/TIndustryCluster.h"
#include "game/ui_core/TNumberText.h"
#include "game/ui_tags_common.h"
#include "game/ui_widgets/TRailCluster.h"
#include "game/ui_widgets/TShipyardCluster.h"
#include "game/ui_widgets/TTradeCluster.h"
#include "game/nation/TGreatPower.h"
#include "game/mfc.h"
#include "game/ui_core/TViewMgr.h"
#include "game/quickdraw_guards.h"

#include "game/ui_widgets/TAmtBar.h"
#include "game/ui_widgets/TProductionCluster.h"

#include "game/GameAssert.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/ui_core/quickdraw_rendering.h"

#include <new>

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

// FUNCTION: IMPERIALISM 0x005869a0
TProductionCluster::~TProductionCluster() {}

// FUNCTION: IMPERIALISM 0x005869c0
void TProductionCluster::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  TNumberText* valueControl = static_cast<TNumberText*>(this->ResolveControlByTag(kControlTagValu));
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
