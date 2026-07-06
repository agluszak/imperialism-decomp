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
#include "game/ui_widget_thunks.h"

#include <new>

#include "game/mfc.h"

// SYNTHETIC: IMPERIALISM 0x00586840
// TProductionCluster::CreateObject
// SYNTHETIC: IMPERIALISM 0x00586900
// TProductionCluster::GetRuntimeClass

IMPLEMENT_DYNCREATE(TProductionCluster, TUberCluster)

// FUNCTION: IMPERIALISM 0x00586920
TProductionCluster::TProductionCluster()
    : TUberCluster(), field88(0), field8c(0), field8e(0), field90(0), field94(0) {}

// SYNTHETIC: IMPERIALISM 0x00586970
// TProductionCluster::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x005869c0
void TProductionCluster::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  TAmtBar* valueControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(0x76616c75));
  if (valueControl == 0) {
    GAME_FAIL_NIL_POINTER();
  }
  this->TCluster::HandleEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x00586a60
void TProductionCluster::ApplyMoveValue(int value) {
  field8c = value;
}

// FUNCTION: IMPERIALISM 0x00586a80
int TProductionCluster::GetControlFlag(int value90, int value94) {
  field90 = value90;
  field94 = value94;
  return 0;
}

// FUNCTION: IMPERIALISM 0x00586ab0
int TProductionCluster::NotifyControlSelectionChange(void* boundEntry, int arg2) {
  field8e = (int)boundEntry;
  return 0;
}

TProductionCluster::~TProductionCluster() {}
