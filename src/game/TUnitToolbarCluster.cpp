#include "game/TIndustryCluster.h"
#include "game/TRailCluster.h"
#include "game/TShipyardCluster.h"
#include "game/TTradeCluster.h"
#include "game/ui_invalidation_guard.h"
#include "game/quickdraw_rendering.h"
#include "game/TGreatPower.h"
#include "game/mfc.h"
#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"

#include "game/TAmtBar.h"
#include "game/TUnitToolbarCluster.h"
#include "game/GameAssert.h"

#include <new>

#include "game/TApplication.h"

extern "C" {
char g_vtblTUnitToolbarCluster = 0;
}

// FUNCTION: IMPERIALISM 0x00585f70
TUnitToolbarCluster* TUnitToolbarCluster::CreateInstance() {
  return new TUnitToolbarCluster();
}
IMPLEMENT_DYNCREATE(TUnitToolbarCluster, TUberCluster)

// FUNCTION: IMPERIALISM 0x00586010
TUnitToolbarCluster::TUnitToolbarCluster() : TUberCluster() {}

// SYNTHETIC: IMPERIALISM 0x00586040
// TUnitToolbarCluster::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00586090
void TUnitToolbarCluster::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  this->TCluster::HandleEvent(commandId, sourceHandler, event);

  if (!(((g_pApplicationUiRootController->screenModeAt24 == 1) && (commandId == 0x68)) ||
        (commandId == 0x67) || (commandId == 10) || (commandId == 0x0c))) {
    return;
  }

  void* ownerPanel = this->OwnerPanel();
  TControl* mainControl = reinterpret_cast<TView*>(ownerPanel)->ResolveControlByTag(0x6d61696e);
  if (mainControl == 0) {
    GAME_FAIL_NIL_POINTER();
    return;
  }

  mainControl->HandleEvent(0, 0, 0);
}

// FUNCTION: IMPERIALISM 0x00586150
int TUnitToolbarCluster::IsTradeControlAtMinimum() {
  return 1;
}

// FUNCTION: IMPERIALISM 0x00586170
void TUnitToolbarCluster::SetControlClassAndRefresh(int classState) {
  *reinterpret_cast<int*>(reinterpret_cast<char*>(this) + 0x84) = classState;

  TControl* resourceControl =
      reinterpret_cast<TView*>(this)->ResolveControlByTag(0x7265736f + classState);
  if (resourceControl == 0) {
    GAME_FAIL_NIL_POINTER();
    return;
  }

  resourceControl->HandleEvent(0, 0, 0);
}

TUnitToolbarCluster::~TUnitToolbarCluster() {}
