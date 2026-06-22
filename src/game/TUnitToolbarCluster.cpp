#include "game/TIndustryCluster.h"
#include "game/TRailCluster.h"
#include "game/TShipyardCluster.h"
#include "game/TTradeCluster.h"
#include "game/trade_quickdraw.h"
#include "game/TGreatPower.h"
#include "game/mfc.h"
#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"

#include "game/TAmtBar.h"
#include "game/TUnitToolbarCluster.h"
#include "game/GameAssert.h"
#include "game/UiRuntimeContext.h"

#include <new>

#include "game/TApplication.h"
#include "game/mfc.h"

extern "C" {
CRuntimeClass g_pClassDescTUnitToolbarCluster = {nullptr, 0, 0, nullptr, nullptr};
char g_vtblTUnitToolbarCluster = 0;
}



// FUNCTION: IMPERIALISM 0x00585f70
TUnitToolbarCluster* TUnitToolbarCluster::CreateInstance() {
  return new TUnitToolbarCluster();
}



// FUNCTION: IMPERIALISM 0x00585ff0
CRuntimeClass* TUnitToolbarCluster::GetRuntimeClass() const {
  return &g_pClassDescTUnitToolbarCluster;
}



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
void TUnitToolbarCluster::UpdateTradeResourceSelectionByIndex(int nResourceIndex) {
  *reinterpret_cast<int*>(reinterpret_cast<char*>(this) + 0x84) = nResourceIndex;

  TControl* resourceControl =
      reinterpret_cast<TView*>(this)->ResolveControlByTag(0x7265736f + nResourceIndex);
  if (resourceControl == 0) {
    GAME_FAIL_NIL_POINTER();
    return;
  }

  resourceControl->HandleEvent(0, 0, 0);
}


TUnitToolbarCluster::~TUnitToolbarCluster() {}
