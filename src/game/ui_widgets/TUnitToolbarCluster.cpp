#include "game/ui_widgets/TIndustryCluster.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_widgets.h"
#include "game/ui_core/TWindow.h"
#include "game/ui_widgets/TRailCluster.h"
#include "game/ui_widgets/TShipyardCluster.h"
#include "game/ui_widgets/TTradeCluster.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/nation/TGreatPower.h"
#include "game/mfc.h"
#include "game/ui_core/TViewMgr.h"
#include "game/quickdraw_guards.h"

#include "game/ui_widgets/TAmtBar.h"
#include "game/ui_widgets/TUnitToolbarCluster.h"
#include "game/GameAssert.h"

#include <new>

#include "game/ui_core/TApplication.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"

extern "C" {
char g_vtblTUnitToolbarCluster = 0;
}

// SYNTHETIC: IMPERIALISM 0x00585f70
// TUnitToolbarCluster::CreateObject
// SYNTHETIC: IMPERIALISM 0x00585ff0
// TUnitToolbarCluster::GetRuntimeClass

IMPLEMENT_DYNCREATE(TUnitToolbarCluster, TUberCluster)

// FUNCTION: IMPERIALISM 0x00586010
TUnitToolbarCluster::TUnitToolbarCluster() : TUberCluster() {}

// SYNTHETIC: IMPERIALISM 0x00586040
// TUnitToolbarCluster::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00586090
void TUnitToolbarCluster::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  this->TCluster::DoEvent(commandId, sourceHandler, event);

  if (!(((g_pApplicationUiRootController->screenModeAt24 == 1) && (commandId == 0x68)) ||
        (commandId == 0x67) || (commandId == 10) || (commandId == 0x0c))) {
    return;
  }

  void* ownerPanel = this->GetWindow();
  TView* mainControl = reinterpret_cast<TView*>(ownerPanel)->ResolveControlByTag(kControlTagMain);
  if (mainControl == 0) {
    GAME_FAIL_NIL_POINTER();
    return;
  }

  mainControl->DoEvent(0, 0, 0);
}

// FUNCTION: IMPERIALISM 0x00586150
int TUnitToolbarCluster::IsTradeControlAtMinimum() {
  return 1;
}

// FUNCTION: IMPERIALISM 0x00586170
void TUnitToolbarCluster::SetSelectedChildTagAndRefresh(int childTag) {
  selectedChildTag = childTag;

  TView* resourceControl =
      reinterpret_cast<TView*>(this)->ResolveControlByTag(kControlTagReso + childTag);
  if (resourceControl == 0) {
    GAME_FAIL_NIL_POINTER();
    return;
  }

  resourceControl->DoEvent(0, 0, 0);
}

TUnitToolbarCluster::~TUnitToolbarCluster() {}
