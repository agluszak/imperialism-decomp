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
#include "game/CSubViewIterator.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"

IMPLEMENT_DYNCREATE(TUnitToolbarCluster, TUberCluster)

// FUNCTION: IMPERIALISM 0x00586070
TUnitToolbarCluster::~TUnitToolbarCluster() {}

// FUNCTION: IMPERIALISM 0x00586090
void TUnitToolbarCluster::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  TCluster::DoEvent(commandId, sourceHandler, event);

  if (((g_pApplication->screenMode != 1) || (commandId != 0x68)) && (commandId != 0x67) &&
      (commandId != 10) && (commandId != 0x0c)) {
    return;
  }

  TWindow* ownerPanel = GetWindow();
  TView* mainControl = ownerPanel->FindSubView(kControlTagMain);
  if (mainControl == 0) {
    GAME_FAIL_NIL_POINTER();
    return;
  }

  mainControl->DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x00586150
bool TUnitToolbarCluster::IsTradeControlAtMinimum() {
  return true;
}

// FUNCTION: IMPERIALISM 0x00586170
void TUnitToolbarCluster::SetCurrentChoice(int childTag) {
  CSubViewIterator iterator(this);
  TView* selectedChild = 0;
  TView* child = iterator.FirstSubView();
  while (iterator.MoreSubViews()) {
    if (child->controlTag == childTag) {
      child->DoEvent(kControlCommandHiliteOn, this, 0);
      selectedChild = child;
    } else {
      child->DoEvent(kControlCommandHiliteOff, this, 0);
    }
    child = iterator.NextSubView();
  }

  selectedChildTag = childTag;
  if (selectedChild != 0) {
    TView* dialog = GetWindow()->FindSubView(kControlTagDialog);
    dialog->AssertValid();
    dialog->DoEvent(0xc, selectedChild, 0);
  }
}
