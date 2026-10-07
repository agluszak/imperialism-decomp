#include "game/navy_ui/TNavyToolbarCluster.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_military.h"
#include "game/ui_core/TWindow.h"

#include "game/CSubViewIterator.h"
#include "game/ui_core/TCluster.h"
#include "game/ui_core/TEventHandler.h"
#include "game/map/TMapUberPicture.h"
#include "game/navy/TOcean.h"
#include "game/navy/TTaskForce.h"
#include "game/ui_core/TViewMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"

IMPLEMENT_DYNCREATE(TNavyToolbarCluster, TUberCluster)

// FUNCTION: IMPERIALISM 0x005694d0
TNavyToolbarCluster::TNavyToolbarCluster() {}

// FUNCTION: IMPERIALISM 0x00569530
TNavyToolbarCluster::~TNavyToolbarCluster() {}

// FUNCTION: IMPERIALISM 0x00569550
void TNavyToolbarCluster::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xc) {
    unsigned int idx = sourceHandler->controlTag - kControlTagAgr0;
    if (idx < 3) {
      TView* main = GetWindow()->ResolveControlByTag(kControlTagMain);
      main->AssertValid();
      TTaskForce* order = GetActiveMapOrderEntry();
      if (order != NULL) {
        order->SetAggression(idx);
      }
    }
  } else if (commandId == 0xa) {
    unsigned int tag = sourceHandler->controlTag;
    switch (tag) {
    case kControlTagDfnd:
    case kControlTagDone: {
      TTaskForce* order = GetActiveMapOrderEntry();
      if (order != NULL) {
        order->DropShips(tag == kControlTagDone);
      }
      g_pViewMgr->mapUberPicture->CycleMapInteractionSelectionAfterHandledClick();
      break;
    }
    case kControlTagNext:
      g_pViewMgr->mapUberPicture->CycleMapInteractionSelectionAfterHandledClick();
      break;
    case kControlTagBomb:
      if ((GetAsyncKeyState(0x11) & 0x8000) == 0) {
        g_pViewMgr->MakeNavyRosterDialog(GetActiveMapOrderEntry());
      } else {
        g_pViewMgr->ShowNavyRosterDialogAndApplySelection();
      }
      break;
    default:
      break;
    }
  }
  TCluster::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x005696d0
char TNavyToolbarCluster::IsTradeControlAtMinimum() {
  return 1;
}

// FUNCTION: IMPERIALISM 0x005696f0
void TNavyToolbarCluster::SetSelectedChildTagAndRefresh(int childTag) {
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
    TView* oceanDialog = GetWindow()->ResolveControlByTag(kControlTagDOOG); // 'DOOG'
    oceanDialog->AssertValid();
    oceanDialog->DoEvent(0xc, selectedChild, 0);
  }
}
