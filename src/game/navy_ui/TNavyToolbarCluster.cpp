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
// SYNTHETIC: IMPERIALISM 0x00569430
// TNavyToolbarCluster::CreateObject

// SYNTHETIC: IMPERIALISM 0x005694b0
// TNavyToolbarCluster::GetRuntimeClass

IMPLEMENT_DYNCREATE(TNavyToolbarCluster, TUberCluster)

// FUNCTION: IMPERIALISM 0x005694d0
TNavyToolbarCluster::TNavyToolbarCluster() {}

// SYNTHETIC: IMPERIALISM 0x00569500
// TNavyToolbarCluster::`scalar deleting destructor'
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
      if (order != nullptr) {
        order->SetAggression(idx);
      }
    }
  } else if (commandId == 0xa) {
    unsigned int tag = sourceHandler->controlTag;
    switch (tag) {
    case kControlTagDfnd:
    case kControlTagDone: {
      TTaskForce* order = GetActiveMapOrderEntry();
      if (order != nullptr) {
        order->DropShips(tag == kControlTagDone);
      }
      g_pViewMgr->mapUberPictureF0->CycleMapInteractionSelectionAfterHandledClick();
      break;
    }
    case kControlTagNext:
      g_pViewMgr->mapUberPictureF0->CycleMapInteractionSelectionAfterHandledClick();
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
int TNavyToolbarCluster::IsTradeControlAtMinimum() {
  return 0;
}

// All three dispatches here go through byte 0x3c = slot 0x0f = DoEvent
// (0x0056972f/0x0056973f/0x0056978a), not slot 0x10 = HandleEvent at byte 0x40.
// The two are one hop apart: HandleEvent forwards to DoEvent on the same object,
// while DoEvent forwards to HandleEvent on the next handler.
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
