#include "game/TNavyToolbarCluster.h"
#include "game/TWindow.h"

#include "game/CSubViewIterator.h"
#include "game/TCluster.h"
#include "game/TEventHandler.h"
#include "game/TMapUberPicture.h"
#include "game/TOcean.h"
#include "game/TTaskForce.h"
#include "game/TViewMgr.h"
#include "game/global_data_tables.h"
#include "game/ui_control_tags.h"
// SYNTHETIC: IMPERIALISM 0x00569430
// TNavyToolbarCluster::CreateObject

// SYNTHETIC: IMPERIALISM 0x005694b0
// TNavyToolbarCluster::GetRuntimeClass

IMPLEMENT_DYNCREATE(TNavyToolbarCluster, TUberCluster)

// FUNCTION: IMPERIALISM 0x005694d0
TNavyToolbarCluster::TNavyToolbarCluster() {}

// SYNTHETIC: IMPERIALISM 0x00569500
// TNavyToolbarCluster::`scalar deleting destructor'
TNavyToolbarCluster::~TNavyToolbarCluster() {}

// FUNCTION: IMPERIALISM 0x00569550
void TNavyToolbarCluster::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xc) {
    unsigned int idx = sourceHandler->controlTag - kControlTagAgr0;
    if (idx < 3) {
      TView* main = GetWindow()->ResolveControlByTag(kControlTagMain);
      main->GetNextHandler();
      TTaskForce* order = GetActiveMapOrderEntry();
      if (order != nullptr) {
        order->SetAggression(idx);
      }
    }
  } else if (commandId == 0xa) {
    unsigned int tag = sourceHandler->controlTag;
    switch (tag) {
    case kControlTagDfnd:
    case kTagDone: {
      TTaskForce* order = GetActiveMapOrderEntry();
      if (order != nullptr) {
        order->DropShips(tag == kTagDone);
      }
      g_pUiRuntimeContext->mapUberPictureF0->CycleMapInteractionSelectionAfterHandledClick();
      break;
    }
    case kControlTagNext:
      g_pUiRuntimeContext->mapUberPictureF0->CycleMapInteractionSelectionAfterHandledClick();
      break;
    case kControlTagBomb:
      if ((GetAsyncKeyState(0x11) & 0x8000) == 0) {
        g_pUiRuntimeContext->MakeNavyRosterDialog(GetActiveMapOrderEntry());
      } else {
        g_pUiRuntimeContext->ShowNavyRosterDialogAndApplySelection();
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

// FUNCTION: IMPERIALISM 0x005696f0
void TNavyToolbarCluster::SetSelectedChildTagAndRefresh(int childTag) {
  CSubViewIterator iterator(this);
  TView* selectedChild = 0;
  TView* child = iterator.FirstSubView();
  while (iterator.MoreSubViews()) {
    if (child->controlTag == childTag) {
      child->HandleEvent(0x1f, this, 0);
      selectedChild = child;
    } else {
      child->HandleEvent(0x20, this, 0);
    }
    child = iterator.NextSubView();
  }

  selectedChildTag = childTag;
  if (selectedChild != 0) {
    TView* oceanDialog = GetWindow()->ResolveControlByTag(0x444f4f47); // 'DOOG'
    oceanDialog->AssertValid();
    oceanDialog->HandleEvent(0xc, selectedChild, 0);
  }
}
