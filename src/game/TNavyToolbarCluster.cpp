#include "game/TNavyToolbarCluster.h"

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
void TNavyToolbarCluster::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xc) {
    unsigned int idx = sourceHandler->controlTag - kControlTagAgr0;
    if (idx < 3) {
      TView* main = OwnerPanel()->ResolveControlByTag(kControlTagMain);
      main->QueryStepValue();
      TTaskForce* order = GetActiveMapOrderEntry();
      if (order != nullptr) {
        order->ResetOrderTypeAndStrengthDword(idx);
      }
    }
  } else if (commandId == 0xa) {
    unsigned int tag = sourceHandler->controlTag;
    switch (tag) {
    case kControlTagDfnd:
    case kTagDone: {
      TTaskForce* order = GetActiveMapOrderEntry();
      if (order != nullptr) {
        order->ApplyTaskForceSelectionModeForCurrentNationOrders(tag == kTagDone);
      }
      g_pUiRuntimeContext->mapUberPictureF0->CycleMapInteractionSelectionAfterHandledClick();
      break;
    }
    case kControlTagNext:
      g_pUiRuntimeContext->mapUberPictureF0->CycleMapInteractionSelectionAfterHandledClick();
      break;
    case kControlTagBomb:
      if ((GetAsyncKeyState(0x11) & 0x8000) == 0) {
        g_pUiRuntimeContext->HandleTurnEventDialogFactorySlotF0(GetActiveMapOrderEntry());
      }
      // TODO: Ctrl+'bomb' should run a map-order page-selection dialog (0x5dd450, 635
      // bytes). Decoded structure: resolves the turn-event dialog node for message
      // context 0x2506, constructs a `new TSuperNavyRoster()` (already a real class,
      // TSuperNavyRoster.h -- field84/field88 already declared and match this
      // constructor's own writes), and calls its slot 0x1b8
      // PopulateNavyOrderPageEntriesByMapContext(int, int*) with 2 real args (its current
      // header declaration is a stale 0-arg placeholder). That populate method (already
      // claimed as a stub in TSuperNavyRoster.cpp, 0x00 score) is itself a genuinely large
      // second function: iterates g_pMapActionContextListHead's TZone list matching
      // per-zone map orders and builds a linked list of `TMiniShipLine` row widgets --
      // TMiniShipLine::CreateLineItemView is now ported (62.92%), so this class-recovery
      // dependency is resolved. Both this constructor and
      // PopulateNavyOrderPageEntriesByMapContext remain independent big-function ports;
      // left unmodeled here rather than faked (blocked by the noop gate).
      break;
    default:
      break;
    }
  }
  TCluster::HandleEvent(commandId, sourceHandler, event);
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
    TView* oceanDialog = OwnerPanel()->ResolveControlByTag(0x444f4f47); // 'DOOG'
    oceanDialog->AssertValid();
    oceanDialog->HandleEvent(0xc, selectedChild, 0);
  }
}
