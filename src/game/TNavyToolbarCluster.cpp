#include "game/TNavyToolbarCluster.h"

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
        // Ctrl+'bomb' should run a map-order page-selection dialog (0x5dd450, 635 bytes,
        // dynamic TSuperNavyRoster construction + dialog scaffolding) -- not yet ported;
        // left as a gap rather than a phantom empty stub (blocked by the noop gate).
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
void TNavyToolbarCluster::SetControlClassAndRefresh(int classState) {
  (void)classState;
}
