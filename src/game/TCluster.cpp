#include "game/TAmtBar.h"
#include "game/TIndustryCluster.h"
#include "game/TRailCluster.h"
#include "game/TShipyardCluster.h"
#include "game/TTradeCluster.h"
#include "game/ui_invalidation_guard.h"
#include "game/quickdraw_rendering.h"
#include "game/TGreatPower.h"
#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"
#include <new>

#include "game/TCluster.h"
#include "game/TControl.h"
#include "game/mfc.h"

#include "decomp_types.h"

// SYNTHETIC: IMPERIALISM 0x00491300
// TCluster::CreateObject

// SYNTHETIC: IMPERIALISM 0x004913e0
// TCluster::GetRuntimeClass

IMPLEMENT_DYNCREATE(TCluster, TControl)

// FUNCTION: IMPERIALISM 0x00491400
TCluster::TCluster() {
  this->eventNumber60 = 5;
  this->selectedChildTag = 0x20202020;
}

// SYNTHETIC: IMPERIALISM 0x00491480
// TCluster::`scalar deleting destructor'
TCluster::~TCluster() {}

// FUNCTION: IMPERIALISM 0x00491650
void TCluster::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xc &&
      reinterpret_cast<TView*>(sourceHandler)->ownerContext == reinterpret_cast<TView*>(this)) {
    POSITION pos = childList44 != 0 ? childList44->GetHeadPosition() : NULL;
    while (pos != NULL) {
      TControl* sibling = reinterpret_cast<TControl*>(childList44->GetNext(pos));
      if (sibling == 0) {
        break;
      }
      if (reinterpret_cast<TEventHandler*>(sibling) != sourceHandler) {
        sibling->HandleEvent(kControlCommandHiliteOff, this, 0);
      }
    }
    selectedChildTag = sourceHandler->controlTag;
  }

  if (commandId == kControlCommandHiliteOn) {
    HiliteState(true, true);
    return;
  }
  if (commandId == kControlCommandHiliteOff) {
    HiliteState(false, true);
    return;
  }
  if (commandId == kControlCommandHiliteToggle) {
    HiliteState(controlState64 == 0, true);
    return;
  }
  TView* child = static_cast<TView*>(GetNextHandler());
  if (child != 0) {
    child->HandleEvent(commandId, sourceHandler, event);
  }
}

// FUNCTION: IMPERIALISM 0x00491770
int TCluster::GetSelectedChildTag() {
  return this->selectedChildTag;
}

// FUNCTION: IMPERIALISM 0x00491790
void TCluster::SetSelectedChildTagAndRefresh(int childTag) {
  selectedChildTag = childTag;
  if (childList44 == 0) {
    return;
  }
  POSITION pos = childList44->GetHeadPosition();
  while (pos != NULL) {
    TControl* child = reinterpret_cast<TControl*>(childList44->GetNext(pos));
    if (child != 0) {
      if (child->controlTag == childTag) {
        child->DoEvent(kControlCommandHiliteOn, this, 0);
      } else {
        child->DoEvent(kControlCommandHiliteOff, this, 0);
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x004918a0
TObject* TCluster::ShallowClone() {
  TCluster* clone = static_cast<TCluster*>(ShallowFree());
  clone->CopyViewStateFromSource(this);
  clone->selectedChildTag = this->selectedChildTag;
  return clone;
}
