#include "game/ui_widgets/TAmtBar.h"
#include "game/ui_tags_common.h"
#include "game/ui_widgets/TIndustryCluster.h"
#include "game/ui_widgets/TRailCluster.h"
#include "game/ui_widgets/TShipyardCluster.h"
#include "game/ui_widgets/TTradeCluster.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_core/TViewMgr.h"
#include "game/quickdraw_guards.h"
#include <new>

#include "game/ui_core/TCluster.h"
#include "game/ui_core/TControl.h"
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
  this->selectedChildTag = kControlTagSpSpSpSp;
}

// SYNTHETIC: IMPERIALISM 0x00491480
// TCluster::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004914b0
TCluster::~TCluster() {}

// Frame this cluster into `parent`. The host window is inherited from the parent when
// one is supplied, the control tag is blanked to four spaces, the enable/visible pair is
// set, and the offset/size point pairs are copied into the frame fields. Registration as
// a child happens through AttachChildControl (slot 0x5c) only when a parent exists, and
// the resource context is cleared last.
// FUNCTION: IMPERIALISM 0x004915d0
void TCluster::InitializeClusterFrameAndAttachToParent(TView* parent, POINT* offset, POINT* size) {
  if (parent != nullptr) {
    nativeWindow50 = parent->nativeWindow50;
  }
  controlTag = kControlTagSpSpSpSp;
  enabled = 1;
  viewEnabled = 1;
  nextHandler = parent;
  ownerLocalX = offset->x;
  ownerLocalY = offset->y;
  frameWidth34 = size->x;
  frameHeight38 = size->y;
  if (parent != nullptr) {
    parent->AttachChildControl(this, 0);
  }
  resourceContext = nullptr;
}

// FUNCTION: IMPERIALISM 0x00491650
void TCluster::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xc && static_cast<TView*>(sourceHandler)->ownerContext == this) {
    POSITION pos = childList44 != 0 ? childList44->GetHeadPosition() : NULL;
    while (pos != NULL) {
      TControl* sibling = static_cast<TControl*>(childList44->GetNext(pos));
      if (sibling == 0) {
        break;
      }
      if (sibling != sourceHandler) {
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
    TControl* child = static_cast<TControl*>(childList44->GetNext(pos));
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
