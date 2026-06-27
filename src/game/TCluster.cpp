#include "game/TAmtBar.h"
#include "game/TIndustryCluster.h"
#include "game/TRailCluster.h"
#include "game/TShipyardCluster.h"
#include "game/TTradeCluster.h"
#include "game/trade_quickdraw.h"
#include "game/TGreatPower.h"
#include "game/ui_widget_thunks.h"
#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"
#include <new>

#include "game/TCluster.h"
#include "game/TControl.h"
#include "game/mfc.h"

#include "decomp_types.h"

extern "C" CRuntimeClass PTR_s_TCluster_006496c0;
IMPLEMENT_DYNCREATE(TCluster, TControl)

// FUNCTION: IMPERIALISM 0x00491400
TCluster::TCluster() {
  this->hasCommandTagResource = 5;
  this->field84 = 0x20202020;
}

// SYNTHETIC: IMPERIALISM 0x00491480
// TCluster::`scalar deleting destructor'
TCluster::~TCluster() {}

// FUNCTION: IMPERIALISM 0x00491650
void TCluster::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xc &&
      reinterpret_cast<TView*>(sourceHandler)->ownerContext == reinterpret_cast<TView*>(this)) {
    POSITION pos = childList44 != 0 ? childList44->GetHeadPosition() : NULL;
    while (pos != NULL) {
      TControl* sibling = reinterpret_cast<TControl*>(childList44->GetNext(pos));
      if (sibling == 0) {
        break;
      }
      if (reinterpret_cast<TEventHandler*>(sibling) != sourceHandler) {
        sibling->DispatchEvent(0x20, this, 0);
      }
    }
    field84 = sourceHandler->controlTag;
  }

  if (commandId == 0x1f) {
    SetControlStateFlagAndMaybeRefresh(true, true);
    return;
  }
  if (commandId == 0x20) {
    SetControlStateFlagAndMaybeRefresh(false, true);
    return;
  }
  if (commandId == 0x21) {
    SetControlStateFlagAndMaybeRefresh(commandTagResourceByte == 0, true);
    return;
  }
  TView* child = reinterpret_cast<TView*>(QueryStepValue());
  if (child != 0) {
    child->DispatchEvent(commandId, sourceHandler, event);
  }
}

// FUNCTION: IMPERIALISM 0x00491770
int TCluster::GetField84() {
  return this->field84;
}

// FUNCTION: IMPERIALISM 0x00491790
void TCluster::SetControlClassAndRefresh(int classState) {
  field84 = classState;
  if (childList44 == 0) {
    return;
  }
  POSITION pos = childList44->GetHeadPosition();
  while (pos != NULL) {
    TControl* child = reinterpret_cast<TControl*>(childList44->GetNext(pos));
    if (child != 0) {
      if (child->controlTag == static_cast<unsigned int>(classState)) {
        child->HandleEvent(0x1f, this, 0);
      } else {
        child->HandleEvent(0x20, this, 0);
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x004918a0
TObject* TCluster::ShallowClone() {
  TCluster* clone = static_cast<TCluster*>(ShallowFree());
  clone->CopyCityDialogStateFromSource(this);
  clone->field84 = this->field84;
  return clone;
}
