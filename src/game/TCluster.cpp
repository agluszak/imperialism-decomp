#include "game/TAmtBar.h"
#include "game/TIndustryCluster.h"
#include "game/TRailCluster.h"
#include "game/TShipyardCluster.h"
#include "game/TTradeCluster.h"
#include "game/trade_quickdraw.h"
#include "game/TGreatPower.h"
#include "game/ui_widget_thunks.h"
#include "game/win_rect.h"
#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"
#include <new>

#include "game/TCluster.h"
#include "game/TControl.h"
#include "game/CPtrList.h"

#include "decomp_types.h"

undefined4 thunk_DispatchPanelControlEvent(void);

// FUNCTION: IMPERIALISM 0x00491400
TCluster::TCluster() {
  this->hasCommandTagResource = 5;
  this->field84 = 0x20202020;
}

// SYNTHETIC: IMPERIALISM 0x00491480
// TCluster::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00491770
int TCluster::GetField84() {
  return this->field84;
}

// FUNCTION: IMPERIALISM 0x00491790
void TCluster::SetControlClassAndRefresh(int classState, int refreshFlag) {
  (void)refreshFlag;
  field84 = classState;
  if (childList44 == 0) {
    return;
  }
  CPtrListNode* node = childList44->headNode;
  while (node != 0) {
    TControl* child = reinterpret_cast<TControl*>(node->data);
    if (child != 0) {
      if (child->controlTag == static_cast<unsigned int>(classState)) {
        child->HandleEvent(0x1f, this, 0);
      } else {
        child->HandleEvent(0x20, this, 0);
      }
    }
    node = node->next;
  }
}

// FUNCTION: IMPERIALISM 0x004918a0
void* TCluster::CloneEngineerDialogStateToNewInstance() {
  TCluster* clone = reinterpret_cast<TCluster*>(HandleTurnEventVtableSlot24CopyPayloadBuffer());
  clone->CopyCityDialogStateFromSource(this);
  clone->field84 = this->field84;
  return clone;
}

void TCluster::DispatchPanelControlEvent(int eventClass, void* eventPayload, int eventFlags) {
  reinterpret_cast<void(__fastcall*)(void*, int, int, void*, int)>(thunk_DispatchPanelControlEvent)(
      this, 0, eventClass, eventPayload, eventFlags);
}
