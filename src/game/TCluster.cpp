#include "game/TAmtBar.h"
#include "game/TIndustryCluster.h"
#include "game/TRailCluster.h"
#include "game/TShipyardCluster.h"
#include "game/TTradeCluster.h"
#include "game/trade_quickdraw.h"
#include "game/TGreatPower.h"
#include "game/ui_widget_thunks.h"
#include "game/mfc.h"
#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"
#include <new>

#include "game/TCluster.h"
#include "game/TControl.h"
#include "game/mfc.h"

#include "decomp_types.h"

extern "C" CRuntimeClass PTR_s_TCluster_006496c0;



// FUNCTION: IMPERIALISM 0x004913e0
CRuntimeClass* TCluster::GetRuntimeClass() const {
  return &PTR_s_TCluster_006496c0;
}



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
void TCluster::SetControlClassAndRefresh(int classState, int refreshFlag) {
  (void)refreshFlag;
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



// FUNCTION: IMPERIALISM 0x00491b10
undefined TCluster::WrapperFor_FreeHeapBufferIfNotNull_At00491b10() {
  return 0;
}



// FUNCTION: IMPERIALISM 0x00491c80
undefined TCluster::OrphanCallChain_C1_I17_00491c80() {
  return 0;
}



// FUNCTION: IMPERIALISM 0x00491cc0
int * TCluster::RunRegisteredDialogFactoriesByEventCode(int nContextId, int * pEventPacket, int nEventCode, int * pAnchorPoint) {
  return 0;
}



// FUNCTION: IMPERIALISM 0x00491d80
int * TCluster::InvokeDialogFactoryFromPacket(int nContextId, int * pEventPacket, int nEventCode, int * pAnchorPoint) {
  return 0;
}



// FUNCTION: IMPERIALISM 0x00491f90
undefined TCluster::GetTFloatWindowClassNamePointer() {
  return 0;
}



// FUNCTION: IMPERIALISM 0x00492110
undefined TCluster::VTableSlotA1() {
  return 0;
}



// FUNCTION: IMPERIALISM 0x00492310
undefined TCluster::OrphanVtableAssignStub_00492310() {
  return 0;
}



// FUNCTION: IMPERIALISM 0x00492330
undefined TCluster::ResetChildSelectionAndNotifyParent468Alt() {
  return 0;
}



// FUNCTION: IMPERIALISM 0x00492670
undefined TCluster::SerializeRecordList_0x0C_WithBlockPool_C() {
  return 0;
}



// FUNCTION: IMPERIALISM 0x004927e0
undefined TCluster::SerializeRecordList_0x0C_WithBlockPool_D() {
  return 0;
}



// FUNCTION: IMPERIALISM 0x00492950
undefined TCluster::WrapperFor_FreeHeapBufferIfNotNull_At00492950() {
  return 0;
}



// FUNCTION: IMPERIALISM 0x00492980
undefined TCluster::WrapperFor_FreeHeapBufferIfNotNull_At00492980() {
  return 0;
}

void TCluster::Serialize_8c(CArchive& archive) {}

void TCluster::Serialize_a2(CArchive& archive) {}

undefined TCluster::OrphanLeaf_NoCall_Ins05_0048d8a0() { return 0; }

undefined TCluster::AssertMcAppUILine2358() { return 0; }

undefined TCluster::OrphanCallChain_C2_I39_0048d900() { return 0; }

int TCluster::IsActionable() { return 0; }

undefined TCluster::WrapperFor_SetWindowTextOrDelegateToOwner_At0048d9c0() { return 0; }

undefined TCluster::WrapperFor_FID_conflict_GetWindowTextA_At0048d9f0() { return 0; }

undefined TCluster::OrphanCallChain_C1_I08_0048da10() { return 0; }

undefined TCluster::OrphanLeaf_NoCall_Ins03_0048da40() { return 0; }

undefined TCluster::ExecuteViewModalStateWithPushPopChain() { return 0; }

undefined TCluster::OrphanCallChain_C1_I08_0048dc60() { return 0; }

undefined TCluster::OrphanCallChain_C2_I12_0048dc90() { return 0; }

undefined TCluster::OrphanLeaf_NoCall_Ins02_0048dcc0() { return 0; }

undefined TCluster::AssertMcAppUILine2554() { return 0; }

void TCluster::OrphanRetStub_0059add0_af() {}

void TCluster::DispatchEvent() {}

undefined TCluster::OrphanCallChain_C2_I19_0048ddc0() { return 0; }

void TCluster::DispatchSlot9CToLinkedChildren() {}

undefined TCluster::OrphanCallChain_C2_I10_0048e120() { return 0; }

undefined TCluster::WrapperFor_CenterWindowWithinOwnerOrWorkArea_At0048e150() { return 0; }

undefined TCluster::CtrlSlot95_TestPointInBoundsFromSlot128_Impl() { return 0; }

undefined TCluster::GetTEventHandlerClassNamePointer_100() { return 0; }

undefined TCluster::VTableSlot101() { return 0; }

undefined TCluster::GetTEventHandlerClassNamePointer_102() { return 0; }

undefined TCluster::GetTEventHandlerClassNamePointer_103() { return 0; }

void TCluster::Free() {}

class TView* TCluster::OwnerPanel() { return 0; }

class TView* TCluster::QueryOwnerContextPanel() { return 0; }

void TCluster::vmethod_0078(int* point ) {}

void TCluster::vmethod_0076(int* point ) {}

void TCluster::DispatchVslot134WithRectAndRectPlus8_Impl() {}

undefined TCluster::CtrlSlot103_SubtractPosAndDispatchSlot19C_Impl() { return 0; }

TObject* TCluster::ShallowClone_a8() { return 0; }
