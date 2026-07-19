#include "game/TMinisterView.h"

#include "game/TAmbitApplication.h"
#include "game/TDisplayMgr.h"
#include "game/TEventHandler.h"
#include "game/TWindow.h"
#include "game/global_data_tables.h"
#include "game/ui_control_tags.h"
// SYNTHETIC: IMPERIALISM 0x004f2bb0
// TMinisterView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004f2c40
// TMinisterView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMinisterView, TView)

// FUNCTION: IMPERIALISM 0x004f2c60
TMinisterView::TMinisterView() : TView(), field60(0) {}

// SYNTHETIC: IMPERIALISM 0x004f2c90
// TMinisterView::`scalar deleting destructor'
TMinisterView::~TMinisterView() {}

// FUNCTION: IMPERIALISM 0x004f2ce0
undefined TMinisterView::OrphanLeaf_NoCall_Ins04_004f2ce0(short param_1) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004f2d10
char TMinisterView::DispatchUiMouseEventToChildrenOrSelf_Impl(CPoint* point, int arg2, int arg3,
                                                              int arg4) {
  (void)point;
  (void)arg2;
  (void)arg3;
  (void)arg4;
  return 0;
}

// FUNCTION: IMPERIALISM 0x004f2e00
void TMinisterView::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  int tag = sourceHandler->controlTag;
  if (commandId == 0xa) {
    if (tag == kControlTagOkay) {
      OrphanLeaf_NoCall_Ins03_004f2ea0();
      TWindow* owner = static_cast<TWindow*>(OwnerPanel());
      g_pGlobalUiRootController->CloseAndFreeWindow(owner);
      return;
    }
    if (tag == kControlTagBack) {
      OrphanLeaf_NoCall_Ins03_004f2ea0();
      return;
    }
  }
  TEventHandler::HandleEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x004f2ea0
undefined TMinisterView::OrphanLeaf_NoCall_Ins03_004f2ea0() {
  return g_pDisplayMgr->DispatchUiWindowStatusTickForClass99Windows();
}

// FUNCTION: IMPERIALISM 0x004f2ec0
undefined TMinisterView::OrphanCallChain_C2_I08_004f2ec0(undefined4 param_1) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004f2ef0
undefined TMinisterView::OrphanCallChain_C1_I09_004f2ef0() {
  return 0;
}
