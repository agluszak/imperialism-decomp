#include "game/TOffersPanelView.h"

#include "game/ui_control_tags.h"
// SYNTHETIC: IMPERIALISM 0x004f8ec0
// TOffersPanelView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004f8f50
// TOffersPanelView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TOffersPanelView, TPanelView)

// FUNCTION: IMPERIALISM 0x004f8f70
TOffersPanelView::TOffersPanelView() : TPanelView(), field68(0), field6c(0) {}

// SYNTHETIC: IMPERIALISM 0x004f8fa0
// TOffersPanelView::`scalar deleting destructor'
TOffersPanelView::~TOffersPanelView() {}

// FUNCTION: IMPERIALISM 0x004f8ff0
void TOffersPanelView::NoOpUiLifecycleHook(int arg) {}

// FUNCTION: IMPERIALISM 0x004f9300
void TOffersPanelView::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  int tag = sourceHandler->controlTag;
  if (commandId == 5 ||
      (commandId == 0xa && (tag == kControlTagAcce || tag == kControlTagReje))) {
    lastNegotiationResponseTag64 = tag;
  }
  TEventHandler::HandleEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x004f9350
void TOffersPanelView::ForwardParam(int param) {}

// FUNCTION: IMPERIALISM 0x004f9420
char TOffersPanelView::DispatchUiMouseEventToChildrenOrSelf_Impl(CPoint* point, int arg2, int arg3,
                                                                 int arg4) {
  (void)point;
  (void)arg2;
  (void)arg3;
  (void)arg4;
  return 0;
}

// FUNCTION: IMPERIALISM 0x004f9450
undefined TOffersPanelView::RunDiplomacyNegotiationPopupAndAwaitResponse() {
  return 0;
}
