#include "game/TTradeBookView.h"

#include "game/TControl.h"
#include "game/TEventHandler.h"
#include "game/ui_control_tags.h"

// SYNTHETIC: IMPERIALISM 0x00435690
// TTradeBookView::`scalar deleting destructor'
TTradeBookView::~TTradeBookView() {}
// SYNTHETIC: IMPERIALISM 0x005bde30
// TTradeBookView::CreateObject

// SYNTHETIC: IMPERIALISM 0x005bded0
// TTradeBookView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTradeBookView, TView)

TTradeBookView::TTradeBookView() {}

// FUNCTION: IMPERIALISM 0x005bdef0
void TTradeBookView::NoOpUiLifecycleHook(int arg) {
}

// FUNCTION: IMPERIALISM 0x005be370
void TTradeBookView::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xa) {
    if (sourceHandler->controlTag == kControlTagRcor) {
      UpdatePagerButtonStatesAndRefreshPanels(field74 + 1);
    } else if (sourceHandler->controlTag == kControlTagLcor) {
      UpdatePagerButtonStatesAndRefreshPanels(field74 - 1);
    }
  }
  TEventHandler::HandleEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x005be3e0
void TTradeBookView::UpdatePagerButtonStatesAndRefreshPanels(int page) {
  field60->SetState(page != 1, 0);
  field60->SetEnabled(page != 1, 1);
  bool hasMore = page + 2 <= field70;
  field64->SetState(hasMore, 0);
  field64->SetEnabled(hasMore, 1);
  field68->ReturnZeroFromUiSlot6C(page);
  field6c->ReturnZeroFromUiSlot6C(page);
}
