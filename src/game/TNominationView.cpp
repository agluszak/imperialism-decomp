#include "game/TNominationView.h"

#include "game/TApplication.h"
#include "game/TControl.h"
#include "game/global_data_tables.h"

// FUNCTION: IMPERIALISM 0x004305c0
undefined TNominationView::OrphanRetStub_004305c0() {
  return 0;
}

// SYNTHETIC: IMPERIALISM 0x004305e0
// TNominationView::`scalar deleting destructor'
TNominationView::~TNominationView() {}
// SYNTHETIC: IMPERIALISM 0x004fb6e0
// TNominationView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004fb760
// TNominationView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TNominationView, TPicture)

TNominationView::TNominationView() {}

// FUNCTION: IMPERIALISM 0x004fb780
void TNominationView::NoOpUiLifecycleHook(int arg) {
}

// FUNCTION: IMPERIALISM 0x004fb990
void TNominationView::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xa) {
    g_pGlobalUiRootController->PostTurnEventCodeMessage2420(0x7e0);
    return;
  }
  TControl::HandleEvent(commandId, sourceHandler, event);
}
