#include "game/TIncludeView.h"
#include "game/CString.h"
#include "game/TView.h"
IMPLEMENT_DYNCREATE(TIncludeView, TView)

TIncludeView::TIncludeView() {}

// SYNTHETIC: IMPERIALISM 0x0048ce40
// TIncludeView::`scalar deleting destructor'
TIncludeView::~TIncludeView() {}

// FUNCTION: IMPERIALISM 0x0048cf10
void TIncludeView::BuildTurnEventFactoryPacket(int arg0, TView* mainView, short eventCode,
                                               void* factoryOut, CString* labelText, int flag) {
  // TODO: port body (turn-event factory packet builder, 0x48cf10).
  (void)arg0;
  (void)mainView;
  (void)eventCode;
  (void)factoryOut;
  (void)labelText;
  (void)flag;
}

// FUNCTION: IMPERIALISM 0x0048cfd0
void TIncludeView::NoOpUiLifecycleHook(int arg) {
}
