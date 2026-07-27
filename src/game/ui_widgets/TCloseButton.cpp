#include "game/ui_widgets/TCloseButton.h"

#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/turn_event_codes.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
// SYNTHETIC: IMPERIALISM 0x00584a50
// TCloseButton::CreateObject

// SYNTHETIC: IMPERIALISM 0x00584ad0
// TCloseButton::GetRuntimeClass

IMPLEMENT_DYNCREATE(TCloseButton, TPictureButton)

// FUNCTION: IMPERIALISM 0x00584af0
TCloseButton::TCloseButton() {}

// SYNTHETIC: IMPERIALISM 0x00584b20
// TCloseButton::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00584b50
TCloseButton::~TCloseButton() {}

// Runs the plain TView press handling (TPictureButton adds none), then closes the screen by
// asking the UI runtime context to rebuild its registered windows. Always reports "handled".
// FUNCTION: IMPERIALISM 0x00584b70
char TCloseButton::HandleMouseDown(const CPoint& point, TToolboxEvent* event, CPoint origin) {
  TView::HandleMouseDown(point, event, origin);
  g_pUiRuntimeContext->DispatchTurnEvent(kTurnEventRebuildRegisteredWindows, 0);
  return 1;
}
