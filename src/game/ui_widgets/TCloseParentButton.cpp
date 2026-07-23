#include "game/ui_widgets/TCloseParentButton.h"
#include "game/ui_core/TWindow.h"
// SYNTHETIC: IMPERIALISM 0x00584bb0
// TCloseParentButton::CreateObject

// SYNTHETIC: IMPERIALISM 0x00584c40
// TCloseParentButton::GetRuntimeClass

IMPLEMENT_DYNCREATE(TCloseParentButton, TButton)

// FUNCTION: IMPERIALISM 0x00584c60
TCloseParentButton::TCloseParentButton() {}

// SYNTHETIC: IMPERIALISM 0x00584ce0
// TCloseParentButton::`scalar deleting destructor'
TCloseParentButton::~TCloseParentButton() {}

// FUNCTION: IMPERIALISM 0x00584d30
void TCloseParentButton::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  (void)sourceHandler;
  (void)event;
  if (commandId == GetEventNumber()) {
    if (IsEnabled() != 0 && LogUnhandledDialogMethodAndReturnFalse() == 0) {
      GetWindow()->Close();
    }
  }
}
