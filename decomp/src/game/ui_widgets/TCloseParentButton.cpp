#include "game/ui_widgets/TCloseParentButton.h"
#include "game/ui_core/TWindow.h"

IMPLEMENT_DYNCREATE(TCloseParentButton, TButton)

// FUNCTION: IMPERIALISM 0x00584c60
TCloseParentButton::TCloseParentButton() {}

// FUNCTION: IMPERIALISM 0x00584d10
TCloseParentButton::~TCloseParentButton() {}

// FUNCTION: IMPERIALISM 0x00584d30
void TCloseParentButton::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == GetEventNumber()) {
    if (IsEnabled() != 0 && !LogUnhandledDialogMethodAndReturnFalse()) {
      GetWindow()->Close();
    }
  }
}
