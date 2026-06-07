#include "game/TButton.h"

undefined4 TemporarilyClearAndRestoreUiInvalidationFlag(void);

// FUNCTION: IMPERIALISM 0x0048ece0
TButton::TButton() : TControl() {
  TemporarilyClearAndRestoreUiInvalidationFlag();
}
