#include "game/gfx/TDialogView.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"

IMPLEMENT_DYNCREATE(TDialogView, TView)

// FUNCTION: IMPERIALISM 0x0049d880
void TDialogView::EnsureStylePayload() {
  int previous = SetInvalidationFlag(0);
  SetInvalidationFlag(previous);
}

// FUNCTION: IMPERIALISM 0x0049d8e0
TDialogView::~TDialogView() {}
