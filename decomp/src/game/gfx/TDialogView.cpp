#include "game/gfx/TDialogView.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"

IMPLEMENT_DYNCREATE(TDialogView, TView)
// FUNCTION: IMPERIALISM 0x0049d880
void TDialogView::EnsureField48Buffer() {
  int previous = SetGlobalUiInvalidationFlagAndReturnPrevious(0);
  SetGlobalUiInvalidationFlagAndReturnPrevious(previous);
}

// FUNCTION: IMPERIALISM 0x0049d8e0
TDialogView::~TDialogView() {}
