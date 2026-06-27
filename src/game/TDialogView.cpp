#include "game/TDialogView.h"
#include "game/ui_runtime_globals.h"

extern "C" char g_pClassDescTDialogView;
IMPLEMENT_DYNCREATE(TDialogView, TView)

TDialogView::TDialogView() {}

// Slot 0x42 override: pulse the global UI-invalidation flag off and back to its prior
// value (a no-op refresh barrier), rather than TView's field48-buffer allocation.
// FUNCTION: IMPERIALISM 0x0049d880
void TDialogView::EnsureField48Buffer() {
  undefined4 previous = SetGlobalUiInvalidationFlagAndReturnPrevious(0);
  SetGlobalUiInvalidationFlagAndReturnPrevious(previous);
}

// SYNTHETIC: IMPERIALISM 0x0049d8b0
// TDialogView::`scalar deleting destructor'
TDialogView::~TDialogView() {}
