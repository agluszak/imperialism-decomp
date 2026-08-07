#include "game/gfx/TDialogView.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"

// SYNTHETIC: IMPERIALISM 0x0049d6f0
// TDialogView::CreateObject

// SYNTHETIC: IMPERIALISM 0x0049d790
// TDialogView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TDialogView, TView)
// Slot 0x42 override: pulse the global UI-invalidation flag off and back to its prior
// value (a no-op refresh barrier), rather than TView's stylePayload48-buffer allocation.
// FUNCTION: IMPERIALISM 0x0049d880
void TDialogView::EnsureField48Buffer() {
  int previous = SetGlobalUiInvalidationFlagAndReturnPrevious(0);
  SetGlobalUiInvalidationFlagAndReturnPrevious(previous);
}

// SYNTHETIC: IMPERIALISM 0x0049d8b0
// TDialogView::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x0049d8e0
TDialogView::~TDialogView() {}
