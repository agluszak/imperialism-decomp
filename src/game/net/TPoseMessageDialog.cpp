#include "game/net/TPoseMessageDialog.h"

#include "game/gfx/TAmbitApplication.h"
#include "game/ui_core/TApplication.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"

// FUNCTION: IMPERIALISM 0x0054aff0
void TPoseMessageDialog::DoIt() {}

// SYNTHETIC: IMPERIALISM 0x0054b010
// TPoseMessageDialog::`scalar deleting destructor'
TPoseMessageDialog::~TPoseMessageDialog() {}
// SYNTHETIC: IMPERIALISM 0x0054b060
// TPoseMessageDialog::CreateObject

// SYNTHETIC: IMPERIALISM 0x0054b0d0
// TPoseMessageDialog::GetRuntimeClass

IMPLEMENT_DYNCREATE(TPoseMessageDialog, TCommand)

// FUNCTION: IMPERIALISM 0x0054b0f0
void __cdecl QueuePoseMessageDialogForNationSlot(int nationSlot) {
  TPoseMessageDialog* command = new TPoseMessageDialog();
  command->kickedByNationSlot18 = nationSlot;
  command->InitializeRangePair(0x706f7365, g_pGlobalUiRootController, 0, 0, 0); // 'pose'
  g_pGlobalUiRootController->DispatchUiSelectionToHandler(command);
}
