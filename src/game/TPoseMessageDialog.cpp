#include "game/TPoseMessageDialog.h"

#include "game/TAmbitApplication.h"
#include "game/TApplication.h"
#include "game/global_data_tables.h"
#include "game/multiplayer_session_tags.h"

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
  command->InitializeRangePair(kSessionTagPose, g_pGlobalUiRootController, 0, 0, 0); // 'pose'
  g_pGlobalUiRootController->DispatchUiSelectionToHandler(command);
}
