#include "game/net/TPoseMessageDialog.h"
#include "game/multiplayer_session_tags.h"

#include "game/gfx/TAmbitApplication.h"
#include "game/ui_core/TApplication.h"
#include "game/net/TMultiplayerMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"

// FUNCTION: IMPERIALISM 0x0054aff0
void TPoseMessageDialog::DoIt() {
  g_pGameFlowState->RefreshPoseMessageDialogNationSelectionControls(kickedByNationSlot18);
}

// SYNTHETIC: IMPERIALISM 0x0054b010
// TPoseMessageDialog::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x0054b040
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
  command->ICommand(kSessionTagPose, g_pAmbitApplication, 0, 0, 0); // 'pose'
  g_pAmbitApplication->DispatchUiSelectionToHandler(command);
}
