#include "game/ui_widgets/TAutomatedPlayDialog.h"
#include "game/ui_tags_widgets.h"

#include "game/ui_core/TNumberText.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_widgets_globals.h"
#include "game/gfx/ui_invalidation_guard.h"

// SYNTHETIC: IMPERIALISM 0x005b4650
// TAutomatedPlayDialog::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x005b4680
TAutomatedPlayDialog::~TAutomatedPlayDialog() {}
// SYNTHETIC: IMPERIALISM 0x005b45c0
// TAutomatedPlayDialog::CreateObject

// SYNTHETIC: IMPERIALISM 0x005b46a0
// TAutomatedPlayDialog::GetRuntimeClass

IMPLEMENT_DYNCREATE(TAutomatedPlayDialog, TDialogView)

// FUNCTION: IMPERIALISM 0x005b46c0
void TAutomatedPlayDialog::Close() {
  TNumberText* turnCount =
      static_cast<TNumberText*>(ResolveControlByTag(kControlTagNumSp)); // 'num '
  if (turnCount == 0) {
    FailNilPointerWithAssert(s_SourcePathUTestDialogs_0069A7F8, 0x34e);
  }

  g_nTurnCooldownDeferCounter006A43C4 =
      static_cast<short>(turnCount->UpdateControlCachedIntFromWindowText());
  g_nTurnCooldownSideFlag00698B10 = static_cast<short>(g_pSimMgr->mode);
  if (g_nTurnCooldownDeferCounter006A43C4 > 0) {
    g_pSimMgr->StartNextPhase();
  }
  TView::Close();
}
