#include "game/ui_widgets/TAutomatedPlayDialog.h"
#include "game/ui_tags_widgets.h"

#include "game/ui_core/TNumberText.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_widgets_globals.h"
#include "game/gfx/ui_invalidation_guard.h"

// FUNCTION: IMPERIALISM 0x005b4680
TAutomatedPlayDialog::~TAutomatedPlayDialog() {}

IMPLEMENT_DYNCREATE(TAutomatedPlayDialog, TDialogView)

// FUNCTION: IMPERIALISM 0x005b46c0
void TAutomatedPlayDialog::Close() {
  TNumberText* turnCount = static_cast<TNumberText*>(FindSubView(kControlTagNumSp)); // 'num '
  if (turnCount == 0) {
    FailNilPointerWithAssert(s_SourcePathUTestDialogs, 0x34e);
  }

  g_nTurnCooldownDeferCounter =
      static_cast<short>(turnCount->UpdateControlCachedIntFromWindowText());
  g_nTurnCooldownSideFlag = static_cast<short>(g_pSimMgr->mode);
  if (g_nTurnCooldownDeferCounter > 0) {
    g_pSimMgr->StartNextPhase();
  }
  TView::Close();
}
