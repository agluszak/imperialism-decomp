#include "game/ui_widgets/TRelationshipDialog.h"

#include "game/military_ui/TDiplomacyMgr.h"
#include "game/ui_core/TNumberText.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_widgets_globals.h"
#include "game/gfx/ui_invalidation_guard.h"

// SYNTHETIC: IMPERIALISM 0x005b2d30
// TRelationshipDialog::`scalar deleting destructor'
TRelationshipDialog::~TRelationshipDialog() {}
// SYNTHETIC: IMPERIALISM 0x005b2ca0
// TRelationshipDialog::CreateObject

// SYNTHETIC: IMPERIALISM 0x005b2d80
// TRelationshipDialog::GetRuntimeClass

IMPLEMENT_DYNCREATE(TRelationshipDialog, TDialogView)

TRelationshipDialog::TRelationshipDialog() {}

// FUNCTION: IMPERIALISM 0x005b2da0
void TRelationshipDialog::Close() {
  for (short targetNation = 0; targetNation < 7; ++targetNation) {
    if (g_apTerrainTypeDescriptorTable[targetNation] == 0) {
      continue;
    }

    TView* nationPanel = ResolveControlByTag(g_majorTreatyPanelTags[targetNation]);
    if (nationPanel == 0) {
      FailNilPointerWithAssert(s_SourcePathUTestDialogs_0069A7F8, 0x1bc);
    }

    for (short sourceNation = 0; sourceNation < 7; ++sourceNation) {
      if (g_apTerrainTypeDescriptorTable[sourceNation] == 0 || sourceNation >= targetNation) {
        continue;
      }
      TNumberText* standingControl = static_cast<TNumberText*>(
          nationPanel->ResolveControlByTag(g_majorTreatyCellTags[sourceNation]));
      if (standingControl == 0) {
        FailNilPointerWithAssert(s_SourcePathUTestDialogs_0069A7F8, 0x1c5);
      }
      int standing = standingControl->UpdateControlCachedIntFromWindowText();
      g_pDiplomacyTurnStateManager->SetStandingScoreSlot28(sourceNation, targetNation, standing);
    }
  }
  TView::Close();
}

// FUNCTION: IMPERIALISM 0x005b2f10
void TRelationshipDialog::VTableSlot68() {}
