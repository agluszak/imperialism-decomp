#include "game/ui_widgets/TRelationshipDialog.h"

#include "game/military_ui/TDiplomacyMgr.h"
#include "game/ui_core/TNumberText.h"
#include "game/ui_core/TStaticText.h"
#include "game/city_ui/TCountry.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_widgets.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_widgets_globals.h"
#include "game/gfx/ui_invalidation_guard.h"

// SYNTHETIC: IMPERIALISM 0x005b2d30
// TRelationshipDialog::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x005b2d60
TRelationshipDialog::~TRelationshipDialog() {}
// SYNTHETIC: IMPERIALISM 0x005b2ca0
// TRelationshipDialog::CreateObject

// SYNTHETIC: IMPERIALISM 0x005b2d80
// TRelationshipDialog::GetRuntimeClass

IMPLEMENT_DYNCREATE(TRelationshipDialog, TDialogView)

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

// Mac oracle: StuffValues(). Fills the 7x7 relation-standing matrix cells (value +
// state for pairs below the diagonal, disabled otherwise) and pushes each nation's
// label into the matching 'nam0'..'nam6' slots of the 'hori'/'vert' name strips.
// FUNCTION: IMPERIALISM 0x005b2f10
void TRelationshipDialog::StuffValues() {
  CString label;
  int nameTags[7] = {kControlTagNam0, kControlTagNam1, kControlTagNam2, kControlTagNam3,
                     kControlTagNam4, kControlTagNam5, kControlTagNam6};

  for (short targetNation = 0; targetNation < 7; ++targetNation) {
    if (g_apTerrainTypeDescriptorTable[targetNation] == 0) {
      continue;
    }
    TView* nationPanel = ResolveControlByTag(g_majorTreatyPanelTags[targetNation]);
    if (nationPanel == 0) {
      FailNilPointerWithAssert(s_SourcePathUTestDialogs_0069A7F8, 0x1e8);
    }
    for (short sourceNation = 0; sourceNation < 7; ++sourceNation) {
      if (g_apTerrainTypeDescriptorTable[sourceNation] == 0) {
        continue;
      }
      TNumberText* cell = static_cast<TNumberText*>(
          nationPanel->ResolveControlByTag(g_majorTreatyCellTags[sourceNation]));
      if (cell == 0) {
        FailNilPointerWithAssert(s_SourcePathUTestDialogs_0069A7F8, 0x1ef);
      }
      if (sourceNation < targetNation) {
        cell->SetControlValue(
            g_pDiplomacyTurnStateManager
                ->relationStandingScoreMatrix79c[sourceNation * 0x17 + targetNation],
            0);
        cell->SetState(static_cast<signed char>(g_bRandomMapDeveloperCheatFlag), 0);
      } else {
        cell->SetEnabled(0, 1);
      }
    }
  }

  TView* horizontalNames = ResolveControlByTag(kControlTagHori);
  if (horizontalNames == 0) {
    FailNilPointerWithAssert(s_SourcePathUTestDialogs_0069A7F8, 0x1fc);
  }
  TView* verticalNames = ResolveControlByTag(kControlTagVert);
  if (verticalNames == 0) {
    FailNilPointerWithAssert(s_SourcePathUTestDialogs_0069A7F8, 0x1fe);
  }
  for (short nation = 0; nation < 7; ++nation) {
    if (g_apTerrainTypeDescriptorTable[nation] == 0) {
      continue;
    }
    g_apTerrainTypeDescriptorTable[nation]->FormatOverlayTerrainLabelText(&label);
    TStaticText* horizontalLabel =
        static_cast<TStaticText*>(horizontalNames->ResolveControlByTag(nameTags[nation]));
    if (horizontalLabel == 0) {
      FailNilPointerWithAssert(s_SourcePathUTestDialogs_0069A7F8, 0x207);
    }
    horizontalLabel->SetTextAndMaybeRefresh(&label, 0);
    TStaticText* verticalLabel =
        static_cast<TStaticText*>(verticalNames->ResolveControlByTag(nameTags[nation]));
    if (verticalLabel == 0) {
      FailNilPointerWithAssert(s_SourcePathUTestDialogs_0069A7F8, 0x20a);
    }
    verticalLabel->SetTextAndMaybeRefresh(&label, 0);
  }
}
