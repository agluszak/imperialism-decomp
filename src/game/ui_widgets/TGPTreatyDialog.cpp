#include "game/ui_widgets/TGPTreatyDialog.h"

#include "game/city_ui/TCountry.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/ui_core/TNumberText.h"
#include "game/ui_core/TStaticText.h"
#include "game/ui_core/TView.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_widgets_globals.h"
#include "game/gfx/ui_invalidation_guard.h"

// SYNTHETIC: IMPERIALISM 0x005b3b70
// TGPTreatyDialog::`scalar deleting destructor'
TGPTreatyDialog::~TGPTreatyDialog() {}
// SYNTHETIC: IMPERIALISM 0x005b3ae0
// TGPTreatyDialog::CreateObject

// SYNTHETIC: IMPERIALISM 0x005b3bc0
// TGPTreatyDialog::GetRuntimeClass

IMPLEMENT_DYNCREATE(TGPTreatyDialog, TDialogView)

TGPTreatyDialog::TGPTreatyDialog() {}

// FUNCTION: IMPERIALISM 0x005b3be0
void TGPTreatyDialog::StuffValues() {
  CString nationName;
  unsigned int nameTags[7] = {0x6e616d30, 0x6e616d31, 0x6e616d32, 0x6e616d33,
                              0x6e616d34, 0x6e616d35, 0x6e616d36};

  for (short row = 0; row < 7; ++row) {
    if (g_apTerrainTypeDescriptorTable[row] == 0) {
      continue;
    }

    TView* rowPanel = ResolveControlByTag(g_majorTreatyPanelTags[row]);
    if (rowPanel == 0) {
      FailNilPointerWithAssert(s_SourcePathUTestDialogs_0069A7F8, 0x2b3);
    }

    for (short column = 0; column < 7; ++column) {
      if (g_apTerrainTypeDescriptorTable[column] == 0) {
        continue;
      }

      TNumberText* relationControl =
          static_cast<TNumberText*>(rowPanel->ResolveControlByTag(g_majorTreatyCellTags[column]));
      if (relationControl == 0) {
        FailNilPointerWithAssert(s_SourcePathUTestDialogs_0069A7F8, 0x2b9);
      }

      if (column < row) {
        relationControl->SetControlValue(
            g_pDiplomacyTurnStateManager->GetNationPairDiplomacyRelationCode(column, row), 0);
        relationControl->SetState(0, 0);
      } else {
        relationControl->SetEnabled(0, 1);
      }
    }
  }

  TView* horizontalNames = ResolveControlByTag(0x686f7269); // 'hori'
  if (horizontalNames == 0) {
    FailNilPointerWithAssert(s_SourcePathUTestDialogs_0069A7F8, 0x2c6);
  }
  TView* verticalNames = ResolveControlByTag(0x76657274); // 'vert'
  if (verticalNames == 0) {
    FailNilPointerWithAssert(s_SourcePathUTestDialogs_0069A7F8, 0x2c8);
  }

  for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
    if (g_apTerrainTypeDescriptorTable[nationSlot] == 0) {
      continue;
    }

    g_apTerrainTypeDescriptorTable[nationSlot]->FormatOverlayTerrainLabelText(&nationName);
    TStaticText* horizontalName =
        static_cast<TStaticText*>(horizontalNames->ResolveControlByTag(nameTags[nationSlot]));
    if (horizontalName == 0) {
      FailNilPointerWithAssert(s_SourcePathUTestDialogs_0069A7F8, 0x2d0);
    }
    horizontalName->SetTextAndMaybeRefresh(&nationName, 0);

    TStaticText* verticalName =
        static_cast<TStaticText*>(verticalNames->ResolveControlByTag(nameTags[nationSlot]));
    if (verticalName == 0) {
      FailNilPointerWithAssert(s_SourcePathUTestDialogs_0069A7F8, 0x2d3);
    }
    verticalName->SetTextAndMaybeRefresh(&nationName, 0);
  }
}
