#include "game/ui_widgets/TGPTreatyDialog.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_widgets.h"

#include "game/city_ui/TCountry.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/ui_core/TNumberText.h"
#include "game/ui_core/TStaticText.h"
#include "game/ui_core/TView.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_widgets_globals.h"
#include "game/gfx/ui_invalidation_guard.h"

// FUNCTION: IMPERIALISM 0x005b3ba0
TGPTreatyDialog::~TGPTreatyDialog() {}

IMPLEMENT_DYNCREATE(TGPTreatyDialog, TDialogView)

// FUNCTION: IMPERIALISM 0x005b3be0
void TGPTreatyDialog::StuffValues() {
  CString nationName;
  unsigned int nameTags[7] = {kControlTagNam0, kControlTagNam1, kControlTagNam2, kControlTagNam3,
                              kControlTagNam4, kControlTagNam5, kControlTagNam6};

  for (short row = 0; row < 7; ++row) {
    if (g_apTerrainTypeDescriptorTable[row] == 0) {
      continue;
    }

    TView* rowPanel = FindSubView(g_majorTreatyPanelTags[row]);
    if (rowPanel == 0) {
      FailNilPointerWithAssert(s_SourcePathUTestDialogs, 0x2b3);
    }

    for (short column = 0; column < 7; ++column) {
      if (g_apTerrainTypeDescriptorTable[column] == 0) {
        continue;
      }

      TNumberText* relationControl =
          static_cast<TNumberText*>(rowPanel->FindSubView(g_majorTreatyCellTags[column]));
      if (relationControl == 0) {
        FailNilPointerWithAssert(s_SourcePathUTestDialogs, 0x2b9);
      }

      if (column < row) {
        relationControl->SetControlValue(g_pDiplomacyTurnStateManager->GetTreatyStatus(column, row),
                                         0);
        relationControl->ViewEnable(0, 0);
      } else {
        relationControl->Show(0, 1);
      }
    }
  }

  TView* horizontalNames = FindSubView(kControlTagHori); // 'hori'
  if (horizontalNames == 0) {
    FailNilPointerWithAssert(s_SourcePathUTestDialogs, 0x2c6);
  }
  TView* verticalNames = FindSubView(kControlTagVert); // 'vert'
  if (verticalNames == 0) {
    FailNilPointerWithAssert(s_SourcePathUTestDialogs, 0x2c8);
  }

  for (int nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
    if (g_apTerrainTypeDescriptorTable[nationSlot] == 0) {
      continue;
    }

    g_apTerrainTypeDescriptorTable[nationSlot]->FormatOverlayTerrainLabelText(&nationName);
    TStaticText* horizontalName =
        static_cast<TStaticText*>(horizontalNames->FindSubView(nameTags[nationSlot]));
    if (horizontalName == 0) {
      FailNilPointerWithAssert(s_SourcePathUTestDialogs, 0x2d0);
    }
    horizontalName->SetTextAndMaybeRefresh(&nationName, false);

    TStaticText* verticalName =
        static_cast<TStaticText*>(verticalNames->FindSubView(nameTags[nationSlot]));
    if (verticalName == 0) {
      FailNilPointerWithAssert(s_SourcePathUTestDialogs, 0x2d3);
    }
    verticalName->SetTextAndMaybeRefresh(&nationName, false);
  }
}
