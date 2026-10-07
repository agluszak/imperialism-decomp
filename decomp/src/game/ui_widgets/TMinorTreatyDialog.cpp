#include "game/nation_domain_types.h"
#include "game/ui_widgets/TMinorTreatyDialog.h"
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

// FUNCTION: IMPERIALISM 0x005b4050
TMinorTreatyDialog::~TMinorTreatyDialog() {}

IMPLEMENT_DYNCREATE(TMinorTreatyDialog, TDialogView)

// FUNCTION: IMPERIALISM 0x005b4090
void TMinorTreatyDialog::StuffValues() {
  CString nationName;
  unsigned int nameTags[8] = {kControlTagNam0, kControlTagNam1, kControlTagNam2, kControlTagNam3,
                              kControlTagNam4, kControlTagNam5, kControlTagNam6, kControlTagNam7};

  for (short minorNationSlot = 7; minorNationSlot < kNationSlotCount; ++minorNationSlot) {
    int minorIndex = minorNationSlot - 7;
    if (g_apTerrainTypeDescriptorTable[minorNationSlot] == 0) {
      continue;
    }

    TView* minorPanel = FindSubView(g_minorTreatyPanelTags[minorIndex]);
    if (minorPanel == 0) {
      FailNilPointerWithAssert(s_SourcePathUTestDialogs, 0x2fe);
    }

    for (short majorNationSlot = 0; majorNationSlot < kMajorNationCount; ++majorNationSlot) {
      if (g_apTerrainTypeDescriptorTable[majorNationSlot] == 0) {
        continue;
      }

      TNumberText* relationControl = static_cast<TNumberText*>(
          minorPanel->FindSubView(g_majorTreatyCellTags[majorNationSlot]));
      if (relationControl == 0) {
        FailNilPointerWithAssert(s_SourcePathUTestDialogs, 0x304);
      }
      relationControl->SetControlValue(
          g_pDiplomacyTurnStateManager->GetTreatyStatus(majorNationSlot, minorNationSlot), 0);
      relationControl->ViewEnable(0, 0);
    }
  }

  TView* firstMajorNameRow = FindSubView(kControlTagRow1); // 'row1'
  if (firstMajorNameRow == 0) {
    FailNilPointerWithAssert(s_SourcePathUTestDialogs, 0x30c);
  }
  TView* secondMajorNameRow = FindSubView(kControlTagRow2); // 'row2'
  if (secondMajorNameRow == 0) {
    FailNilPointerWithAssert(s_SourcePathUTestDialogs, 0x30e);
  }

  for (int nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
    if (g_apTerrainTypeDescriptorTable[nationSlot] == 0) {
      continue;
    }

    g_apTerrainTypeDescriptorTable[nationSlot]->FormatOverlayTerrainLabelText(&nationName);
    TStaticText* firstRowName =
        static_cast<TStaticText*>(firstMajorNameRow->FindSubView(nameTags[nationSlot]));
    if (firstRowName == 0) {
      FailNilPointerWithAssert(s_SourcePathUTestDialogs, 0x316);
    }
    firstRowName->SetTextAndMaybeRefresh(&nationName, false);

    TStaticText* secondRowName =
        static_cast<TStaticText*>(secondMajorNameRow->FindSubView(nameTags[nationSlot]));
    if (secondRowName == 0) {
      FailNilPointerWithAssert(s_SourcePathUTestDialogs, 0x319);
    }
    secondRowName->SetTextAndMaybeRefresh(&nationName, false);
  }

  TView* firstMinorNameColumn = FindSubView(kControlTagCol1); // 'col1'
  if (firstMinorNameColumn == 0) {
    FailNilPointerWithAssert(s_SourcePathUTestDialogs, 0x31e);
  }
  TView* secondMinorNameColumn = FindSubView(kControlTagCol2); // 'col2'
  if (secondMinorNameColumn == 0) {
    FailNilPointerWithAssert(s_SourcePathUTestDialogs, 0x320);
  }

  for (int row = 0; row < 8; ++row) {
    int firstNationSlot = row + 7;
    if (g_apTerrainTypeDescriptorTable[firstNationSlot] != 0) {
      g_apTerrainTypeDescriptorTable[firstNationSlot]->FormatOverlayTerrainLabelText(&nationName);
      TStaticText* firstColumnName =
          static_cast<TStaticText*>(firstMinorNameColumn->FindSubView(nameTags[row]));
      if (firstColumnName == 0) {
        FailNilPointerWithAssert(s_SourcePathUTestDialogs, 0x329);
      }
      firstColumnName->SetTextAndMaybeRefresh(&nationName, false);
    }

    int secondNationSlot = row + 15;
    if (g_apTerrainTypeDescriptorTable[secondNationSlot] != 0) {
      g_apTerrainTypeDescriptorTable[secondNationSlot]->FormatOverlayTerrainLabelText(&nationName);
      TStaticText* secondColumnName =
          static_cast<TStaticText*>(secondMinorNameColumn->FindSubView(nameTags[row]));
      if (secondColumnName == 0) {
        FailNilPointerWithAssert(s_SourcePathUTestDialogs, 0x331);
      }
      secondColumnName->SetTextAndMaybeRefresh(&nationName, false);
    }
  }
}
