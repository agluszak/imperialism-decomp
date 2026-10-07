#include "game/nation_domain_types.h"
#include "game/ui_widgets/TMinorRelationshipDialog.h"

#include "game/military_ui/TDiplomacyMgr.h"
#include "game/ui_core/TNumberText.h"
#include "game/ui_core/TStaticText.h"
#include "game/city_ui/TCountry.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_widgets.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_widgets_globals.h"
#include "game/gfx/ui_invalidation_guard.h"

// FUNCTION: IMPERIALISM 0x005b33c0
TMinorRelationshipDialog::~TMinorRelationshipDialog() {}

IMPLEMENT_DYNCREATE(TMinorRelationshipDialog, TDialogView)

// FUNCTION: IMPERIALISM 0x005b3400
void TMinorRelationshipDialog::Close() {
  for (short minorNation = 7; minorNation < kNationSlotCount; ++minorNation) {
    int minorIndex = minorNation - 7;
    if (g_apTerrainTypeDescriptorTable[minorNation] == 0) {
      continue;
    }

    TView* nationPanel = FindSubView(g_minorTreatyPanelTags[minorIndex]);
    if (nationPanel == 0) {
      FailNilPointerWithAssert(s_SourcePathUTestDialogs, 0x229);
    }

    for (short majorNation = 0; majorNation < kMajorNationCount; ++majorNation) {
      if (g_apTerrainTypeDescriptorTable[majorNation] == 0) {
        continue;
      }
      TNumberText* standingControl =
          static_cast<TNumberText*>(nationPanel->FindSubView(g_majorTreatyCellTags[majorNation]));
      if (standingControl == 0) {
        FailNilPointerWithAssert(s_SourcePathUTestDialogs, 0x22f);
      }
      int standing = standingControl->UpdateControlCachedIntFromWindowText();
      g_pDiplomacyTurnStateManager->SetRelationship(majorNation, minorNation, standing);
    }
  }
  TView::Close();
}

// FUNCTION: IMPERIALISM 0x005b3570
void TMinorRelationshipDialog::StuffValues() {
  CString label;
  int nameTags[8] = {kControlTagNam0, kControlTagNam1, kControlTagNam2, kControlTagNam3,
                     kControlTagNam4, kControlTagNam5, kControlTagNam6, kControlTagNam7};

  for (short minorIndex = 0; minorIndex < kMinorNationCount; ++minorIndex) {
    if (g_apTerrainTypeDescriptorTable[minorIndex + 7] == 0) {
      continue;
    }
    TView* minorPanel = FindSubView(g_minorTreatyPanelTags[minorIndex]);
    if (minorPanel == 0) {
      FailNilPointerWithAssert(s_SourcePathUTestDialogs, 0x252);
    }
    for (short majorNation = 0; majorNation < kMajorNationCount; ++majorNation) {
      if (g_apTerrainTypeDescriptorTable[majorNation] == 0) {
        continue;
      }
      TNumberText* cell =
          static_cast<TNumberText*>(minorPanel->FindSubView(g_majorTreatyCellTags[majorNation]));
      if (cell == 0) {
        FailNilPointerWithAssert(s_SourcePathUTestDialogs, 0x258);
      }
      cell->SetControlValue(
          g_pDiplomacyTurnStateManager->GetRelationship(majorNation, (minorIndex + 7)), 0);
      cell->ViewEnable(static_cast<signed char>(g_bRandomMapDeveloperCheatFlag), 0);
    }
  }

  // Major-nation name strips.
  TView* majorNames1 = FindSubView(kControlTagWor1);
  if (majorNames1 == 0) {
    FailNilPointerWithAssert(s_SourcePathUTestDialogs, 0x261);
  }
  TView* majorNames2 = FindSubView(kControlTagWor2);
  if (majorNames2 == 0) {
    FailNilPointerWithAssert(s_SourcePathUTestDialogs, 0x263);
  }
  for (short majorNation = 0; majorNation < kMajorNationCount; ++majorNation) {
    if (g_apTerrainTypeDescriptorTable[majorNation] == 0) {
      continue;
    }
    g_apTerrainTypeDescriptorTable[majorNation]->FormatOverlayTerrainLabelText(&label);
    TStaticText* nameControl =
        static_cast<TStaticText*>(majorNames1->FindSubView(nameTags[majorNation]));
    if (nameControl == 0) {
      FailNilPointerWithAssert(s_SourcePathUTestDialogs, 0x26c);
    }
    nameControl->SetTextAndMaybeRefresh(&label, false);
    nameControl = static_cast<TStaticText*>(majorNames2->FindSubView(nameTags[majorNation]));
    if (nameControl == 0) {
      FailNilPointerWithAssert(s_SourcePathUTestDialogs, 0x26f);
    }
    nameControl->SetTextAndMaybeRefresh(&label, false);
  }

  // Minor-nation name columns: 'col1' lists minors 7..14, 'col2' minors 15..22.
  TView* minorNames1 = FindSubView(kControlTagCol1);
  if (minorNames1 == 0) {
    FailNilPointerWithAssert(s_SourcePathUTestDialogs, 0x274);
  }
  TView* minorNames2 = FindSubView(kControlTagCol2);
  if (minorNames2 == 0) {
    FailNilPointerWithAssert(s_SourcePathUTestDialogs, 0x276);
  }
  for (short row = 0; row < 8; ++row) {
    if (g_apTerrainTypeDescriptorTable[row + 7] != 0) {
      g_apTerrainTypeDescriptorTable[row + 7]->FormatOverlayTerrainLabelText(&label);
      TStaticText* rowControl = static_cast<TStaticText*>(minorNames1->FindSubView(nameTags[row]));
      if (rowControl == 0) {
        FailNilPointerWithAssert(s_SourcePathUTestDialogs, 0x27f);
      }
      rowControl->SetTextAndMaybeRefresh(&label, false);
    }
    if (g_apTerrainTypeDescriptorTable[row + 15] != 0) {
      g_apTerrainTypeDescriptorTable[row + 15]->FormatOverlayTerrainLabelText(&label);
      TStaticText* rowControl = static_cast<TStaticText*>(minorNames2->FindSubView(nameTags[row]));
      if (rowControl == 0) {
        FailNilPointerWithAssert(s_SourcePathUTestDialogs, 0x287);
      }
      rowControl->SetTextAndMaybeRefresh(&label, false);
    }
  }
}
