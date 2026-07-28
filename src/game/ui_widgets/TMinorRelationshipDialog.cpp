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

// SYNTHETIC: IMPERIALISM 0x005b3390
// TMinorRelationshipDialog::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x005b33c0
TMinorRelationshipDialog::~TMinorRelationshipDialog() {}
// SYNTHETIC: IMPERIALISM 0x005b3300
// TMinorRelationshipDialog::CreateObject

// SYNTHETIC: IMPERIALISM 0x005b33e0
// TMinorRelationshipDialog::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMinorRelationshipDialog, TDialogView)

// FUNCTION: IMPERIALISM 0x005b3400
void TMinorRelationshipDialog::Close() {
  for (short minorNation = 7; minorNation < 0x17; ++minorNation) {
    int minorIndex = minorNation - 7;
    if (g_apTerrainTypeDescriptorTable[minorNation] == 0) {
      continue;
    }

    TView* nationPanel = ResolveControlByTag(g_minorTreatyPanelTags[minorIndex]);
    if (nationPanel == 0) {
      FailNilPointerWithAssert(s_SourcePathUTestDialogs_0069A7F8, 0x229);
    }

    for (short majorNation = 0; majorNation < 7; ++majorNation) {
      if (g_apTerrainTypeDescriptorTable[majorNation] == 0) {
        continue;
      }
      TNumberText* standingControl = static_cast<TNumberText*>(
          nationPanel->ResolveControlByTag(g_majorTreatyCellTags[majorNation]));
      if (standingControl == 0) {
        FailNilPointerWithAssert(s_SourcePathUTestDialogs_0069A7F8, 0x22f);
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

  // 16 minor-nation panels ('M7 '..'M22 '), each holding one relation-standing cell
  // per major nation: value = matrix[major][minor], state from the shared byte gate.
  for (short minorIndex = 0; minorIndex < 16; ++minorIndex) {
    if (g_apTerrainTypeDescriptorTable[minorIndex + 7] == 0) {
      continue;
    }
    TView* minorPanel = ResolveControlByTag(g_minorTreatyPanelTags[minorIndex]);
    if (minorPanel == 0) {
      FailNilPointerWithAssert(s_SourcePathUTestDialogs_0069A7F8, 0x252);
    }
    for (short majorNation = 0; majorNation < 7; ++majorNation) {
      if (g_apTerrainTypeDescriptorTable[majorNation] == 0) {
        continue;
      }
      TNumberText* cell = static_cast<TNumberText*>(
          minorPanel->ResolveControlByTag(g_majorTreatyCellTags[majorNation]));
      if (cell == 0) {
        FailNilPointerWithAssert(s_SourcePathUTestDialogs_0069A7F8, 0x258);
      }
      cell->SetControlValue(
          g_pDiplomacyTurnStateManager
              ->relationStandingScores[majorNation * kNationSlotCount + (minorIndex + 7)],
          0);
      cell->SetState(static_cast<signed char>(g_bRandomMapDeveloperCheatFlag), 0);
    }
  }

  // Major-nation name strips.
  TView* majorNames1 = ResolveControlByTag(kControlTagWor1);
  if (majorNames1 == 0) {
    FailNilPointerWithAssert(s_SourcePathUTestDialogs_0069A7F8, 0x261);
  }
  TView* majorNames2 = ResolveControlByTag(kControlTagWor2);
  if (majorNames2 == 0) {
    FailNilPointerWithAssert(s_SourcePathUTestDialogs_0069A7F8, 0x263);
  }
  for (short majorNation = 0; majorNation < 7; ++majorNation) {
    if (g_apTerrainTypeDescriptorTable[majorNation] == 0) {
      continue;
    }
    g_apTerrainTypeDescriptorTable[majorNation]->FormatOverlayTerrainLabelText(&label);
    TStaticText* nameControl =
        static_cast<TStaticText*>(majorNames1->ResolveControlByTag(nameTags[majorNation]));
    if (nameControl == 0) {
      FailNilPointerWithAssert(s_SourcePathUTestDialogs_0069A7F8, 0x26c);
    }
    nameControl->SetTextAndMaybeRefresh(&label, 0);
    nameControl =
        static_cast<TStaticText*>(majorNames2->ResolveControlByTag(nameTags[majorNation]));
    if (nameControl == 0) {
      FailNilPointerWithAssert(s_SourcePathUTestDialogs_0069A7F8, 0x26f);
    }
    nameControl->SetTextAndMaybeRefresh(&label, 0);
  }

  // Minor-nation name columns: 'col1' lists minors 7..14, 'col2' minors 15..22.
  TView* minorNames1 = ResolveControlByTag(kControlTagCol1);
  if (minorNames1 == 0) {
    FailNilPointerWithAssert(s_SourcePathUTestDialogs_0069A7F8, 0x274);
  }
  TView* minorNames2 = ResolveControlByTag(kControlTagCol2);
  if (minorNames2 == 0) {
    FailNilPointerWithAssert(s_SourcePathUTestDialogs_0069A7F8, 0x276);
  }
  for (short row = 0; row < 8; ++row) {
    if (g_apTerrainTypeDescriptorTable[row + 7] != 0) {
      g_apTerrainTypeDescriptorTable[row + 7]->FormatOverlayTerrainLabelText(&label);
      TStaticText* rowControl =
          static_cast<TStaticText*>(minorNames1->ResolveControlByTag(nameTags[row]));
      if (rowControl == 0) {
        FailNilPointerWithAssert(s_SourcePathUTestDialogs_0069A7F8, 0x27f);
      }
      rowControl->SetTextAndMaybeRefresh(&label, 0);
    }
    if (g_apTerrainTypeDescriptorTable[row + 15] != 0) {
      g_apTerrainTypeDescriptorTable[row + 15]->FormatOverlayTerrainLabelText(&label);
      TStaticText* rowControl =
          static_cast<TStaticText*>(minorNames2->ResolveControlByTag(nameTags[row]));
      if (rowControl == 0) {
        FailNilPointerWithAssert(s_SourcePathUTestDialogs_0069A7F8, 0x287);
      }
      rowControl->SetTextAndMaybeRefresh(&label, 0);
    }
  }
}
