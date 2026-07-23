#include "game/TMinorTreatyDialog.h"

#include "game/TCountry.h"
#include "game/TDiplomacyMgr.h"
#include "game/TNumberText.h"
#include "game/TStaticText.h"
#include "game/TView.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_widgets_globals.h"
#include "game/ui_invalidation_guard.h"

// SYNTHETIC: IMPERIALISM 0x005b4020
// TMinorTreatyDialog::`scalar deleting destructor'
TMinorTreatyDialog::~TMinorTreatyDialog() {}
// SYNTHETIC: IMPERIALISM 0x005b3f90
// TMinorTreatyDialog::CreateObject

// SYNTHETIC: IMPERIALISM 0x005b4070
// TMinorTreatyDialog::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMinorTreatyDialog, TDialogView)

TMinorTreatyDialog::TMinorTreatyDialog() {}

// FUNCTION: IMPERIALISM 0x005b4090
void TMinorTreatyDialog::StuffValues() {
  CString nationName;
  unsigned int nameTags[8] = {0x6e616d30, 0x6e616d31, 0x6e616d32, 0x6e616d33,
                              0x6e616d34, 0x6e616d35, 0x6e616d36, 0x6e616d37};

  for (short minorNationSlot = 7; minorNationSlot < 0x17; ++minorNationSlot) {
    int minorIndex = minorNationSlot - 7;
    if (g_apMinorNationCapabilityObjects[minorIndex] == 0) {
      continue;
    }

    TView* minorPanel = ResolveControlByTag(g_minorTreatyPanelTags[minorIndex]);
    if (minorPanel == 0) {
      FailNilPointerWithAssert(s_SourcePathUTestDialogs_0069A7F8, 0x2fe);
    }

    for (short majorNationSlot = 0; majorNationSlot < 7; ++majorNationSlot) {
      if (g_apTerrainTypeDescriptorTable[majorNationSlot] == 0) {
        continue;
      }

      TNumberText* relationControl = static_cast<TNumberText*>(
          minorPanel->ResolveControlByTag(g_majorTreatyCellTags[majorNationSlot]));
      if (relationControl == 0) {
        FailNilPointerWithAssert(s_SourcePathUTestDialogs_0069A7F8, 0x304);
      }
      relationControl->SetControlValue(
          g_pDiplomacyTurnStateManager->GetNationPairDiplomacyRelationCode(majorNationSlot,
                                                                           minorNationSlot),
          0);
      relationControl->SetState(0, 0);
    }
  }

  TView* firstMajorNameRow = ResolveControlByTag(0x726f7731); // 'row1'
  if (firstMajorNameRow == 0) {
    FailNilPointerWithAssert(s_SourcePathUTestDialogs_0069A7F8, 0x30c);
  }
  TView* secondMajorNameRow = ResolveControlByTag(0x726f7732); // 'row2'
  if (secondMajorNameRow == 0) {
    FailNilPointerWithAssert(s_SourcePathUTestDialogs_0069A7F8, 0x30e);
  }

  for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
    if (g_apTerrainTypeDescriptorTable[nationSlot] == 0) {
      continue;
    }

    g_apTerrainTypeDescriptorTable[nationSlot]->FormatOverlayTerrainLabelText(&nationName);
    TStaticText* firstRowName =
        static_cast<TStaticText*>(firstMajorNameRow->ResolveControlByTag(nameTags[nationSlot]));
    if (firstRowName == 0) {
      FailNilPointerWithAssert(s_SourcePathUTestDialogs_0069A7F8, 0x316);
    }
    firstRowName->SetTextAndMaybeRefresh(&nationName, 0);

    TStaticText* secondRowName =
        static_cast<TStaticText*>(secondMajorNameRow->ResolveControlByTag(nameTags[nationSlot]));
    if (secondRowName == 0) {
      FailNilPointerWithAssert(s_SourcePathUTestDialogs_0069A7F8, 0x319);
    }
    secondRowName->SetTextAndMaybeRefresh(&nationName, 0);
  }

  TView* firstMinorNameColumn = ResolveControlByTag(0x636f6c31); // 'col1'
  if (firstMinorNameColumn == 0) {
    FailNilPointerWithAssert(s_SourcePathUTestDialogs_0069A7F8, 0x31e);
  }
  TView* secondMinorNameColumn = ResolveControlByTag(0x636f6c32); // 'col2'
  if (secondMinorNameColumn == 0) {
    FailNilPointerWithAssert(s_SourcePathUTestDialogs_0069A7F8, 0x320);
  }

  for (int row = 0; row < 8; ++row) {
    int firstNationSlot = row + 7;
    if (g_apTerrainTypeDescriptorTable[firstNationSlot] != 0) {
      g_apTerrainTypeDescriptorTable[firstNationSlot]->FormatOverlayTerrainLabelText(&nationName);
      TStaticText* firstColumnName =
          static_cast<TStaticText*>(firstMinorNameColumn->ResolveControlByTag(nameTags[row]));
      if (firstColumnName == 0) {
        FailNilPointerWithAssert(s_SourcePathUTestDialogs_0069A7F8, 0x329);
      }
      firstColumnName->SetTextAndMaybeRefresh(&nationName, 0);
    }

    int secondNationSlot = row + 15;
    if (g_apTerrainTypeDescriptorTable[secondNationSlot] != 0) {
      g_apTerrainTypeDescriptorTable[secondNationSlot]->FormatOverlayTerrainLabelText(&nationName);
      TStaticText* secondColumnName =
          static_cast<TStaticText*>(secondMinorNameColumn->ResolveControlByTag(nameTags[row]));
      if (secondColumnName == 0) {
        FailNilPointerWithAssert(s_SourcePathUTestDialogs_0069A7F8, 0x331);
      }
      secondColumnName->SetTextAndMaybeRefresh(&nationName, 0);
    }
  }
}
