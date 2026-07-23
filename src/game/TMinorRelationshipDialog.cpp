#include "game/TMinorRelationshipDialog.h"

#include "game/TDiplomacyMgr.h"
#include "game/TNumberText.h"
#include "game/global_data_tables.h"
#include "game/ui_invalidation_guard.h"

// SYNTHETIC: IMPERIALISM 0x005b3390
// TMinorRelationshipDialog::`scalar deleting destructor'
TMinorRelationshipDialog::~TMinorRelationshipDialog() {}
// SYNTHETIC: IMPERIALISM 0x005b3300
// TMinorRelationshipDialog::CreateObject

// SYNTHETIC: IMPERIALISM 0x005b33e0
// TMinorRelationshipDialog::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMinorRelationshipDialog, TDialogView)

TMinorRelationshipDialog::TMinorRelationshipDialog() {}

// FUNCTION: IMPERIALISM 0x005b3400
void TMinorRelationshipDialog::Close() {
  for (short minorNation = 7; minorNation < 0x17; ++minorNation) {
    int minorIndex = minorNation - 7;
    if (g_apMinorNationCapabilityObjects[minorIndex] == 0) {
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
      g_pDiplomacyTurnStateManager->SetStandingScoreSlot28(majorNation, minorNation, standing);
    }
  }
  TView::Close();
}

// FUNCTION: IMPERIALISM 0x005b3570
void TMinorRelationshipDialog::VTableSlot68() {}
