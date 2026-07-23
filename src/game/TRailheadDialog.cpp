#include "game/TRailheadDialog.h"

#include "game/TCity.h"
#include "game/TCluster.h"
#include "game/TControl.h"
#include "game/globals/prelude.h"
#include "game/globals/city_ui_globals.h"
#include "game/globals/shared_globals.h"
#include "game/ui_invalidation_guard.h"

// SYNTHETIC: IMPERIALISM 0x004bcfd0
// TRailheadDialog::`scalar deleting destructor'
TRailheadDialog::~TRailheadDialog() {}
// SYNTHETIC: IMPERIALISM 0x004bcf40
// TRailheadDialog::CreateObject

// SYNTHETIC: IMPERIALISM 0x004bd020
// TRailheadDialog::GetRuntimeClass

IMPLEMENT_DYNCREATE(TRailheadDialog, TDialogView)

TRailheadDialog::TRailheadDialog() {}

// FUNCTION: IMPERIALISM 0x004bd040
void TRailheadDialog::StuffValues(TCity* city) {
  city60 = city;

  TCluster* choice = static_cast<TCluster*>(ResolveControlByTag(0x63686f69)); // 'choi'
  if (choice == 0) {
    FailNilPointerWithAssert(s_SourcePathUCityDialogs_006962E8, 0x732);
  }
  choice->SetSelectedChildTagAndRefresh(g_pTradeSummarySelectionMap[0]);

  if (city->serializedState0a == 0) {
    TControl* coal = static_cast<TControl*>(ResolveControlByTag(g_pTradeSummarySelectionMap[3]));
    if (coal == 0) {
      FailNilPointerWithAssert(s_SourcePathUCityDialogs_006962E8, 0x73a);
    }
    coal->SetState(0, 1);
    coal->AssertCityProductionGlobalStateInitialized(1, 1);

    TControl* iron = static_cast<TControl*>(ResolveControlByTag(g_pTradeSummarySelectionMap[4]));
    if (iron == 0) {
      FailNilPointerWithAssert(s_SourcePathUCityDialogs_006962E8, 0x73f);
    }
    iron->SetState(0, 1);
    iron->AssertCityProductionGlobalStateInitialized(1, 1);

    TControl* gold = static_cast<TControl*>(ResolveControlByTag(g_pTradeSummarySelectionMap[22]));
    if (gold == 0) {
      FailNilPointerWithAssert(s_SourcePathUCityDialogs_006962E8, 0x744);
    }
    gold->SetState(0, 1);
    gold->AssertCityProductionGlobalStateInitialized(1, 1);

    TControl* oil = static_cast<TControl*>(ResolveControlByTag(g_pTradeSummarySelectionMap[6]));
    if (oil == 0) {
      FailNilPointerWithAssert(s_SourcePathUCityDialogs_006962E8, 0x749);
    }
    oil->SetState(0, 1);
    oil->AssertCityProductionGlobalStateInitialized(1, 1);
  }
}

// FUNCTION: IMPERIALISM 0x004bd260
void TRailheadDialog::DoClosingAction(unsigned long dialogActionTag) {
  if (dialogActionTag == 0x6f6b6179) {                                          // 'okay'
    TCluster* choice = static_cast<TCluster*>(ResolveControlByTag(0x63686f69)); // 'choi'
    if (choice == 0) {
      FailNilPointerWithAssert(s_SourcePathUCityDialogs_006962E8, 0x75e);
    }

    int selectedTag = choice->GetSelectedChildTag();
    short selectedResourceType = 0;
    while (selectedResourceType < 0x17 &&
           g_pTradeSummarySelectionMap[selectedResourceType] != selectedTag) {
      ++selectedResourceType;
    }
    city60->MakeTown(selectedResourceType);
  }
}
