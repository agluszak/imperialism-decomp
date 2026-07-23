#include "game/TTransportView.h"

#include "game/TGreatPower.h"
#include "game/TNumberText.h"
#include "game/globals/prelude.h"
#include "game/globals/city_ui_globals.h"
#include "game/globals/shared_globals.h"
#include "game/ui_invalidation_guard.h"

// SYNTHETIC: IMPERIALISM 0x004bd370
// TTransportView::`scalar deleting destructor'
TTransportView::~TTransportView() {}
// SYNTHETIC: IMPERIALISM 0x004bd300
// TTransportView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004bd3c0
// TTransportView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTransportView, TView)

TTransportView::TTransportView() {}

// FUNCTION: IMPERIALISM 0x004bd3e0
void TTransportView::StuffValues(TGreatPower* nation) {
  CString scratch;
  nation60 = nation;

  TView* supplyPanel = ResolveControlByTag(0x73757070); // 'supp'
  if (supplyPanel == 0) {
    FailNilPointerWithAssert(s_SourcePathUCityDialogs_006962E8, 0x783);
  }
  for (short currentResourceType = 0; currentResourceType < 0x17; ++currentResourceType) {
    TNumberText* amount = static_cast<TNumberText*>(
        supplyPanel->ResolveControlByTag(g_pTradeSummarySelectionMap[currentResourceType]));
    if (amount == 0) {
      FailNilPointerWithAssert(s_SourcePathUCityDialogs_006962E8, 0x787);
    }
    amount->SetControlValue(nation->needCurrentByType[currentResourceType], 1);
  }

  TView* transportPanel = ResolveControlByTag(0x7472616e); // 'tran'
  if (transportPanel == 0) {
    FailNilPointerWithAssert(s_SourcePathUCityDialogs_006962E8, 0x78d);
  }
  for (short targetResourceType = 0; targetResourceType < 0x17; ++targetResourceType) {
    TNumberText* amount = static_cast<TNumberText*>(
        transportPanel->ResolveControlByTag(g_pTradeSummarySelectionMap[targetResourceType]));
    if (amount == 0) {
      FailNilPointerWithAssert(s_SourcePathUCityDialogs_006962E8, 0x791);
    }
    amount->SetControlValue(nation->needTargetByType[targetResourceType], 1);
  }

  TNumberText* total = static_cast<TNumberText*>(ResolveControlByTag(0x746f7461)); // 'tota'
  if (total == 0) {
    FailNilPointerWithAssert(s_SourcePathUCityDialogs_006962E8, 0x797);
  }
  total->SetControlValue(nation != 0 ? nation->needCapA6 : 0, 1);
}

// FUNCTION: IMPERIALISM 0x004bd690
void TTransportView::Close() {
  TView* transportPanel = ResolveControlByTag(0x7472616e); // 'tran'
  if (transportPanel == 0) {
    FailNilPointerWithAssert(s_SourcePathUCityDialogs_006962E8, 0x7a7);
  }

  for (int resourceType = 0; resourceType < 0x17; ++resourceType) {
    TNumberText* amount = static_cast<TNumberText*>(
        transportPanel->ResolveControlByTag(g_pTradeSummarySelectionMap[resourceType]));
    if (amount == 0) {
      FailNilPointerWithAssert(s_SourcePathUCityDialogs_006962E8, 0x7ab);
    }
    nation60->UpdateNeedTargetAndAccumulateOverCap(
        static_cast<short>(resourceType),
        static_cast<short>(amount->UpdateControlCachedIntFromWindowText()));
  }
}
