#include "game/ui_screens/TDipDlgCluster.h"

#include "game/gfx/ui_invalidation_guard.h"
#include "game/globals/prelude.h"
#include "game/globals/ui_widgets_globals.h"
#include "game/ui_screens/TToggleButton.h"
#include "game/resource_manifest_tags.h"
#include "game/ui_tags_common.h"
// SYNTHETIC: IMPERIALISM 0x00584040
// TDipDlgCluster::CreateObject

// SYNTHETIC: IMPERIALISM 0x005840c0
// TDipDlgCluster::GetRuntimeClass

IMPLEMENT_DYNCREATE(TDipDlgCluster, TUberCluster)

// FUNCTION: IMPERIALISM 0x005840e0
TDipDlgCluster::TDipDlgCluster() {}

// SYNTHETIC: IMPERIALISM 0x00584110
// TDipDlgCluster::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00584140
TDipDlgCluster::~TDipDlgCluster() {}

// True when either trade-policy toggle in the hosting dialog is selected. Only the
// subsidy control is asserted non-null; a missing sanction control just reads as false.
// FUNCTION: IMPERIALISM 0x00584160
int TDipDlgCluster::IsTradeControlAtMinimum() {
  // 'subs' is already owned by resource_manifest_tags.h (scenario-script subsidy
  // instruction); one declaration per FourCC value, so the control lookup reuses it.
  TToggleButton* subsidyToggle =
      static_cast<TToggleButton*>(ownerContext->ResolveControlByTag(kManifestTagSubs));
  if (subsidyToggle == 0) {
    FailNilPointerWithAssert(s_SourcePathUSmallViews_006992F0, 0x1cd);
  }
  TToggleButton* sanctionToggle =
      static_cast<TToggleButton*>(ownerContext->ResolveControlByTag(kControlTagSanc));
  if (subsidyToggle->IsSelected()) {
    return 1;
  }
  if (sanctionToggle != 0) {
    return sanctionToggle->IsSelected() != 0;
  }
  return 0;
}
