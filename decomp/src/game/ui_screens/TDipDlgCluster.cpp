#include "game/ui_screens/TDipDlgCluster.h"

#include "game/gfx/ui_invalidation_guard.h"
#include "game/globals/global_types.h"
#include "game/globals/ui_widgets_globals.h"
#include "game/ui_screens/TToggleButton.h"
#include "game/resource_manifest_tags.h"
#include "game/ui_tags_common.h"

IMPLEMENT_DYNCREATE(TDipDlgCluster, TUberCluster)

// FUNCTION: IMPERIALISM 0x005840e0
TDipDlgCluster::TDipDlgCluster() {}

// FUNCTION: IMPERIALISM 0x00584140
TDipDlgCluster::~TDipDlgCluster() {}

// FUNCTION: IMPERIALISM 0x00584160
char TDipDlgCluster::IsTradeControlAtMinimum() {
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
    return sanctionToggle->IsSelected();
  }
  return 0;
}
