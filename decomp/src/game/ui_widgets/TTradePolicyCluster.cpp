#include "game/ui_widgets/TTradePolicyCluster.h"
#include "game/ui_tags_common.h"
#include "game/ui_core/TWindow.h"

#include "game/ui_core/TCluster.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/globals/ui_widgets_globals.h"

IMPLEMENT_DYNCREATE(TTradePolicyCluster, TUberCluster)

// FUNCTION: IMPERIALISM 0x005842a0
TTradePolicyCluster::TTradePolicyCluster() {}

// FUNCTION: IMPERIALISM 0x00584300
TTradePolicyCluster::~TTradePolicyCluster() {}

// FUNCTION: IMPERIALISM 0x00584320
void TTradePolicyCluster::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId != 0x67) {
    TCluster::DoEvent(commandId, sourceHandler, event);
    return;
  }
  TView* owner = GetWindow();
  SetSelectedChildTagAndRefresh(kControlTagSpSpSpSp);
  TView* clusControl = owner->ResolveControlByTag(kControlTagClus);
  if (clusControl == nullptr) {
    FailNilPointerWithAssert(s_SourcePathUSmallViews, 0x203);
  }
  static_cast<TCluster*>(clusControl)->SetSelectedChildTagAndRefresh(kControlTagSpSpSpSp);
}
