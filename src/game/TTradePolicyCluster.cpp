#include "game/TTradePolicyCluster.h"
#include "game/TWindow.h"

#include "game/TCluster.h"
#include "game/ui_invalidation_guard.h"
#include "game/ui_tags_common.h"
// SYNTHETIC: IMPERIALISM 0x00584200
// TTradePolicyCluster::CreateObject

// SYNTHETIC: IMPERIALISM 0x00584280
// TTradePolicyCluster::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTradePolicyCluster, TUberCluster)

// FUNCTION: IMPERIALISM 0x005842a0
TTradePolicyCluster::TTradePolicyCluster() {}

// SYNTHETIC: IMPERIALISM 0x005842d0
// TTradePolicyCluster::`scalar deleting destructor'
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
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\USmallViews.cpp", 0x203);
  }
  static_cast<TCluster*>(clusControl)->SetSelectedChildTagAndRefresh(kControlTagSpSpSpSp);
}
