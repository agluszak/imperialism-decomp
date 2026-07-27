#include "StrategicMapDriver.h"

#include "RuntimeUiDriver.h"
#include "game/ui_core/TControl.h"
#include "game/ui_core/TView.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_map.h"
#include "game/ui_tags_widgets.h"

StrategicMapDriver::StrategicMapDriver(TView* view) : root(view) {}

bool StrategicMapDriver::EndTurnThroughNativeMessages() {
  TControl* done =
      root != 0 ? static_cast<TControl*>(root->ResolveControlByTag(kControlTagDoneCaps)) : 0;
  if (done == 0) {
    return false;
  }
  return RuntimeUiDriver::ClickViewThroughNativeMessages(done);
}

bool StrategicMapDriver::ActivateCitySemantically() {
  TView* toolbar = root != 0 ? root->ResolveControlByTag(kControlTagTool) : 0;
  return RuntimeUiDriver::ActivateControlSemantically(toolbar, kControlTagCity);
}

bool StrategicMapDriver::ActivateDiplomacySemantically() {
  TView* toolbar = root != 0 ? root->ResolveControlByTag(kControlTagTool) : 0;
  return RuntimeUiDriver::ActivateControlSemantically(toolbar, kControlTagDipl);
}

bool StrategicMapDriver::ActivateTradeSemantically() {
  TView* toolbar = root != 0 ? root->ResolveControlByTag(kControlTagTool) : 0;
  return RuntimeUiDriver::ActivateControlSemantically(toolbar, kControlTagTrad);
}
