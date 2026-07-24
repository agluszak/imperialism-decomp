#include "StrategicMapDriver.h"

#include "RuntimeUiDriver.h"
#include "game/ui_core/TControl.h"
#include "game/ui_core/TView.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_map.h"

StrategicMapDriver::StrategicMapDriver(TView* view) : root(view) {}

bool StrategicMapDriver::EndTurn() {
  return RuntimeUiDriver::ClickControl(root, kControlTagSend);
}

bool StrategicMapDriver::ActivateCity() {
  TView* toolbar = root != 0 ? root->ResolveControlByTag(kControlTagTool) : 0;
  TControl* city =
      toolbar != 0 ? static_cast<TControl*>(toolbar->ResolveControlByTag(kControlTagCity)) : 0;
  if (city == 0 || city->IsActionable() == 0) {
    return false;
  }
  city->HandleEvent(city->GetEventNumber(), city, 0);
  return true;
}
