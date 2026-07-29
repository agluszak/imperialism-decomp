#include "StrategicMapDriver.h"

#include "RuntimeUiDriver.h"
#include "game/ui_core/TControl.h"
#include "game/ui_core/TView.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_map.h"
#include "game/ui_tags_widgets.h"

StrategicMapDriver::StrategicMapDriver(TView* view) : root(view) {}

bool StrategicMapDriver::EndTurn() {
  return RuntimeUiDriver::Activate(
      root, RuntimeControlSelector(kControlTagDoneCaps, RUNTIME_CLASS(TControl)));
}

bool StrategicMapDriver::OpenCity() {
  return RuntimeUiDriver::Activate(
      root, RuntimeControlSelector(kControlTagTool, kControlTagCity, RUNTIME_CLASS(TControl)));
}

bool StrategicMapDriver::ActivateTransport() {
  return RuntimeUiDriver::Activate(
      root, RuntimeControlSelector(kControlTagTool, kControlTagTran, RUNTIME_CLASS(TControl)));
}

bool StrategicMapDriver::OpenDiplomacy() {
  return RuntimeUiDriver::Activate(
      root, RuntimeControlSelector(kControlTagTool, kControlTagDipl, RUNTIME_CLASS(TControl)));
}

bool StrategicMapDriver::OpenTrade() {
  return RuntimeUiDriver::Activate(
      root, RuntimeControlSelector(kControlTagTool, kControlTagTrad, RUNTIME_CLASS(TControl)));
}
