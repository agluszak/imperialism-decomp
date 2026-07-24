#include "MainMenuDriver.h"

#include "RuntimeUiDriver.h"
#include "game/ui_tags_common.h"

MainMenuDriver::MainMenuDriver(TView* view) : root(view) {}

bool MainMenuDriver::StartRandomGame() {
  return RuntimeUiDriver::ClickControl(root, kControlTagRand);
}
