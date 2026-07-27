#include "MainMenuDriver.h"

#include "RuntimeUiDriver.h"
#include "game/ui_tags_common.h"

MainMenuDriver::MainMenuDriver(TView* view) : root(view) {}

bool MainMenuDriver::StartRandomGameSemantically() {
  return RuntimeUiDriver::ActivateControlSemantically(root, kControlTagRand);
}
