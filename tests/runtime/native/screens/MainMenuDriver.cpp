#include "MainMenuDriver.h"

#include "RuntimeUiDriver.h"
#include "game/ui_core/TControl.h"
#include "game/ui_tags_common.h"

MainMenuDriver::MainMenuDriver(TView* view) : root(view) {}

bool MainMenuDriver::StartRandomGame(CString* failure) {
  return RuntimeUiDriver::Activate(
      root, RuntimeControlSelector(kControlTagRand, RUNTIME_CLASS(TControl), 0x14), failure);
}
