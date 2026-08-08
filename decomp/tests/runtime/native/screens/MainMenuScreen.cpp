#include "MainMenuScreen.h"

#include "game/turn_event_codes.h"
#include "game/ui_core/TControl.h"
#include "game/ui_screens/TGameSetupPicture.h"
#include "game/ui_tags_common.h"

namespace {

// The menu buttons publish this command rather than the usual control event, so the selector has
// to say so or it resolves the right control and refuses it.
const int kMenuButtonEventNumber = 0x14;

} // namespace

MainMenuScreen::MainMenuScreen()
    : MainViewScreen(RUNTIME_CLASS(TGameSetupPicture), kTurnEventMainMenu, "the main menu") {}

bool MainMenuScreen::IsCurrent() {
  return MainViewIsCurrent(RUNTIME_CLASS(TGameSetupPicture), kTurnEventMainMenu);
}

RuntimeActionResult MainMenuScreen::StartRandomGame() {
  if (!IsValid()) {
    return InvalidScreen("start a random game");
  }
  return Activate(kControlTagRand, RUNTIME_CLASS(TControl), kMenuButtonEventNumber,
                  "start a random game");
}
