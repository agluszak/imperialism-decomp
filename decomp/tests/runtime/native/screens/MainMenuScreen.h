#pragma once

#ifndef IMPERIALISM_MAIN_MENU_SCREEN_H
#define IMPERIALISM_MAIN_MENU_SCREEN_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error MainMenuScreen is test-only and must not be included in the production build
#endif

#include "MainViewScreen.h"

// The main menu.
//
// Replaces MainMenuDriver, which took a root the caller had already resolved and validated and
// returned a bare bool. The navigation flow and the one scenario that comes back out to this
// screen now ask the same object.
class MainMenuScreen : public MainViewScreen {
public:
  MainMenuScreen();

  static bool IsCurrent();

  RuntimeActionResult StartRandomGame();
};

inline MainMenuScreen MainMenu() {
  return MainMenuScreen();
}

#endif
