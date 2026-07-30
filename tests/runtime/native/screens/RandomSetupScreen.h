#pragma once

#ifndef IMPERIALISM_RANDOM_SETUP_SCREEN_H
#define IMPERIALISM_RANDOM_SETUP_SCREEN_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error RandomSetupScreen is test-only and must not be included in the production build
#endif

#include "MainViewScreen.h"

class TSetupRandomMapPicture;

// The random-map setup screen: country name, difficulty, okay, cancel.
//
// Replaces RandomSetupDriver. Difficulty is addressed by level rather than by tag, because the
// level is what every caller has -- the flow passes the scenario's DifficultyLevel() and the
// tags are consecutive from 'dif0'.
class RandomSetupScreen : public MainViewScreen {
public:
  RandomSetupScreen();

  static bool IsCurrent();

  TSetupRandomMapPicture* View() const;
  short SelectedNationSlot() const;

  RuntimeActionResult SetCountryName(const char* name);
  RuntimeActionResult SelectDifficulty(int level);
  bool DifficultyIsSelected(int level) const;
  RuntimeActionResult Accept();
  RuntimeActionResult Cancel();

private:
  TSetupRandomMapPicture* setupView;
};

inline RandomSetupScreen RandomSetup() {
  return RandomSetupScreen();
}

#endif
