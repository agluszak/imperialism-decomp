#pragma once

#ifndef IMPERIALISM_CAPITAL_SELECTION_SCREEN_H
#define IMPERIALISM_CAPITAL_SELECTION_SCREEN_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error CapitalSelectionScreen is test-only and must not be included in the production build
#endif

#include "MainViewScreen.h"

// The map while the player is picking a capital.
//
// The same view class as the strategic map on a different turn event, which is exactly why it needs
// its own screen: StrategicMapScreen would report itself invalid here (right class, wrong event)
// and refuse every action, and a scenario that reached for it would be told the map "is not the
// current screen" while looking straight at it.
class CapitalSelectionScreen : public MainViewScreen {
public:
  CapitalSelectionScreen();

  static bool IsCurrent();

  // Leave capital selection, which returns to the random-map setup screen.
  RuntimeActionResult CancelToSetup();
};

inline CapitalSelectionScreen CapitalSelection() {
  return CapitalSelectionScreen();
}

#endif
