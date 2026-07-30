#pragma once

#ifndef IMPERIALISM_STRATEGIC_MAP_SCREEN_H
#define IMPERIALISM_STRATEGIC_MAP_SCREEN_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error StrategicMapScreen is test-only and must not be included in the production build
#endif

#include "MainViewScreen.h"

class TMapUberPicture;
class TMapDialog;
class TView;

// The strategic map, as a script sees it.
//
// Replaces StrategicMapDriver, which took a root TView the caller had to resolve and validate
// itself and returned a bare bool, so every call site repeated the same two things: the
// four-part "is the map idle" predicate (spelled out 22 times across the suite) and a
// hand-written failure string that was vaguer than the diagnosis RuntimeUiDriver had already
// produced and discarded.
//
// This resolves and validates the current screen in its constructor. When the current screen
// is not the strategic map the object is *invalid* and every action returns a failure naming
// what was current instead -- so a script never needs a screen check before an action, and a
// mis-sequenced script says "expected TMapUberPicture at 0x07dd, found TTradeScreenPicture at
// 0x07d9" rather than "control is missing".
class StrategicMapScreen : public MainViewScreen {
public:
  StrategicMapScreen();

  // True when the map is the current main view at its own turn event with no modal above it.
  static bool IsCurrent();

  // Toolbar and command actions.
  RuntimeActionResult EndTurn();
  RuntimeActionResult OpenTrade();
  RuntimeActionResult OpenDiplomacy();
  RuntimeActionResult OpenCity();
  RuntimeActionResult OpenTransport();
  RuntimeActionResult ZoomOut();
  RuntimeActionResult ZoomIn();
  RuntimeActionResult CancelToSetup();

  // Non-input map manipulation. These are model/view calls rather than control activations,
  // so they are actions only in the sense that a script sequences them.
  RuntimeActionResult ScrollBy(int direction);
  RuntimeActionResult SetViewportCell(short cellX, short cellY);

  // Queries.
  TMapUberPicture* View() const;
  TMapDialog* Dialog() const;
  // Zoomed out shows the alternate map mode; the zoom-in control is present in that state and
  // the zoom-out control in the other, which is how the toggle is observable.
  bool IsZoomedOut() const;
  bool IsZoomedIn() const;
  int ViewportOriginX() const;
  int ViewportOriginY() const;

private:
  TMapUberPicture* mapView;
};

// Reads as StrategicMap().OpenTrade() in a script. Free function rather than a method on the
// scenario base, so the base does not have to include every screen header.
inline StrategicMapScreen StrategicMap() {
  return StrategicMapScreen();
}

#endif
