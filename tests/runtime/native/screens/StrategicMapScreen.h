#pragma once

#ifndef IMPERIALISM_STRATEGIC_MAP_SCREEN_H
#define IMPERIALISM_STRATEGIC_MAP_SCREEN_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error StrategicMapScreen is test-only and must not be included in the production build
#endif

#include "MainViewScreen.h"

class TArmyPlacard;
class TArmyToolbar;
class TCivDescription;
class TCivToolbar;
class TMapUberPicture;
class TNumberedArrowButton;
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

  // This screen's view class, turn event and name -- the single source of the
  // identity. RT_OPEN_TO/RT_AWAIT_CURRENT read it, so a script never repeats either.
  static MainViewScreenIdentity Identity();

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
  // Re-enter the map through the game's own turn-event dispatch, for a script that left it by
  // dispatching some other screen and so has no control to click its way back with.
  RuntimeActionResult ReopenByTurnEvent(short nationSlot);

  // Register an animation owned by the map view, so a scenario can check that leaving the map
  // takes it away again. Tagged, because that is how the animator addresses its registry.
  RuntimeActionResult SeedOwnedAnimation(int tag);

  // Non-input map manipulation. These are model/view calls rather than control activations,
  // so they are actions only in the sense that a script sequences them.
  RuntimeActionResult ScrollBy(int direction);
  RuntimeActionResult SetViewportCell(short cellX, short cellY);

  // The civilian category page of the map toolbar. Showing it is a mode change on the map, not a
  // control activation: the page is already built and the mode decides which one is placed.
  RuntimeActionResult ShowCivilianToolbar();
  TCivToolbar* CivilianToolbar() const;
  // The page has moved to the position the map shows it at. Its off-screen parking spot is what
  // it holds while another category is selected, so this is how "the toolbar appeared" is
  // observable at all.
  bool CivilianToolbarIsPlaced() const;
  // The portrait of the selected civilian: which artwork it chose, and whether that artwork
  // actually loaded rather than leaving an empty frame.
  short CivilianPortraitGlyph() const;
  bool CivilianPortraitIsLoaded() const;
  // The legend beside the portrait: the per-profile target counters and the control that cycles
  // the camera through them.
  TCivDescription* CivilianLegend() const;

  // The army category page of the map toolbar, and its per-category widgets. The toolbar is a
  // child page of the map view rather than a screen of its own, so it lives here.
  RuntimeActionResult SelectArmyProvince(short province);
  bool ArmyMenuIsActiveForProvince(short province) const;
  TArmyToolbar* ArmyToolbar() const;
  TArmyPlacard* ArmyPlacard(int category) const;
  TNumberedArrowButton* ArmyRatioArrow(int category) const;
  // A numbered arrow is a two-zone widget: its lower half moves a unit out of the idle pool and
  // its upper half returns one. Driven through TrackMouse at a bounds-derived point because the
  // zone *is* the semantics -- there is no separate control per direction.
  RuntimeActionResult ClickArrowLowerHalf(TNumberedArrowButton* arrow);
  RuntimeActionResult ClickArrowUpperHalf(TNumberedArrowButton* arrow);

  // Queries.
  TMapUberPicture* View() const;
  TMapDialog* Dialog() const;
  // Zoomed out shows the alternate map mode; the zoom-in control is present in that state and
  // the zoom-out control in the other, which is how the toggle is observable.
  // The load path builds the end-turn control separately from the map view, so a loaded map can
  // legitimately be missing it for a tick. Its own predicate, so a test can wait for it.
  bool HasEndTurnControl() const;
  bool HasMiniMap() const;
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
