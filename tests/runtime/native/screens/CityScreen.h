#pragma once

#ifndef IMPERIALISM_CITY_SCREEN_H
#define IMPERIALISM_CITY_SCREEN_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error CityScreen is test-only and must not be included in the production build
#endif

#include "MainViewScreen.h"

class TCityProductionView;

// The city production screen: the industry map of one city, with a floating page per building.
class CityScreen : public MainViewScreen {
public:
  CityScreen();

  // This screen's view class, turn event and name -- the single source of the
  // identity. RT_OPEN_TO/RT_AWAIT_CURRENT read it, so a script never repeats either.
  static MainViewScreenIdentity Identity();

  static bool IsCurrent();

  TCityProductionView* View() const;

  // The screen is not usable without its labour-pool and food readouts.
  bool HasProductionControls() const;
  // Status placards for sickness and death exist but must be invisible while their counts are
  // zero: a placard left showing is the "the city looks stricken on turn one" regression.
  bool SicknessPlacardsAreCleared() const;

  // Repaint the whole screen, children included, and wait for it to land. Used to prove the
  // screen settles: after one forced paint there must be nothing left invalidated.
  RuntimeActionResult ForceOnePaint();
  bool HasPendingPaint() const;

  // Open a building's floating page by clicking its hit region on the city artwork.
  RuntimeActionResult OpenBuilding(short buildingSlot);
  bool BuildingIsOpen(short buildingSlot) const;
  // Whether a building has an animation to run while it is working. Answerable without opening
  // the page, so a scenario can choose an industry that is worth visiting.
  bool HasBuildingAnimation(short buildingSlot) const;

  RuntimeActionResult Close();

private:
  TCityProductionView* cityView;
};

// Reads as City().OpenBuilding(slot) in a script.
inline CityScreen City() {
  return CityScreen();
}

// The production view a building page belongs to, for CityBuildingScreen. Not part of a script's
// vocabulary -- a script asks the city screen or a building page, never for the view itself.
TCityProductionView* CityScreenProductionView();

#endif
