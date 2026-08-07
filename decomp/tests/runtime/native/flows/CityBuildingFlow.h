#pragma once

#ifndef IMPERIALISM_CITY_BUILDING_FLOW_H
#define IMPERIALISM_CITY_BUILDING_FLOW_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error CityBuildingFlow is test-only and must not be included in the production build
#endif

#include "scenarios/RuntimeScriptFragment.h"
#include "screens/CityBuildingScreen.h"

// Opening and closing one of the city's building pages.
//
// Six buildings, one sequence each way, and both ways have a wait in them: the page is built
// after the click on the city artwork, and torn down after the window's system close. A scenario
// that opens six pages would otherwise repeat the same four steps six times -- which is what
// CityScreenTest did.
//
// Opening also confirms what was opened. A page that belongs to another city, or is the embedded
// variant rather than this slot's own window, or has lost its floating frame, is a defect the
// scenario after it would otherwise report as a wrong count.
class OpenCityBuildingFlow : public RuntimeScriptFragment {
public:
  OpenCityBuildingFlow();

  RuntimeScriptStatus Open(short buildingSlot, CityBuildingKind kind,
                           RuntimeScriptScenario& scenario);

private:
  RuntimeScriptStatus Advance();

  short slot;
  CityBuildingKind kind;
  bool started;
};

class CloseCityBuildingFlow : public RuntimeScriptFragment {
public:
  CloseCityBuildingFlow();

  RuntimeScriptStatus Close(short buildingSlot, CityBuildingKind kind,
                            RuntimeScriptScenario& scenario);

private:
  RuntimeScriptStatus Advance();

  short slot;
  CityBuildingKind kind;
  bool started;
};

#endif
