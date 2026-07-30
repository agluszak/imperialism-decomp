#include "CityBuildingFlow.h"

#include "RuntimeObservation.h"
#include "scenarios/RuntimeScriptMacros.h"
#include "screens/CityScreen.h"

OpenCityBuildingFlow::OpenCityBuildingFlow()
    : slot(-1), kind(kCityBuildingUniversity), started(false) {}

RuntimeScriptStatus OpenCityBuildingFlow::Open(short buildingSlot, CityBuildingKind buildingKind,
                                               RuntimeScriptScenario& scenario) {
  if (!started) {
    // Rewind: the same scenario opens six pages through this one fragment, and a fragment that
    // is not rewound resumes where the previous run finished.
    BeginFragment(scenario);
    slot = buildingSlot;
    kind = buildingKind;
    started = true;
  }
  RuntimeScriptStatus status = Advance();
  if (status != kRuntimeScriptRunning) {
    started = false;
  }
  return status;
}

RuntimeScriptStatus OpenCityBuildingFlow::Advance() {
  RT_FRAGMENT_BEGIN();

  RT_FRAGMENT_ACTION("open a city building", City().OpenBuilding(slot));
  RT_FRAGMENT_AWAIT(CityBuildingScreen(slot, kind).IsOpen(), kObserveUiStateChanged);
  RT_FRAGMENT_STEP("confirm the building page", CityBuildingScreen(slot, kind).VerifyIdentity());
  RT_FRAGMENT_STEP("confirm the building window frame",
                   CityBuildingScreen(slot, kind).VerifyRetailFloatingFrame());
  // What the page shows on arrival has to agree with the orders behind it, before anything is
  // clicked: a page that opens wrong would otherwise be blamed on the click that followed.
  RT_FRAGMENT_STEP("confirm the building's counts",
                   CityBuildingScreen(slot, kind).VerifyLiveOrderState());
  RT_FRAGMENT_DONE();

  RT_FRAGMENT_END();
}

CloseCityBuildingFlow::CloseCityBuildingFlow()
    : slot(-1), kind(kCityBuildingUniversity), started(false) {}

RuntimeScriptStatus CloseCityBuildingFlow::Close(short buildingSlot, CityBuildingKind buildingKind,
                                                 RuntimeScriptScenario& scenario) {
  if (!started) {
    BeginFragment(scenario);
    slot = buildingSlot;
    kind = buildingKind;
    started = true;
  }
  RuntimeScriptStatus status = Advance();
  if (status != kRuntimeScriptRunning) {
    started = false;
  }
  return status;
}

RuntimeScriptStatus CloseCityBuildingFlow::Advance() {
  RT_FRAGMENT_BEGIN();

  RT_FRAGMENT_ACTION("close the building window", CityBuildingScreen(slot, kind).CloseNatively());
  RT_FRAGMENT_AWAIT(!CityBuildingScreen(slot, kind).IsOpen(), kObserveUiStateChanged);
  RT_FRAGMENT_DONE();

  RT_FRAGMENT_END();
}
