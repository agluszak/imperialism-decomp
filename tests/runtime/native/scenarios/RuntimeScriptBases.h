#pragma once

#ifndef IMPERIALISM_RUNTIME_SCRIPT_BASES_H
#define IMPERIALISM_RUNTIME_SCRIPT_BASES_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error RuntimeScriptBases is test-only and must not be included in the production build
#endif

#include "RuntimeScriptScenario.h"
#include "flows/LoadGameFlow.h"
#include "flows/RandomGameFlow.h"

// Where a script starts.
//
// Every scenario used to repeat the same preamble: pick a difficulty, override the matching
// checkpoint hook (OnMapReadyWithoutCapitalSelection or OnCombinedMapReady depending on that
// difficulty), assign the initial phase, call EnterScenarioStep and yield. Getting the
// difficulty and the hook out of step is silent -- the hook simply never fires and the run
// stalls.
//
// A script scenario picks a base instead and overrides Script() only. The difficulty and the
// hook are chosen together here, so they cannot disagree.
//
// These re-derive the navigation flow rather than inheriting RandomGameScenario, so there is
// no multiple inheritance and the phase-machine bases stay untouched for tests that have not
// migrated yet.

// Random game reaching the map. Not used directly -- pick one of the difficulty bases below.
class RandomGameScriptScenario : public RuntimeScriptScenario {
protected:
  RuntimeFlow* NavigationFlow() override;
  // For a script that needs to re-enter the flow (returning to setup and back to the map).
  void RestartRandomGameAtStrategicMapEntry();

private:
  RandomGameFlow randomGameFlow;
};

// Easy: no capital selection, so the flow hands over at kRuntimeMapReadyWithoutCapitalSelection.
// The right default for anything that just needs to be on the map.
class EasyMapScriptScenario : public RandomGameScriptScenario {
public:
  int DifficultyLevel() const override;
  void OnMapReadyWithoutCapitalSelection() override;
};

// Introductory: also skips capital selection, but shows the opening newspaper.
class IntroductoryMapScriptScenario : public RandomGameScriptScenario {
public:
  int DifficultyLevel() const override;
  void OnMapReadyWithoutCapitalSelection() override;
};

// Normal and above: the player picks a capital first, so the flow hands over at
// kRuntimeCombinedMapReady.
class CombinedMapScriptScenario : public RandomGameScriptScenario {
public:
  int DifficultyLevel() const override;
  void OnCombinedMapReady() override;
};

// A saved game loaded from a fixture. RequiresFixture() is enforced by the base against
// IMPERIALISM_RUNTIME_TEST_FIXTURE, so a missing fixture fails with that reason rather than
// stalling.
class LoadedMapScriptScenario : public RuntimeScriptScenario {
public:
  bool RequiresFixture() const override;
  void OnCombinedMapReady() override;

protected:
  RuntimeFlow* NavigationFlow() override;

private:
  LoadGameFlow loadGameFlow;
};

// Managers only: no main window, no navigation flow. For scenarios that assert on model state
// without needing a screen.
class ManagersReadyScriptScenario : public RuntimeScriptScenario {
public:
  bool RequiresMainWindow() const override;
  void OnManagersReady() override;
};

#endif
