#include "FirstTurnPhaseHelpers.h"
#include "RuntimeRun.h"
#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "screens/DealBookScreen.h"
#include "screens/NewspaperScreen.h"
#include "screens/OfferScreen.h"
#include "screens/StrategicMapScreen.h"

#include "game/globals/shared_globals.h"
#include "game/ui_screens/TSimMgr.h"


namespace {

enum TailPresentation {
  kOfferSheetPresentation,
  kDealBookPresentation,
  kNewspaperPresentation,
  kStrategicMapPresentation
};

enum TailOutcome { kContinues, kUiGate, kPlayerOrders };

bool HasPresentation(TailPresentation presentation) {
  switch (presentation) {
  case kOfferSheetPresentation:
    return OfferScreen::IsCurrent();
  case kDealBookPresentation:
    return DealBookScreen::IsCurrent();
  case kNewspaperPresentation:
    return NewspaperScreen::IsCurrent();
  case kStrategicMapPresentation:
    return StrategicMapScreen::IsCurrent();
  }
  return false;
}

bool DiscardScheduledTurnAdvances(HWND mainWindow) {
  MSG message;
  while (PeekMessageA(&message, mainWindow, WM_COMMAND, WM_COMMAND, PM_NOREMOVE)) {
    if (LOWORD(message.wParam) != 100 || message.lParam != 0) {
      return false;
    }
    PeekMessageA(&message, mainWindow, WM_COMMAND, WM_COMMAND, PM_REMOVE);
  }
  return true;
}

class FirstTurnTailPhaseTestCase : public LoadedMapScriptScenario {
public:
  FirstTurnTailPhaseTestCase(int fromPhase, int toPhase, TailPresentation beforePresentation,
                             TailPresentation afterPresentation, TailOutcome outcome,
                             const char* uiGate)
      : fromPhase_(fromPhase), toPhase_(toPhase), beforePresentation_(beforePresentation),
        afterPresentation_(afterPresentation), outcome_(outcome), uiGate_(uiGate) {}

protected:
  void Script() override {
    RT_BEGIN();

    RT_DO("advance one first-turn tail phase", AdvanceTailPhaseOnce());
    RT_PASS();

    RT_END();
  }

private:
  RuntimeActionResult AdvanceTailPhaseOnce() {
    const int prerequisitePhases[] = {7,    9,    10,   0x14, 0x15, 0x0d, 0x19, 8,
                                      0x0b, 0x0c, 0x0e, 0x10, 0x11, 0x0f, 0x12};
    RuntimeActionResult advanced =
        AdvanceFirstTurnToPhase(prerequisitePhases, 15, fromPhase_);
    if (!advanced.Succeeded()) {
      return advanced;
    }
    if (!HasPresentation(beforePresentation_)) {
      return RuntimeActionResult::Failure(
          "the requested tail phase began with the wrong presentation state");
    }

    RuntimeActionResult before = CaptureTurnStepBefore(RunState());
    if (!before.Succeeded()) {
      return before;
    }
    MarkScriptStep("tail phase before state captured");

    g_pSimMgr->AdvanceGlobalTurnStateMachine();
    if (g_pSimMgr->turnStateCode != toPhase_) {
      return RuntimeActionResult::Failure("the tail phase advanced to the wrong phase");
    }
    if (!HasPresentation(afterPresentation_)) {
      return RuntimeActionResult::Failure("the tail phase produced the wrong presentation state");
    }
    MarkScriptStep("tail phase dispatched");

    RuntimeActionResult after;
    if (outcome_ == kContinues) {
      after = CaptureTurnStepContinuesAfter(RunState(), fromPhase_, toPhase_);
    } else if (outcome_ == kUiGate) {
      after = CaptureTurnStepBlockedAfter(RunState(), toPhase_, "ui", uiGate_);
    } else {
      after = CaptureTurnStepBlockedAfter(RunState(), toPhase_, "player_orders", 0);
    }
    if (!after.Succeeded()) {
      return after;
    }
    if (!DiscardScheduledTurnAdvances(RunState().MainWindowHandle())) {
      return RuntimeActionResult::Failure(
          "a non-turn command was queued while dispatching prerequisite phases");
    }
    MarkScriptStep("tail phase after state captured");
    return RuntimeActionResult::Success();
  }

  int fromPhase_;
  int toPhase_;
  TailPresentation beforePresentation_;
  TailPresentation afterPresentation_;
  TailOutcome outcome_;
  const char* uiGate_;
};

class FirstTurnGreatPowerPressurePhaseTestCase : public FirstTurnTailPhaseTestCase {
public:
  FirstTurnGreatPowerPressurePhaseTestCase()
      : FirstTurnTailPhaseTestCase(0x0b, 0x0c, kOfferSheetPresentation, kOfferSheetPresentation,
                                   kContinues, 0) {}
};

class FirstTurnDealBookPhaseTestCase : public FirstTurnTailPhaseTestCase {
public:
  FirstTurnDealBookPhaseTestCase()
      : FirstTurnTailPhaseTestCase(0x0c, 0x0e, kOfferSheetPresentation, kDealBookPresentation,
                                   kUiGate, "deal_book") {}
};

class FirstTurnQuarterGatePhaseTestCase : public FirstTurnTailPhaseTestCase {
public:
  FirstTurnQuarterGatePhaseTestCase()
      : FirstTurnTailPhaseTestCase(0x0e, 0x10, kDealBookPresentation, kDealBookPresentation,
                                   kContinues, 0) {}
};

class FirstTurnSeasonAdvancePhaseTestCase : public FirstTurnTailPhaseTestCase {
public:
  FirstTurnSeasonAdvancePhaseTestCase()
      : FirstTurnTailPhaseTestCase(0x10, 0x11, kDealBookPresentation, kDealBookPresentation,
                                   kContinues, 0) {}
};

class FirstTurnTechnologyAdvancesPhaseTestCase : public FirstTurnTailPhaseTestCase {
public:
  FirstTurnTechnologyAdvancesPhaseTestCase()
      : FirstTurnTailPhaseTestCase(0x11, 0x0f, kDealBookPresentation, kDealBookPresentation,
                                   kContinues, 0) {}
};

class FirstTurnNewspaperPhaseTestCase : public FirstTurnTailPhaseTestCase {
public:
  FirstTurnNewspaperPhaseTestCase()
      : FirstTurnTailPhaseTestCase(0x0f, 0x12, kDealBookPresentation, kNewspaperPresentation,
                                   kUiGate, "newspaper") {}
};

class FirstTurnReturnToMapPhaseTestCase : public FirstTurnTailPhaseTestCase {
public:
  FirstTurnReturnToMapPhaseTestCase()
      : FirstTurnTailPhaseTestCase(0x12, 5, kNewspaperPresentation, kStrategicMapPresentation,
                                   kPlayerOrders, 0) {}
};

} // namespace

RUNTIME_TEST_FACTORY(FirstTurnGreatPowerPressurePhaseTestCase, FirstTurnGreatPowerPressurePhaseTest)
RUNTIME_TEST_FACTORY(FirstTurnDealBookPhaseTestCase, FirstTurnDealBookPhaseTest)
RUNTIME_TEST_FACTORY(FirstTurnQuarterGatePhaseTestCase, FirstTurnQuarterGatePhaseTest)
RUNTIME_TEST_FACTORY(FirstTurnSeasonAdvancePhaseTestCase, FirstTurnSeasonAdvancePhaseTest)
RUNTIME_TEST_FACTORY(FirstTurnTechnologyAdvancesPhaseTestCase, FirstTurnTechnologyAdvancesPhaseTest)
RUNTIME_TEST_FACTORY(FirstTurnNewspaperPhaseTestCase, FirstTurnNewspaperPhaseTest)
RUNTIME_TEST_FACTORY(FirstTurnReturnToMapPhaseTestCase, FirstTurnReturnToMapPhaseTest)
