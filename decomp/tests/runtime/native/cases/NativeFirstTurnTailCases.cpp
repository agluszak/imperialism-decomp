#include "NativeCases.h"
#include "JsonArray.h"
#include "JsonObject.h"
#include "RuntimeRun.h"
#include "screens/DealBookScreen.h"
#include "screens/NewspaperScreen.h"
#include "screens/OfferScreen.h"
#include "screens/StrategicMapScreen.h"

#include "game/globals/shared_globals.h"
#include "game/ui_screens/TSimMgr.h"

#include <windows.h>

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

RuntimeActionResult RunFirstTurnTailPhase(NativeTransition& transition, int fromPhase, int toPhase,
                                          TailPresentation beforePresentation,
                                          TailPresentation afterPresentation, TailOutcome outcome,
                                          const char* uiGate) {
  if (g_pSimMgr == 0 || g_pSimMgr->economicTurn != 1 || g_pSimMgr->turnStateCode != 5) {
    return RuntimeActionResult::Failure("the loaded fixture is not at first-turn phase 5");
  }

  g_pSimMgr->turnStateCode = 6;
  const int prerequisitePhases[] = {7,    9,    10,   0x14, 0x15, 0x0d, 0x19, 8,
                                    0x0b, 0x0c, 0x0e, 0x10, 0x11, 0x0f, 0x12};
  bool reached = false;
  for (int index = 0; index < 15; ++index) {
    g_pSimMgr->AdvanceGlobalTurnStateMachine();
    if (g_pSimMgr->turnStateCode != prerequisitePhases[index]) {
      return RuntimeActionResult::Failure(
          "the prerequisite turn phases did not reach the requested tail phase");
    }
    if (g_pSimMgr->turnStateCode == fromPhase) {
      reached = true;
      break;
    }
  }
  if (!reached || !HasPresentation(beforePresentation)) {
    return RuntimeActionResult::Failure(
        "the requested tail phase began with the wrong presentation state");
  }

  RuntimeActionResult started = transition.Begin(JsonNullValue());
  if (!started.Succeeded()) {
    return started;
  }

  g_pSimMgr->AdvanceGlobalTurnStateMachine();
  if (g_pSimMgr->turnStateCode != toPhase) {
    return RuntimeActionResult::Failure("the tail phase advanced to the wrong phase");
  }
  if (!HasPresentation(afterPresentation)) {
    return RuntimeActionResult::Failure("the tail phase produced the wrong presentation state");
  }

  JsonArray effects;
  JsonObject result;
  if (outcome == kContinues) {
    result.Set("kind", "continues");
    result.Set("from", fromPhase);
    result.Set("to", toPhase);
  } else {
    result.Set("kind", "blocked");
    result.Set("phase", toPhase);
    JsonObject block;
    if (outcome == kUiGate) {
      block.Set("kind", "ui");
      block.Set("gate", uiGate);
    } else {
      block.Set("kind", "player_orders");
    }
    result.Set("block", block.Release());
  }
  result.Set("effects", effects.Release());
  RuntimeActionResult finished = transition.Finish(result.Release());
  if (!finished.Succeeded()) {
    return finished;
  }
  if (!DiscardScheduledTurnAdvances(transition.Run().MainWindowHandle())) {
    return RuntimeActionResult::Failure(
        "a non-turn command was queued while dispatching prerequisite phases");
  }
  return RuntimeActionResult::Success();
}

} // namespace

RuntimeActionResult RunFirstTurnGreatPowerPressurePhase(NativeTransition& transition) {
  return RunFirstTurnTailPhase(transition, 0x0b, 0x0c, kOfferSheetPresentation,
                               kOfferSheetPresentation, kContinues, 0);
}

RuntimeActionResult RunFirstTurnDealBookPhase(NativeTransition& transition) {
  return RunFirstTurnTailPhase(transition, 0x0c, 0x0e, kOfferSheetPresentation,
                               kDealBookPresentation, kUiGate, "deal_book");
}

RuntimeActionResult RunFirstTurnQuarterGatePhase(NativeTransition& transition) {
  return RunFirstTurnTailPhase(transition, 0x0e, 0x10, kDealBookPresentation, kDealBookPresentation,
                               kContinues, 0);
}

RuntimeActionResult RunFirstTurnSeasonAdvancePhase(NativeTransition& transition) {
  return RunFirstTurnTailPhase(transition, 0x10, 0x11, kDealBookPresentation, kDealBookPresentation,
                               kContinues, 0);
}

RuntimeActionResult RunFirstTurnTechnologyAdvancesPhase(NativeTransition& transition) {
  return RunFirstTurnTailPhase(transition, 0x11, 0x0f, kDealBookPresentation, kDealBookPresentation,
                               kContinues, 0);
}

RuntimeActionResult RunFirstTurnNewspaperPhase(NativeTransition& transition) {
  return RunFirstTurnTailPhase(transition, 0x0f, 0x12, kDealBookPresentation,
                               kNewspaperPresentation, kUiGate, "newspaper");
}

RuntimeActionResult RunFirstTurnReturnToMapPhase(NativeTransition& transition) {
  return RunFirstTurnTailPhase(transition, 0x12, 5, kNewspaperPresentation,
                               kStrategicMapPresentation, kPlayerOrders, 0);
}
