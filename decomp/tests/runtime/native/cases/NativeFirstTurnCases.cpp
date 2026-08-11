#include "NativeTransition.h"
#include "JsonArray.h"
#include "JsonObject.h"
#include "RuntimeRun.h"
#include "screens/DealBookScreen.h"
#include "screens/NewspaperScreen.h"
#include "screens/OfferScreen.h"
#include "screens/StrategicMapScreen.h"

#include "game/globals/shared_globals.h"
#include "game/globals/trade_ui_globals.h"
#include "game/military/TArmyMgr.h"
#include "game/nation/TGreatPower.h"
#include "game/nation/TMinor.h"
#include "game/trade_ui/TOfferDeskPicture.h"
#include "game/turn_event_codes.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_widgets/TTradeMgr.h"

#include <windows.h>

namespace {

enum { kSecondaryNationStateSlotCount = 36 };

enum TailPresentation {
  kOfferSheetPresentation,
  kDealBookPresentation,
  kNewspaperPresentation,
  kStrategicMapPresentation
};

enum TailOutcome { kContinues, kUiGate, kPlayerOrders };

int CurrentTurnEvent() {
  return g_pViewMgr != 0 ? g_pViewMgr->currentTurnEventCode : -1;
}

RuntimeActionResult RequireFirstTurnFixture() {
  if (g_pSimMgr == 0 || g_pSimMgr->economicTurn != 1 || g_pSimMgr->turnStateCode != 5) {
    return RuntimeActionResult::Failure("the loaded fixture is not at first-turn phase 5");
  }
  return RuntimeActionResult::Success();
}

RuntimeActionResult AdvancePrerequisitesTo(int fromPhase) {
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
  if (!reached) {
    return RuntimeActionResult::Failure(
        "the prerequisite turn phases did not reach the requested tail phase");
  }
  return RuntimeActionResult::Success();
}

RuntimeActionResult FinishContinues(NativeTransition& transition, int from, int to,
                                    JSON_Value* effects) {
  JsonObject result;
  result.Set("kind", "continues");
  result.Set("from", from);
  result.Set("to", to);
  result.Set("effects", effects);
  return transition.Finish(result.Release());
}

RuntimeActionResult FinishContinuesEmpty(NativeTransition& transition, int from, int to) {
  JsonArray effects;
  return FinishContinues(transition, from, to, effects.Release());
}

bool HasFirstTurnNationSurvivalTopology() {
  if (g_pSimMgr->numMinorCountries != kNationSlotCount - kMinorNationFirstSlot) {
    return false;
  }
  for (int majorSlot = 0; majorSlot < kMajorNationCount; ++majorSlot) {
    TGreatPower* nation = g_apNationStates[majorSlot];
    if (nation == 0 || g_apTerrainTypeDescriptorTable[majorSlot] != nation ||
        nation->ownedRegionList == 0 || nation->ownedRegionList->GetSize() == 0) {
      return false;
    }
  }
  for (int minorSlot = kMinorNationFirstSlot; minorSlot < kNationSlotCount; ++minorSlot) {
    TMinor* nation = g_apSecondaryNationStateSlots[minorSlot];
    if (nation == 0 || g_apTerrainTypeDescriptorTable[minorSlot] != nation ||
        nation->ownedRegionList == 0 || nation->ownedRegionList->GetSize() == 0) {
      return false;
    }
  }
  for (int unusedSecondarySlot = kNationSlotCount;
       unusedSecondarySlot < kSecondaryNationStateSlotCount; ++unusedSecondarySlot) {
    if (g_apSecondaryNationStateSlots[unusedSecondarySlot] != 0) {
      return false;
    }
  }
  return true;
}

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

RuntimeActionResult RunOfferContinuesPhase(NativeTransition& transition, int fromPhase, int toPhase,
                                           bool needArmyMgr) {
  RuntimeActionResult ready = RequireFirstTurnFixture();
  if (!ready.Succeeded()) {
    return ready;
  }
  if (needArmyMgr && g_pMapContextActionManager == 0) {
    return RuntimeActionResult::Failure("the loaded fixture is not at first-turn phase 5");
  }

  RuntimeActionResult advanced = AdvancePrerequisitesTo(fromPhase);
  if (!advanced.Succeeded()) {
    return advanced;
  }
  if (CurrentTurnEvent() != kTurnEventOfferSheet || !OfferScreen::IsCurrent()) {
    return RuntimeActionResult::Failure("the phase did not begin from the retained offer sheet");
  }
  if (fromPhase == 0x0d && g_pMapContextActionManager->GetByteFlagAtOffset8() != 0) {
    return RuntimeActionResult::Failure(
        "the beginning-save fixture unexpectedly has a pending combat report");
  }

  RuntimeActionResult started = transition.Begin(JsonNullValue());
  if (!started.Succeeded()) {
    return started;
  }

  g_pSimMgr->AdvanceGlobalTurnStateMachine();
  if (g_pSimMgr->turnStateCode != toPhase) {
    return RuntimeActionResult::Failure("the phase did not advance to the expected turn state");
  }
  if (CurrentTurnEvent() != kTurnEventOfferSheet || !OfferScreen::IsCurrent()) {
    return RuntimeActionResult::Failure("the phase unexpectedly changed presentation");
  }

  return FinishContinuesEmpty(transition, fromPhase, toPhase);
}

RuntimeActionResult RunFirstTurnTailPhase(NativeTransition& transition, int fromPhase, int toPhase,
                                          TailPresentation beforePresentation,
                                          TailPresentation afterPresentation, TailOutcome outcome,
                                          const char* uiGate) {
  RuntimeActionResult ready = RequireFirstTurnFixture();
  if (!ready.Succeeded()) {
    return ready;
  }

  RuntimeActionResult advanced = AdvancePrerequisitesTo(fromPhase);
  if (!advanced.Succeeded()) {
    return advanced;
  }
  if (!HasPresentation(beforePresentation)) {
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

RuntimeActionResult RunFirstTurnAlertPhase(NativeTransition& transition) {
  RuntimeActionResult ready = RequireFirstTurnFixture();
  if (!ready.Succeeded()) {
    return ready;
  }

  RuntimeActionResult started = transition.Begin(JsonNullValue());
  if (!started.Succeeded()) {
    return started;
  }

  g_pSimMgr->AdvanceGlobalTurnStateMachine();
  return transition.Finish();
}

RuntimeActionResult RunFirstTurnDiplomacyPhase(NativeTransition& transition) {
  RuntimeActionResult ready = RequireFirstTurnFixture();
  if (!ready.Succeeded()) {
    return ready;
  }

  // Phase 5 has no first-turn alert work. Put the fixture at the exact phase-6 operation
  // boundary so this case observes only diplomacy application and replies.
  g_pSimMgr->turnStateCode = 6;

  RuntimeActionResult started = transition.Begin(JsonNullValue());
  if (!started.Succeeded()) {
    return started;
  }

  g_pSimMgr->AdvanceGlobalTurnStateMachine();
  if (g_pSimMgr->turnStateCode != 7) {
    return RuntimeActionResult::Failure("the diplomacy phase did not advance to phase 7");
  }
  if (CurrentTurnEvent() != kTurnEventDiplomacyMap) {
    return RuntimeActionResult::Failure("the diplomacy phase did not show the diplomacy map");
  }

  JsonObject effect;
  effect.Set("kind", "show_diplomacy_map");
  effect.Set("nation", static_cast<int>(g_pSimMgr->activeNationSlot));
  JsonArray effects;
  effects.Add(effect.Release());
  return FinishContinues(transition, 6, 7, effects.Release());
}

RuntimeActionResult RunFirstTurnTradePhase(NativeTransition& transition) {
  if (g_pSimMgr == 0 || g_pTradeMgr == 0 || g_pSimMgr->economicTurn != 1 ||
      g_pSimMgr->turnStateCode != 5) {
    return RuntimeActionResult::Failure("the loaded fixture is not at first-turn phase 5");
  }

  // Phase 5 has no first-turn alert work. Execute phase 6 to reach the same phase-7 trade
  // boundary that normal turn progression reaches after diplomacy application and replies.
  RuntimeActionResult advanced = AdvancePrerequisitesTo(7);
  if (!advanced.Succeeded()) {
    return RuntimeActionResult::Failure("the diplomacy phase did not advance to phase 7");
  }
  if (CurrentTurnEvent() != kTurnEventDiplomacyMap) {
    return RuntimeActionResult::Failure("the trade phase did not begin from the diplomacy map");
  }

  RuntimeActionResult started = transition.Begin(JsonNullValue());
  if (!started.Succeeded()) {
    return started;
  }

  g_pSimMgr->AdvanceGlobalTurnStateMachine();
  if (g_pSimMgr->turnStateCode != 9) {
    return RuntimeActionResult::Failure("the trade phase did not advance to phase 9");
  }
  if (CurrentTurnEvent() != kTurnEventOfferSheet) {
    return RuntimeActionResult::Failure("the trade phase did not dispatch its offer-sheet event");
  }
  if (!OfferScreen::IsCurrent()) {
    return RuntimeActionResult::Failure(
        "the beginning-save trade phase did not present the offer desk");
  }
  OfferScreen offerScreen;
  TOfferDeskPicture* offer = offerScreen.View();
  if (offer == 0) {
    return RuntimeActionResult::Failure("the presented offer desk is unavailable");
  }
  // DoTrade opens the offer-desk presentation before constructing deals. No retail offer is
  // posed for this fixture: the desk retains its zero-initialized payload and the deal cursor
  // runs past all seventeen commodity categories.
  if (offer->respondingNationSlot != 0 || offer->offeringNationSlot != 0 ||
      offer->commodityType != 0 || offer->proposedAmount != 0 || offer->maxAmount != 0) {
    return RuntimeActionResult::Failure(
        "the beginning-save trade phase unexpectedly posed a concrete offer");
  }
  if (g_pTradeMgr->categoryRows[0].dealCategoryOrderIndex != 0x11 ||
      g_pTradeMgr->categoryRows[0].dealEntryOrdinal != 1) {
    return RuntimeActionResult::Failure("the beginning-save trade deals did not finish");
  }

  JsonObject effect;
  effect.Set("kind", "show_offer_sheet");
  effect.Set("nation", static_cast<int>(g_pSimMgr->activeNationSlot));
  JsonArray effects;
  effects.Add(effect.Release());
  return FinishContinues(transition, 7, 9, effects.Release());
}

RuntimeActionResult RunFirstTurnCivilianPhase(NativeTransition& transition) {
  return RunOfferContinuesPhase(transition, 9, 10, false);
}

RuntimeActionResult RunFirstTurnMilitaryPhase(NativeTransition& transition) {
  return RunOfferContinuesPhase(transition, 10, 0x14, false);
}

RuntimeActionResult RunFirstTurnCombatMovementPhase(NativeTransition& transition) {
  return RunOfferContinuesPhase(transition, 0x14, 0x15, true);
}

RuntimeActionResult RunFirstTurnMilitaryCleanupPhase(NativeTransition& transition) {
  return RunOfferContinuesPhase(transition, 0x15, 0x0d, true);
}

RuntimeActionResult RunFirstTurnDiplomacyOfferPhase(NativeTransition& transition) {
  return RunOfferContinuesPhase(transition, 0x0d, 0x19, true);
}

RuntimeActionResult RunFirstTurnEliminationPhase(NativeTransition& transition) {
  RuntimeActionResult ready = RequireFirstTurnFixture();
  if (!ready.Succeeded()) {
    return ready;
  }
  if (g_pMapContextActionManager == 0) {
    return RuntimeActionResult::Failure("the loaded fixture is not at first-turn phase 5");
  }

  RuntimeActionResult advanced = AdvancePrerequisitesTo(0x19);
  if (!advanced.Succeeded()) {
    return advanced;
  }
  if (CurrentTurnEvent() != kTurnEventOfferSheet || !OfferScreen::IsCurrent()) {
    return RuntimeActionResult::Failure("elimination did not begin from the retained offer sheet");
  }
  if (!HasFirstTurnNationSurvivalTopology()) {
    return RuntimeActionResult::Failure(
        "the beginning-save fixture has an unexpected nation survival topology");
  }

  TGreatPower* majorNationsBefore[kMajorNationCount];
  TMinor* minorNationsBefore[kNationSlotCount - kMinorNationFirstSlot];
  for (int beforeMajorSlot = 0; beforeMajorSlot < kMajorNationCount; ++beforeMajorSlot) {
    majorNationsBefore[beforeMajorSlot] = g_apNationStates[beforeMajorSlot];
  }
  for (int beforeMinorSlot = kMinorNationFirstSlot; beforeMinorSlot < kNationSlotCount;
       ++beforeMinorSlot) {
    minorNationsBefore[beforeMinorSlot - kMinorNationFirstSlot] =
        g_apSecondaryNationStateSlots[beforeMinorSlot];
  }

  RuntimeActionResult started = transition.Begin(JsonNullValue());
  if (!started.Succeeded()) {
    return started;
  }

  g_pSimMgr->AdvanceGlobalTurnStateMachine();
  if (g_pSimMgr->turnStateCode != 8) {
    return RuntimeActionResult::Failure("elimination did not advance to city and transport");
  }
  if (CurrentTurnEvent() != kTurnEventOfferSheet || !OfferScreen::IsCurrent()) {
    return RuntimeActionResult::Failure(
        "the no-elimination branch unexpectedly changed presentation");
  }
  if (!HasFirstTurnNationSurvivalTopology()) {
    return RuntimeActionResult::Failure("elimination unexpectedly removed a surviving nation");
  }
  for (int afterMajorSlot = 0; afterMajorSlot < kMajorNationCount; ++afterMajorSlot) {
    if (g_apNationStates[afterMajorSlot] != majorNationsBefore[afterMajorSlot]) {
      return RuntimeActionResult::Failure("elimination replaced a surviving major nation");
    }
  }
  for (int afterMinorSlot = kMinorNationFirstSlot; afterMinorSlot < kNationSlotCount;
       ++afterMinorSlot) {
    if (g_apSecondaryNationStateSlots[afterMinorSlot] !=
        minorNationsBefore[afterMinorSlot - kMinorNationFirstSlot]) {
      return RuntimeActionResult::Failure("elimination replaced a surviving minor nation");
    }
  }

  return FinishContinuesEmpty(transition, 0x19, 8);
}

RuntimeActionResult RunFirstTurnCityTransportPhase(NativeTransition& transition) {
  return RunOfferContinuesPhase(transition, 8, 0x0b, false);
}

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
