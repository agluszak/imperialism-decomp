#include "NativeCases.h"
#include "JsonArray.h"
#include "JsonObject.h"
#include "screens/OfferScreen.h"

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

namespace {

enum { kSecondaryNationStateSlotCount = 36 };

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

int CurrentTurnEvent() {
  return g_pViewMgr != 0 ? g_pViewMgr->currentTurnEventCode : -1;
}

} // namespace

RuntimeActionResult RunFirstTurnTradePhase(NativeTransition& transition) {
  if (g_pSimMgr == 0 || g_pTradeMgr == 0 || g_pSimMgr->economicTurn != 1 ||
      g_pSimMgr->turnStateCode != 5) {
    return RuntimeActionResult::Failure("the loaded fixture is not at first-turn phase 5");
  }

  // Phase 5 has no first-turn alert work. Execute phase 6 to reach the same phase-7 trade
  // boundary that normal turn progression reaches after diplomacy application and replies.
  g_pSimMgr->turnStateCode = 6;
  g_pSimMgr->AdvanceGlobalTurnStateMachine();
  if (g_pSimMgr->turnStateCode != 7) {
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
  JsonObject result;
  result.Set("kind", "continues");
  result.Set("from", 7);
  result.Set("to", 9);
  result.Set("effects", effects.Release());
  return transition.Finish(result.Release());
}

RuntimeActionResult RunFirstTurnCivilianPhase(NativeTransition& transition) {
  if (g_pSimMgr == 0 || g_pSimMgr->economicTurn != 1 || g_pSimMgr->turnStateCode != 5) {
    return RuntimeActionResult::Failure("the loaded fixture is not at first-turn phase 5");
  }

  g_pSimMgr->turnStateCode = 6;
  g_pSimMgr->AdvanceGlobalTurnStateMachine();
  if (g_pSimMgr->turnStateCode != 7) {
    return RuntimeActionResult::Failure("the diplomacy phase did not advance to phase 7");
  }
  g_pSimMgr->AdvanceGlobalTurnStateMachine();
  if (g_pSimMgr->turnStateCode != 9) {
    return RuntimeActionResult::Failure("the trade phase did not advance to phase 9");
  }
  if (CurrentTurnEvent() != kTurnEventOfferSheet || !OfferScreen::IsCurrent()) {
    return RuntimeActionResult::Failure("the civilian phase did not begin from the offer desk");
  }

  RuntimeActionResult started = transition.Begin(JsonNullValue());
  if (!started.Succeeded()) {
    return started;
  }

  g_pSimMgr->AdvanceGlobalTurnStateMachine();
  if (g_pSimMgr->turnStateCode != 10) {
    return RuntimeActionResult::Failure("the civilian phase did not advance to phase 10");
  }
  if (CurrentTurnEvent() != kTurnEventOfferSheet || !OfferScreen::IsCurrent()) {
    return RuntimeActionResult::Failure("the civilian phase unexpectedly changed presentation");
  }

  JsonArray effects;
  JsonObject result;
  result.Set("kind", "continues");
  result.Set("from", 9);
  result.Set("to", 10);
  result.Set("effects", effects.Release());
  return transition.Finish(result.Release());
}

RuntimeActionResult RunFirstTurnMilitaryPhase(NativeTransition& transition) {
  if (g_pSimMgr == 0 || g_pSimMgr->economicTurn != 1 || g_pSimMgr->turnStateCode != 5) {
    return RuntimeActionResult::Failure("the loaded fixture is not at first-turn phase 5");
  }

  g_pSimMgr->turnStateCode = 6;
  g_pSimMgr->AdvanceGlobalTurnStateMachine();
  if (g_pSimMgr->turnStateCode != 7) {
    return RuntimeActionResult::Failure("the diplomacy phase did not advance to phase 7");
  }
  g_pSimMgr->AdvanceGlobalTurnStateMachine();
  if (g_pSimMgr->turnStateCode != 9) {
    return RuntimeActionResult::Failure("the trade phase did not advance to phase 9");
  }
  if (CurrentTurnEvent() != kTurnEventOfferSheet || !OfferScreen::IsCurrent()) {
    return RuntimeActionResult::Failure("the civilian phase did not begin from the offer desk");
  }
  g_pSimMgr->AdvanceGlobalTurnStateMachine();
  if (g_pSimMgr->turnStateCode != 10) {
    return RuntimeActionResult::Failure("the civilian phase did not advance to phase 10");
  }
  if (CurrentTurnEvent() != kTurnEventOfferSheet || !OfferScreen::IsCurrent()) {
    return RuntimeActionResult::Failure("the military phase did not begin from the offer desk");
  }

  RuntimeActionResult started = transition.Begin(JsonNullValue());
  if (!started.Succeeded()) {
    return started;
  }

  g_pSimMgr->AdvanceGlobalTurnStateMachine();
  if (g_pSimMgr->turnStateCode != 0x14) {
    return RuntimeActionResult::Failure("the military phase did not advance to phase 0x14");
  }
  if (CurrentTurnEvent() != kTurnEventOfferSheet || !OfferScreen::IsCurrent()) {
    return RuntimeActionResult::Failure("the military phase unexpectedly changed presentation");
  }

  JsonArray effects;
  JsonObject result;
  result.Set("kind", "continues");
  result.Set("from", 10);
  result.Set("to", 0x14);
  result.Set("effects", effects.Release());
  return transition.Finish(result.Release());
}

RuntimeActionResult RunFirstTurnCombatMovementPhase(NativeTransition& transition) {
  if (g_pSimMgr == 0 || g_pMapContextActionManager == 0 || g_pSimMgr->economicTurn != 1 ||
      g_pSimMgr->turnStateCode != 5) {
    return RuntimeActionResult::Failure("the loaded fixture is not at first-turn phase 5");
  }

  g_pSimMgr->turnStateCode = 6;
  const int expectedPhases[] = {7, 9, 10, 0x14};
  for (int index = 0; index < 4; ++index) {
    g_pSimMgr->AdvanceGlobalTurnStateMachine();
    if (g_pSimMgr->turnStateCode != expectedPhases[index]) {
      return RuntimeActionResult::Failure(
          "the prerequisite turn phases did not reach combat movement");
    }
  }
  if (!OfferScreen::IsCurrent()) {
    return RuntimeActionResult::Failure(
        "combat movement did not begin from the retained offer-sheet presentation");
  }

  RuntimeActionResult started = transition.Begin(JsonNullValue());
  if (!started.Succeeded()) {
    return started;
  }

  g_pSimMgr->AdvanceGlobalTurnStateMachine();
  if (g_pSimMgr->turnStateCode != 0x15) {
    return RuntimeActionResult::Failure("combat movement did not advance to military cleanup");
  }
  if (!OfferScreen::IsCurrent()) {
    return RuntimeActionResult::Failure(
        "the zero-stack combat pass unexpectedly changed presentation");
  }

  JsonArray effects;
  JsonObject result;
  result.Set("kind", "continues");
  result.Set("from", 0x14);
  result.Set("to", 0x15);
  result.Set("effects", effects.Release());
  return transition.Finish(result.Release());
}

RuntimeActionResult RunFirstTurnMilitaryCleanupPhase(NativeTransition& transition) {
  if (g_pSimMgr == 0 || g_pMapContextActionManager == 0 || g_pSimMgr->economicTurn != 1 ||
      g_pSimMgr->turnStateCode != 5) {
    return RuntimeActionResult::Failure("the loaded fixture is not at first-turn phase 5");
  }

  g_pSimMgr->turnStateCode = 6;
  const int expectedPhases[] = {7, 9, 10, 0x14, 0x15};
  for (int index = 0; index < 5; ++index) {
    g_pSimMgr->AdvanceGlobalTurnStateMachine();
    if (g_pSimMgr->turnStateCode != expectedPhases[index]) {
      return RuntimeActionResult::Failure(
          "the prerequisite turn phases did not reach military cleanup");
    }
  }
  if (!OfferScreen::IsCurrent()) {
    return RuntimeActionResult::Failure(
        "military cleanup did not begin from the retained offer-sheet presentation");
  }

  RuntimeActionResult started = transition.Begin(JsonNullValue());
  if (!started.Succeeded()) {
    return started;
  }

  g_pSimMgr->AdvanceGlobalTurnStateMachine();
  if (g_pSimMgr->turnStateCode != 0xd) {
    return RuntimeActionResult::Failure(
        "military cleanup did not advance to the diplomatic-offer phase");
  }
  if (!OfferScreen::IsCurrent()) {
    return RuntimeActionResult::Failure("military cleanup unexpectedly changed presentation");
  }

  JsonArray effects;
  JsonObject result;
  result.Set("kind", "continues");
  result.Set("from", 0x15);
  result.Set("to", 0xd);
  result.Set("effects", effects.Release());
  return transition.Finish(result.Release());
}

RuntimeActionResult RunFirstTurnDiplomacyOfferPhase(NativeTransition& transition) {
  if (g_pSimMgr == 0 || g_pMapContextActionManager == 0 || g_pSimMgr->economicTurn != 1 ||
      g_pSimMgr->turnStateCode != 5) {
    return RuntimeActionResult::Failure("the loaded fixture is not at first-turn phase 5");
  }

  g_pSimMgr->turnStateCode = 6;
  const int expectedPhases[] = {7, 9, 10, 0x14, 0x15, 0x0d};
  for (int index = 0; index < 6; ++index) {
    g_pSimMgr->AdvanceGlobalTurnStateMachine();
    if (g_pSimMgr->turnStateCode != expectedPhases[index]) {
      return RuntimeActionResult::Failure(
          "the prerequisite turn phases did not reach the diplomacy-offer phase");
    }
  }
  if (CurrentTurnEvent() != kTurnEventOfferSheet || !OfferScreen::IsCurrent()) {
    return RuntimeActionResult::Failure(
        "the diplomacy-offer phase did not begin from the retained offer sheet");
  }
  if (g_pMapContextActionManager->GetByteFlagAtOffset8() != 0) {
    return RuntimeActionResult::Failure(
        "the beginning-save fixture unexpectedly has a pending combat report");
  }

  RuntimeActionResult started = transition.Begin(JsonNullValue());
  if (!started.Succeeded()) {
    return started;
  }

  g_pSimMgr->AdvanceGlobalTurnStateMachine();
  if (g_pSimMgr->turnStateCode != 0x19) {
    return RuntimeActionResult::Failure("the diplomacy-offer phase did not advance to elimination");
  }
  if (CurrentTurnEvent() != kTurnEventOfferSheet || !OfferScreen::IsCurrent()) {
    return RuntimeActionResult::Failure(
        "the empty diplomacy-offer phase unexpectedly changed presentation");
  }

  JsonArray effects;
  JsonObject result;
  result.Set("kind", "continues");
  result.Set("from", 0x0d);
  result.Set("to", 0x19);
  result.Set("effects", effects.Release());
  return transition.Finish(result.Release());
}

RuntimeActionResult RunFirstTurnEliminationPhase(NativeTransition& transition) {
  if (g_pSimMgr == 0 || g_pMapContextActionManager == 0 || g_pSimMgr->economicTurn != 1 ||
      g_pSimMgr->turnStateCode != 5) {
    return RuntimeActionResult::Failure("the loaded fixture is not at first-turn phase 5");
  }

  g_pSimMgr->turnStateCode = 6;
  const int expectedPhases[] = {7, 9, 10, 0x14, 0x15, 0x0d, 0x19};
  for (int index = 0; index < 7; ++index) {
    g_pSimMgr->AdvanceGlobalTurnStateMachine();
    if (g_pSimMgr->turnStateCode != expectedPhases[index]) {
      return RuntimeActionResult::Failure("the prerequisite turn phases did not reach elimination");
    }
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

  JsonArray effects;
  JsonObject result;
  result.Set("kind", "continues");
  result.Set("from", 0x19);
  result.Set("to", 8);
  result.Set("effects", effects.Release());
  return transition.Finish(result.Release());
}

RuntimeActionResult RunFirstTurnCityTransportPhase(NativeTransition& transition) {
  if (g_pSimMgr == 0 || g_pSimMgr->economicTurn != 1 || g_pSimMgr->turnStateCode != 5) {
    return RuntimeActionResult::Failure("the loaded fixture is not at first-turn phase 5");
  }

  g_pSimMgr->turnStateCode = 6;
  const int expectedPhases[] = {7, 9, 10, 0x14, 0x15, 0x0d, 0x19, 8};
  for (int index = 0; index < 8; ++index) {
    g_pSimMgr->AdvanceGlobalTurnStateMachine();
    if (g_pSimMgr->turnStateCode != expectedPhases[index]) {
      return RuntimeActionResult::Failure(
          "the prerequisite turn phases did not reach city and transport");
    }
  }
  if (CurrentTurnEvent() != kTurnEventOfferSheet || !OfferScreen::IsCurrent()) {
    return RuntimeActionResult::Failure(
        "city and transport did not begin from the retained offer sheet");
  }

  RuntimeActionResult started = transition.Begin(JsonNullValue());
  if (!started.Succeeded()) {
    return started;
  }

  g_pSimMgr->AdvanceGlobalTurnStateMachine();
  if (g_pSimMgr->turnStateCode != 0x0b) {
    return RuntimeActionResult::Failure(
        "city and transport did not advance to great-power pressure");
  }
  if (CurrentTurnEvent() != kTurnEventOfferSheet || !OfferScreen::IsCurrent()) {
    return RuntimeActionResult::Failure("city and transport unexpectedly changed presentation");
  }

  JsonArray effects;
  JsonObject result;
  result.Set("kind", "continues");
  result.Set("from", 8);
  result.Set("to", 0x0b);
  result.Set("effects", effects.Release());
  return transition.Finish(result.Release());
}
