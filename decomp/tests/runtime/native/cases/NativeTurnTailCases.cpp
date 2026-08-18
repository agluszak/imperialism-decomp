#include "NativeCases.h"
#include "JsonObject.h"

#include "game/city/TCity.h"
#include "game/civilian_domain_types.h"
#include "game/globals/navy_globals.h"
#include "game/globals/nation_globals.h"
#include "game/globals/shared_globals.h"
#include "game/map/TMapMgr.h"
#include "game/military/TCivUnit.h"
#include "game/military/TArmyMgr.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/nation/TGreatPower.h"
#include "game/nation/TMinor.h"
#include "game/navy/TShip.h"
#include "game/ui_core/THelpMgr.h"
#include "game/ui_screens/TSimMgr.h"

#include <stdlib.h>

namespace {

JSON_Value* ContinueOutcome() {
  JSON_Value* json = json_value_init_string("continue");
  if (json == 0) {
    abort();
  }
  return json;
}

short OtherGreatPowerSlot(short activeNationSlot) {
  return activeNationSlot == 0 ? 1 : 0;
}

} // namespace

RuntimeActionResult RunGreatPowerPressureHumanDebt(NativeTransition& transition) {
  TGreatPower* nation = ActiveNation();
  if (nation == 0 || g_pSimMgr == 0) {
    return RuntimeActionResult::Failure("great-power pressure state is unavailable");
  }

  g_pSimMgr->difficultyLevel = 1;
  nation->treasuryValue10 = -100;
  nation->diplomacyBudgetBase = 50000;
  nation->escalationCounter = 10;
  nation->pressureCounter = 0;

  RuntimeActionResult started = transition.Begin(JsonNullValue());
  if (!started.Succeeded()) {
    return started;
  }

  char lost = 0;
  for (int nationSlot = 6; nationSlot >= 0; --nationSlot) {
    TGreatPower* slotNation = g_apNationStates[nationSlot];
    if (slotNation == 0) {
      continue;
    }
    if (slotNation->UpdateGreatPowerPressureStateAndDispatchEscalationMessage() != 0) {
      lost = 1;
    }
  }
  return transition.Finish(lost != 0);
}

RuntimeActionResult RunGreatPowerPressureAiNoop(NativeTransition& transition) {
  if (g_pSimMgr == 0) {
    return RuntimeActionResult::Failure("great-power pressure state is unavailable");
  }

  const short aiNationSlot = OtherGreatPowerSlot(ActiveNationSlot());
  TGreatPower* aiNation = g_apNationStates[aiNationSlot];
  if (aiNation == 0) {
    return RuntimeActionResult::Failure("the loaded game has no AI great-power slot");
  }

  aiNation->treasuryValue10 = -10000;
  aiNation->pressureCounter = 4;

  JsonObject args;
  args.Set("nation", static_cast<int>(aiNationSlot));
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  const char lost = aiNation->UpdateGreatPowerPressureStateAndDispatchEscalationMessage();
  return transition.Finish(lost != 0);
}

RuntimeActionResult RunSeasonAdvanceClearsStatusFlags(NativeTransition& transition) {
  if (g_pSimMgr == 0) {
    return RuntimeActionResult::Failure("turn state is unavailable");
  }

  g_pSimMgr->economicTurn = 4;
  g_pSimMgr->turnFlowStatusFlags = 0x51;
  g_pSimMgr->turnStateCode = 0x10;

  RuntimeActionResult started = transition.Begin(JsonNullValue());
  if (!started.Succeeded()) {
    return started;
  }

  g_pSimMgr->turnStateCode = 0x11;
  g_pSimMgr->turnFlowStatusFlags = 0;
  g_pSimMgr->AdvanceSeason();
  return transition.Finish();
}

RuntimeActionResult RunTurnAlertsSkipFirstEconomicTurn(NativeTransition& transition) {
  if (g_pSimMgr == 0) {
    return RuntimeActionResult::Failure("turn state is unavailable");
  }

  g_pSimMgr->economicTurn = 1;

  RuntimeActionResult started = transition.Begin(JsonNullValue());
  if (!started.Succeeded()) {
    return started;
  }

  const char shown = ShowTurnAlertsForActiveNation();
  return transition.Finish(shown != 0);
}

RuntimeActionResult RunDiplomacyOfferGate(NativeTransition& transition) {
  if (g_pSimMgr == 0 || g_pMapContextActionManager == 0) {
    return RuntimeActionResult::Failure("diplomacy-offer gate state is unavailable");
  }

  RuntimeActionResult started = transition.Begin(JsonNullValue());
  if (!started.Succeeded()) {
    return started;
  }

  const bool showOffer = g_pMapContextActionManager->GetByteFlagAtOffset8() != 0 &&
                         g_pSimMgr->IsNationSlotEligibleForEventProcessing(ActiveNationSlot()) != 0;
  return transition.Finish(showOffer);
}

RuntimeActionResult RunQuarterGateOffDecade(NativeTransition& transition) {
  if (g_pSimMgr == 0 || g_pDiplomacyTurnStateManager == 0) {
    return RuntimeActionResult::Failure("quarter-gate state is unavailable");
  }

  g_pSimMgr->economicTurn = 1;
  g_pDiplomacyTurnStateManager->lastProcessedNationSlot = ActiveNationSlot();

  RuntimeActionResult started = transition.Begin(JsonNullValue());
  if (!started.Succeeded()) {
    return started;
  }

  g_pSimMgr->turnStateCode = 0x10;
  if (g_pDiplomacyTurnStateManager->lastProcessedNationSlot != -1) {
    const short lastProcessed = g_pDiplomacyTurnStateManager->lastProcessedNationSlot;
    g_pSimMgr->turnStateCode =
        static_cast<int>(lastProcessed != g_pSimMgr->activeNationSlot) + 0x16;
  }

  const short tick = g_pSimMgr->GetEconomicTurn();
  const bool decadeCinematic =
      (tick % 0x28) == 0 && g_pSimMgr->phaseStateByDecade[tick / 0x28] != 0;
  return transition.Finish(decadeCinematic);
}

RuntimeActionResult RunReturnToMapClearsNoticeQueues(NativeTransition& transition) {
  if (g_pSimMgr == 0) {
    return RuntimeActionResult::Failure("turn state is unavailable");
  }

  g_pSimMgr->turnStateCode = 0x12;

  RuntimeActionResult started = transition.Begin(JsonNullValue());
  if (!started.Succeeded()) {
    return started;
  }

  g_pSimMgr->turnStateCode = 5;
  for (short nationSlot = 0; nationSlot < 7; ++nationSlot) {
    TGreatPower* nation = g_apNationStates[nationSlot];
    if (nation == 0) {
      continue;
    }
    if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(nationSlot) == 0) {
      continue;
    }
    nation->InitializeDiplomacyNotices();
    nation->DispatchMissionNodeCallbacksAndClearQueue();
  }
  return transition.Finish();
}

RuntimeActionResult RunNewspaperNavyGrowthRewardLevels(NativeTransition& transition) {
  TGreatPower* nation = ActiveNation();
  if (nation == 0) {
    return RuntimeActionResult::Failure("the loaded fixture has no active great power");
  }

  nation->pendingActionStatus.byAction[0] = 0x32;
  nation->field8d6[0] = 1;

  RuntimeActionResult started = transition.Begin(JsonNullValue());
  if (!started.Succeeded()) {
    return started;
  }

  for (short nationSlot = 0; nationSlot < 7; ++nationSlot) {
    if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(nationSlot) == 0) {
      continue;
    }
    TGreatPower* slotNation = g_apNationStates[nationSlot];
    if (slotNation != 0) {
      slotNation->MarkAllPendingStatusFlagsHandled();
    }
  }
  return transition.Finish();
}

RuntimeActionResult RunEliminationPhaseWithLandedGreatPowers(NativeTransition& transition) {
  if (g_pSimMgr == 0) {
    return RuntimeActionResult::Failure("elimination state is unavailable");
  }

  RuntimeActionResult started = transition.Begin(JsonNullValue());
  if (!started.Succeeded()) {
    return started;
  }

  const short activeNationSlot = ActiveNationSlot();
  char lost = 0;
  TGreatPower* localizationNationState = g_apNationStates[g_pSimMgr->activeNationSlot];
  if (localizationNationState != 0) {
    const short encoded = localizationNationState->encodedNationSlot;
    if (encoded > 99 && encoded < 200) {
      lost = 1;
    }
  }
  for (int removeNationSlot = 0; removeNationSlot < 7; ++removeNationSlot) {
    if (g_apTerrainTypeDescriptorTable[removeNationSlot] == 0 ||
        g_apNationStates[removeNationSlot] == 0) {
      continue;
    }
    if (g_apNationStates[removeNationSlot]->ownedRegionList->GetSize() == 0) {
      g_pSimMgr->RemoveNationSlotAndNotifyPeers(static_cast<short>(removeNationSlot));
    }
  }
  for (int secondaryIndex = 7; secondaryIndex < 36; ++secondaryIndex) {
    TMinor* secondaryNation = g_apSecondaryNationStateSlots[secondaryIndex];
    if (secondaryNation != 0 && secondaryNation->ownedRegionList->GetSize() == 0) {
      for (short percentNationSlot = 0; percentNationSlot < 7; ++percentNationSlot) {
        if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(percentNationSlot) == 0) {
          continue;
        }
        TGreatPower* nation = g_apNationStates[percentNationSlot];
        if (nation != 0) {
          nation->NewStatusFor(0, 100);
        }
      }
    }
  }

  int eligibleCount = 0;
  for (int countNationSlot = 0; countNationSlot < 7; ++countNationSlot) {
    if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(countNationSlot)) !=
        0) {
      ++eligibleCount;
    }
  }
  if (lost == 0 && eligibleCount == 1 &&
      g_pSimMgr->IsNationSlotEligibleForEventProcessing(activeNationSlot) != 0) {
    return transition.Finish(json_value_init_string("victory"));
  }
  if (lost != 0) {
    return transition.Finish(json_value_init_string("player_eliminated"));
  }
  return transition.Finish(ContinueOutcome());
}

RuntimeActionResult RunOpeningCivilianGrant(NativeTransition& transition) {
  TGreatPower* nation = ActiveNation();
  if (nation == 0 || nation->city == 0 || g_pSimMgr == 0 || g_pGlobalMapState == 0) {
    return RuntimeActionResult::Failure("opening civilian grant state is unavailable");
  }

  g_pSimMgr->difficultyLevel = 0;
  g_pSimMgr->scenarioMapIndexPlusOne = 0;
  nation->diplomacyEligibilityA0 = 1;

  RuntimeActionResult started = transition.Begin(JsonNullValue());
  if (!started.Succeeded()) {
    return started;
  }

  TCity* city = nation->city;
  short result1 =
      g_pGlobalMapState->FindReachableRecruitSpawnTileWithVisitedReset(nation->homeTileIndex, 0);
  TCivUnit* civ1 = new TCivUnit();
  civ1->ICivUnit(kCivilianUnitProspector, result1, nation->nationSlot);

  short result2 =
      g_pGlobalMapState->FindReachableRecruitSpawnTileWithVisitedReset(nation->homeTileIndex, 1);
  TCivUnit* civ2 = new TCivUnit();
  civ2->ICivUnit(kCivilianUnitEngineer, result2, nation->nationSlot);

  city->orderCountByType5c[1] += 2;

  if (g_pSimMgr->difficultyLevel == 0 && nation->diplomacyEligibilityA0) {
    city->orderCountByType5c[1] += 6;

    short result3 =
        g_pGlobalMapState->FindReachableRecruitSpawnTileWithVisitedReset(nation->homeTileIndex, 0);
    TCivUnit* civ3 = new TCivUnit();
    civ3->ICivUnit(kCivilianUnitProspector, result3, nation->nationSlot);

    short result4 =
        g_pGlobalMapState->FindReachableRecruitSpawnTileWithVisitedReset(nation->homeTileIndex, 0);
    TCivUnit* civ4 = new TCivUnit();
    civ4->ICivUnit(kCivilianUnitMiner, result4, nation->nationSlot);

    short result5 =
        g_pGlobalMapState->FindReachableRecruitSpawnTileWithVisitedReset(nation->homeTileIndex, 0);
    TCivUnit* civ5 = new TCivUnit();
    civ5->ICivUnit(kCivilianUnitFarmer, result5, nation->nationSlot);
  }

  return transition.Finish();
}

RuntimeActionResult RunDealBookTurnStop(NativeTransition& transition) {
  if (g_pSimMgr == 0) {
    return RuntimeActionResult::Failure("turn state is unavailable");
  }
  g_pSimMgr->turnStateCode = 0xc;

  RuntimeActionResult started = transition.Begin(JsonNullValue());
  if (!started.Succeeded()) {
    return started;
  }
  g_pSimMgr->AdvanceGlobalTurnStateMachine();
  return transition.Finish(json_value_init_string("deal_book"));
}

RuntimeActionResult RunCityAndTransportTurnStop(NativeTransition& transition) {
  if (g_pSimMgr == 0) {
    return RuntimeActionResult::Failure("turn state is unavailable");
  }
  g_pSimMgr->turnStateCode = 8;

  RuntimeActionResult started = transition.Begin(JsonNullValue());
  if (!started.Succeeded()) {
    return started;
  }
  g_pSimMgr->turnStateCode = 0xb;
  g_pSimMgr->DoCityAndTransport();
  return transition.Finish();
}

RuntimeActionResult RunOpeningHomeCitySetup(NativeTransition& transition) {
  if (g_pSimMgr == 0) {
    return RuntimeActionResult::Failure("turn state is unavailable");
  }

  g_bMultiplayerScenarioSetupActive = 0;

  RuntimeActionResult started = transition.Begin(JsonNullValue());
  if (!started.Succeeded()) {
    return started;
  }

  for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
    TGreatPower* nation = g_apNationStates[nationSlot];
    if (nation == 0 || nation->IsRemote() != 0 || g_bMultiplayerScenarioSetupActive != 0) {
      continue;
    }
    nation->SetHomeCityTileAndDisplayName(-1, 0);
  }

  return transition.Finish();
}

RuntimeActionResult RunNewspaperPendingStatus(NativeTransition& transition) {
  if (g_pSimMgr == 0) {
    return RuntimeActionResult::Failure("turn state is unavailable");
  }

  for (short nationSlot = 0; nationSlot < 7; ++nationSlot) {
    if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(nationSlot) == 0) {
      continue;
    }
    TGreatPower* nation = g_apNationStates[nationSlot];
    if (nation == 0) {
      continue;
    }
    nation->pendingActionStatus.byAction[0] = 0x32;
    nation->field8d6[0] = 3;
    nation->pendingActionStatus.byAction[1] = 0x32;
    nation->field8d6[1] = 6;
    nation->pendingActionStatus.byAction[3] = 0x32;
    nation->field8d6[3] = -1;
  }

  RuntimeActionResult started = transition.Begin(JsonNullValue());
  if (!started.Succeeded()) {
    return started;
  }

  for (short eligibleSlot = 0; eligibleSlot < 7; ++eligibleSlot) {
    if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(eligibleSlot) == 0) {
      continue;
    }
    TGreatPower* nation = g_apNationStates[eligibleSlot];
    if (nation != 0) {
      nation->MarkAllPendingStatusFlagsHandled();
    }
  }
  return transition.Finish();
}
