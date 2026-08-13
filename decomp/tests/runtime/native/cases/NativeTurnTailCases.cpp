#include "NativeCases.h"
#include "JsonObject.h"

#include "game/globals/shared_globals.h"
#include "game/military/TArmyMgr.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/nation/TGreatPower.h"
#include "game/nation/TMinor.h"
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
