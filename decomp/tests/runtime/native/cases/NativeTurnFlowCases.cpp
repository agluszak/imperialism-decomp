#include "NativeCases.h"
#include "JsonObject.h"
#include "parson.h"

#include "game/city_ui/TCountry.h"
#include "game/diplomacy_domain_types.h"
#include "game/globals/navy_globals.h"
#include "game/globals/shared_globals.h"
#include "game/map/TMapMgr.h"
#include "game/military/TArmyMgr.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/military_ui/TSortedByRelationshipList.h"
#include "game/ui_core/TSortedPtrList.h"
#include "game/nation/TAutoGreatPower.h"
#include "game/nation/TGreatPower.h"
#include "game/nation/TMinor.h"
#include "game/navy/TShip.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_screens/turn_flow_cooldown.h"

namespace {

void ReplyToDiplomacyOffersRejectingDialogs(TGreatPower* nation) {
  TSortedByRelationshipList* queue = nation->proposalQueue;
  short proposalCount = queue == 0 ? 0 : static_cast<short>(queue->GetSize());
  if (proposalCount > 0) {
    int proposalIndex = 1;
    int queueIndex = 1;
    do {
      short* proposalEntry = static_cast<short*>(queue->GetPtrListEntryByOneBasedIndex(queueIndex));
      DiplomacyProposalCodeStorage proposalCode = proposalEntry[0];
      short targetNation = proposalEntry[1];
      char shouldApplyProposal = 0;
      if (IsTurnFlowCooldownActiveAndResetExpiredState() == 0) {
        if (nation->diplomacyPolicyByNation[targetNation] == proposalCode) {
          shouldApplyProposal = 1;
        } else if (proposalCode == kDiplomacyProposalAlliance &&
                   g_pDiplomacyTurnStateManager->GetNationPairDiplomacyRelationCode(
                       nation->nationSlot, targetNation) != kDiplomacyRelationshipPeace) {
          shouldApplyProposal = 0;
        }
      }
      if (shouldApplyProposal == 0) {
        nation->RejectOffer(static_cast<short>(proposalIndex));
      } else {
        nation->AcceptOffer(static_cast<short>(proposalIndex));
      }
      ++proposalIndex;
      ++queueIndex;
    } while (static_cast<short>(proposalIndex) <= proposalCount);
  }
  nation->ResetDiplomacyPolicyAndGrantEntriesPreserveRecurringGrants();
}

void RunDiplomacyWithoutDialogs() {
  g_pDiplomacyTurnStateManager->ApplyDiplomacyInterNationStatesForTurn();
  for (int nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
    TGreatPower* nation = g_apNationStates[nationSlot];
    if (nation == 0) {
      continue;
    }
    if (nation->IsKindOf(RUNTIME_CLASS(TAutoGreatPower)) != 0) {
      nation->ReplyToDiplomacyOffers();
    } else {
      ReplyToDiplomacyOffersRejectingDialogs(nation);
    }
  }
}

void RunMilitarySubset() {
  int slot;
  g_pGlobalMapState->RecomputeTileStrategicScoreHeatmap();
  for (slot = 0; slot < kNationSlotCount; ++slot) {
    TCountry* country = g_apTerrainTypeDescriptorTable[slot];
    if (country == 0) {
      continue;
    }
    if (slot < 7) {
      const short profileCode = country->encodedNationSlot;
      if (profileCode >= 100 && profileCode < 200) {
        continue;
      }
    }
    country->GrowMilitia();
  }
  for (slot = 0; slot < 7; ++slot) {
    TCountry* country = g_apTerrainTypeDescriptorTable[slot];
    if (country == 0) {
      continue;
    }
    if (country->encodedNationSlot >= 100 && country->encodedNationSlot < 200) {
      continue;
    }
    TGreatPower* nation = g_apNationStates[slot];
    nation->PayForMilitary();
    if (nation->IsKindOf(RUNTIME_CLASS(TAutoGreatPower)) == 0) {
      nation->MoveArmy();
    }
  }
}

void RunMilitaryCleanupSubset() {
  int slot;
  if (g_pNavyPrimaryOrderListHead != 0) {
    TShip* ship;
    for (ship = g_pNavyPrimaryOrderListHead; ship != 0; ship = ship->next) {
      if (ship->selection == 1) {
        ship->selection = 0;
      }
    }
  }
  g_pGlobalMapState->RecomputeTileStrategicScoreHeatmap();
  for (slot = 0; slot < 7; ++slot) {
    TCountry* country = g_apTerrainTypeDescriptorTable[slot];
    if (country == 0) {
      continue;
    }
    if (country->encodedNationSlot >= 100 && country->encodedNationSlot < 200) {
      continue;
    }
    if (g_apNationStates[slot] != 0) {
      g_apNationStates[slot]->AddPurchasedItems();
    }
  }
}

char RunPressurePhase() {
  char lost = 0;
  for (int nationSlot = 6; nationSlot >= 0; --nationSlot) {
    TGreatPower* nation = g_apNationStates[nationSlot];
    if (nation == 0) {
      continue;
    }
    if (nation->UpdateGreatPowerPressureStateAndDispatchEscalationMessage() != 0) {
      lost = 1;
    }
  }
  return lost;
}

void RunEliminationPhase() {
  TGreatPower* localizationNationState = g_apNationStates[g_pSimMgr->activeNationSlot];
  if (localizationNationState != 0) {
    const short encoded = localizationNationState->encodedNationSlot;
    if (encoded > 99 && encoded < 200) {
      return;
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
}

void RunQuarterGateAndSeason() {
  g_pSimMgr->turnStateCode = 0x10;
  g_pSimMgr->turnStateCode = 0x11;
  g_pSimMgr->turnFlowStatusFlags = 0;
  g_pSimMgr->AdvanceSeason();
}

void ConsumeTechnologyUnlocks() {
  const short activeNationSlot = ActiveNationSlot();
  for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
    TGreatPower* nation = g_apNationStates[nationSlot];
    if (nation != 0 && nationSlot == activeNationSlot && nation->diplomacyEligibilityA0 != 0 &&
        g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(nationSlot)) != 0) {
      continue;
    }
    while (g_pTechMgr->ConsumeFirstPendingAbilityUnlock(static_cast<short>(nationSlot)) != -1) {
    }
  }
  while (g_pTechMgr->ConsumeFirstPendingAbilityUnlock(activeNationSlot) != -1) {
  }
}

void ReturnToMap() {
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
}

} // namespace

RuntimeActionResult RunPeacefulWholeTurn(NativeTransition& transition) {
  if (g_pSimMgr == 0 || g_pDiplomacyTurnStateManager == 0 || g_pTradeMgr == 0 ||
      g_pMapContextActionManager == 0 || g_pTechMgr == 0) {
    return RuntimeActionResult::Failure("the loaded game is missing turn-flow managers");
  }

  RuntimeActionResult started = transition.Begin(JsonNullValue());
  if (!started.Succeeded()) {
    return started;
  }

  RunDiplomacyWithoutDialogs();
  if (g_pDiplomacyTurnStateManager->pendingWarTransitionQueue != 0 &&
      g_pDiplomacyTurnStateManager->pendingWarTransitionQueue->GetSize() != 0) {
    return RuntimeActionResult::Failure("the peaceful turn queued a war transition");
  }

  RunTradeWithoutUi();
  g_pSimMgr->DoCivilians();
  RunMilitarySubset();

  JSON_Value* combat = CombatMovesWithoutBattleUi();
  if (combat != 0 && json_value_get_type(combat) == JSONObject) {
    JsonFreeValue(combat);
    return RuntimeActionResult::Failure("the peaceful turn created a land battle");
  }
  JsonFreeValue(combat);

  RunMilitaryCleanupSubset();

  if (g_pMapContextActionManager->GetByteFlagAtOffset8() != 0 &&
      g_pSimMgr->IsNationSlotEligibleForEventProcessing(ActiveNationSlot()) != 0) {
    return RuntimeActionResult::Failure("the peaceful turn stopped on the diplomacy-offer gate");
  }

  RunEliminationPhase();
  g_pSimMgr->DoCityAndTransport();
  if (RunPressurePhase() != 0) {
    return RuntimeActionResult::Failure("the peaceful turn triggered great-power pressure loss");
  }

  const short tick = g_pSimMgr->GetEconomicTurn();
  if ((tick % 0x28) == 0 && g_pSimMgr->phaseStateByDecade[tick / 0x28] != 0) {
    return RuntimeActionResult::Failure("the peaceful turn opened a decade cinematic");
  }
  if (g_pDiplomacyTurnStateManager->lastProcessedNationSlot != -1) {
    return RuntimeActionResult::Failure("the peaceful turn opened a decade or end-game branch");
  }

  RunQuarterGateAndSeason();
  g_pTechMgr->CheckForAdvances();
  ConsumeTechnologyUnlocks();
  ReturnToMap();
  return transition.Finish();
}
