// TSimMgr::AdvanceGlobalTurnStateMachine (0x0057da70) is a single ~4 KB monolithic function in
// the original. It lives in its own translation unit (rather than alongside the rest of TSimMgr)
// so the per-case bodies and the predicate helpers below do not perturb the codegen of the
// neighbouring TSimMgr methods. The helpers are marked inline (the build uses /Ob1, which only
// expands inline-marked functions) so they fold back into the switch body instead of becoming
// out-of-line calls.

#include "game/gfx/TAmbitApplication.h"
#include "game/ui_screens/TLoadSavePicture.h"
#include "game/ui_screens/TNewsMgr.h"
#include "game/ui_core/THelpMgr.h"
#include "game/ui_screens/TSimMgr.h"

#include "decomp_types.h"
#include "game/military/TArmyMgr.h"
#include "game/assets/TAssetMgr.h"
#include "game/city_ui/TCountry.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/nation/TGreatPower.h"
#include "game/TGreatPower_internal.h"
#include "game/map/TMapMgr.h"
#include "game/nation/TMinor.h"
#include "game/net/TMultiplayerMgr.h"
#include "game/navy/TNavyMgr.h"
#include "game/military_ui/TNextDiplomationCommand.h"
#include "game/ui_core/TApplication.h"
#include "game/ui_widgets/TSoundPlayer.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/ui_core/TViewMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/raw_globals.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_screens_globals.h"
#include "game/globals/ui_widgets_globals.h"

static inline bool IsNationTerrainEligible(short nationSlot) {
  if (nationSlot == -1) {
    return false;
  }
  TCountry* terrain = g_apTerrainTypeDescriptorTable[nationSlot];
  if (terrain == nullptr) {
    return false;
  }
  if (nationSlot > 6) {
    return true;
  }
  const short code = terrain->encodedNationSlot;
  return code < 100 || code > 199;
}

static inline int GetNationTrackedOrderCount(TGreatPower* nation) {
  if (nation == nullptr || nation->trackedObjectList == nullptr) {
    return 0;
  }
  return nation->trackedObjectList->GetCount();
}

static inline bool ShouldDispatchNextTradePacket(TSimMgr* simMgr) {
  if (simMgr->multiplayerSessionRole == 0) {
    return true;
  }
  if (simMgr->multiplayerSessionRole == 1 && !IsNationTerrainEligible(simMgr->activeNationSlot)) {
    return true;
  }
  return false;
}

static inline void RunQuarterGateCheckAndMaybeRequeue(TSimMgr* simMgr) {
  const short tickA = simMgr->GetEconomicTurn();
  const short tickB = simMgr->GetEconomicTurn();
  if (((tickB % 0x28) != 0) || (simMgr->phaseStateByDecade[tickA / 0x28] == 0)) {
    simMgr->StartNextPhase();
    return;
  }
  g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventOpeningCinematic),
                                simMgr->activeNationSlot);
}

static inline short ReadCityOrderCapabilityField262(void) {
  if (g_pTechMgr == nullptr) {
    return 0;
  }
  // 0x262 is the active-tech marker short sitting just past the nationCapRows table.
  return g_pTechMgr->marker262;
}

static inline void HandleTurnEndSavePaths(TSimMgr* simMgr) {
  if (simMgr->multiplayerSessionRole == 0) {
    SaveGameWithModeAndOptionalLabel(0xa1, 0);
    return;
  }
  if (simMgr->multiplayerSessionRole == 1) {
    g_pGameFlowState->TrySaveGameAndMaybeShowFailureDialog(0xa1, 0, 1);
  }
}

// FUNCTION: IMPERIALISM 0x0057da70
void TSimMgr::AdvanceGlobalTurnStateMachine() {
  // Verified against 0x0057da8e: the original constructs this CString unconditionally
  // right after the prologue, before even the deferCounter check below -- it is a
  // function-scope local (only case 2's loop reads it, passed by value per iteration),
  // not a temporary re-created each loop iteration. Its non-trivial dtor is what forces
  // MSVC to route every case's `break` through one shared epilogue/cleanup block instead
  // of inlining a separate epilogue per case (see 0x57db01's `jmp` to the common tail).
  CString emptyString;

  if (turnStateCode == 0x10 && g_nTurnCooldownDeferCounter006A43C4 > 0) {
    --g_nTurnCooldownDeferCounter006A43C4;
  }
  mode = turnStateCode;

  switch (turnStateCode) {
  case 1:
    turnStateCode = 3;
    if (g_bTurnFlowBootstrapComplete == 0) {
      // Verified against 0x0057daf5: real event code is 0x11f8, payload 0, no null
      // guard on g_pViewMgr (matches the original — see heuristics for the
      // full re-verification note on this switch).
      g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventOpeningCinematic), 0);
      break;
    }
    // Verified against 0x0057db06: real event code is 0x5dc, payload 0 (not
    // activeNationSlot/0x5e4 — that call was misattributed to this branch).
    g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventMainMenu), 0);
    break;

  case 2: {
    turnStateCode = 0x10;
    for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
      TGreatPower* nation = g_apNationStates[nationSlot];
      nation->AssertValid();
      if (nation->IsRemote() == 0 && g_bMultiplayerScenarioSetupActive == 0) {
        nation->SetHomeCityTileAndDisplayName(-1, 0);
      }
    }
    if (g_bMultiplayerScenarioSetupActive == 0) {
      if (scenarioMapIndexPlusOne == 0) {
        if (multiplayerSessionRole == 0) {
          NameCapitals();
        }
      } else {
        ProcessScenarioScript();
      }
    }
    TGreatPower* activeNation = g_apNationStates[activeNationSlot];
    activeNation->ResetDiplomacyNeedScoresAndClearAidAllocationMatrix();
    activeNation->ResetDiplomacyNeedSlots7012AndRefreshIfModeGateMatches();
    g_pHelpMgr->ResetHelpSetRanksAndFlags();
    if (multiplayerSessionRole != 0) {
      g_pGameFlowState->ConfigureTurnResumeStateAndNationMask(mode, turnStateCode);
      turnStateCode = 0x13;
      StartNextPhase();
      break;
    }
    StartNextPhase();
    break;
  }

  case 3:
    turnStateCode = 2;
    if (reloadPoliticalMapState != 0) {
      // Verified against 0x0057db25/0x0057db32: both are real TSimMgr thiscall
      // methods on g_pSimMgr (not `this`, and not free functions).
      g_pSimMgr->RebuildGlobalOrderManagersAndCapabilityState(1);
      g_pSimMgr->RebuildMapContextAndGlobalMapState(1, s_Chunk_00698C0C, 1);
    }
    if (g_bMultiplayerScenarioSetupActive != 0) {
      break;
    }
    // Verified against 0x0057db53: real TSimMgr thiscall on `this` this time.
    RebuildNationStateSlotsAndAvailability(1);
    // Verified against 0x0057db5c-0x57db89: the condition reads g_pSimMgr's
    // difficultyLevel (this+0x40 on that object, NOT this->field34), the dispatch uses
    // event code 0x3b8 (not 0x5e4) with (code, activeNationSlot) argument order, and
    // there is no null guard on g_pViewMgr -- same missing-guard pattern as
    // case 1 above. field34/0x5e4/guarded call was an unverified placeholder shape.
    if (g_pSimMgr->difficultyLevel > 1 && scenarioMapIndexPlusOne == 0) {
      g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventCitySiteSelector),
                                    activeNationSlot);
    } else {
      StartNextPhase();
    }
    break;

  case 4:
    turnStateCode = 5;
    g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventStrategicMap),
                                  g_pSimMgr->activeNationSlot);
    if (multiplayerSessionRole != 0) {
      if (activeNationSlot == -1 || g_apTerrainTypeDescriptorTable[activeNationSlot] == nullptr ||
          (activeNationSlot <= 6 &&
           g_apTerrainTypeDescriptorTable[activeNationSlot]->encodedNationSlot >= 100 &&
           g_apTerrainTypeDescriptorTable[activeNationSlot]->encodedNationSlot <= 199)) {
        StartNextPhase();
      }
    }
    break;

  case 5: {
    const char alertsPending = ShowTurnAlertsForActiveNation();
    alertsPendingFlag38 = alertsPending;
    if (alertsPending != 0) {
      break;
    }
    turnStateCode = 6;
    if (multiplayerSessionRole != 0) {
      g_pGameFlowState->ConfigureTurnResumeStateAndNationMask(mode, turnStateCode);
      turnStateCode = 0x13;
    }
    StartNextPhase();
    break;
  }

  case 6: {
    turnStateCode = 7;
    if (multiplayerSessionRole != 0) {
      g_pGameFlowState->ConfigureTurnResumeStateAndNationMask(mode, turnStateCode);
    }
    if (multiplayerSessionRole != 1) {
      g_pDiplomacyTurnStateManager->ApplyDiplomacyInterNationStatesForTurn();
    }
    if (multiplayerSessionRole == 0) {
      TGreatPower** nationCursor = g_apNationStates;
      TGreatPower** nationEnd = &g_apNationStates_End;
      while (nationCursor < nationEnd) {
        TGreatPower* nation = *nationCursor;
        if (nation != nullptr && nation->diplomacyEligibilityA0 != 0 &&
            GetNationTrackedOrderCount(nation) > 0) {
          g_pSfxPlaybackSystem->SetActiveAudioCueAndResetQueue(4, true);
          g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventDiplomacyMap),
                                        activeNationSlot);
          break;
        }
        ++nationCursor;
      }
    } else if (IsNationTerrainEligible(activeNationSlot)) {
      g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventDiplomacyMap), activeNationSlot);
    }
    for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
      TGreatPower* nation = g_apNationStates[nationSlot];
      if (nation != nullptr) {
        nation->ReplyToDiplomacyOffers();
      }
    }
    if (ShouldDispatchNextTradePacket(this)) {
      // 0x57df05: new TNextDiplomationCommand() + immediate dispatch; the original
      // calls the method even when operator new returned null (kept faithfully).
      TNextDiplomationCommand* nextCommand = new TNextDiplomationCommand();
      nextCommand->DispatchUiPacketWithTagNEXT();
    }
    break;
  }

  case 7: {
    turnStateCode = 9;
    g_pDiplomacyTurnStateManager->ApplyDiplomacyInterNationStatesForTurn();
    if (multiplayerSessionRole != 0) {
      g_pGameFlowState->ConfigureTurnResumeStateAndNationMask(mode, turnStateCode);
      g_pSfxPlaybackSystem->SetActiveAudioCueAndResetQueue(4, true);
      g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventOfferSheet), activeNationSlot);
      g_pViewMgr->DispatchNationActionToMainControl(-1, 0, 0, 0, 0x16);
    }
    if (multiplayerSessionRole != 2) {
      DoTrade();
    }
    break;
  }

  case 8: {
    turnStateCode = 0xb;
    DoCityAndTransport();
    if (multiplayerSessionRole != 0) {
      g_pGameFlowState->ConfigureTurnResumeStateAndNationMask(mode, turnStateCode);
      turnStateCode = 0x13;
      StartNextPhase();
      break;
    }
    StartNextPhase();
    break;
  }

  case 9: {
    turnStateCode = 10;
    if (multiplayerSessionRole != 2) {
      DoCivilians();
      StartNextPhase();
      break;
    }
    StartNextPhase();
    break;
  }

  case 10: {
    turnStateCode = 0x14;
    if (g_pSimMgr != nullptr) {
      g_pSimMgr->DoMilitary();
    }
    StartNextPhase();
    break;
  }

  case 0xb: {
    turnStateCode = 0xc;
    char actionNeeded = 0;
    // For each live nation slot 6..0, slot 0xaf (the pressure-state update, byte 0x2bc)
    // returns a char: when set, fire the active nation's no-payload turn-event dispatch
    // (slot 0xab, byte 0x2ac). The original derefs the active nation's vtable with no
    // null guard here, so this stays a direct virtual call.
    for (int nationSlot = 6; nationSlot >= 0; --nationSlot) {
      TGreatPower* nation = g_apNationStates[nationSlot];
      if (nation == nullptr) {
        continue;
      }
      if (nation->UpdateGreatPowerPressureStateAndDispatchEscalationMessage() == 0) {
        continue;
      }
      TGreatPower* activeNation = g_apNationStates[activeNationSlot];
      activeNation->SorryYouLose();
      actionNeeded = 1;
    }
    if (actionNeeded == 0) {
      StartNextPhase();
    }
    break;
  }

  case 0xc: {
    turnStateCode = 0xe;
    if (IsNationTerrainEligible(activeNationSlot)) {
      g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventDealBook), activeNationSlot);
      g_pSfxPlaybackSystem->SetActiveAudioCueAndResetQueue(4, true);
      break;
    }
    if (!IsNationTerrainEligible(activeNationSlot)) {
      StartNextPhase();
    }
    break;
  }

  case 0xd: {
    turnStateCode = 0x19;
    // Verified against 0x0057e487: real receiver is g_pMapContextActionManager (no null
    // guard on it, matching the missing-guard pattern used elsewhere in this switch).
    if (g_pMapContextActionManager->GetByteFlagAtOffset8() != 0 &&
        IsNationTerrainEligible(activeNationSlot)) {
      g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventDiplomacyOffer),
                                    activeNationSlot);
      break;
    }
    StartNextPhase();
    break;
  }

  case 0xe: {
    turnStateCode = 0x10;
    if (g_pDiplomacyTurnStateManager != nullptr &&
        g_pDiplomacyTurnStateManager->lastProcessedNationSlot != -1) {
      const short lastProcessed = g_pDiplomacyTurnStateManager->lastProcessedNationSlot;
      turnStateCode = static_cast<int>(lastProcessed != activeNationSlot) + 0x16;
    }
    RunQuarterGateCheckAndMaybeRequeue(this);
    break;
  }

  case 0xf: {
    turnStateCode = 0x12;
    g_pAssetMgr->OpenFilesFor(0xa);
    g_pNewsMgr->StartNewsPhase();
    g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventNewspaperStatus), activeNationSlot);
    for (short nationSlot = 0; nationSlot < 7; ++nationSlot) {
      if (!IsNationTerrainEligible(nationSlot)) {
        continue;
      }
      TGreatPower* nation = g_apNationStates[nationSlot];
      if (nation != nullptr) {
        nation->ExecuteNationPendingActionStateMachine();
      }
    }
    if (g_nTurnCooldownDeferCounter006A43C4 < 1) {
      g_nTurnCooldownDeferCounter006A43C4 = 0;
      g_nTurnCooldownSideFlag00698B10 = 1;
      HandleTurnEndSavePaths(this);
    } else {
      const int phaseFlags = InLinearPhase();
      if ((phaseFlags & 0xf) == 10) {
        HandleTurnEndSavePaths(this);
      }
    }
    if (multiplayerSessionRole != 0) {
      if (!IsNationTerrainEligible(activeNationSlot)) {
        StartNextPhase();
      }
    }
    break;
  }

  case 0x10: {
    turnStateCode = 0x11;
    alertsPendingFlag38 = 0;
    turnFlowStatusFlags = 0;
    AdvanceSeason();
    StartNextPhase();
    break;
  }

  case 0x11: {
    turnStateCode = 0xf;
    char actionNeeded = 1;
    const short capabilityBefore = ReadCityOrderCapabilityField262();
    g_pTechMgr->CheckForAdvances();
    if (capabilityBefore == ReadCityOrderCapabilityField262()) {
      turnFlowStatusFlags |= 0x40;
    }
    for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
      if (g_pSimMgr != nullptr && g_pSimMgr->activeNationSlot == nationSlot &&
          g_nTurnCooldownDeferCounter006A43C4 < 1) {
        g_nTurnCooldownDeferCounter006A43C4 = 0;
        g_nTurnCooldownSideFlag00698B10 = 1;
        if (IsNationTerrainEligible(activeNationSlot)) {
          short unlockSlot =
              g_pTechMgr->ConsumeFirstPendingAbilityUnlock(static_cast<short>(nationSlot));
          if (unlockSlot != -1) {
            g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventTechnologyAdvance),
                                          unlockSlot);
            actionNeeded = 0;
          }
          continue;
        }
      }
      short unlockSlot =
          g_pTechMgr->ConsumeFirstPendingAbilityUnlock(static_cast<short>(nationSlot));
      while (unlockSlot != -1) {
        unlockSlot = g_pTechMgr->ConsumeFirstPendingAbilityUnlock(static_cast<short>(nationSlot));
      }
    }
    if (actionNeeded != 0) {
      StartNextPhase();
    }
    break;
  }

  case 0x12: {
    turnStateCode = 5;
    g_pAssetMgr->OpenFilesFor(0x13);
    g_pGlobalMapState->DispatchTurnEvent7DDForActiveNation();
    g_pViewMgr->RefreshViewSlot48();
    for (short nationSlot = 0; nationSlot < 7; ++nationSlot) {
      TGreatPower* nation = g_apNationStates[nationSlot];
      if (nation == nullptr || nationSlot == -1) {
        continue;
      }
      if (!IsNationTerrainEligible(nationSlot)) {
        continue;
      }
      nation->IsEncodedNationSlotMinus200Equal(0);
      nation->DispatchMissionNodeCallbacksAndClearQueue();
    }
    g_pSfxPlaybackSystem->ResetDualAudioCuePools();
    g_pSfxPlaybackSystem->PushCueToDualAudioCuePools(2);
    g_pSfxPlaybackSystem->PushCueToDualAudioCuePools(3);
    g_pSfxPlaybackSystem->SelectAndScheduleRandomAudioCue();
    if (!IsNationTerrainEligible(activeNationSlot)) {
      StartNextPhase();
    }
    break;
  }

  case 0x13: {
    turnStateCode = g_pGameFlowState->activeNationSlotIndex;
    g_pGameFlowState->HandleTurnResumeStateTelemetry();
    g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventNetworkGameOptions),
                                  activeNationSlot);
    break;
  }

  case 0x14: {
    turnStateCode = 0x15;
    if (g_pMapContextActionManager != nullptr) {
      g_pMapContextActionManager->DoCombatMoves();
    }
    if (multiplayerSessionRole != 0) {
      g_pGameFlowState->ConfigureTurnResumeStateAndNationMask(mode, turnStateCode);
      turnStateCode = 0x13;
    }
    break;
  }

  case 0x15: {
    turnStateCode = 0xd;
    g_pNavyOrderManager->ClearAllTransientOrders();
    if (multiplayerSessionRole != 2) {
      g_pGlobalMapState->RecomputeTileStrategicScoreHeatmap();
      RecomputeNationOrderPriorityMetrics();
      for (short nationSlot = 0; nationSlot < 7; ++nationSlot) {
        if (nationSlot == -1 || g_apTerrainTypeDescriptorTable[nationSlot] == nullptr) {
          continue;
        }
        // Verified against 0x0057e0b7: real receiver is g_apTerrainTypeDescriptorTable[nationSlot]
        // (a TCountry*), not a bare free-function predicate.
        if (nationSlot < 7 &&
            g_apTerrainTypeDescriptorTable[nationSlot]->IsNationProfileInMinorRange100To199()) {
          continue;
        }
        TGreatPower* nation = g_apNationStates[nationSlot];
        if (nation != nullptr) {
          nation->RefreshTrackedEntriesAndReplanAiDevelopment(0);
        }
      }
    }
    for (short nationSlot = 0; nationSlot < 7; ++nationSlot) {
      if (!IsNationTerrainEligible(nationSlot)) {
        continue;
      }
      TGreatPower* nation = g_apNationStates[nationSlot];
      if (nation != nullptr) {
        nation->AddPurchasedItems();
      }
    }
    const short tickA = GetEconomicTurn();
    const short tickB = GetEconomicTurn();
    if (((tickB % 0x28) == 0) && (phaseStateByDecade[tickA / 0x28] != 0) &&
        multiplayerSessionRole != 2 && g_pDiplomacyTurnStateManager != nullptr) {
      g_pDiplomacyTurnStateManager->SelectPriorityNationIndicesForMinorCapabilityRows();
    }
    if (multiplayerSessionRole != 0) {
      g_pGameFlowState->ConfigureTurnResumeStateAndNationMask(mode, turnStateCode);
      turnStateCode = 0x13;
    }
    StartNextPhase();
    break;
  }

  case 0x17:
    g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventOpeningCinematic), 0);
    break;

  case 0x19: {
    turnStateCode = 8;
    char actionNeeded = 0;
    // Verified against 0x0057e1be: the original reads g_pSimMgr->activeNationSlot with no
    // null guard, and when the localization nation's encoded slot is in [100,200) it fires
    // the active nation's no-payload turn-event dispatch (slot 0xab, byte 0x2ac) with no
    // arg and no null check on the active nation.
    {
      const short localizationNation = g_pSimMgr->activeNationSlot;
      TGreatPower* localizationNationState = g_apNationStates[localizationNation];
      if (localizationNationState != nullptr) {
        const short encoded = localizationNationState->encodedNationSlot;
        if (encoded > 99 && encoded < 200) {
          TGreatPower* activeNation = g_apNationStates[activeNationSlot];
          activeNation->SorryYouLose();
          actionNeeded = 1;
        }
      }
    }
    for (int removeNationSlot = 0; removeNationSlot < 7; ++removeNationSlot) {
      if (g_apTerrainTypeDescriptorTable[removeNationSlot] == nullptr ||
          g_apNationStates[removeNationSlot] == nullptr) {
        continue;
      }
      if (g_apNationStates[removeNationSlot]->ownedRegionList->GetSize() == 0) {
        RemoveNationSlotAndNotifyPeers(static_cast<short>(removeNationSlot));
      }
    }
    for (int secondaryIndex = 7; secondaryIndex < 36; ++secondaryIndex) {
      TMinor* secondaryNation = g_apSecondaryNationStateSlots[secondaryIndex];
      if (secondaryNation != nullptr && secondaryNation->ownedRegionList->GetSize() == 0) {
        for (short percentNationSlot = 0; percentNationSlot < 7; ++percentNationSlot) {
          if (!IsNationTerrainEligible(percentNationSlot)) {
            continue;
          }
          TGreatPower* nation = g_apNationStates[percentNationSlot];
          if (nation != nullptr) {
            nation->SetNationPercentFieldByModeAndDescriptorLinks(0, 100);
          }
        }
      }
    }
    if (actionNeeded != 0) {
      break;
    }
    int eligibleMinorCount = 0;
    for (int countNationSlot = 0; countNationSlot < 7; ++countNationSlot) {
      if (IsNationTerrainEligible(static_cast<short>(countNationSlot))) {
        ++eligibleMinorCount;
      }
    }
    if (eligibleMinorCount == 1 && IsNationTerrainEligible(activeNationSlot)) {
      actionNeeded = 1;
      UpdatePersistentTopTenNationScores();
      g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventOpeningCinematic), 0);
    }
    if (actionNeeded == 0) {
      StartNextPhase();
    }
    break;
  }

  case 0x16:
    UpdatePersistentTopTenNationScores();
    g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventOpeningCinematic), 0);
    break;

  case 100:
    turnStateCode = 4;
    g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventDealBook), activeNationSlot);
    break;

  // Jump-table ground truth (0x57dad8, index-byte table 0x57ebec): case 0x71 -> 0x57eabf
  // (posts 0x104f), case 0x72 -> 0x57ead8 (posts 0x5e4). The old merged port dropped both
  // event codes.
  case 0x71:
    turnStateCode = 4;
    g_pAmbitApplication->PostTurnEventCodeMessage2420(EncodeTurnEventCode(kTurnEventCredits));
    break;

  case 0x72:
    turnStateCode = 4;
    g_pAmbitApplication->PostTurnEventCodeMessage2420(
        EncodeTurnEventCode(kTurnEventNetworkGameOptions));
    break;

  case 0x65:
    turnStateCode = 4;
    g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventDiplomacyOffer), activeNationSlot);
    break;

  case 0x66:
    turnStateCode = 4;
    g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventNewspaperStatus), activeNationSlot);
    break;

  case 0x67:
    turnStateCode = 4;
    g_pViewMgr->DispatchTurnEvent(
        g_pTechMgr->perTechUnlockFlag180[TTechMgr::kProductionOrderTechId] != 0
            ? kTurnEventIndustryOverview
            : kTurnEventTradeOverview,
        activeNationSlot);
    break;

  case 0x68:
    turnStateCode = 4;
    g_apNationStates[activeNationSlot]->SetDiplomacyPolicies();
    g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventDiplomacyMap), activeNationSlot);
    g_pDiplomacyTurnStateManager->SetLastDiploEffort();
    break;

  case 0x69:
    turnStateCode = 4;
    g_apNationStates[activeNationSlot]->RebuildNationResourceYieldCountersAndDevelopmentTargets();
    g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventTransport), activeNationSlot);
    break;

  case 0x6a:
    turnStateCode = 4;
    g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventCityProduction), activeNationSlot);
    break;

  case 0x6b:
    turnStateCode = 4;
    g_pAmbitApplication->PostTurnEventCodeMessage2420(
        EncodeTurnEventCode(kTurnEventGamePreferences));
    break;

  case 0x6c:
    turnStateCode = 4;
    g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventUnitHistory), activeNationSlot);
    break;

  case 0x6d:
    turnStateCode = 4;
    turnFlowStatusFlags |= 0x40;
    g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventTechnologyStore), activeNationSlot);
    break;

  case 0x6e:
    turnStateCode = 4;
    g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventGameStatus), activeNationSlot);
    break;

  case 0x6f:
    turnStateCode = 4;
    g_nSaveFormatVersion = -1;
    g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventLoadSave), activeNationSlot);
    break;

  case 0x70:
    turnStateCode = 4;
    g_nSaveFormatVersion = -2;
    g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventLoadSave), activeNationSlot);
    break;

  default:
    break;
  }
}
