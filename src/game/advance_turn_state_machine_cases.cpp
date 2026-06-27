#include "game/advance_turn_state_machine_cases.h"

#include "game/TSimMgr.h"

#include "game/TCountry.h"
#include "game/TDiplomacyMgr.h"
#include "game/TGreatPower.h"
#include "game/THelpMgr.h"
#include "game/TMinor.h"
#include "game/TMapMgr.h"
#include "game/TMultiplayerMgr.h"
#include "game/TSoundPlayer.h"
#include "game/TTechMgr.h"
#include "game/TViewMgr.h"
#include "game/diplomacy_globals.h"

extern "C" char DAT_006a43f0;
extern "C" short g_nTurnCooldownDeferCounter006A43C4;
extern "C" short g_nTurnCooldownSideFlag00698B10;

extern undefined4 RebuildNationStateSlotsAndAvailability(void);
extern undefined4 ConfigureTurnResumeStateAndNationMask(void);
extern undefined4 ShowTurnAlertsForActiveNation(void);
extern undefined4 RefreshNationAdvisorLabelStrings(void);
extern undefined4 ProcessTurnInstructionStreamAndFinalizePhase(void);
extern undefined4 PostTurnEventCodeMessage2420(void);
extern undefined4 SyncNationField790FromLocalizationStateId(void);
extern undefined4 UpdatePersistentTopTenNationScores(void);
extern undefined4 RebuildNationRankingDataAndUiCache(void);
extern undefined4 HandleTurnResumeStateTelemetry(void);
extern undefined4 GetByteFlagAtOffset8(void);
extern undefined4 UpdateCityOrderCapabilityUnlockProgress(void);
extern undefined4 ConsumeFirstPendingAbilityUnlock(void);
extern undefined4 SaveGameWithModeAndOptionalLabel(void);
extern undefined4 TrySaveGameAndMaybeShowFailureDialog(void);
extern undefined4 RefreshNavyOrderCycleAndClearReadyFlags(void);
extern undefined4 RecomputeTileStrategicScoreHeatmap(void);
extern undefined4 RecomputeNationOrderPriorityMetrics(void);
extern undefined4 RemoveNationSlotAndNotifyPeers(void);
extern undefined4 ResetDualAudioCuePools(void);
extern undefined4 PushCueToDualAudioCuePools(void);
extern undefined4 SelectAndScheduleRandomAudioCue(void);
extern undefined4 IsNationProfileInMinorRange100To199(void);
extern undefined4 SetOutputDevice(void);
extern undefined4 DispatchUiPacketWithTagNEXT(void);
extern undefined4 QueryNationAdvisorSlot90Predicate28(TGreatPower* nation);
extern undefined4 QueryJoinEmpireModePendingForNationAf(TGreatPower* nation);

static bool IsNationTerrainEligible(short nationSlot) {
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

static void DispatchUiSlot4C() {
  if (g_pUiRuntimeContext != nullptr) {
    g_pUiRuntimeContext->DispatchTurnEventSlot4C(0, 0);
  }
}

static void RequeueTurnFlow(TSimMgr* simMgr) {
  simMgr->PostMainWindowCommand100ForTurnFlow();
}

static void RequeueUnlessActiveNationMinorRange(TSimMgr* simMgr) {
  if (!IsNationTerrainEligible(simMgr->activeNationSlot)) {
    RequeueTurnFlow(simMgr);
  }
}

static int GetNationTrackedOrderCount(TGreatPower* nation) {
  if (nation == nullptr || nation->trackedObjectList == nullptr) {
    return 0;
  }
  return nation->trackedObjectList->GetCountSlot48();
}

static bool ShouldDispatchNextTradePacket(TSimMgr* simMgr) {
  if (simMgr->redrawEnabled == 0) {
    return true;
  }
  if (simMgr->redrawEnabled == 1 && !IsNationTerrainEligible(simMgr->activeNationSlot)) {
    return true;
  }
  return false;
}

static void RunQuarterGateCheckAndMaybeRequeue(TSimMgr* simMgr) {
  const short tickA = simMgr->GetTurnTickSlot3C();
  const short tickB = simMgr->GetTurnTickSlot3C();
  if (((tickB % 0x28) != 0) ||
      (simMgr->phaseFlags[tickA / 0x28] == 0)) {
    RequeueTurnFlow(simMgr);
    return;
  }
  DispatchUiSlot4C();
}

static short ReadCityOrderCapabilityField262(void) {
  if (g_pCityOrderCapabilityState == nullptr) {
    return 0;
  }
  return *reinterpret_cast<short*>(reinterpret_cast<char*>(g_pCityOrderCapabilityState) + 0x262);
}

static void HandleTurnEndSavePaths(TSimMgr* simMgr) {
  if (simMgr->redrawEnabled == 0) {
    SaveGameWithModeAndOptionalLabel();
    return;
  }
  if (simMgr->redrawEnabled == 1) {
    TrySaveGameAndMaybeShowFailureDialog();
  }
}

void AdvanceGlobalTurnStateMachineCase6(TSimMgr* simMgr) {
  simMgr->turnStateCode = 7;
  if (simMgr->redrawEnabled != 0) {
    ConfigureTurnResumeStateAndNationMask();
  }
  if (simMgr->redrawEnabled != 1 && g_pDiplomacyTurnStateManager != nullptr) {
    g_pDiplomacyTurnStateManager->ApplyDiplomacyInterNationStatesForTurn();
  }
  if (simMgr->redrawEnabled == 0) {
    TGreatPower** nationCursor = g_apNationStates;
    TGreatPower** nationEnd = reinterpret_cast<TGreatPower**>(&g_apNationStates_End);
    while (nationCursor < nationEnd) {
      TGreatPower* nation = *nationCursor;
      if (nation != nullptr && nation->diplomacyEligibilityA0 != 0 &&
          GetNationTrackedOrderCount(nation) > 0) {
        SetOutputDevice();
        DispatchUiSlot4C();
        break;
      }
      ++nationCursor;
    }
  } else if (IsNationTerrainEligible(simMgr->activeNationSlot)) {
    DispatchUiSlot4C();
  }

  for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
    TGreatPower* nation = g_apNationStates[nationSlot];
    if (nation != nullptr) {
      nation->ProcessPendingDiplomacyProposalQueue();
    }
  }

  if (ShouldDispatchNextTradePacket(simMgr)) {
    DispatchUiPacketWithTagNEXT();
  }
}

void AdvanceGlobalTurnStateMachineCase7(TSimMgr* simMgr) {
  simMgr->turnStateCode = 9;
  if (g_pDiplomacyTurnStateManager != nullptr) {
    g_pDiplomacyTurnStateManager->ApplyDiplomacyInterNationStatesForTurn();
  }
  if (simMgr->redrawEnabled != 0) {
    ConfigureTurnResumeStateAndNationMask();
    SetOutputDevice();
    DispatchUiSlot4C();
    if (g_pUiRuntimeContext != nullptr) {
      g_pUiRuntimeContext->DispatchDecisionSlot98(-1, 0, 0, 0x16);
    }
  }
  if (simMgr->redrawEnabled != 2) {
    simMgr->DispatchTurnEvent2134AndRefreshNationPanels();
  }
}

void AdvanceGlobalTurnStateMachineCase8(TSimMgr* simMgr) {
  simMgr->turnStateCode = 0xb;
  simMgr->RefreshMapSystemsAndPrepareOrderExecution();
  if (simMgr->redrawEnabled != 0) {
    ConfigureTurnResumeStateAndNationMask();
    simMgr->turnStateCode = 0x13;
    RequeueTurnFlow(simMgr);
    return;
  }
  RequeueTurnFlow(simMgr);
}

void AdvanceGlobalTurnStateMachineCase9(TSimMgr* simMgr) {
  simMgr->turnStateCode = 10;
  if (simMgr->redrawEnabled != 2) {
    simMgr->DispatchEligibleNationTurnCallback158();
    RequeueTurnFlow(simMgr);
    return;
  }
  RequeueTurnFlow(simMgr);
}

void AdvanceGlobalTurnStateMachineCase10(TSimMgr* simMgr) {
  simMgr->turnStateCode = 0x14;
  if (g_pLocalizationTable != nullptr) {
    g_pLocalizationTable->RebuildPrimaryNationStateForSlot(0, 0);
  }
  RequeueTurnFlow(simMgr);
}

void AdvanceGlobalTurnStateMachineCaseB(TSimMgr* simMgr) {
  char actionNeeded = 0;
  for (int nationSlot = 6; nationSlot >= 0; --nationSlot) {
    TGreatPower* nation = g_apNationStates[nationSlot];
    if (nation == nullptr) {
      continue;
    }
    if (QueryJoinEmpireModePendingForNationAf(nation) == 0) {
      continue;
    }
    TGreatPower* activeNation = g_apNationStates[simMgr->activeNationSlot];
    if (activeNation != nullptr) {
      activeNation->ApplyJoinEmpireMode1TargetTransition(nationSlot);
      actionNeeded = 1;
    }
  }
  if (actionNeeded == 0) {
    RequeueTurnFlow(simMgr);
  }
}

void AdvanceGlobalTurnStateMachineCaseC(TSimMgr* simMgr) {
  simMgr->turnStateCode = 0xe;
  if (IsNationTerrainEligible(simMgr->activeNationSlot)) {
    DispatchUiSlot4C();
    SetOutputDevice();
    return;
  }
  RequeueUnlessActiveNationMinorRange(simMgr);
}

void AdvanceGlobalTurnStateMachineCaseD(TSimMgr* simMgr) {
  simMgr->turnStateCode = 0x19;
  if (GetByteFlagAtOffset8() != 0 && IsNationTerrainEligible(simMgr->activeNationSlot)) {
    DispatchUiSlot4C();
    return;
  }
  RequeueUnlessActiveNationMinorRange(simMgr);
}

void AdvanceGlobalTurnStateMachineCaseE(TSimMgr* simMgr) {
  simMgr->turnStateCode = 0x10;
  if (g_pDiplomacyTurnStateManager != nullptr &&
      g_pDiplomacyTurnStateManager->lastProcessedNationSlot78e != -1) {
    const short lastProcessed = g_pDiplomacyTurnStateManager->lastProcessedNationSlot78e;
    simMgr->turnStateCode =
        static_cast<int>(lastProcessed != simMgr->activeNationSlot) + 0x16;
  }
  RunQuarterGateCheckAndMaybeRequeue(simMgr);
}

void AdvanceGlobalTurnStateMachineCaseF(TSimMgr* simMgr) {
  simMgr->turnStateCode = 0x12;
  if (g_pUiViewManager != nullptr) {
    // TODO: port TAssetMgr/TViewMgr slot used at 0x005df3f0.
  }
  RebuildNationRankingDataAndUiCache();
  DispatchUiSlot4C();

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
    HandleTurnEndSavePaths(simMgr);
  } else {
    const int phaseFlags = simMgr->IsTurnFlowPhaseOutsideRange4To5();
    if ((phaseFlags & 0xf) == 10) {
      HandleTurnEndSavePaths(simMgr);
    }
  }

  if (simMgr->redrawEnabled != 0) {
    RequeueUnlessActiveNationMinorRange(simMgr);
  }
}

void AdvanceGlobalTurnStateMachineCase10State(TSimMgr* simMgr) {
  simMgr->turnStateCode = 0x11;
  simMgr->turnFlowStatusFlags = 0;
  simMgr->runtimeSubsystemIndex = 0;
  simMgr->SetGlobalTurnStateCodeIfAllowed(0);
  RequeueTurnFlow(simMgr);
}

void AdvanceGlobalTurnStateMachineCase11(TSimMgr* simMgr) {
  simMgr->turnStateCode = 0xf;
  char actionNeeded = 1;
  const short capabilityBefore = ReadCityOrderCapabilityField262();
  UpdateCityOrderCapabilityUnlockProgress();
  if (capabilityBefore == ReadCityOrderCapabilityField262()) {
    simMgr->runtimeSubsystemIndex |= 0x40;
  }

  for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
    if (g_pLocalizationTable != nullptr &&
        g_pLocalizationTable->activeNationSlot == nationSlot &&
        g_nTurnCooldownDeferCounter006A43C4 < 1) {
      g_nTurnCooldownDeferCounter006A43C4 = 0;
      g_nTurnCooldownSideFlag00698B10 = 1;
      if (!IsNationTerrainEligible(simMgr->activeNationSlot)) {
        short unlockSlot = ConsumeFirstPendingAbilityUnlock();
        if (unlockSlot != -1) {
          DispatchUiSlot4C();
          actionNeeded = 0;
        }
        continue;
      }
    }

    short unlockSlot = ConsumeFirstPendingAbilityUnlock();
    while (unlockSlot != -1) {
      unlockSlot = ConsumeFirstPendingAbilityUnlock();
    }
  }

  if (actionNeeded != 0) {
    RequeueTurnFlow(simMgr);
  }
}

void AdvanceGlobalTurnStateMachineCase12(TSimMgr* simMgr) {
  simMgr->turnStateCode = 5;
  if (g_pUiViewManager != nullptr) {
    // TODO: port TAssetMgr/TViewMgr slot used at 0x005df3f0.
  }
  if (g_pGlobalMapState != nullptr) {
    g_pGlobalMapState->DispatchTurnEvent7DDForActiveNation();
  }
  if (g_pUiRuntimeContext != nullptr) {
    g_pUiRuntimeContext->RefreshViewSlot48();
  }

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

  ResetDualAudioCuePools();
  PushCueToDualAudioCuePools();
  PushCueToDualAudioCuePools();
  SelectAndScheduleRandomAudioCue();
  RequeueUnlessActiveNationMinorRange(simMgr);
}

void AdvanceGlobalTurnStateMachineCase13(TSimMgr* simMgr) {
  TMultiplayerMgr* gameFlow = reinterpret_cast<TMultiplayerMgr*>(g_pGameFlowState);
  if (gameFlow != nullptr) {
    simMgr->turnStateCode = gameFlow->activeNationSlotIndex;
  }
  HandleTurnResumeStateTelemetry();
  if (g_pUiRuntimeContext != nullptr) {
    g_pUiRuntimeContext->DispatchTurnEventSlot4C(simMgr->activeNationSlot, 0x5e4);
  }
}

void AdvanceGlobalTurnStateMachineCase14(TSimMgr* simMgr) {
  simMgr->turnStateCode = 0x15;
  if (g_pMapContextActionManager != nullptr) {
    // TODO: port map-context slot at 0x004a1e40.
  }
  if (simMgr->redrawEnabled != 0) {
    ConfigureTurnResumeStateAndNationMask();
    simMgr->turnStateCode = 0x13;
  }
}

void AdvanceGlobalTurnStateMachineCase15(TSimMgr* simMgr) {
  simMgr->turnStateCode = 0xd;
  RefreshNavyOrderCycleAndClearReadyFlags();
  if (simMgr->redrawEnabled != 2) {
    RecomputeTileStrategicScoreHeatmap();
    RecomputeNationOrderPriorityMetrics();
    for (short nationSlot = 0; nationSlot < 7; ++nationSlot) {
      if (nationSlot == -1 || g_apTerrainTypeDescriptorTable[nationSlot] == nullptr) {
        continue;
      }
      if (nationSlot < 7 && IsNationProfileInMinorRange100To199() != 0) {
        continue;
      }
      TGreatPower* nation = g_apNationStates[nationSlot];
      if (nation != nullptr) {
        // TODO: port TGreatPower slot at 0x004d8920 (turn-prep per nation).
      }
    }
  }

  for (short nationSlot = 0; nationSlot < 7; ++nationSlot) {
    if (!IsNationTerrainEligible(nationSlot)) {
      continue;
    }
    TGreatPower* nation = g_apNationStates[nationSlot];
    if (nation != nullptr) {
      nation->SetNationTransferTargetCodeAndNotifyEligiblePeers(0);
    }
  }

  const short tickA = simMgr->GetTurnTickSlot3C();
  const short tickB = simMgr->GetTurnTickSlot3C();
  if (((tickB % 0x28) == 0) && (simMgr->phaseFlags[tickA / 0x28] != 0) &&
      simMgr->redrawEnabled != 2 && g_pDiplomacyTurnStateManager != nullptr) {
    g_pDiplomacyTurnStateManager->SelectPriorityNationIndicesForMinorCapabilityRows();
  }

  if (simMgr->redrawEnabled != 0) {
    ConfigureTurnResumeStateAndNationMask();
    simMgr->turnStateCode = 0x13;
  }
  RequeueTurnFlow(simMgr);
}

void AdvanceGlobalTurnStateMachineCase17(TSimMgr* simMgr) {
  (void)simMgr;
  DispatchUiSlot4C();
}

void AdvanceGlobalTurnStateMachineCase19(TSimMgr* simMgr) {
  simMgr->turnStateCode = 8;
  char actionNeeded = 0;

  if (g_pLocalizationTable != nullptr) {
    const short localizationNation = g_pLocalizationTable->activeNationSlot;
    TGreatPower* localizationNationState = g_apNationStates[localizationNation];
    if (localizationNationState != nullptr) {
      const short encoded = localizationNationState->encodedNationSlot;
      if (encoded > 99 && encoded < 200) {
        TGreatPower* activeNation = g_apNationStates[simMgr->activeNationSlot];
        if (activeNation != nullptr) {
          activeNation->ApplyJoinEmpireMode1TargetTransition(localizationNation);
          actionNeeded = 1;
        }
      }
    }
  }

  for (int removeNationSlot = 0; removeNationSlot < 7; ++removeNationSlot) {
    if (g_apTerrainTypeDescriptorTable[removeNationSlot] == nullptr ||
        g_apNationStates[removeNationSlot] == nullptr) {
      continue;
    }
    if (QueryNationAdvisorSlot90Predicate28(g_apNationStates[removeNationSlot]) == 0) {
      RemoveNationSlotAndNotifyPeers();
    }
  }

  for (int secondaryIndex = 7; secondaryIndex < 36; ++secondaryIndex) {
    TMinor* secondaryNation = g_apSecondaryNationStateSlots[secondaryIndex];
    if (secondaryNation != nullptr &&
        QueryNationAdvisorSlot90Predicate28(reinterpret_cast<TGreatPower*>(secondaryNation)) ==
            0) {
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
    return;
  }

  int eligibleMinorCount = 0;
  for (int countNationSlot = 0; countNationSlot < 7; ++countNationSlot) {
    if (IsNationTerrainEligible(static_cast<short>(countNationSlot))) {
      ++eligibleMinorCount;
    }
  }

  if (eligibleMinorCount == 1 && IsNationTerrainEligible(simMgr->activeNationSlot)) {
    actionNeeded = 1;
    UpdatePersistentTopTenNationScores();
    DispatchUiSlot4C();
  }

  if (actionNeeded == 0) {
    RequeueTurnFlow(simMgr);
  }
}

extern undefined4 RefreshHelpManagerForTurnAdvance(void) {
  if (g_pHelpMgr != nullptr) {
    g_pHelpMgr->OrphanCallChain_C1_I22_00500f10();
  }
  return 0;
}

void AdvanceGlobalTurnStateMachineCase2RefreshNationSlots(TSimMgr* simMgr) {
  for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
    TGreatPower* nation = g_apNationStates[nationSlot];
    if (nation == nullptr) {
      continue;
    }
    if (nation->ShouldDispatchImmediatelySlot28() == 0 && DAT_006a43f0 == 0) {
      CString emptyString;
      nation->RefreshNationCivilianWorkOrdersForTurn(emptyString, reinterpret_cast<char*>(-1));
    }
  }

  if (simMgr->activeNationSlot >= 0 && simMgr->activeNationSlot < 7) {
    TGreatPower* activeNation = g_apNationStates[simMgr->activeNationSlot];
    if (activeNation != nullptr) {
      activeNation->ResetDiplomacyNeedScoresAndClearAidAllocationMatrix();
      activeNation->ResetDiplomacyNeedSlots7012AndRefreshIfModeGateMatches();
    }
  }
}

extern undefined4 QueryNationAdvisorSlot90Predicate28(TGreatPower* nation) {
  (void)nation;
  return 1;
}

extern undefined4 QueryJoinEmpireModePendingForNationAf(TGreatPower* nation) {
  (void)nation;
  return 0;
}
