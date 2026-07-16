// TSimMgr::AdvanceGlobalTurnStateMachine (0x0057da70) is a single ~4 KB monolithic function in
// the original. It lives in its own translation unit (rather than alongside the rest of TSimMgr)
// so the per-case bodies and the predicate helpers below do not perturb the codegen of the
// neighbouring TSimMgr methods. The helpers are marked inline (the build uses /Ob1, which only
// expands inline-marked functions) so they fold back into the switch body instead of becoming
// out-of-line calls.

#include "game/TLoadSavePicture.h"
#include "game/TNewsMgr.h"
#include "game/TSimMgr.h"

#include "decomp_types.h"
#include "game/TArmyMgr.h"
#include "game/TCountry.h"
#include "game/TDiplomacyMgr.h"
#include "game/TGreatPower.h"
#include "game/TGreatPower_internal.h"
#include "game/THelpMgr.h"
#include "game/TMapMgr.h"
#include "game/TMinor.h"
#include "game/TMultiplayerMgr.h"
#include "game/TNextDiplomationCommand.h"
#include "game/TApplication.h"
#include "game/TSoundPlayer.h"
#include "game/TTechMgr.h"
#include "game/TViewMgr.h"
#include "game/global_data_tables.h"

extern undefined4 RefreshNationAdvisorLabelStrings(void);
extern undefined4 ProcessTurnInstructionStreamAndFinalizePhase(void);
extern undefined4 ShowTurnAlertsForActiveNation(void);
extern undefined4 UpdatePersistentTopTenNationScores(void);
extern undefined4 UpdateCityOrderCapabilityUnlockProgress(void);
extern undefined4 ConsumeFirstPendingAbilityUnlock(void);
extern undefined4 RefreshNavyOrderCycleAndClearReadyFlags(void);
extern undefined4 RemoveNationSlotAndNotifyPeers(void);
extern undefined4 SetOutputDevice(void);

// QueryNationAdvisorSlot90Predicate28 / QueryJoinEmpireModePendingForNationAf are placeholder
// per-nation checks that still need to be ported (cases 0x19 / 0xb); constant returns make those
// branches no-ops for now.
static int QueryNationAdvisorSlot90Predicate28(TGreatPower* nation) {
  (void)nation;
  return 1;
}

static int QueryJoinEmpireModePendingForNationAf(TGreatPower* nation) {
  (void)nation;
  return 0;
}

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

static inline void DispatchUiSlot4C() {
  if (g_pUiRuntimeContext != nullptr) {
    g_pUiRuntimeContext->DispatchTurnEventSlot4C(0, 0);
  }
}

static inline int GetNationTrackedOrderCount(TGreatPower* nation) {
  if (nation == nullptr || nation->trackedObjectList == nullptr) {
    return 0;
  }
  return nation->trackedObjectList->GetCount();
}

static inline bool ShouldDispatchNextTradePacket(TSimMgr* simMgr) {
  if (simMgr->redrawEnabled == 0) {
    return true;
  }
  if (simMgr->redrawEnabled == 1 && !IsNationTerrainEligible(simMgr->activeNationSlot)) {
    return true;
  }
  return false;
}

static inline void RunQuarterGateCheckAndMaybeRequeue(TSimMgr* simMgr) {
  const short tickA = simMgr->GetTurnTickSlot3C();
  const short tickB = simMgr->GetTurnTickSlot3C();
  if (((tickB % 0x28) != 0) || (simMgr->phaseFlags[tickA / 0x28] == 0)) {
    simMgr->PostMainWindowCommand100ForTurnFlow();
    return;
  }
  DispatchUiSlot4C();
}

static inline short ReadCityOrderCapabilityField262(void) {
  if (g_pCityOrderCapabilityState == nullptr) {
    return 0;
  }
  // 0x262 is the active-tech marker short sitting just past the nationCapRows table.
  return g_pCityOrderCapabilityState->marker262;
}

static inline void HandleTurnEndSavePaths(TSimMgr* simMgr) {
  if (simMgr->redrawEnabled == 0) {
    SaveGameWithModeAndOptionalLabel(0xa1, 0);
    return;
  }
  if (simMgr->redrawEnabled == 1) {
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
  previousTurnStateCode = turnStateCode;

  switch (turnStateCode) {
  case 1:
    turnStateCode = 3;
    if (g_bTurnFlowBootstrapComplete == 0) {
      // Verified against 0x0057daf5: real event code is 0x11f8, payload 0, no null
      // guard on g_pUiRuntimeContext (matches the original — see heuristics for the
      // full re-verification note on this switch).
      g_pUiRuntimeContext->DispatchTurnEventSlot4C(0x11f8, 0);
      break;
    }
    // Verified against 0x0057db06: real event code is 0x5dc, payload 0 (not
    // activeNationSlot/0x5e4 — that call was misattributed to this branch).
    g_pUiRuntimeContext->DispatchTurnEventSlot4C(0x5dc, 0);
    break;

  case 2: {
    turnStateCode = 0x10;
    for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
      TGreatPower* nation = g_apNationStates[nationSlot];
      if (nation == nullptr) {
        continue;
      }
      if (nation->ShouldDispatchImmediatelySlot28() == 0 &&
          g_bMultiplayerScenarioSetupActive == 0) {
        nation->SetHomeCityTileAndDisplayName(-1, 0);
      }
    }
    if (activeNationSlot >= 0 && activeNationSlot < 7) {
      TGreatPower* activeNation = g_apNationStates[activeNationSlot];
      if (activeNation != nullptr) {
        activeNation->ResetDiplomacyNeedScoresAndClearAidAllocationMatrix();
        activeNation->ResetDiplomacyNeedSlots7012AndRefreshIfModeGateMatches();
      }
    }
    if (g_bMultiplayerScenarioSetupActive == 0) {
      if (stateFlag114 == 0) {
        if (redrawEnabled == 0) {
          RefreshNationAdvisorLabelStrings();
        }
      } else {
        ProcessTurnInstructionStreamAndFinalizePhase();
      }
    }
    if (g_pHelpMgr != nullptr) {
      g_pHelpMgr->OrphanCallChain_C1_I22_00500f10();
    }
    if (redrawEnabled != 0) {
      g_pGameFlowState->ConfigureTurnResumeStateAndNationMask(previousTurnStateCode, turnStateCode);
      turnStateCode = 0x13;
      PostMainWindowCommand100ForTurnFlow();
      break;
    }
    PostMainWindowCommand100ForTurnFlow();
    break;
  }

  case 3:
    turnStateCode = 2;
    if (field112 != 0) {
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
    // redrawEnabled (this+0x40 on that object, NOT this->field34), the dispatch uses
    // event code 0x3b8 (not 0x5e4) with (code, activeNationSlot) argument order, and
    // there is no null guard on g_pUiRuntimeContext -- same missing-guard pattern as
    // case 1 above. field34/0x5e4/guarded call was an unverified placeholder shape.
    if (g_pSimMgr->redrawEnabled > 1 && stateFlag114 == 0) {
      g_pUiRuntimeContext->DispatchTurnEventSlot4C(0x3b8, activeNationSlot);
    } else {
      PostMainWindowCommand100ForTurnFlow();
    }
    break;

  case 4:
    turnStateCode = 5;
    if (g_pUiRuntimeContext != nullptr) {
      g_pUiRuntimeContext->DispatchTurnEventSlot4C(0, 0);
    }
    if (redrawEnabled != 0) {
      if (activeNationSlot == -1 || g_apTerrainTypeDescriptorTable[activeNationSlot] == nullptr ||
          (activeNationSlot <= 6 &&
           g_apTerrainTypeDescriptorTable[activeNationSlot]->encodedNationSlot >= 100 &&
           g_apTerrainTypeDescriptorTable[activeNationSlot]->encodedNationSlot <= 199)) {
        PostMainWindowCommand100ForTurnFlow();
      }
    }
    break;

  case 5: {
    const char alertsPending = ShowTurnAlertsForActiveNation();
    turnFlowStatusFlags = alertsPending;
    if (alertsPending != 0) {
      break;
    }
    turnStateCode = 6;
    if (redrawEnabled != 0) {
      g_pGameFlowState->ConfigureTurnResumeStateAndNationMask(previousTurnStateCode, turnStateCode);
      turnStateCode = 0x13;
    }
    PostMainWindowCommand100ForTurnFlow();
    break;
  }

  case 6: {
    turnStateCode = 7;
    if (redrawEnabled != 0) {
      g_pGameFlowState->ConfigureTurnResumeStateAndNationMask(previousTurnStateCode, turnStateCode);
    }
    if (redrawEnabled != 1 && g_pDiplomacyTurnStateManager != nullptr) {
      g_pDiplomacyTurnStateManager->ApplyDiplomacyInterNationStatesForTurn();
    }
    if (redrawEnabled == 0) {
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
    } else if (IsNationTerrainEligible(activeNationSlot)) {
      DispatchUiSlot4C();
    }
    for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
      TGreatPower* nation = g_apNationStates[nationSlot];
      if (nation != nullptr) {
        nation->ProcessPendingDiplomacyProposalQueue();
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
    if (g_pDiplomacyTurnStateManager != nullptr) {
      g_pDiplomacyTurnStateManager->ApplyDiplomacyInterNationStatesForTurn();
    }
    if (redrawEnabled != 0) {
      g_pGameFlowState->ConfigureTurnResumeStateAndNationMask(previousTurnStateCode, turnStateCode);
      SetOutputDevice();
      DispatchUiSlot4C();
      if (g_pUiRuntimeContext != nullptr) {
        g_pUiRuntimeContext->DispatchDecisionSlot98(-1, 0, 0, 0x16);
      }
    }
    if (redrawEnabled != 2) {
      DispatchTurnEvent2134AndRefreshNationPanels();
    }
    break;
  }

  case 8: {
    turnStateCode = 0xb;
    RefreshMapSystemsAndPrepareOrderExecution();
    if (redrawEnabled != 0) {
      g_pGameFlowState->ConfigureTurnResumeStateAndNationMask(previousTurnStateCode, turnStateCode);
      turnStateCode = 0x13;
      PostMainWindowCommand100ForTurnFlow();
      break;
    }
    PostMainWindowCommand100ForTurnFlow();
    break;
  }

  case 9: {
    turnStateCode = 10;
    if (redrawEnabled != 2) {
      DispatchEligibleNationTurnCallback158();
      PostMainWindowCommand100ForTurnFlow();
      break;
    }
    PostMainWindowCommand100ForTurnFlow();
    break;
  }

  case 10: {
    turnStateCode = 0x14;
    if (g_pSimMgr != nullptr) {
      g_pSimMgr->RebuildPrimaryNationStateForSlot(0, 0);
    }
    PostMainWindowCommand100ForTurnFlow();
    break;
  }

  case 0xb: {
    char actionNeeded = 0;
    for (int nationSlot = 6; nationSlot >= 0; --nationSlot) {
      TGreatPower* nation = g_apNationStates[nationSlot];
      if (nation == nullptr) {
        continue;
      }
      if (QueryJoinEmpireModePendingForNationAf(nation) == 0) {
        continue;
      }
      TGreatPower* activeNation = g_apNationStates[activeNationSlot];
      if (activeNation != nullptr) {
        activeNation->ApplyJoinEmpireMode1TargetTransition(nationSlot);
        actionNeeded = 1;
      }
    }
    if (actionNeeded == 0) {
      PostMainWindowCommand100ForTurnFlow();
    }
    break;
  }

  case 0xc: {
    turnStateCode = 0xe;
    if (IsNationTerrainEligible(activeNationSlot)) {
      DispatchUiSlot4C();
      SetOutputDevice();
      break;
    }
    if (!IsNationTerrainEligible(activeNationSlot)) {
      PostMainWindowCommand100ForTurnFlow();
    }
    break;
  }

  case 0xd: {
    turnStateCode = 0x19;
    // Verified against 0x0057e487: real receiver is g_pMapContextActionManager (no null
    // guard on it, matching the missing-guard pattern used elsewhere in this switch).
    if (g_pMapContextActionManager->GetByteFlagAtOffset8() != 0 &&
        IsNationTerrainEligible(activeNationSlot)) {
      DispatchUiSlot4C();
      break;
    }
    if (!IsNationTerrainEligible(activeNationSlot)) {
      PostMainWindowCommand100ForTurnFlow();
    }
    break;
  }

  case 0xe: {
    turnStateCode = 0x10;
    if (g_pDiplomacyTurnStateManager != nullptr &&
        g_pDiplomacyTurnStateManager->lastProcessedNationSlot78e != -1) {
      const short lastProcessed = g_pDiplomacyTurnStateManager->lastProcessedNationSlot78e;
      turnStateCode = static_cast<int>(lastProcessed != activeNationSlot) + 0x16;
    }
    RunQuarterGateCheckAndMaybeRequeue(this);
    break;
  }

  case 0xf: {
    turnStateCode = 0x12;
    if (g_pUiViewManager != nullptr) {
      // TODO: port TAssetMgr/TViewMgr slot used at 0x005df3f0.
    }
    g_pInterNationEventQueueManager->StartNewsPhase();
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
      HandleTurnEndSavePaths(this);
    } else {
      const int phaseFlags = IsTurnFlowPhaseOutsideRange4To5();
      if ((phaseFlags & 0xf) == 10) {
        HandleTurnEndSavePaths(this);
      }
    }
    if (redrawEnabled != 0) {
      if (!IsNationTerrainEligible(activeNationSlot)) {
        PostMainWindowCommand100ForTurnFlow();
      }
    }
    break;
  }

  case 0x10: {
    turnStateCode = 0x11;
    turnFlowStatusFlags = 0;
    runtimeSubsystemIndex = 0;
    SetGlobalTurnStateCodeIfAllowed(0);
    PostMainWindowCommand100ForTurnFlow();
    break;
  }

  case 0x11: {
    turnStateCode = 0xf;
    char actionNeeded = 1;
    const short capabilityBefore = ReadCityOrderCapabilityField262();
    UpdateCityOrderCapabilityUnlockProgress();
    if (capabilityBefore == ReadCityOrderCapabilityField262()) {
      runtimeSubsystemIndex |= 0x40;
    }
    for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
      if (g_pSimMgr != nullptr && g_pSimMgr->activeNationSlot == nationSlot &&
          g_nTurnCooldownDeferCounter006A43C4 < 1) {
        g_nTurnCooldownDeferCounter006A43C4 = 0;
        g_nTurnCooldownSideFlag00698B10 = 1;
        if (!IsNationTerrainEligible(activeNationSlot)) {
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
      PostMainWindowCommand100ForTurnFlow();
    }
    break;
  }

  case 0x12: {
    turnStateCode = 5;
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
    g_pSfxPlaybackSystem->ResetDualAudioCuePools();
    g_pSfxPlaybackSystem->PushCueToDualAudioCuePools(2);
    g_pSfxPlaybackSystem->PushCueToDualAudioCuePools(3);
    g_pSfxPlaybackSystem->SelectAndScheduleRandomAudioCue();
    if (!IsNationTerrainEligible(activeNationSlot)) {
      PostMainWindowCommand100ForTurnFlow();
    }
    break;
  }

  case 0x13: {
    if (g_pGameFlowState != nullptr) {
      turnStateCode = g_pGameFlowState->activeNationSlotIndex;
    }
    g_pGameFlowState->HandleTurnResumeStateTelemetry();
    if (g_pUiRuntimeContext != nullptr) {
      g_pUiRuntimeContext->DispatchTurnEventSlot4C(activeNationSlot, 0x5e4);
    }
    break;
  }

  case 0x14: {
    turnStateCode = 0x15;
    if (g_pMapContextActionManager != nullptr) {
      // TODO: port map-context slot at 0x004a1e40.
    }
    if (redrawEnabled != 0) {
      g_pGameFlowState->ConfigureTurnResumeStateAndNationMask(previousTurnStateCode, turnStateCode);
      turnStateCode = 0x13;
    }
    break;
  }

  case 0x15: {
    turnStateCode = 0xd;
    RefreshNavyOrderCycleAndClearReadyFlags();
    if (redrawEnabled != 2) {
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
          // TODO: port TGreatPower vtable slot 0xae (0x2b8), which resolves to a near-empty
          // stub at 0x4d8be0 (RET 4) -- the real per-nation override(s), if any, are not yet
          // identified. (A prior version of this TODO cited 0x4d8920 --
          // TCountry::ResetDiplomacyLevelForNationSlot12 at unrelated vtable slot 0x12/0x48 --
          // which was a mistaken address; corrected here.)
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
    const short tickA = GetTurnTickSlot3C();
    const short tickB = GetTurnTickSlot3C();
    if (((tickB % 0x28) == 0) && (phaseFlags[tickA / 0x28] != 0) && redrawEnabled != 2 &&
        g_pDiplomacyTurnStateManager != nullptr) {
      g_pDiplomacyTurnStateManager->SelectPriorityNationIndicesForMinorCapabilityRows();
    }
    if (redrawEnabled != 0) {
      g_pGameFlowState->ConfigureTurnResumeStateAndNationMask(previousTurnStateCode, turnStateCode);
      turnStateCode = 0x13;
    }
    PostMainWindowCommand100ForTurnFlow();
    break;
  }

  case 0x17:
    DispatchUiSlot4C();
    break;

  case 0x19: {
    turnStateCode = 8;
    char actionNeeded = 0;
    if (g_pSimMgr != nullptr) {
      const short localizationNation = g_pSimMgr->activeNationSlot;
      TGreatPower* localizationNationState = g_apNationStates[localizationNation];
      if (localizationNationState != nullptr) {
        const short encoded = localizationNationState->encodedNationSlot;
        if (encoded > 99 && encoded < 200) {
          TGreatPower* activeNation = g_apNationStates[activeNationSlot];
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
      if (secondaryNation != nullptr && QueryNationAdvisorSlot90Predicate28(
                                            reinterpret_cast<TGreatPower*>(secondaryNation)) == 0) {
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
      DispatchUiSlot4C();
    }
    if (actionNeeded == 0) {
      PostMainWindowCommand100ForTurnFlow();
    }
    break;
  }

  case 0x16:
    UpdatePersistentTopTenNationScores();
    if (g_pUiRuntimeContext != nullptr) {
      g_pUiRuntimeContext->DispatchTurnEventSlot4C(0, 0);
    }
    break;

  case 100:
    turnStateCode = 4;
    if (g_pUiRuntimeContext != nullptr) {
      g_pUiRuntimeContext->DispatchTurnEventSlot4C(0, 0);
    }
    break;

  // Jump-table ground truth (0x57dad8, index-byte table 0x57ebec): case 0x71 -> 0x57eabf
  // (posts 0x104f), case 0x72 -> 0x57ead8 (posts 0x5e4). The old merged port dropped both
  // event codes.
  case 0x71:
    turnStateCode = 4;
    g_pGlobalUiRootController->PostTurnEventCodeMessage2420(0x104f);
    break;

  case 0x72:
    turnStateCode = 4;
    g_pGlobalUiRootController->PostTurnEventCodeMessage2420(0x5e4);
    break;

  case 0x68:
    turnStateCode = 4;
    // Verified against 0x0057e9f9: real receiver is g_pDiplomacyTurnStateManager (no
    // null guard on it, matching the missing-guard pattern used elsewhere in this switch).
    g_pDiplomacyTurnStateManager->SyncNationField790FromLocalizationStateId();
    if (g_pUiRuntimeContext != nullptr) {
      g_pUiRuntimeContext->DispatchTurnEventSlot4C(0, 0);
    }
    break;

  case 0x6b:
  case 0x65:
  case 0x66:
  case 0x67:
  case 0x69:
  case 0x6a:
  case 0x6c:
  case 0x6d:
  case 0x6e:
  case 0x6f:
  case 0x70:
    turnStateCode = 4;
    if (g_pUiRuntimeContext != nullptr) {
      g_pUiRuntimeContext->DispatchTurnEventSlot4C(0, 0);
    }
    break;

  default:
    break;
  }
}
