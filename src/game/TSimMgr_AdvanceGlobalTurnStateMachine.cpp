// TSimMgr::AdvanceGlobalTurnStateMachine (0x0057da70) is a single ~4 KB monolithic function in
// the original. It lives in its own translation unit (rather than alongside the rest of TSimMgr)
// so the inline per-case bodies and the predicate helpers below do not perturb the codegen of the
// neighbouring TSimMgr methods. The per-case bodies are inlined from
// advance_turn_state_machine_switch.inc so the recompiled function matches the original's
// one-function shape; the helpers are marked inline (the build uses /Ob1, which only expands
// inline-marked functions) so they fold back into the switch body instead of becoming
// out-of-line calls.

#include "game/TSimMgr.h"

#include "decomp_types.h"
#include "game/TCountry.h"
#include "game/TDiplomacyMgr.h"
#include "game/TGreatPower.h"
#include "game/THelpMgr.h"
#include "game/TMapMgr.h"
#include "game/TMinor.h"
#include "game/TMultiplayerMgr.h"
#include "game/TNextDiplomationCommand.h"
#include "game/TSoundPlayer.h"
#include "game/TTechMgr.h"
#include "game/TViewMgr.h"
#include "game/global_data_tables.h"

extern "C" char DAT_006a43f0;
extern "C" char DAT_006a43c0;

extern undefined4 ConfigureTurnResumeStateAndNationMask(void);
extern undefined4 RefreshNationAdvisorLabelStrings(void);
extern undefined4 ProcessTurnInstructionStreamAndFinalizePhase(void);
extern undefined4 ShowTurnAlertsForActiveNation(void);
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
  return nation->trackedObjectList->GetCountSlot48();
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
  return *reinterpret_cast<short*>(reinterpret_cast<char*>(g_pCityOrderCapabilityState) + 0x262);
}

static inline void HandleTurnEndSavePaths(TSimMgr* simMgr) {
  if (simMgr->redrawEnabled == 0) {
    SaveGameWithModeAndOptionalLabel();
    return;
  }
  if (simMgr->redrawEnabled == 1) {
    TrySaveGameAndMaybeShowFailureDialog();
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
    if (DAT_006a43c0 == 0) {
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
      if (nation->ShouldDispatchImmediatelySlot28() == 0 && DAT_006a43f0 == 0) {
        nation->RefreshNationCivilianWorkOrdersForTurn(emptyString, reinterpret_cast<char*>(-1));
      }
    }
    if (activeNationSlot >= 0 && activeNationSlot < 7) {
      TGreatPower* activeNation = g_apNationStates[activeNationSlot];
      if (activeNation != nullptr) {
        activeNation->ResetDiplomacyNeedScoresAndClearAidAllocationMatrix();
        activeNation->ResetDiplomacyNeedSlots7012AndRefreshIfModeGateMatches();
      }
    }
    if (DAT_006a43f0 == 0) {
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
      ConfigureTurnResumeStateAndNationMask();
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
    if (DAT_006a43f0 != 0) {
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

#include "advance_turn_state_machine_switch.inc"

  default:
    break;
  }
}
