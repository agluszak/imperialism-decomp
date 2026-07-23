#include "decomp_types.h"
#include <stdlib.h>
#include <string.h>
#include "game/navy_order.h"

#include "game/TAutoGreatPower.h"

#include "game/TCityMinisterPersonalities.h"
#include "game/TDefenseMinisterPersonalities.h"
#include "game/TForeignMinisterPersonalities.h"
#include "game/TList.h"
#include "game/TOcean.h"
#include "game/TSortedByRelationshipList.h"
#include "game/nation_stream_serialization.h"
#include "game/CIterator.h"
#include "game/TDiplomacyMgr.h"
#include "game/TMapMgr.h"
#include "game/TSortedList.h"
#include "game/TSimMgr.h"
#include "game/TTechMgr.h"
#include "game/TTradeMgr.h"
#include "game/TMinister.h"
#include "game/TForeignMinister.h"
#include "game/TCityInteriorMinister.h"
#include "game/TDefenseMinister.h"
#include "game/TDefendProvinceMission.h"
#include "game/TStream.h"
#include "game/TMission.h"
#include "game/TMinor.h"
#include "game/TCity.h"
#include "game/global_data_tables.h"
#include "game/TZone.h"
#include <new>

#include "game/TMultiplayerMgr.h"
#include "game/TShip.h"
#include "game/GameAssert.h"
#include "game/ui_invalidation_guard.h"
#include "game/TMilitaryUnit.h"
#include "game/TProvinceDesirabilityList.h"

// kNationSlotCount (0x17) comes from TDiplomacyMgr.h.
static const int kAidAllocationRowCount = 0x10;
static const int kAidAllocationColumnCount = 0x17;
static const int kMapNodeCount = 0x180;
static const int kPortZoneCount = 0x70;

// SYNTHETIC: IMPERIALISM 0x004e6a70
// TAutoGreatPower::CreateObject

// FUNCTION: IMPERIALISM 0x004e6b10
char TAutoGreatPower::UpdateGreatPowerPressureStateAndDispatchEscalationMessage(void) {
  return 0;
}

// SYNTHETIC: IMPERIALISM 0x004e6b30
// TAutoGreatPower::GetRuntimeClass

IMPLEMENT_DYNCREATE(TAutoGreatPower, TGreatPower)

// FUNCTION: IMPERIALISM 0x004e6b50
TAutoGreatPower::TAutoGreatPower() : TGreatPower() {
  missionQueue = 0;
}

// SYNTHETIC: IMPERIALISM 0x004e6b80
// TAutoGreatPower::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x004e6bb0
TAutoGreatPower::~TAutoGreatPower() {}

// FUNCTION: IMPERIALISM 0x004e6c20
void TAutoGreatPower::InitializeNationMinisterSubsystemsByPolicyIds(int nationSlot,
                                                                    int nationInitializationMode,
                                                                    short cityMinisterPolicyId,
                                                                    short foreignMinisterPolicyId,
                                                                    short defenseMinisterPolicyId) {
  InitializeNationStateRuntimeSubsystems(nationSlot, nationInitializationMode);
  treasuryValue10 = 10000;
  memset(actionMetricByQuarter, 0, sizeof(actionMetricByQuarter));

  switch (defenseMinisterPolicyId) {
  case 0: {
    TNapoleonMinister* minister = new TNapoleonMinister();
    minister->InitializeOrderArrayPreset50_0_10_50(this);
    defenseMinister = minister;
    break;
  }
  case 1: {
    TBismarckMinister* minister = new TBismarckMinister();
    minister->InitializeOrderArrayPreset10_10_10_50(this);
    defenseMinister = minister;
    break;
  }
  case 2: {
    TPirateMinister* minister = new TPirateMinister();
    minister->InitializeOrderArrayPreset15_20_50_75(this);
    defenseMinister = minister;
    break;
  }
  case 3: {
    TDefenderMinister* minister = new TDefenderMinister();
    minister->InitializeOrderArrayPreset20_10_10_50(this);
    defenseMinister = minister;
    break;
  }
  case 4: {
    TBullyMinister* minister = new TBullyMinister();
    minister->InitializeOrderArrayPreset25_10_20_50(this);
    defenseMinister = minister;
    break;
  }
  }

  switch (foreignMinisterPolicyId) {
  case 0: {
    TArmsForeignMinister* minister = new TArmsForeignMinister();
    minister->InitializeStateAndCounters(this);
    foreignMinister = minister;
    break;
  }
  case 1: {
    TTraderForeignMinister* minister = new TTraderForeignMinister();
    minister->InitializeStateAndCounters(this);
    foreignMinister = minister;
    break;
  }
  case 2: {
    TTextileForeignMinister* minister = new TTextileForeignMinister();
    minister->InitializeStateAndCounters(this);
    foreignMinister = minister;
    break;
  }
  case 3: {
    TDiplomatForeignMinister* minister = new TDiplomatForeignMinister();
    minister->InitializeStateAndCounters(this);
    foreignMinister = minister;
    break;
  }
  case 4: {
    TBillForeignMinister* minister = new TBillForeignMinister();
    minister->InitializeStateAndCounters(this);
    foreignMinister = minister;
    break;
  }
  case 5: {
    TTedForeignMinister* minister = new TTedForeignMinister();
    minister->InitializeStateAndCounters(this);
    foreignMinister = minister;
    break;
  }
  }

  switch (cityMinisterPolicyId) {
  case 0: {
    TSteelCityMinister* minister = new TSteelCityMinister();
    minister->InitializeCityInteriorState(this);
    interiorMinister = minister;
    minister->MinisterSlot12(1, 2);
    break;
  }
  case 1: {
    TRailCityMinister* minister = new TRailCityMinister();
    minister->InitializeCityInteriorState(this);
    interiorMinister = minister;
    minister->MinisterSlot12(1, 2);
    break;
  }
  case 2: {
    TShipBuilderCityMinister* minister = new TShipBuilderCityMinister();
    minister->InitializeCityInteriorState(this);
    interiorMinister = minister;
    minister->MinisterSlot12(1, 2);
    break;
  }
  case 3: {
    TEvenCityMinister* minister = new TEvenCityMinister();
    minister->InitializeCityInteriorState(this);
    interiorMinister = minister;
    minister->MinisterSlot12(1, 2);
    break;
  }
  }

  memset(mapNodeStateFlags, 0, sizeof(mapNodeStateFlags));
  memset(portZoneStateFlags, 0, sizeof(portZoneStateFlags));
  missionQueue = new TList();
}

// FUNCTION: IMPERIALISM 0x004e7230
void TAutoGreatPower::Free(void) {
  if (this->missionQueue != 0) {
    int ordinal = this->missionQueue->GetCount();
    for (; ordinal > 0; --ordinal) {
      TMission* entry = static_cast<TMission*>(this->missionQueue->GetEntryByOrdinal(ordinal));
      // Vtable index 3 (byte offset 0xc): the real, inherited CObject::AssertValid()
      // (zero-arg MFC diagnostic check) -- TMission does not override it. Confirmed
      // against the assembly at 0x004e725d: `mov ecx,edi / call [ebx+0xc]`, no pushed args.
      entry->AssertValid();
      this->missionQueue->RemoveAtOrdinal(ordinal);
      entry->Free();
    }
    if (this->missionQueue != 0) {
      this->missionQueue->FreePayloadsAndDestroy();
    }
    this->missionQueue = 0;
  }
  TGreatPower::Free();
}

// FUNCTION: IMPERIALISM 0x004e72c0
void TAutoGreatPower::ReadFrom(TStream* stream) {
  TGreatPower::ReadFrom(stream);
  stream->ReadBytes(this->actionMetricByQuarter, 0x0C);
  SwapShortArrayBytes(this->actionMetricByQuarter, 6);

  stream->ReadBytes(this->mapNodeStateFlags, 0x180);
  stream->ReadBytes(this->portZoneStateFlags, 0x70);

  TSortedList* missionQueue = this->missionQueue;
  if (missionQueue->GetCount() != 0) {
    missionQueue->FreePayloads();
  }
  missionQueue->ReadFrom(stream);

  int missionContext = 0;
  stream->ReadBytes(&missionContext, 4);
  for (int queueIndex = 1; queueIndex < 0x71; ++queueIndex) {
    missionContext = 0;
    char hasMission = stream->ReadByte(&missionContext);
    if (hasMission != 0) {
      missionQueue->AddTailInt(missionContext);
    }
  }

  if (g_nSaveFormatVersion < 0x39) {
    this->CreateMission(kMissionTypeScatteredShips, -1, 0, -1);
  }
}

// FUNCTION: IMPERIALISM 0x004e73f0
void TAutoGreatPower::WriteTo(TStream* stream) {
  TGreatPower::WriteTo(stream);

  WriteShortArrayElems(stream, this->actionMetricByQuarter, 6);

  stream->WriteBytesSlot78(this->mapNodeStateFlags, 0x180);
  stream->WriteBytesSlot78(this->portZoneStateFlags, 0x70);

  TSortedList* missionQueue = this->missionQueue;
  missionQueue->WriteTo(stream);
  int missionQueueCount = missionQueue->GetCount();

  int zeroWord = 0;
  stream->WriteBytesSlot78(&zeroWord, 4);
  int index = 1;
  if (index <= missionQueueCount) {
    do {
      stream->WriteObjectSlotB4(missionQueue->GetEntryByOrdinal(index), 0);
      ++index;
    } while (index <= missionQueueCount);
  }
}

// FUNCTION: IMPERIALISM 0x004e7510
void TAutoGreatPower::SorryYouLose(void) {
  if (g_pSimMgr->difficultyLevel != 0) {
    g_pGameFlowState->DispatchTaggedGameStateEvent1F20(0x6c6f7374, this->nationSlot, -3);
  }
}

// FUNCTION: IMPERIALISM 0x004e7550
void TAutoGreatPower::RefreshGreatPowerRelationPanelsAndDispatchDeltaSummary(void) {
  if (this->city != 0) {
    this->RebuildNationResourceYieldCountersAndDevelopmentTargets();
    this->AdvanceOwnedRegionDevelopmentCountersAndHandleEvents();
  }
}

// FUNCTION: IMPERIALISM 0x004e7590
void TAutoGreatPower::FillInteriorMinisterOrders(void) {
  if (this->city != 0) {
    this->interiorMinister->FillOrders();
  }
}

// FUNCTION: IMPERIALISM 0x004e75c0
void TAutoGreatPower::RaiseNeedPlanningMetrics(int needSlot) {
  actionMetricByQuarter[static_cast<short>(needSlot) - 7] += 4;
  SetCityStockCounterAndRefresh(needSlot, GetDiplomacyExternalStateByTarget(needSlot) + 4);
  SetDiplomacyState1c6ClampedToCounterA4(needSlot, QueryNationMetricBySlot7C(needSlot) + 4);
}

// FUNCTION: IMPERIALISM 0x004e7630
void TAutoGreatPower::ApplyIndexedResourceDeltaAndAdjustNationTotals(int resourceIndex, int delta,
                                                                     int multiplier) {
  if (delta < 0 && resourceIndex > 6 && resourceIndex < 0x0D) {
    this->needCurrentByType[resourceIndex] =
        static_cast<short>(this->needCurrentByType[resourceIndex] + delta);
  }

  TGreatPower::ApplyIndexedResourceDeltaAndAdjustNationTotals(resourceIndex, delta, multiplier);
}

// FUNCTION: IMPERIALISM 0x004e7680
void TAutoGreatPower::SetTradeOffersFor(short resourceKind, short offerContext) {
  if (g_apNationStates[static_cast<short>(offerContext)]->diplomacyEligibilityA0 != 0) {
    if (static_cast<short>(resourceKind) != 5) {
      short relationScore = g_pDiplomacyTurnStateManager
                                ->relationStandingScoreMatrix79c[this->nationSlot * 0x17 +
                                                                 static_cast<short>(offerContext)];
      double scaledScore = static_cast<double>(relationScore) * g_DAT_00653fc0_Value_00653FC0;
      int roll = rand();
      if (static_cast<double>(roll) > scaledScore * g_DAT_00653fc8_Value_00653FC8) {
        this->RaiseNeedPlanningMetrics(resourceKind);
      }
      return;
    }
  } else if (static_cast<short>(resourceKind) != 5) {
    short metricCap = 10;
    if (this->GetDiplomacyExternalStateByTarget(static_cast<short>(resourceKind)) < 10) {
      metricCap = this->GetDiplomacyExternalStateByTarget(static_cast<short>(resourceKind));
    }
    if (this->tradeCapacity < metricCap) {
      metricCap = this->tradeCapacity;
    }
    if (this->QueryNationMetricBySlot7C(static_cast<short>(resourceKind)) == -1) {
      return;
    }
    this->SetDiplomacyState1c6ClampedToCounterA4(static_cast<short>(resourceKind), metricCap);
    return;
  }
  if (this->GetDiplomacyExternalStateByTarget(5) != 0 && this->QueryNationMetricBySlot7C(5) != -1) {
    short metric = this->GetDiplomacyExternalStateByTarget(5);
    int assignAmount = (metric != 1) + 1;
    if (this->tradeCapacity < static_cast<short>(assignAmount)) {
      assignAmount = this->tradeCapacity;
    }
    this->SetDiplomacyState1c6ClampedToCounterA4(5, static_cast<short>(assignAmount));
  }
}

// FUNCTION: IMPERIALISM 0x004e7810
void TAutoGreatPower::ResetDiplomacyNeedScoresAndClearAidAllocationMatrix(void) {
  int total = 0;
  for (int resourceType = 0; static_cast<short>(resourceType) < 0x0E; ++resourceType) {
    short resourceWeight = GetResourceDescriptorWeightWord0ByType(static_cast<short>(resourceType));
    short orderCount = this->city->orderCountByType5c[resourceType];
    total += static_cast<short>(resourceWeight * orderCount);
  }

  this->tradeCapacity = static_cast<short>(total);
  this->diplomacyCounterA2 = static_cast<short>(total);
  this->diplomacyCounterB0 = 0;
  this->budgetPoolDelta = 0;
  this->budgetPoolBase = 0;

  for (int nationIndex = 0; nationIndex < kNationSlotCount; ++nationIndex) {
    this->diplomacyState1c6[nationIndex] = 0;
    for (int rowIndex = 0; rowIndex < kAidAllocationRowCount; ++rowIndex) {
      this->aidAllocationMatrix[rowIndex * kAidAllocationColumnCount + nationIndex] = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x004e78d0
void TAutoGreatPower::RunSlot4CThenSortTrackedOrders(void) {
  static_cast<TCityInteriorMinister*>(this->interiorMinister)->ProcessUnitOrders();
}

// FUNCTION: IMPERIALISM 0x004e78f0
void TAutoGreatPower::ResetField900FromNeedCapA6(void) {
  this->defenseMinister->Call4C();
}

// FUNCTION: IMPERIALISM 0x004e7910
void TAutoGreatPower::DispatchGreatPowerQuarterlyStatusMessageLevel2(CString* message) {
  (void)message;
}

// FUNCTION: IMPERIALISM 0x004e7930
void TAutoGreatPower::DispatchGreatPowerQuarterlyStatusMessageLevel1(CString* message) {
  (void)message;
}

// FUNCTION: IMPERIALISM 0x004e7950
void TAutoGreatPower::DispatchGreatPowerQuarterlyStatusMessageLevel0(CString* message) {
  (void)message;
}

// FUNCTION: IMPERIALISM 0x004e7970
void TAutoGreatPower::SnapshotDiplomacyState1c6Into250(void) {}

// FUNCTION: IMPERIALISM 0x004e7990
void TAutoGreatPower::ResetDiplomacyNeedSlots7012AndRefreshIfModeGateMatches(void) {
  this->foreignMinister->SetTradeBids();
  this->foreignMinister->DoUsualSubsidyRule();
}

// FUNCTION: IMPERIALISM 0x004e79d0
char TAutoGreatPower::TryDispatchNationActionViaUiContextOrFallback(int targetNation, int arg2,
                                                                    int arg3, int slotIndex) {
  if (this->IsDiplomacyState1C6UnsetAndCounterPositiveForTarget(static_cast<short>(slotIndex)) !=
      0) {
    this->foreignMinister->ReplyToTradeOffer(static_cast<short>(targetNation),
                                             static_cast<short>(arg2), static_cast<short>(arg3),
                                             static_cast<short>(slotIndex));
    return 0;
  }
  this->AppendTrackedSlotEntry(kTrackedSlotOfferEntry, targetNation, 0,
                               static_cast<short>(slotIndex), 0);
  return 0;
}

// FUNCTION: IMPERIALISM 0x004e7a50
void TAutoGreatPower::ClearDiplomacyState1c6Block(void) {
  if (this->city != 0) {
    this->foreignMinister->EndTradePhase();
    short* pendingMetric = this->actionMetricByQuarter;
    for (short needSlot = 7; needSlot < 0x0d; ++needSlot) {
      short pending = *pendingMetric;
      if (pending > 0) {
        short current = this->GetDiplomacyExternalStateByTarget(needSlot);
        short remaining;
        if (current < pending) {
          remaining = 0;
        } else {
          remaining = static_cast<short>(current - pending);
        }
        this->SetCityStockCounterAndRefresh(needSlot, remaining);
      }
      *pendingMetric = 0;
      ++pendingMetric;
    }
    TGreatPower::ClearDiplomacyState1c6Block();
  }
}

// FUNCTION: IMPERIALISM 0x004e7af0
void TAutoGreatPower::BeginTurnDiplomacyPrePassSlot1c8() {
  if (this->city != 0) {
    this->foreignMinister->SetDiplomacyPolicies();
  }
}

// FUNCTION: IMPERIALISM 0x004e7b20
bool TAutoGreatPower::ApplyDiplomacyPolicyStateForTargetWithCostChecks(short targetClass,
                                                                       short policyCode) {
  return TGreatPower::ApplyDiplomacyPolicyStateForTargetWithCostChecks(targetClass, policyCode);
}

// FUNCTION: IMPERIALISM 0x004e7b50
void TAutoGreatPower::QueueDiplomacyProposalCodeForTargetNation(
    DiplomacyProposalCodeStorage proposalCode, NationSlot targetNationSlot) {
  switch (proposalCode) {
  case kDiplomacyProposalJoinEmpire:
  case kDiplomacyProposalNonAggressionPact:
    return;
  case kDiplomacyProposalAlliance:
  case kDiplomacyProposalJoinEmpireWithWarEntanglements: {
    if (g_pDiplomacyTurnStateManager != 0) {
      bool hasAllianceGuard = g_pDiplomacyTurnStateManager->HasAllianceGuardForNationPair(
          targetNationSlot, this->nationSlot);
      if (hasAllianceGuard == 0) {
        TGreatPower::QueueDiplomacyProposalCodeForTargetNation(proposalCode, targetNationSlot);
      }
    }
    return;
  }
  default:
    TGreatPower::QueueDiplomacyProposalCodeForTargetNation(proposalCode, targetNationSlot);
    return;
  }
}

// FUNCTION: IMPERIALISM 0x004e7be0
void TAutoGreatPower::ReplyToDiplomacyOffers(void) {
  if (this->city == 0) {
    return;
  }

  int rowIndex = 1;
  if (this->proposalQueue->GetSize() >= rowIndex) {
    do {
      this->foreignMinister->ReplyToDiplomacyOffers(static_cast<short>(rowIndex));
      ++rowIndex;
    } while (rowIndex <= this->proposalQueue->GetSize());
  }

  this->ResetDiplomacyPolicyAndGrantEntriesPreserveRecurringGrants();
}

// FUNCTION: IMPERIALISM 0x004e7c50
void TAutoGreatPower::NotifyActionSlot94(int sourceNation, int actionCode) {
  if (actionCode == kDiplomacyProposalDeclareWar) {
    this->SetCandidateNationFlagAndPortZoneState(static_cast<short>(sourceNation));
  }
  TGreatPower::NotifyActionSlot94(sourceNation, actionCode);
}

// FUNCTION: IMPERIALISM 0x004e7ca0
void TAutoGreatPower::DispatchTurnEvent2103WithNationFromRecord() {}

// FUNCTION: IMPERIALISM 0x004e7cc0
int TAutoGreatPower::HandleWarTransitionRequest(int targetNation, int sourceNation) {
  bool allBeatable = true;
  bool beatableByNation[7] = {false, false, false, false, false, false, false};
  int nation = 0;
  while (allBeatable) {
    if (nation >= 7) {
      break;
    }
    if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(nation) != 0 &&
        nation != this->nationSlot) {
      if (g_pDiplomacyTurnStateManager->IsNationPairAtWar(this->nationSlot, nation) == 0 &&
          g_pDiplomacyTurnStateManager->IsNationPairAtWar(targetNation, nation) != 0) {
        char borderLinked =
            g_pGlobalMapState->AreNationsBorderLinked(targetNation, this->nationSlot);
        float combinedScore;
        if (borderLinked != 0) {
          combinedScore =
              this->ComputeArmyScoreRatioVsNationWithSecondary(sourceNation, targetNation);
          combinedScore =
              this->ComputeArmyScoreStandingRatioVsNationPair(sourceNation, targetNation) +
              combinedScore;
        } else {
          combinedScore =
              this->ComputeNavyScoreRatioVsNationWithSecondary(sourceNation, targetNation);
          combinedScore =
              this->ComputeNavyScoreStandingRatioVsNationPair(sourceNation, targetNation) +
              combinedScore;
        }
        if (this->ComputeMinisterSkillFloatSlot88() > combinedScore) {
          allBeatable = false;
        } else {
          beatableByNation[nation] = true;
        }
      }
    }
    ++nation;
  }
  if (allBeatable) {
    for (int helperNation = 0; helperNation < 7; ++helperNation) {
      if (beatableByNation[helperNation]) {
        this->QueueWarTransitionAndNotifyThirdPartyIfNeeded(helperNation, 1, targetNation);
      }
    }
    TMinor* minor = g_apSecondaryNationStateSlots[targetNation];
    short ownerSlot = minor->encodedNationSlot;
    if (ownerSlot >= 200) {
      ownerSlot = static_cast<short>(ownerSlot + -200);
    } else if (ownerSlot >= 100) {
      ownerSlot = static_cast<short>(ownerSlot + -100);
    } else {
      ownerSlot = minor->nationSlot;
    }
    if (ownerSlot != this->nationSlot) {
      minor->ApplyJoinEmpireModeForTargetNation(this->nationSlot, 1);
    }
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x004e7ec0
int TAutoGreatPower::HandleWarTransitionRequestWithRoleSwap(int targetNation, int sourceNation,
                                                            char swapRoles) {
  char hasPolicy = 0;
  if (swapRoles == 0) {
    if (g_pDiplomacyTurnStateManager->IsNationPairAtWar(this->nationSlot, sourceNation) != 0) {
      hasPolicy = 1;
    }
  } else {
    if (g_pDiplomacyTurnStateManager->IsNationPairAtWar(this->nationSlot, targetNation) != 0) {
      hasPolicy = 1;
    }
  }
  if (hasPolicy == 0) {
    char borderLinked = g_pGlobalMapState->AreNationsBorderLinked(sourceNation, this->nationSlot);
    float ratioScore;
    float standingScore;
    if (borderLinked != 0) {
      ratioScore = this->ComputeArmyScoreRatioForNationPair(sourceNation, targetNation, swapRoles);
      standingScore =
          this->ComputeArmyScoreStandingRatioForNationPair(sourceNation, targetNation, swapRoles);
    } else {
      ratioScore = this->ComputeNavyScoreRatioForNationPair(sourceNation, targetNation, swapRoles);
      standingScore =
          this->ComputeNavyScoreStandingRatioForNationPair(sourceNation, targetNation, swapRoles);
    }
    float combinedScore = standingScore + ratioScore;
    if (this->ComputeMinisterSkillFloatSlot88() <= combinedScore) {
      if (swapRoles == 0) {
        this->QueueWarTransitionAndNotifyThirdPartyIfNeeded(sourceNation, 2, targetNation);
        return 1;
      }
      this->QueueWarTransitionAndNotifyThirdPartyIfNeeded(targetNation, 2, sourceNation);
      return 1;
    }
    if (swapRoles == 0) {
      g_pDiplomacyTurnStateManager->ApplyPeaceRelationshipAndQueueEvent18ForTargetNation(
          this->nationSlot, targetNation, 1);
    } else {
      g_pDiplomacyTurnStateManager->ApplyPeaceRelationshipAndQueueEvent18ForTargetNation(
          this->nationSlot, sourceNation, 0);
    }
  }
  return 1;
}

// Port-zone refit fields live on TZone (+0x28..+0x30).

// FUNCTION: IMPERIALISM 0x004e8040
char TAutoGreatPower::PassesDiplomacyStrengthThresholdForTarget(int targetNation) {
  if (g_pDiplomacyTurnStateManager->HasAllianceGuardForNationPair(targetNation, this->nationSlot) !=
      0) {
    return 0;
  }
  float allyNavyAccum = 0.0f;
  float allyArmyAccum = 0.0f;
  float armyScore = this->GetScoreFactorSlot23C();
  float navyScore = this->GetScoreFactorSlot240();
  int allyIndex = 0;
  if (g_pDiplomacyTurnStateManager->CountMajorAllianceRelationsSlot8c(this->nationSlot) > 0) {
    do {
      int allyNation =
          g_pDiplomacyTurnStateManager->GetNthAlliedMajorNationSlot90(allyIndex, this->nationSlot);
      allyArmyAccum = g_apNationStates[allyNation]->GetScoreFactorSlot23C() + allyArmyAccum;
      allyNavyAccum = g_apNationStates[allyNation]->GetScoreFactorSlot240() + allyNavyAccum;
      ++allyIndex;
    } while (allyIndex <
             g_pDiplomacyTurnStateManager->CountMajorAllianceRelationsSlot8c(this->nationSlot));
  }
  int ownNavyInt = static_cast<int>(navyScore);
  int ownStrength = static_cast<int>(armyScore);
  if (ownStrength <= ownNavyInt) {
    ownStrength = ownNavyInt;
  }
  float ownStrengthScore = static_cast<float>(ownStrength);
  int allyNavyInt = static_cast<int>(allyNavyAccum);
  int allyStrength = static_cast<int>(allyArmyAccum);
  if (allyStrength <= allyNavyInt) {
    allyStrength = allyNavyInt;
  }
  float allyQuarterScore = static_cast<float>(allyStrength / 4);
  float strongestPeer = 0.0f;
  int peerSlot = 0;
  TGreatPower** peerCursor = g_apNationStates;
  do {
    if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(peerSlot) != 0) {
      float peerArmy = (*peerCursor)->GetScoreFactorSlot23C();
      if (strongestPeer < peerArmy) {
        strongestPeer = peerArmy;
      }
      float peerNavy = (*peerCursor)->GetScoreFactorSlot240();
      if (strongestPeer < peerNavy) {
        strongestPeer = peerNavy;
      }
    }
    ++peerCursor;
    ++peerSlot;
  } while (peerCursor < g_apNationStates + 7);
  int tickQuarter = static_cast<short>(g_pSimMgr->economicTurn / 4);
  if (tickQuarter >= 0x3c) {
    tickQuarter = 0x3c;
  }
  short relationScore = g_pDiplomacyTurnStateManager
                            ->relationStandingScoreMatrix79c[this->nationSlot * 0x17 +
                                                             static_cast<short>(targetNation)];
  float combinedStrength = ownStrengthScore + allyQuarterScore;
  float combinedScore =
      static_cast<float>((strongestPeer / combinedStrength +
                          (static_cast<float>(relationScore) + ownStrengthScore) /
                              ((static_cast<float>(tickQuarter) + combinedStrength) -
                               g_Compute_Advisory_Map_Value_00653FD4)) *
                         g_Evaluate_Advisory_Case11_Value_00653FD8);
  if (this->ComputeMinisterSkillFloatSlot8A() <= combinedScore) {
    return 1;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004e83d0
void TAutoGreatPower::QueueMapActionMissionsForPortZoneCandidates() {
  TLongintList* regionList = this->ownedRegionList;
  int regionCount = regionList->GetSize();

  for (int i = 1; i <= regionCount; i++) {
    int regionId = regionList->At(i);
    bool unavailable = g_pGlobalMapState->IsNodeTypeLinkUnavailableAndNoActiveMapActionContext(
        regionId, this->nationSlot);
    this->mapNodeStateFlags[regionId] = (unavailable == false);
    CreateMission(kMissionTypeDefendProvince, regionId, 0, -1);
  }

  TZone* portZone = g_pActiveMapOrderContext->FindFirstPortZoneContextByNation(this->nationSlot);

  TZone* firstEntry = portZone->primaryNeighbors[0];

  short index = firstEntry->GetContextOrdinalOrInvalid();
  this->portZoneStateFlags[index] = 1;
  CreateMission(kMissionTypeDefendProvince, -1, firstEntry, -1);

  index = portZone->GetContextOrdinalOrInvalid();
  this->portZoneStateFlags[index] = 1;
  CreateMission(kMissionTypeDefendProvince, -1, portZone, -1);

  CreateMission(kMissionTypeScatteredShips, -1, 0, -1);
}

// FUNCTION: IMPERIALISM 0x004e8540
void TAutoGreatPower::CreateMission(eMissionType missionType, int mapNodeIndex, TZone* zoneContext,
                                    int relatedMapNodeIndex) {
  const unsigned char kNodeStateAvailable = 1;
  const unsigned char kNodeStateQueued = 2;

  if (mapNodeIndex != -1 && this->mapNodeStateFlags[mapNodeIndex] != kNodeStateAvailable) {
    return;
  }

  if ((zoneContext != 0) && (relatedMapNodeIndex == -1)) {
    short index = zoneContext->GetContextOrdinalOrInvalid();
    if (this->portZoneStateFlags[index] != kNodeStateAvailable) {
      return;
    }
  }

  eMissionType missionKind = missionType;
  if ((zoneContext != 0) && (mapNodeIndex == -1) && (relatedMapNodeIndex == -1) &&
      (missionType != kMissionTypeBlockadePort)) {
    missionKind = kMissionTypeDefendProvince;
  }

  TMission* missionObj = TMission::CreateMission(this->nationSlot, missionKind, mapNodeIndex,
                                                 zoneContext, relatedMapNodeIndex);
  if (missionObj == 0) {
    GAME_FAIL_NIL_POINTER();
    TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Cross\\UCountryAuto.cpp", 0x5ed);
  }

  TSortedList* missionQueue = this->missionQueue;
  missionQueue->AddTail(missionObj);

  if (mapNodeIndex != -1) {
    this->mapNodeStateFlags[mapNodeIndex] = kNodeStateQueued;
  }
  if ((zoneContext != 0) && (relatedMapNodeIndex == -1)) {
    short index = zoneContext->GetContextOrdinalOrInvalid();
    this->portZoneStateFlags[index] = kNodeStateQueued;
  }
  if (relatedMapNodeIndex != -1) {
    this->mapNodeStateFlags[relatedMapNodeIndex] = kNodeStateQueued;
  }
}

// FUNCTION: IMPERIALISM 0x004e8680
void TAutoGreatPower::RemoveMission(eMissionType missionType, int key, TZone* zoneContext) {
  CIterator iter(missionQueue);
  for (TMission* mission = static_cast<TMission*>(iter.Reset()); iter.More();
       mission = static_cast<TMission*>(iter.Advance())) {
    if (mission->Matches(missionType, key, zoneContext)) {
      CPtrList* list = &missionQueue->listState;
      POSITION position = list->Find(mission, 0);
      if (position != 0) {
        list->RemoveAt(position);
      }
      mission->Free();
      return;
    }
  }
}
// province's map-action-context link is unavailable for this nation, in which case it's
// forced to 0 -- the same gate/array QueueMapActionMissionsForPortZoneCandidates above
// already uses directly.
// FUNCTION: IMPERIALISM 0x004e8b50
void TAutoGreatPower::SetMapStateByteFlag970WithRuntimeGate(int provinceIndex, int value) {
  if (value == 1 && g_pGlobalMapState->IsNodeTypeLinkUnavailableAndNoActiveMapActionContext(
                        provinceIndex, nationSlot)) {
    value = 0;
  }
  mapNodeStateFlags[provinceIndex] = static_cast<unsigned char>(value);
}

// FUNCTION: IMPERIALISM 0x004e8bf0
void TAutoGreatPower::SetByteFlagAtOffsetAF0ByIndex(int contextOrdinal, char value) {
  portZoneStateFlags[contextOrdinal] = static_cast<unsigned char>(value);
}

// FUNCTION: IMPERIALISM 0x004e92b0
void TAutoGreatPower::PopulateCase16AdvisoryMapNodeCandidateState() {
  int orderTypes[4];
  orderTypes[0] = 2;
  orderTypes[1] = 3;
  orderTypes[2] = 4;
  orderTypes[3] = 6;

  // Reset the transient (value 1) candidate flags; sticky values survive.
  int i;
  for (i = 0; i < 0x180; ++i) {
    if (mapNodeStateFlags[i] == 1) {
      mapNodeStateFlags[i] = 0;
    }
  }

  // Mark candidate regions from every flagged great power's owned regions, plus (for
  // eligible slots) the minors whose capability rows decode to that slot.
  int slot;
  for (slot = 0; slot < 7; ++slot) {
    if (g_apNationStates[slot] != 0 && candidateNationFlags[slot] != 0) {
      int j;
      for (j = 1; j <= g_apNationStates[slot]->ownedRegionList->GetSize(); ++j) {
        int region = g_apNationStates[slot]->ownedRegionList->At(j);
        if (mapNodeStateFlags[region] == 0) {
          char markValue = 1;
          if (g_pGlobalMapState->IsNodeTypeLinkUnavailableAndNoActiveMapActionContext(
                  region, this->nationSlot) != 0) {
            markValue = 0;
          }
          mapNodeStateFlags[region] = markValue;
        }
      }
      if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(slot) != 0) {
        int minorIndex;
        for (minorIndex = 0; minorIndex < 9; ++minorIndex) {
          if (g_apMinorNationCapabilityObjects[minorIndex]->IsEncodedNationSlotMinus200Equal(
                  slot) != 0) {
            int m;
            for (m = 1;
                 m <= g_apMinorNationCapabilityObjects[minorIndex]->ownedRegionList->GetSize();
                 ++m) {
              int minorRegion =
                  g_apMinorNationCapabilityObjects[minorIndex]->ownedRegionList->At(m);
              if (mapNodeStateFlags[minorRegion] == 0) {
                char markValue = 1;
                if (g_pGlobalMapState->IsNodeTypeLinkUnavailableAndNoActiveMapActionContext(
                        minorRegion, this->nationSlot) != 0) {
                  markValue = 0;
                }
                mapNodeStateFlags[minorRegion] = markValue;
              }
            }
          }
        }
      }
    }
  }

  // Same marking for every flagged minor's own regions.
  int minorSlot;
  for (minorSlot = 0; minorSlot < 16; ++minorSlot) {
    if (candidateNationFlags[7 + minorSlot] != 0) {
      int j;
      for (j = 1; j <= g_apSecondaryNationStateSlots[7 + minorSlot]->ownedRegionList->GetSize();
           ++j) {
        int region = g_apSecondaryNationStateSlots[7 + minorSlot]->ownedRegionList->At(j);
        if (mapNodeStateFlags[region] == 0) {
          char markValue = 1;
          if (g_pGlobalMapState->IsNodeTypeLinkUnavailableAndNoActiveMapActionContext(
                  region, this->nationSlot) != 0) {
            markValue = 0;
          }
          mapNodeStateFlags[region] = markValue;
        }
      }
    }
  }

  if (g_pDiplomacyTurnStateManager->HasAnyWarRelationForNation(this->nationSlot) != 0) {
    // At war: purge the interior minister's queues for each advisory order type.
    int t;
    for (t = 0; t < 4; ++t) {
      interiorMinister->InteriorSlot1F(orderTypes[t]);
    }
    return;
  }

  CString nationText;
  CString turnText;
  CString preludeText;
  FormatOverlayTerrainLabelText(&nationText);
  turnText.Format(g_szDecimalFormat, static_cast<short>(g_pSimMgr->economicTurn / 4));

  int t;
  for (t = 0; t < 4; ++t) {
    g_pSimMgr->GetStringPrelude(static_cast<short>(orderTypes[t]), &preludeText);
    if (interiorMinister->InteriorSlot1E(orderTypes[t]) >= 5) {
      TProvinceDesirabilityList* candidates = new TProvinceDesirabilityList();
      candidates->InitializeProvinceRecordSize();

      int rec;
      for (rec = 0; rec < 0x180; ++rec) {
        short owner = g_pGlobalMapState->cityScoreTable[rec].ownerNationCode00;
        if (owner == -1) {
          continue;
        }
        if (g_pDiplomacyTurnStateManager->GetNationPairDiplomacyRelationCode(
                this->nationSlot, owner) == kDiplomacyRelationshipAlliance) {
          continue;
        }
        if (g_apTerrainTypeDescriptorTable[owner]->encodedNationSlot >= 200) {
          if (g_pDiplomacyTurnStateManager->GetNationPairDiplomacyRelationCode(
                  this->nationSlot,
                  g_apTerrainTypeDescriptorTable[owner]->DecodeOwnerNationSlot()) ==
              kDiplomacyRelationshipAlliance) {
            continue;
          }
        }
        if (mapNodeStateFlags[rec] != 0) {
          continue;
        }
        if (((1 << orderTypes[t]) &
             g_pGlobalMapState->cityScoreTable[rec].resourcePresenceMaskA2) == 0) {
          continue;
        }

        short score = g_pDiplomacyTurnStateManager
                          ->relationStandingScoreMatrix79c[this->nationSlot * 0x17 + owner];
        int linkBonus;
        int nodeBuffer[12];
        if (g_pGlobalMapState->HasDirectOrFallbackLinkedNodeType(rec, this->nationSlot, 1) != 0) {
          linkBonus = 0;
        } else if (g_pGlobalMapState->CollectSecondDegreeLinksWithMinorNationFallback(
                       rec, this->nationSlot, nodeBuffer, 1) != 0) {
          linkBonus = 0x14;
        } else if (g_pActiveMapOrderContext->FindMapActionContextContainingNodeByIndex(rec) != 0) {
          linkBonus = 0x28;
        } else {
          continue;
        }
        score = static_cast<short>(score + linkBonus);

        struct ProvinceCandidateRecord {
          short regionIndex;
          short score;
        } candidate;
        candidate.regionIndex = static_cast<short>(rec);
        candidate.score = score;
        if (owner < 7 && g_pSimMgr->IsNationSlotEligibleForEventProcessing(owner) != 0) {
          candidate.score = static_cast<short>(candidate.score + 0x14);
        }
        candidates->InsertCopiedRecordSortedByComparator(&candidate);
      }

      // Flag the top one or two candidates.
      if (candidates->GetSize() != 0) {
        short* topRecord = static_cast<short*>(candidates->GetPtrListEntryByOneBasedIndex(1));
        int topRegion = topRecord[0];
        if (mapNodeStateFlags[topRegion] == 0) {
          char markValue = 1;
          if (g_pGlobalMapState->IsNodeTypeLinkUnavailableAndNoActiveMapActionContext(
                  topRegion, this->nationSlot) != 0) {
            markValue = 0;
          }
          mapNodeStateFlags[topRegion] = markValue;
        }
        if (candidates->GetSize() >= 2) {
          short* secondRecord = static_cast<short*>(candidates->GetPtrListEntryByOneBasedIndex(2));
          int secondRegion = secondRecord[0];
          if (mapNodeStateFlags[secondRegion] == 0) {
            char markValue = 1;
            if (g_pGlobalMapState->IsNodeTypeLinkUnavailableAndNoActiveMapActionContext(
                    secondRegion, this->nationSlot) != 0) {
              markValue = 0;
            }
            mapNodeStateFlags[secondRegion] = markValue;
          }
        }
      }
      if (candidates != 0) {
        candidates->ReleasePtrList();
      }
    }
  }
}

// Sets mapNodeStateFlags[provinceIndex] to `value`, except when value == 1 and the

// FUNCTION: IMPERIALISM 0x004e9a50
void TAutoGreatPower::SelectAndQueueAdvisoryMapMissionsCase16(void) {
  // Declaration order fixes the frame slot layout (0x12..0x34); the split
  // assignment blocks mirror the original's two init waves around the city gate.
  char hasActiveMission;
  char queueSecondaryDefend;
  float bestScore;
  int bestRegion;
  float bestDirectScore;
  int bestTier;
  int directRegion;
  float secondBestDirectScore;
  TZone* bestPortZone;
  int bestLinkRegion;
  int secondBestDirectRegion;

  bestTier = -1;
  bestPortZone = 0;
  bestLinkRegion = -1;
  hasActiveMission = 0;
  bestDirectScore = 0.0f;
  directRegion = -1;
  queueSecondaryDefend = 0;
  if (this->city == 0) {
    return;
  }
  bestScore = 0.0f;
  bestRegion = -1;
  secondBestDirectScore = 0.0f;
  secondBestDirectRegion = -1;

  PopulateCase16AdvisoryMapNodeCandidateState();

  int region;
  for (region = 0; region < 0x180; ++region) {
    unsigned char nodeFlag = mapNodeStateFlags[region];
    int linkRegion = -1;
    if (nodeFlag != 1) {
      continue;
    }
    float score;
    // Garbage on the no-link path exactly like the original: a zero score can never
    // beat bestScore, so the tier value is never consumed there.
    int tier;
    int nodeBuffer[12];
    if (g_pGlobalMapState->HasDirectOrFallbackLinkedNodeType(region, nationSlot, 1) != 0) {
      score = ComputeAdvisoryMapNodeCompositeScoreByMode(region, 0, -1);
      bestDirectScore = score;
      tier = 0;
      directRegion = region;
    } else if (g_pGlobalMapState->CollectSecondDegreeLinksWithMinorNationFallback(
                   region, nationSlot, nodeBuffer, 1) != 0) {
      linkRegion = nodeBuffer[0];
      score = ComputeAdvisoryMapNodeCompositeScoreByMode(region, 1, linkRegion);
      tier = 1;
    } else if (g_pActiveMapOrderContext->FindMapActionContextContainingNodeByIndex(region) != 0) {
      score = ComputeAdvisoryMapNodeCompositeScoreByMode(region, 2, -1);
      tier = 2;
    } else {
      score = g_Compute_Advisory_Zero_00653FD0;
      mapNodeStateFlags[region] = 0;
    }
    if (score > bestScore) {
      bestScore = score;
      bestRegion = region;
      bestLinkRegion = linkRegion;
      bestTier = tier;
    }
    if (bestDirectScore > secondBestDirectScore && directRegion != -1) {
      secondBestDirectRegion = directRegion;
      secondBestDirectScore = bestDirectScore;
    }
  }

  // Port-zone contexts flagged available (state 1) compete with the region winner.
  TZone* zone;
  for (zone = g_pMapActionContextListHead; zone != 0; zone = zone->prev18) {
    if (portZoneStateFlags[zone->GetContextOrdinalOrInvalid()] == 1) {
      float zoneScore = ComputeMapActionContextCompositeScoreForNation(zone);
      if (zoneScore > bestScore) {
        bestPortZone = zone;
        zone->GetContextOrdinalOrInvalid(); // dead call kept from the original
        bestScore = zoneScore;
        bestTier = zone->QueryPortZoneCapability() ? 4 : 2;
      }
    }
  }

  int tier = bestTier;
  if (tier != -1) {
    char acceptMission = 0;
    if (g_afAdvisoryMissionTierThresholdByMinisterSkill_00653F18[defenseMinister->skillIndexC]
                                                                [tier] < bestScore) {
      acceptMission = 1;
    } else if (g_pDiplomacyTurnStateManager->HasAnyWarRelationForNation(nationSlot) != 0) {
      CIterator missionIter(missionQueue);
      for (TMission* mission = static_cast<TMission*>(missionIter.Reset()); missionIter.More();
           mission = static_cast<TMission*>(missionIter.Advance())) {
        if ((mission->marker11 & 1) != 0) {
          hasActiveMission = 1;
          break;
        }
      }
      if (hasActiveMission == 0) {
        queueSecondaryDefend = 1;
      }
    }
    if (acceptMission != 0) {
      if (bestPortZone == 0) {
        if (tier == 2) {
          TZone* contextZone =
              g_pActiveMapOrderContext->FindMapActionContextContainingNodeByIndex(bestRegion);
          if (contextZone != 0) {
            CreateMission(static_cast<eMissionType>(tier), -1, contextZone, bestRegion);
          } else {
            mapNodeStateFlags[bestRegion] = 0;
          }
        } else if (bestLinkRegion != -1) {
          CreateMission(static_cast<eMissionType>(tier), bestLinkRegion, 0, bestRegion);
        } else {
          CreateMission(static_cast<eMissionType>(tier), bestRegion, 0, -1);
        }
      } else {
        CreateMission(static_cast<eMissionType>(tier), -1, bestPortZone, -1);
      }
    }
    if (queueSecondaryDefend != 0 && secondBestDirectRegion != -1) {
      CreateMission(kMissionTypeAttackProvince, secondBestDirectRegion, 0, -1);
    }
  }

  // War fallback: when any eligible major is at war with us, queue defend missions on
  // non-queued contexts whose secondary neighbors include this nation.
  char anyEligibleAtWar = 0;
  int n;
  for (n = 0; n < 7 && anyEligibleAtWar == 0; ++n) {
    if (g_pDiplomacyTurnStateManager->IsNationPairAtWar(static_cast<short>(n), nationSlot) != 0 &&
        g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(n)) != 0) {
      anyEligibleAtWar = 1;
    }
  }
  if (anyEligibleAtWar != 0) {
    for (zone = g_pMapActionContextListHead; zone != 0; zone = zone->prev18) {
      short contextOrdinal = zone->GetContextOrdinalOrInvalid();
      if (portZoneStateFlags[contextOrdinal] != 2 &&
          zone->HasSecondaryNeighborWithNationTag(nationSlot) != 0) {
        for (n = 0; n < 7; ++n) {
          if (n != nationSlot &&
              g_pDiplomacyTurnStateManager->IsNationPairAtWar(nationSlot, static_cast<short>(n)) !=
                  0 &&
              (zone->nationKeyMask10 & static_cast<unsigned char>(1 << n)) != 0) {
            portZoneStateFlags[contextOrdinal] = 1;
            CreateMission(kMissionTypeDefendProvince, -1, zone, -1);
          }
        }
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x004e9ed0
void TAutoGreatPower::QueueWarTransitionAndNotifyThirdPartyIfNeeded(int targetNationSlot,
                                                                    int transitionMode,
                                                                    int sourceNationSlot) {
  this->SetCandidateNationFlagAndPortZoneState(targetNationSlot);
  TGreatPower::QueueWarTransitionAndNotifyThirdPartyIfNeeded(targetNationSlot, transitionMode,
                                                             sourceNationSlot);
}

// FUNCTION: IMPERIALISM 0x004e9f10
char TAutoGreatPower::HasActiveCandidateNationSlots(void) {
  char anyActive = 0;
  int candidate = 0;
  TGreatPower** nationCursor = g_apNationStates;
  do {
    if (*nationCursor == 0) {
      this->candidateNationFlags[candidate] = 0;
    } else if (this->candidateNationFlags[candidate] != 0) {
      anyActive = 1;
    }
    ++nationCursor;
    ++candidate;
  } while (nationCursor < g_apNationStates + 7);
  candidate = 7;
  TMinor** minorCursor = g_apNationAuxRuntimeStateSlots;
  do {
    if (this->candidateNationFlags[candidate] != 0) {
      if ((*minorCursor)->ownedRegionList->GetSize() == 0) {
        this->candidateNationFlags[candidate] = 0;
        if (g_pDiplomacyTurnStateManager->IsNationPairAtWar(this->nationSlot, candidate) != 0) {
          g_pDiplomacyTurnStateManager->SetNationPairDiplomacyRelationCodeFinal(
              this->nationSlot, candidate, kDiplomacyRelationshipPeace);
        }
      } else {
        anyActive = 1;
      }
    }
    ++minorCursor;
    ++candidate;
  } while (minorCursor < g_apNationAuxRuntimeStateSlots + 16);
  return anyActive;
}

// FUNCTION: IMPERIALISM 0x004e9ff0
void TAutoGreatPower::SetCandidateNationFlagAndPortZoneState(int targetNation) {
  if (this->HasActiveCandidateNationSlots() != 0) {
    int nation = 0;
    TCountry** descriptorCursor = g_apTerrainTypeDescriptorTable;
    do {
      if (*descriptorCursor != 0 && nation != static_cast<short>(this->nationSlot)) {
        if (g_pDiplomacyTurnStateManager->IsNationPairAtWar(
                nation, static_cast<short>(this->nationSlot)) == 0) {
          this->NotifyAllianceSlot214(nation);
        }
      }
      ++descriptorCursor;
      ++nation;
    } while (descriptorCursor < g_apTerrainTypeDescriptorTable + 0x17);
  }
  this->candidateNationFlags[targetNation] = 1;
  if (g_apTerrainTypeDescriptorTable[targetNation] != 0) {
    if (g_apTerrainTypeDescriptorTable[targetNation]->ownedRegionList->GetSize() > 0) {
      short ownerTag;
      if (g_apTerrainTypeDescriptorTable[targetNation] == 0 ||
          (ownerTag = g_apTerrainTypeDescriptorTable[targetNation]->encodedNationSlot,
           ownerTag < 100) ||
          199 < ownerTag) {
        g_pActiveMapOrderContext->FindFirstPortZoneContextByNation(
            static_cast<short>(targetNation));
        short portZoneId = g_pMapActionContextListHead->GetContextOrdinalOrInvalid();
        this->portZoneStateFlags[portZoneId] = 1;
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x004ea0e0
void TAutoGreatPower::NotifyAllianceSlot214(int targetNation) {
  this->candidateNationFlags[targetNation] = 0;
  if (g_apTerrainTypeDescriptorTable[targetNation] != 0) {
    if (g_apTerrainTypeDescriptorTable[targetNation]->ownedRegionList->GetSize() > 0) {
      g_pActiveMapOrderContext->FindFirstPortZoneContextByNation(static_cast<short>(targetNation));
      short portZoneId = g_pMapActionContextListHead->GetContextOrdinalOrInvalid();
      this->portZoneStateFlags[portZoneId] = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x004ea150
void TAutoGreatPower::SetNationTransferTargetCodeAndNotifyEligiblePeers(int targetNationSlot) {
  TGreatPower::SetNationTransferTargetCodeAndNotifyEligiblePeers(targetNationSlot);

  int i = 0;
  for (i = 0; i < 6; ++i) {
    this->actionMetricByQuarter[i] = 0;
  }
  for (i = 0; i < kMapNodeCount; ++i) {
    this->mapNodeStateFlags[i] = 0;
  }
  for (i = 0; i < kPortZoneCount; ++i) {
    this->portZoneStateFlags[i] = 0;
  }
}

// FUNCTION: IMPERIALISM 0x004ea1c0
void TAutoGreatPower::RemoveRegionIdFromNationOwnedRegionList(int regionId) {
  CIterator missionCursor(this->missionQueue);
  TMission* mission = static_cast<TMission*>(missionCursor.Reset());
  while (missionCursor.More() != 0) {
    if (mission->Matches(kMissionTypeDefendProvince, regionId, nullptr)) {
      CPtrList* listState = &this->missionQueue->listState;
      POSITION pos = listState->Find(mission, 0);
      if (pos != 0) {
        listState->RemoveAt(pos);
      }
      mission->Free();
      break;
    }
    mission = static_cast<TMission*>(missionCursor.Advance());
  }
  this->mapNodeStateFlags[regionId] = 0;
  TGreatPower::RemoveRegionIdFromNationOwnedRegionList(regionId);
}

// FUNCTION: IMPERIALISM 0x004ea290
void TAutoGreatPower::AddRegionIdToNationOwnedRegionList(int regionId) {
  TGreatPower::AddRegionIdToNationOwnedRegionList(regionId);

  if (regionId >= 0 && regionId < kMapNodeCount) {
    this->mapNodeStateFlags[regionId] = 1;
    this->CreateMission(kMissionTypeDefendProvince, regionId, 0, -1);
  }
}

// FUNCTION: IMPERIALISM 0x004ea300
void TAutoGreatPower::ResetNationDiplomacySlotsAndMarkRelatedNations(int targetNation) {
  TGreatPower::ResetNationDiplomacySlotsAndMarkRelatedNations(targetNation);
  int ordinal = 1;
  TLongintList* regionList = g_apTerrainTypeDescriptorTable[targetNation]->ownedRegionList;
  if (regionList->GetSize() > 0) {
    do {
      int regionId = regionList->At(ordinal);
      this->mapNodeStateFlags[regionId] = 1;
      this->CreateMission(kMissionTypeDefendProvince, regionId, 0, -1);
      ++ordinal;
    } while (ordinal <= regionList->GetSize());
  }
  TZone* portZone =
      g_pActiveMapOrderContext->FindFirstPortZoneContextByNation(static_cast<short>(targetNation));
  TZone* firstOrder = portZone->primaryNeighbors[0];
  short portZoneId = g_pMapActionContextListHead->GetContextOrdinalOrInvalid();
  this->portZoneStateFlags[portZoneId] = 1;
  this->CreateMission(kMissionTypeDefendProvince, -1, firstOrder, -1);
}

// FUNCTION: IMPERIALISM 0x004ea430
void TAutoGreatPower::DispatchTurnOrderActionSlotB0(short orderKind, short payload, short flags) {
  (void)orderKind;
  (void)payload;
  (void)flags;
}

// FUNCTION: IMPERIALISM 0x004ea450
void TAutoGreatPower::BuildGreatPowerTurnMessageSummaryAndDispatch(void) {}

// FUNCTION: IMPERIALISM 0x004ea470
void TAutoGreatPower::RebuildNationResourceYieldCountersAndDevelopmentTargets(void) {
  TGreatPower::RebuildNationResourceYieldCountersAndDevelopmentTargets();
  short carryValue = this->needCurrentByType[0x13];
  this->needCurrentByType[0x13] = 0;
  this->needCurrentByType[0x14] = static_cast<short>(this->needCurrentByType[0x14] + carryValue);
}

// FUNCTION: IMPERIALISM 0x004ea610
float TAutoGreatPower::ComputeAiIndustryActionCostFromSlot(short industrySlot) {
  int cost = g_pNationInteractionStateManager->QueryProposalWeightSlot4C(0x0b) *
             g_industryActionCostWeightResCode0B[industrySlot];
  cost += g_pNationInteractionStateManager->QueryProposalWeightSlot4C(0x08) *
          g_industryActionCostWeightResCode08[industrySlot];
  cost += g_pNationInteractionStateManager->QueryProposalWeightSlot4C(0x09) *
          g_industryActionCostWeightResCode09[industrySlot];
  cost += g_pNationInteractionStateManager->QueryProposalWeightSlot4C(0x0c) *
          g_industryActionCostWeightResCode0C[industrySlot];
  cost += g_pNationInteractionStateManager->QueryProposalWeightSlot4C(0x10) *
          g_industryActionCostWeightResCode10[industrySlot];
  cost += g_pNationInteractionStateManager->QueryProposalWeightSlot4C(0x03) *
          g_industryActionCostWeightResCode03[industrySlot];
  return static_cast<float>(cost);
}

// FUNCTION: IMPERIALISM 0x004ea700
float TAutoGreatPower::ComputeAiCityActionCostFromSlotAndMode(short actionSlot,
                                                              char skipContextBias) {
  AiCityActionCostProfile& profile = g_aiCityActionCostProfiles[actionSlot];
  short capabilityLevel = needCurrentByType[5];
  float cost = static_cast<float>(profile.baseCost);

  if (profile.primaryMetricCode != -1 &&
      (profile.primaryMetricCode != 5 || capabilityLevel < profile.primaryMetricMultiplier)) {
    cost += static_cast<float>(
        g_pNationInteractionStateManager->QueryProposalWeightSlot4C(profile.primaryMetricCode) *
        profile.primaryMetricMultiplier);
  }
  if (profile.secondaryMetricCode != -1 &&
      (profile.secondaryMetricCode != 5 || capabilityLevel < profile.secondaryMetricMultiplier)) {
    cost += static_cast<float>(
        g_pNationInteractionStateManager->QueryProposalWeightSlot4C(profile.secondaryMetricCode) *
        profile.secondaryMetricMultiplier);
  }
  if (skipContextBias == 0) {
    cost += GetCachedAiCityActionContextBias(profile.contextBiasSelector);
  }
  return cost;
}

// FUNCTION: IMPERIALISM 0x004ea830
float TAutoGreatPower::GetCachedAiCityActionContextBias(short selector) {
  int cacheIndex;
  if (selector == 1) {
    cacheIndex = 0;
  } else if (selector == 2) {
    cacheIndex = 1;
  } else {
    cacheIndex = 2;
  }

  if (g_cachedAiCityActionTurnTick_006967d8 != g_pSimMgr->GetEconomicTurn()) {
    int base = g_pNationInteractionStateManager->QueryProposalWeightSlot4C(0x0d) +
               g_pNationInteractionStateManager->QueryProposalWeightSlot4C(0x0e) +
               g_pNationInteractionStateManager->QueryProposalWeightSlot4C(0x07);
    int middle = g_pNationInteractionStateManager->QueryProposalWeightSlot4C(0x0a) + 100;
    int tail = g_pNationInteractionStateManager->QueryProposalWeightSlot4C(0x0a) * 2 + 1000;
    g_cachedAiCityActionContextBias[0] = static_cast<float>(base);
    g_cachedAiCityActionContextBias[1] = static_cast<float>(base + middle);
    g_cachedAiCityActionContextBias[2] = static_cast<float>(base + middle + tail);
    g_cachedAiCityActionNationSlot_006967d4 = nationSlot;
    g_cachedAiCityActionTurnTick_006967d8 = g_pSimMgr->GetEconomicTurn();
  }

  return g_cachedAiCityActionContextBias[cacheIndex];
}

// FUNCTION: IMPERIALISM 0x004ea990
void TAutoGreatPower::KillMissions() {
  char removedMission;
  do {
    removedMission = 0;
    CIterator iter(missionQueue);
    TMission* mission = static_cast<TMission*>(iter.Reset());
    CPtrList* list;
    if (iter.More() != 0) {
      list = &missionQueue->listState;
      POSITION position = list->Find(mission, 0);
      if (position != 0) {
        list->RemoveAt(position);
      }
      mission->Free();
      removedMission = 1;
    }
  } while (removedMission != 0);
}

// FUNCTION: IMPERIALISM 0x004eaa20
void TAutoGreatPower::RecomputeAiExpansionAndMissionPressureScores(void) {
  int totalRegionCount = 0;
  int compatibleRegionCount = 0;
  int activeMissionCount = 0;

  int regionOrdinal;
  for (regionOrdinal = 1; regionOrdinal <= ownedRegionList->GetSize(); ++regionOrdinal) {
    int regionId = ownedRegionList->At(regionOrdinal);
    if (IsMapTileCompatibleWithCurrentTerrainOrActionContext(regionId) != 0) {
      ++compatibleRegionCount;
    }
    ++totalRegionCount;
  }

  TMinor** minorCursor = g_apNationAuxRuntimeStateSlots;
  do {
    if (*minorCursor != 0 && (*minorCursor)->IsEncodedNationSlotMinus200Equal(nationSlot)) {
      for (regionOrdinal = 1; regionOrdinal <= (*minorCursor)->ownedRegionList->GetSize();
           ++regionOrdinal) {
        int regionId = (*minorCursor)->ownedRegionList->At(regionOrdinal);
        if (IsMapTileCompatibleWithCurrentTerrainOrActionContext(regionId) != 0) {
          ++compatibleRegionCount;
        }
        ++totalRegionCount;
      }
    }
    ++minorCursor;
  } while (minorCursor < g_apNationAuxRuntimeStateSlots + 16);

  CIterator missionIterator(missionQueue);
  TMission* mission = static_cast<TMission*>(missionIterator.Reset());
  while (missionIterator.More()) {
    mission->AssertValid();
    if (mission->IsDefensiveSeaZoneMission()) {
      ++activeMissionCount;
    }
    mission = static_cast<TMission*>(missionIterator.Advance());
  }

  float ownUnitDivergence = g_afNationCombinedUnitDivergence_006a3b50[nationSlot] -
                            g_afNationMobileUnitDivergence_006a3ae0[nationSlot];
  averageUnitDivergencePerOwnedRegionB68 = ownUnitDivergence / static_cast<float>(totalRegionCount);

  float maximumAdjustedMilitaryScore = 0.0f;
  float maximumAdjustedMissionScore = 0.0f;
  float maximumRawMilitaryScore = 0.0f;
  float minimumPeerCombinedDivergence = -1.0f;
  float minimumPeerOrderQueueDivergence = -1.0f;

  int peerNation;
  for (peerNation = 0; peerNation < 7; ++peerNation) {
    if (peerNation == nationSlot || g_apNationStates[peerNation] == 0) {
      continue;
    }

    float peerCombinedDivergence = g_afNationCombinedUnitDivergence_006a3b50[peerNation];
    if (peerCombinedDivergence < minimumPeerCombinedDivergence ||
        minimumPeerCombinedDivergence == g_AiPressureUnsetSentinel_006545c8) {
      minimumPeerCombinedDivergence = peerCombinedDivergence;
    }

    float peerOrderQueueDivergence = g_afNationOrderQueueDivergence_006a3a88[peerNation];
    if (peerOrderQueueDivergence < minimumPeerOrderQueueDivergence ||
        minimumPeerOrderQueueDivergence == g_AiPressureUnsetSentinel_006545c8) {
      minimumPeerOrderQueueDivergence = peerOrderQueueDivergence;
    }

    float militaryScore;
    if (g_pGlobalMapState->TMapMaker_CheckTerrainTypePairReachabilityByRegionClassMask(
            nationSlot, static_cast<short>(peerNation))) {
      militaryScore = g_afNationMobileUnitScore_006a3b88[peerNation];
    } else {
      militaryScore = g_afNationWeightedMilitaryOrderScore_006a3b20[peerNation];
    }

    if (militaryScore > maximumRawMilitaryScore) {
      maximumRawMilitaryScore = militaryScore;
    }

    float missionScore = g_afNationOrderQueueDivergenceMirror_006a3ac0[peerNation];
    if (g_pDiplomacyTurnStateManager
            ->relationStandingScoreMatrix79c[nationSlot * 0x17 + peerNation] >= 100) {
      maximumAdjustedMilitaryScore =
          static_cast<float>(defenseMinister->GetPersonalityWeightByFlag(1) * militaryScore);
      missionScore =
          static_cast<float>(defenseMinister->GetPersonalityWeightByFlag(0) * missionScore);
    }

    if (militaryScore > maximumAdjustedMilitaryScore) {
      maximumAdjustedMilitaryScore = militaryScore;
    }
    if (missionScore > maximumAdjustedMissionScore) {
      maximumAdjustedMissionScore = missionScore;
    }
  }

  float militaryRatio =
      maximumRawMilitaryScore / (g_afNationMobileUnitDivergence_006a3ae0[nationSlot] +
                                 averageUnitDivergencePerOwnedRegionB68);
  if (militaryRatio > g_MissionScoreOneConstant_006545d8) {
    militaryRatio = g_AiPressureRatioCap_006545e0;
  }

  float peerScaledMilitaryScore = (militaryRatio - g_AiPressureUnsetSentinel_006545c8) *
                                  g_AiPressureMidpointScale_006545e8 *
                                  g_AiPressurePeerScale_006543e8 * minimumPeerCombinedDivergence;
  if (peerScaledMilitaryScore > maximumAdjustedMilitaryScore) {
    maximumAdjustedMilitaryScore = peerScaledMilitaryScore;
  }

  float expansionPressure = maximumAdjustedMilitaryScore - ownUnitDivergence;
  if (expansionPressure < g_MissionScoreZeroThreshold_006545f0) {
    expansionPressure = g_MissionDefaultScore_006545d0;
  }
  if (compatibleRegionCount != 0) {
    expansionPressure /= static_cast<float>(compatibleRegionCount);
  }
  expansionPressurePerCompatibleRegionB64 = expansionPressure;

  if (activeMissionCount == 0) {
    activeMissionPressureAverageB6c = maximumAdjustedMissionScore;
  } else {
    activeMissionPressureAverageB6c =
        maximumAdjustedMissionScore / static_cast<float>(activeMissionCount);
  }
}

// FUNCTION: IMPERIALISM 0x004eae70
void TAutoGreatPower::RefreshTrackedEntriesAndReplanAiDevelopment(int unused) {
  (void)unused;
  if (city == nullptr) {
    return;
  }

  CIterator unitIter(militaryUnitList44);
  for (TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(unitIter.Reset()); unitIter.More();
       unit = static_cast<TMilitaryUnit*>(unitIter.Advance())) {
    if (unit->ownerMission40 == nullptr &&
        unit->GetCategory() == EncodeArmyUnitCategory(kArmyUnitCategoryMilitia)) {
      TMission* mission =
          TMission::Find(missionQueue, kMissionTypeDefendProvince, unit->tileIndex06, nullptr);
      mission->AdoptUnitSlot80(unit, 1);
    }
  }

  CIterator missionIter(missionQueue);
  for (TMission* mission = static_cast<TMission*>(missionIter.Reset()); missionIter.More();
       mission = static_cast<TMission*>(missionIter.Advance())) {
    mission->Reassess();
  }

  PruneInvalidTrackedEntriesAndNotifyOwner();
  UpdateTrackedEntryEligibilityByClassMaskAndRatio(0);
  AssignTrackedEntryActionsByProfileToOrdersOrUnits(0);
  PlanAiDevelopmentActionsFromResourcePools(0);
}

// For every unassigned (ownerMission40 == nullptr) militia-category unit in
// militaryUnitList44, finds the queued mission (kind 3, keyed by the unit's own tileIndex06)
// in missionQueue and adopts the unit into it (AdoptUnitSlot80).
// FUNCTION: IMPERIALISM 0x004eafa0
void TAutoGreatPower::SeedTrackedEntryAssignmentsFromEligibleUnits() {
  CIterator iter(militaryUnitList44);
  for (TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(iter.Reset()); iter.More();
       unit = static_cast<TMilitaryUnit*>(iter.Advance())) {
    if (unit->ownerMission40 == nullptr &&
        unit->GetCategory() == EncodeArmyUnitCategory(kArmyUnitCategoryMilitia)) {
      TMission* handler =
          TMission::Find(missionQueue, kMissionTypeDefendProvince, unit->tileIndex06, nullptr);
      handler->AdoptUnitSlot80(unit, 1);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004eb040
void TAutoGreatPower::MReassess() {
  CIterator iter(missionQueue);
  for (TMission* mission = static_cast<TMission*>(iter.Reset()); iter.More();
       mission = static_cast<TMission*>(iter.Advance())) {
    mission->Reassess();
  }
}

// FUNCTION: IMPERIALISM 0x004eb0d0
void TAutoGreatPower::PruneInvalidTrackedEntriesAndNotifyOwner(void) {
  for (;;) {
    CIterator missionCursor(this->missionQueue);
    TMission* mission = static_cast<TMission*>(missionCursor.Reset());
    TMission* replacement;
    for (;;) {
      if (missionCursor.More() == 0) {
        return;
      }
      replacement = mission->GetReplacementSlot48();
      if (replacement != mission) {
        break;
      }
      mission = static_cast<TMission*>(missionCursor.Advance());
    }
    CPtrList* listState = &this->missionQueue->listState;
    POSITION pos = listState->Find(mission, 0);
    if (pos != 0) {
      listState->RemoveAt(pos);
    }
    mission->Free();
    if (replacement != 0) {
      this->missionQueue->AddTail(replacement);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004eb190
void TAutoGreatPower::PlanAiDevelopmentActionsFromResourcePools(int unused) {
  (void)unused;
  if (this == 0) {
    return;
  }
  if (city == 0) {
    return;
  }

  int resourcePools[9] = {0};
  TMilitaryUnit* bestUnitByType[30] = {0};

  CIterator unitIter(militaryUnitList44);
  for (TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(unitIter.Reset()); unitIter.More();
       unit = static_cast<TMilitaryUnit*>(unitIter.Advance())) {
    if (unit->CanUpgrade()) {
      int qualityLevel = unit->field_38 / 100;
      short unitType = unit->orderType;
      if (bestUnitByType[unitType] == 0 ||
          bestUnitByType[unitType]->field_38 / 100 < qualityLevel) {
        bestUnitByType[unitType] = unit;
      }
    }
  }

  CIterator missionIter(missionQueue);
  for (TMission* mission = static_cast<TMission*>(missionIter.Reset()); missionIter.More();
       mission = static_cast<TMission*>(missionIter.Advance())) {
    mission->AssertValid();
    if (mission->flag10 == 0) {
      mission->AccumulateLack(resourcePools + 1, 1);
    }
  }

  interiorMinister->AssertValid();
  int averageAllocation = interiorMinister->GetAverageDevelopmentOrderAllocation();
  int cityActionLimit = averageAllocation + 2;
  int industryActionLimit = averageAllocation / 2 + 1;
  float developmentBudget =
      interiorMinister->GetAiDevelopmentResourceBudgetScale(resourcePools + 1);
  int industryActionCount = 0;
  int cityActionCount = 0;

  for (int iteration = 0; iteration < 99; ++iteration) {
    int selectedSlot = -1;
    char selectedIsIndustry;
    char selectedIsUpgrade;
    float selectedWeightedCost;
    if (!SelectBestCityDevelopmentFromResourcePools(nationSlot, resourcePools, bestUnitByType,
                                                    &selectedIsIndustry, &selectedIsUpgrade,
                                                    &selectedSlot, 0, &selectedWeightedCost)) {
      return;
    }

    bool applyAction;
    if (selectedIsIndustry != 0) {
      applyAction = industryActionCount++ < industryActionLimit;
    } else {
      applyAction = cityActionCount++ < cityActionLimit;
    }
    if (industryActionCount > industryActionLimit && cityActionCount > cityActionLimit) {
      return;
    }

    if (selectedIsIndustry != 0) {
      if (applyAction) {
        interiorMinister->IndustryOrder(static_cast<short>(selectedSlot));
      }

      int actionCost = g_pNationInteractionStateManager->QueryProposalWeightSlot4C(0x0b) *
                       g_industryActionCostWeightResCode0B[selectedSlot];
      actionCost += g_pNationInteractionStateManager->QueryProposalWeightSlot4C(0x08) *
                    g_industryActionCostWeightResCode08[selectedSlot];
      actionCost += g_pNationInteractionStateManager->QueryProposalWeightSlot4C(0x09) *
                    g_industryActionCostWeightResCode09[selectedSlot];
      actionCost += g_pNationInteractionStateManager->QueryProposalWeightSlot4C(0x10) *
                    g_industryActionCostWeightResCode10[selectedSlot];
      actionCost += g_pNationInteractionStateManager->QueryProposalWeightSlot4C(0x0c) *
                    g_industryActionCostWeightResCode0C[selectedSlot];
      actionCost += g_pNationInteractionStateManager->QueryProposalWeightSlot4C(0x03) *
                    g_industryActionCostWeightResCode03[selectedSlot];
      developmentBudget -= static_cast<float>(actionCost);

      for (int resourceIndex = 0; resourceIndex < 4; ++resourceIndex) {
        resourcePools[5 + resourceIndex] -= GetNormalizedIndustryActionResourceCostPercent(
            resourceIndex, static_cast<short>(selectedSlot));
      }
    } else {
      if (applyAction) {
        interiorMinister->InteriorSlot1C(static_cast<short>(selectedSlot));
      }
      developmentBudget -=
          ComputeAiCityActionCostFromSlotAndMode(static_cast<short>(selectedSlot), 0);
      for (int resourceIndex = 0; resourceIndex < 5; ++resourceIndex) {
        resourcePools[resourceIndex] -= TMilitaryUnit::GetTypeAttribute(
            static_cast<short>(selectedSlot), static_cast<short>(resourceIndex));
      }
    }
  }
  // Listing 0x004eb190 stores and decrements this float but never consumes its value.
  (void)developmentBudget;
}

// FUNCTION: IMPERIALISM 0x004eb6b0
void TAutoGreatPower::UpdateTrackedEntryEligibilityByClassMaskAndRatio(int unused) {
  (void)unused;
  missionQueue->SortBy(&CompareMissionOrderEntriesByMovementClassThenEfficiency, this);

  TMission* nextByClass[4] = {nullptr, nullptr, nullptr, nullptr};
  int availableClassMask = 3;
  {
    CIterator candidateIter(missionQueue);
    for (TMission* mission = static_cast<TMission*>(candidateIter.Reset()); candidateIter.More();
         mission = static_cast<TMission*>(candidateIter.Advance())) {
      int classMask = static_cast<char>(mission->marker11);
      if (mission->flag10 == 0 && classMask != 0) {
        nextByClass[classMask] = mission;
      }
    }
  }

  CIterator missionIter(missionQueue);
  for (TMission* mission = static_cast<TMission*>(missionIter.Reset()); missionIter.More();
       mission = static_cast<TMission*>(missionIter.Advance())) {
    int classMask = static_cast<char>(mission->marker11);
    if (nextByClass[classMask] == mission) {
      nextByClass[classMask] = nullptr;
    }

    unsigned char eligible =
        classMask == 0 || (classMask & availableClassMask) == classMask || mission->state08 != 0;
    if (eligible && (classMask & 1) != 0 && !mission->IsArmyMission()) {
      eligible = 0;
    }
    if (eligible && classMask != 0) {
      TMission* nextMission = nextByClass[classMask];
      if (nextMission != nullptr &&
          mission->importanceScore0c / mission->IndustrialCostOfNeeds() <
              (nextMission->importanceScore0c / nextMission->IndustrialCostOfNeeds()) *
                  g_MissionEligibilityRatioMargin_006545f8) {
        eligible = 0;
      } else {
        availableClassMask &= ~classMask;
      }
    }
    mission->Hold(!eligible);
  }
}

// FUNCTION: IMPERIALISM 0x00535b00
bool SelectBestCityDevelopmentFromResourcePools(int nationSlot, int* resourcePools,
                                                TMilitaryUnit** bestUnitByType,
                                                char* selectedIsIndustry, char* selectedIsUpgrade,
                                                int* selectedSlot, int unused,
                                                float* selectedWeightedCost) {
  (void)unused;
  *selectedSlot = -1;
  int resourceIndex = 0;
  while (resourceIndex < 9 && resourcePools[resourceIndex] <= 0) {
    ++resourceIndex;
  }
  if (resourceIndex >= 9) {
    return false;
  }

  float bestScore = 0.0f;
  for (short actionSlot = 0; actionSlot < 30; ++actionSlot) {
    if (g_pCityOrderCapabilityState->abilityActiveRows395[nationSlot]
            .abilityActiveById[actionSlot] == 0) {
      continue;
    }
    ArmyUnitCategoryStorage category = TMilitaryUnit::GetTypeCategory(actionSlot);
    if (category == EncodeArmyUnitCategory(kArmyUnitCategoryMilitia) ||
        category == EncodeArmyUnitCategory(kArmyUnitCategoryGeneral)) {
      continue;
    }

    float weightedCost = 0.0f;
    for (short poolIndex = 0; poolIndex < 5; ++poolIndex) {
      if (resourcePools[poolIndex] > 0) {
        weightedCost += static_cast<float>(TMilitaryUnit::GetTypeAttribute(actionSlot, poolIndex) *
                                           resourcePools[poolIndex]);
      }
    }
    float score = weightedCost / static_cast<TAutoGreatPower*>(g_apNationStates[nationSlot])
                                     ->ComputeAiCityActionCostFromSlotAndMode(actionSlot, 0);
    if (score > bestScore) {
      bestScore = score;
      *selectedSlot = actionSlot;
      *selectedIsIndustry = 0;
      *selectedIsUpgrade = 0;
      if (selectedWeightedCost != 0) {
        *selectedWeightedCost = weightedCost;
      }
    }
  }

  for (short unitType = 0; unitType < 30; ++unitType) {
    ArmyUnitCategoryStorage category = TMilitaryUnit::GetTypeCategory(unitType);
    if (category == EncodeArmyUnitCategory(kArmyUnitCategoryMilitia) ||
        category == EncodeArmyUnitCategory(kArmyUnitCategoryGeneral) ||
        bestUnitByType[unitType] == 0) {
      continue;
    }

    short upgradeSlot = bestUnitByType[unitType]->UpgradeType();
    float weightedCost = 0.0f;
    for (short poolIndex = 0; poolIndex < 5; ++poolIndex) {
      if (resourcePools[poolIndex] > 0) {
        int costDelta = TMilitaryUnit::GetTypeAttribute(upgradeSlot, poolIndex) -
                        TMilitaryUnit::GetTypeAttribute(unitType, poolIndex);
        weightedCost += static_cast<float>(costDelta * resourcePools[poolIndex]);
      }
    }
    int qualityMultiplier = (bestUnitByType[unitType]->field_38 / 100 + 10) / 10;
    weightedCost *= static_cast<float>(qualityMultiplier);
    float score = weightedCost / static_cast<TAutoGreatPower*>(g_apNationStates[nationSlot])
                                     ->ComputeAiCityActionCostFromSlotAndMode(upgradeSlot, 1);
    if (score > bestScore) {
      bestScore = score;
      *selectedSlot = upgradeSlot;
      *selectedIsIndustry = 0;
      *selectedIsUpgrade = 1;
      if (selectedWeightedCost != 0) {
        *selectedWeightedCost = weightedCost;
      }
    }
  }

  for (short industryClass = 0; industryClass < 4; ++industryClass) {
    short industrySlot = GetEnabledIndustryCapabilitySlotByClass(industryClass);
    if (industrySlot <= 0) {
      continue;
    }

    float weightedCost = 0.0f;
    for (int poolIndex = 0; poolIndex < 4; ++poolIndex) {
      if (resourcePools[5 + poolIndex] > 0) {
        weightedCost += static_cast<float>(
            GetNormalizedIndustryActionResourceCostPercent(poolIndex, industrySlot) *
            resourcePools[5 + poolIndex]);
      }
    }
    float score = weightedCost / static_cast<TAutoGreatPower*>(g_apNationStates[nationSlot])
                                     ->ComputeAiIndustryActionCostFromSlot(industrySlot);
    if (score > bestScore) {
      bestScore = score;
      *selectedSlot = industrySlot;
      *selectedIsIndustry = 1;
      *selectedIsUpgrade = 0;
      if (selectedWeightedCost != 0) {
        *selectedWeightedCost = weightedCost;
      }
    }
  }

  if (*selectedSlot < 0) {
    return false;
  }

  if (*selectedIsIndustry != 0) {
    for (int poolIndex = 0; poolIndex < 4; ++poolIndex) {
      resourcePools[5 + poolIndex] -= GetNormalizedIndustryActionResourceCostPercent(
          poolIndex, static_cast<short>(*selectedSlot));
    }
  } else {
    for (short poolIndex = 0; poolIndex < 5; ++poolIndex) {
      resourcePools[poolIndex] -=
          TMilitaryUnit::GetTypeAttribute(static_cast<short>(*selectedSlot), poolIndex);
    }
  }
  return true;
}
