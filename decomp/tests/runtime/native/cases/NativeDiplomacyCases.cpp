#include "NativeCases.h"
#include "JsonObject.h"

#include "game/diplomacy_domain_types.h"
#include "game/city_ui/TCountry.h"
#include "game/globals/shared_globals.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/nation/TGreatPower.h"
#include "game/resource_domain_types.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

short OtherMajorNation(short activeNationSlot, int offset) {
  return static_cast<short>((static_cast<int>(activeNationSlot) + offset) % kMajorNationCount);
}

void SetMissionLevel(short source, short target, DiplomaticMissionLevelStorage level) {
  const int forward = source * kNationSlotCount + target;
  const int reverse = target * kNationSlotCount + source;
  g_pDiplomacyTurnStateManager->relationSideEffectMatrix[forward] = level;
  g_pDiplomacyTurnStateManager->relationSideEffectMatrix[reverse] = level;
}

void SetRelationshipAndStamp(short source, short target, DiplomacyRelationshipStorage relationship,
                             short turnStamp) {
  const int forward = source * kNationSlotCount + target;
  const int reverse = target * kNationSlotCount + source;
  g_pDiplomacyTurnStateManager->relationPropagationMatrix[forward] = relationship;
  g_pDiplomacyTurnStateManager->relationPropagationMatrix[reverse] = relationship;
  g_pDiplomacyTurnStateManager->relationTurnStampMatrix[forward] = turnStamp;
  g_pDiplomacyTurnStateManager->relationTurnStampMatrix[reverse] = turnStamp;
}

int TogglePlayerDiplomacyPolicyResult(TGreatPower* nation, short targetNationSlot, short policyCode,
                                      eDipAction action, bool confirmEntanglements) {
  if (nation->nationSlot == targetNationSlot) {
    return 3;
  }
  if (nation->diplomacyPolicyByNation[targetNationSlot] == policyCode) {
    return nation->ApplyDiplomacyPolicyStateForTargetWithCostChecks(targetNationSlot, -1) ? 1 : 0;
  }
  if (!g_pDiplomacyTurnStateManager->ValidateDiplomacyActionTypeAgainstTargetAndSetRejectCode(
          nation->nationSlot, targetNationSlot, action)) {
    return -g_pDiplomacyTurnStateManager->proposalArrayMode;
  }
  if (!confirmEntanglements && (action == kDipActionJoinEmpire || action == kDipActionAlliance) &&
      g_pDiplomacyTurnStateManager->HasAllianceGuardForNationPair(targetNationSlot,
                                                                  nation->nationSlot)) {
    return 2;
  }
  return nation->ApplyDiplomacyPolicyStateForTargetWithCostChecks(targetNationSlot, policyCode) ? 1
                                                                                                : 0;
}

RuntimeActionResult RunConfiguredPlayerPolicy(NativeTransition& transition, short targetNationSlot,
                                              short policyCode, eDipAction action,
                                              bool confirmEntanglements) {
  TGreatPower* nation = ActiveNation();
  JsonObject args;
  args.Set("source", static_cast<int>(nation->nationSlot));
  args.Set("target", static_cast<int>(targetNationSlot));
  switch (policyCode) {
  case kDiplomacyProposalJoinEmpire:
    args.Set("policy", "join_empire");
    break;
  case kDiplomacyProposalAlliance:
    args.Set("policy", "alliance");
    break;
  case kDiplomacyProposalNonAggressionPact:
    args.Set("policy", "non_aggression_pact");
    break;
  case kDiplomacyProposalPeaceTreaty:
    args.Set("policy", "peace_treaty");
    break;
  case kDiplomacyProposalDeclareWar:
    args.Set("policy", "declare_war");
    break;
  case kDiplomacyProposalBuildConsulate:
    args.Set("policy", "build_consulate");
    break;
  case kDiplomacyProposalBuildEmbassy:
    args.Set("policy", "build_embassy");
    break;
  default:
    return RuntimeActionResult::Failure("unsupported player diplomacy policy case");
  }
  args.Set("confirm_entanglements", confirmEntanglements);
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }
  return transition.Finish(TogglePlayerDiplomacyPolicyResult(nation, targetNationSlot, policyCode,
                                                             action, confirmEntanglements));
}

int TogglePlayerTradePolicyResult(TGreatPower* nation, short targetNationSlot, short policyValue) {
  const eDipAction action = policyValue == 300 ? kDipActionBoycott : kDipActionTradeSubsidy;
  if (nation->nationSlot == targetNationSlot) {
    return 3;
  }
  if (!g_pDiplomacyTurnStateManager->ValidateDiplomacyActionTypeAgainstTargetAndSetRejectCode(
          nation->nationSlot, targetNationSlot, action)) {
    return -g_pDiplomacyTurnStateManager->proposalArrayMode;
  }
  nation->SetTradePolicyTo(
      static_cast<NationSlot>(targetNationSlot),
      nation->needLevelByNation[targetNationSlot] == policyValue ? 100 : policyValue);
  return 1;
}

RuntimeActionResult RunConfiguredPlayerTradePolicy(NativeTransition& transition,
                                                   short targetNationSlot, short policyValue) {
  TGreatPower* nation = ActiveNation();
  JsonObject args;
  args.Set("source", static_cast<int>(nation->nationSlot));
  args.Set("target", static_cast<int>(targetNationSlot));
  args.Set("policy", static_cast<int>(policyValue));
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }
  return transition.Finish(TogglePlayerTradePolicyResult(nation, targetNationSlot, policyValue));
}

RuntimeActionResult RunConfiguredPlayerColonyBoycott(NativeTransition& transition,
                                                     short targetNationSlot) {
  TGreatPower* nation = ActiveNation();
  JsonObject args;
  args.Set("source", static_cast<int>(nation->nationSlot));
  args.Set("target", static_cast<int>(targetNationSlot));
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  TCountry* targetNation = g_apTerrainTypeDescriptorTable[targetNationSlot];
  short controllingNation = targetNation->encodedNationSlot;
  if (controllingNation >= 200) {
    controllingNation = static_cast<short>(controllingNation - 200);
  } else if (controllingNation >= 100) {
    controllingNation = static_cast<short>(controllingNation - 100);
  } else {
    controllingNation = targetNation->nationSlot;
  }
  if (controllingNation != nation->nationSlot) {
    nation->SetDiplomacyColonyBoycottFlagForTargetAndRefreshMinorNations(
        targetNationSlot, nation->colonyBoycottFlags[targetNationSlot] == 0);
  }
  return transition.Finish(1);
}

} // namespace

RuntimeActionResult RunAidAllocation(NativeTransition& transition) {
  TGreatPower* nation = ActiveNation();

  JsonObject args;
  args.Set("nation", static_cast<int>(ActiveNationSlot()));
  args.Set("minor_nation", static_cast<int>(kMinorNationFirstSlot));
  args.Set("resource", "steel");
  args.Set("amount", 37);
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  nation->AddAmountToAidAllocationMatrixCellAndTotal(37, kResourceSteel, kMinorNationFirstSlot);
  return transition.Finish();
}

RuntimeActionResult RunDiplomacyGrantEntry(NativeTransition& transition) {
  const short activeNationSlot = ActiveNationSlot();
  const short targetNationSlot = 0;
  const short grantAmount = 10000;
  TGreatPower* nation = ActiveNation();

  JsonObject args;
  args.Set("nation", static_cast<int>(activeNationSlot));
  args.Set("target", static_cast<int>(targetNationSlot));
  args.Set("amount", static_cast<int>(grantAmount));
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  const bool accepted =
      nation->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(targetNationSlot, grantAmount);
  return transition.Finish(accepted);
}

RuntimeActionResult RunDiplomacyReset(NativeTransition& transition) {
  const short activeNationSlot = ActiveNationSlot();
  TGreatPower* nation = ActiveNation();

  const short policyTarget = OtherMajorNation(activeNationSlot, 1);
  const short oneTimeGrantTarget = OtherMajorNation(activeNationSlot, 2);
  const short recurringGrantTarget = OtherMajorNation(activeNationSlot, 3);
  const short oneTimeGrant = 1000;
  const short recurringGrant = 3000;
  const short kRecurringGrantFlag = 0x4000;
  const short recurringGrantEntry = static_cast<short>(recurringGrant | kRecurringGrantFlag);

  for (short targetNation = 0; targetNation < kNationSlotCount; ++targetNation) {
    nation->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(targetNation, -1);
  }

  nation->diplomacyPolicyByNation[policyTarget] = kDiplomacyProposalBuildConsulate;
  nation->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(oneTimeGrantTarget, oneTimeGrant);
  nation->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(recurringGrantTarget,
                                                           recurringGrantEntry);

  JsonObject args;
  args.Set("nation", static_cast<int>(activeNationSlot));
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  nation->ResetDiplomacyPolicyAndGrantEntriesPreserveRecurringGrants();
  return transition.Finish();
}

RuntimeActionResult RunDiplomacyPhase(NativeTransition& transition) {
  const short activeNationSlot = g_pSimMgr->GetActiveNationId();
  TGreatPower* nation = g_apNationStates[activeNationSlot];
  if (nation == 0 || g_pDiplomacyTurnStateManager == 0) {
    return RuntimeActionResult::Failure("the loaded player has no diplomacy state");
  }

  const short grantTarget = OtherMajorNation(activeNationSlot, 1);
  const short consulateTarget = kMinorNationFirstSlot;
  if (g_apTerrainTypeDescriptorTable[consulateTarget] == 0) {
    return RuntimeActionResult::Failure("the loaded fixture has no first minor nation");
  }

  // Skip the AI policy planner so this case isolates posted-order resolution.
  for (int nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
    if (g_apNationStates[nationSlot] != 0) {
      g_apNationStates[nationSlot]->diplomacyEligibilityA0 = 1;
    }
  }

  if (!nation->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(grantTarget, 1000)) {
    return RuntimeActionResult::Failure("retail rejected the seeded diplomacy grant");
  }
  nation->diplomacyPolicyByNation[consulateTarget] = kDiplomacyProposalBuildConsulate;

  RuntimeActionResult started = transition.Begin(JsonNullValue());
  if (!started.Succeeded()) {
    return started;
  }

  g_pDiplomacyTurnStateManager->ApplyDiplomacyInterNationStatesForTurn();
  for (int replyNationSlot = 0; replyNationSlot < kMajorNationCount; ++replyNationSlot) {
    if (g_apNationStates[replyNationSlot] != 0) {
      g_apNationStates[replyNationSlot]->ReplyToDiplomacyOffers();
    }
  }

  JsonObject result;
  result.Set("kind", "resolved");
  return transition.Finish(result.Release());
}

bool TogglePlayerDiplomacyPolicy(TGreatPower* nation, short targetNationSlot, short policyCode,
                                 eDipAction action) {
  if (nation->diplomacyPolicyByNation[targetNationSlot] == policyCode) {
    return nation->ApplyDiplomacyPolicyStateForTargetWithCostChecks(targetNationSlot, -1);
  }
  if (!g_pDiplomacyTurnStateManager->ValidateDiplomacyActionTypeAgainstTargetAndSetRejectCode(
          nation->nationSlot, targetNationSlot, action)) {
    return false;
  }
  return nation->ApplyDiplomacyPolicyStateForTargetWithCostChecks(targetNationSlot, policyCode);
}

RuntimeActionResult RunPlayerDiplomacyPolicyPostJoinEmpire(NativeTransition& transition) {
  const short source = ActiveNationSlot();
  const short target = kMinorNationFirstSlot;
  SetMissionLevel(source, target, 2);
  SetRelationshipAndStamp(source, target, kDiplomacyRelationshipPeace, -1);
  return RunConfiguredPlayerPolicy(transition, target, kDiplomacyProposalJoinEmpire,
                                   kDipActionJoinEmpire, false);
}

RuntimeActionResult RunPlayerDiplomacyPolicyPostAlliance(NativeTransition& transition) {
  const short source = ActiveNationSlot();
  const short target = OtherMajorNation(source, 1);
  SetMissionLevel(source, target, 2);
  SetRelationshipAndStamp(source, target, kDiplomacyRelationshipPeace, -1);
  return RunConfiguredPlayerPolicy(transition, target, kDiplomacyProposalAlliance,
                                   kDipActionAlliance, false);
}

RuntimeActionResult
RunPlayerDiplomacyPolicyNeedsAllianceEntanglement(NativeTransition& transition) {
  const short source = ActiveNationSlot();
  const short target = OtherMajorNation(source, 1);
  const short third = OtherMajorNation(source, 2);
  SetMissionLevel(source, target, 2);
  SetRelationshipAndStamp(source, target, kDiplomacyRelationshipPeace, -1);
  SetRelationshipAndStamp(target, third, kDiplomacyRelationshipWar, -1);
  return RunConfiguredPlayerPolicy(transition, target, kDiplomacyProposalAlliance,
                                   kDipActionAlliance, false);
}

RuntimeActionResult
RunPlayerDiplomacyPolicyConfirmsAllianceEntanglement(NativeTransition& transition) {
  const short source = ActiveNationSlot();
  const short target = OtherMajorNation(source, 1);
  const short third = OtherMajorNation(source, 2);
  SetMissionLevel(source, target, 2);
  SetRelationshipAndStamp(source, target, kDiplomacyRelationshipPeace, -1);
  SetRelationshipAndStamp(target, third, kDiplomacyRelationshipWar, -1);
  return RunConfiguredPlayerPolicy(transition, target, kDiplomacyProposalAlliance,
                                   kDipActionAlliance, true);
}

RuntimeActionResult RunPlayerDiplomacyPolicyPostNonAggressionPact(NativeTransition& transition) {
  const short source = ActiveNationSlot();
  const short target = kMinorNationFirstSlot;
  SetMissionLevel(source, target, 2);
  SetRelationshipAndStamp(source, target, kDiplomacyRelationshipPeace, -1);
  return RunConfiguredPlayerPolicy(transition, target, kDiplomacyProposalNonAggressionPact,
                                   kDipActionNonAggressionPact, false);
}

RuntimeActionResult RunPlayerDiplomacyPolicyPostPeaceTreaty(NativeTransition& transition) {
  const short source = ActiveNationSlot();
  const short target = OtherMajorNation(source, 1);
  SetRelationshipAndStamp(source, target, kDiplomacyRelationshipWar, -1);
  return RunConfiguredPlayerPolicy(transition, target, kDiplomacyProposalPeaceTreaty,
                                   kDipActionPeaceTreaty, false);
}

RuntimeActionResult RunPlayerDiplomacyPolicyPostDeclareWar(NativeTransition& transition) {
  const short source = ActiveNationSlot();
  const short target = OtherMajorNation(source, 1);
  SetRelationshipAndStamp(source, target, kDiplomacyRelationshipAlliance, -1);
  ActiveNation()->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(target, 1000);
  return RunConfiguredPlayerPolicy(transition, target, kDiplomacyProposalDeclareWar,
                                   kDipActionDeclareWar, false);
}

RuntimeActionResult RunPlayerDiplomacyPolicyPostEmbassy(NativeTransition& transition) {
  const short source = ActiveNationSlot();
  const short target = kMinorNationFirstSlot;
  SetMissionLevel(source, target, 1);
  SetRelationshipAndStamp(source, target, kDiplomacyRelationshipPeace, -1);
  return RunConfiguredPlayerPolicy(transition, target, kDiplomacyProposalBuildEmbassy,
                                   kDipActionBuildEmbassy, false);
}

RuntimeActionResult RunPlayerDiplomacyPolicyRetractEmbassy(NativeTransition& transition) {
  const short target = kMinorNationFirstSlot;
  ActiveNation()->diplomacyPolicyByNation[target] = kDiplomacyProposalBuildEmbassy;
  return RunConfiguredPlayerPolicy(transition, target, kDiplomacyProposalBuildEmbassy,
                                   kDipActionBuildEmbassy, false);
}

RuntimeActionResult
RunPlayerDiplomacyPolicyCannotAffordCommittedConsulate(NativeTransition& transition) {
  const short source = ActiveNationSlot();
  const short target = kMinorNationFirstSlot;
  TGreatPower* nation = ActiveNation();
  SetMissionLevel(source, target, 0);
  SetRelationshipAndStamp(source, target, kDiplomacyRelationshipPeace, -1);
  nation->treasuryValue10 = 500;
  nation->diplomacyBudgetBase = 0;
  nation->grantTotalCost = 1;
  return RunConfiguredPlayerPolicy(transition, target, kDiplomacyProposalBuildConsulate,
                                   kDipActionBuildConsulate, false);
}

RuntimeActionResult RunPlayerDiplomacyPolicyRejectColony(NativeTransition& transition) {
  const short source = ActiveNationSlot();
  const short target = kMinorNationFirstSlot;
  g_apTerrainTypeDescriptorTable[target]->encodedNationSlot =
      static_cast<short>(200 + OtherMajorNation(source, 1));
  return RunConfiguredPlayerPolicy(transition, target, kDiplomacyProposalDeclareWar,
                                   kDipActionDeclareWar, false);
}

RuntimeActionResult RunPlayerDiplomacyPolicySelectSelf(NativeTransition& transition) {
  const short source = ActiveNationSlot();
  return RunConfiguredPlayerPolicy(transition, source, kDiplomacyProposalAlliance,
                                   kDipActionAlliance, false);
}

RuntimeActionResult RunPlayerTradePolicyPostSubsidy(NativeTransition& transition) {
  const short source = ActiveNationSlot();
  const short target = kMinorNationFirstSlot;
  SetMissionLevel(source, target, 1);
  return RunConfiguredPlayerTradePolicy(transition, target, 95);
}

RuntimeActionResult RunPlayerTradePolicyRetractSubsidy(NativeTransition& transition) {
  const short source = ActiveNationSlot();
  const short target = kMinorNationFirstSlot;
  SetMissionLevel(source, target, 1);
  ActiveNation()->needLevelByNation[target] = 95;
  return RunConfiguredPlayerTradePolicy(transition, target, 95);
}

RuntimeActionResult RunPlayerTradePolicyBoycottClearsGrant(NativeTransition& transition) {
  const short target = OtherMajorNation(ActiveNationSlot(), 1);
  ActiveNation()->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(target, 1000);
  return RunConfiguredPlayerTradePolicy(transition, target, 300);
}

RuntimeActionResult RunPlayerTradePolicyRejectsAlliedBoycott(NativeTransition& transition) {
  const short source = ActiveNationSlot();
  const short target = OtherMajorNation(source, 1);
  SetRelationshipAndStamp(source, target, kDiplomacyRelationshipAlliance, -1);
  return RunConfiguredPlayerTradePolicy(transition, target, 300);
}

RuntimeActionResult RunPlayerColonyBoycottPostsAndPropagates(NativeTransition& transition) {
  const short source = ActiveNationSlot();
  const short target = OtherMajorNation(source, 1);
  g_apTerrainTypeDescriptorTable[kMinorNationFirstSlot]->encodedNationSlot =
      static_cast<short>(200 + source);
  return RunConfiguredPlayerColonyBoycott(transition, target);
}

RuntimeActionResult RunPlayerColonyBoycottRetractsAndPropagates(NativeTransition& transition) {
  const short source = ActiveNationSlot();
  const short target = OtherMajorNation(source, 1);
  TGreatPower* nation = ActiveNation();
  TCountry* colony = g_apTerrainTypeDescriptorTable[kMinorNationFirstSlot];
  colony->encodedNationSlot = static_cast<short>(200 + source);
  nation->colonyBoycottFlags[target] = 1;
  colony->SetTradePolicyTo(static_cast<NationSlot>(target), 300);
  return RunConfiguredPlayerColonyBoycott(transition, target);
}

RuntimeActionResult RunPlayerColonyBoycottOwnColonyNoOp(NativeTransition& transition) {
  const short source = ActiveNationSlot();
  const short target = kMinorNationFirstSlot;
  g_apTerrainTypeDescriptorTable[target]->encodedNationSlot = static_cast<short>(200 + source);
  return RunConfiguredPlayerColonyBoycott(transition, target);
}

RuntimeActionResult RunPlayerDiplomacyPolicyPostConsulate(NativeTransition& transition) {
  const short sourceNationSlot = ActiveNationSlot();
  const short targetNationSlot = kMinorNationFirstSlot;
  TGreatPower* nation = ActiveNation();
  if (nation == 0 || g_apTerrainTypeDescriptorTable[targetNationSlot] == 0) {
    return RuntimeActionResult::Failure("the loaded fixture has no first minor nation");
  }

  JsonObject args;
  args.Set("source", static_cast<int>(sourceNationSlot));
  args.Set("target", static_cast<int>(targetNationSlot));
  args.Set("policy", "build_consulate");
  args.Set("confirm_entanglements", false);
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  return transition.Finish(TogglePlayerDiplomacyPolicy(
      nation, targetNationSlot, kDiplomacyProposalBuildConsulate, kDipActionBuildConsulate));
}

RuntimeActionResult RunPlayerDiplomacyPolicyRejectConsulateOnMajor(NativeTransition& transition) {
  const short sourceNationSlot = ActiveNationSlot();
  const short targetNationSlot = OtherMajorNation(sourceNationSlot, 1);
  TGreatPower* nation = ActiveNation();
  if (nation == 0 || g_apTerrainTypeDescriptorTable[targetNationSlot] == 0) {
    return RuntimeActionResult::Failure("the loaded fixture has no other great power");
  }

  JsonObject args;
  args.Set("source", static_cast<int>(sourceNationSlot));
  args.Set("target", static_cast<int>(targetNationSlot));
  args.Set("policy", "build_consulate");
  args.Set("confirm_entanglements", false);
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  return transition.Finish(TogglePlayerDiplomacyPolicy(
      nation, targetNationSlot, kDiplomacyProposalBuildConsulate, kDipActionBuildConsulate));
}
