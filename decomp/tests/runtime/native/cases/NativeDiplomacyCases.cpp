#include "NativeCases.h"
#include "JsonObject.h"

#include "game/diplomacy_domain_types.h"
#include "game/globals/shared_globals.h"
#include "game/nation/TGreatPower.h"
#include "game/resource_domain_types.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

short OtherMajorNation(short activeNationSlot, int offset) {
  return static_cast<short>((static_cast<int>(activeNationSlot) + offset) % kMajorNationCount);
}

} // namespace

RuntimeActionResult RunAidAllocation(NativeTransition& transition) {
  const NationSlot nationSlot = g_pSimMgr->GetActiveNationId();
  TGreatPower* nation = g_apNationStates[nationSlot];
  if (nation == 0) {
    return RuntimeActionResult::Failure("the loaded player has no major-nation state");
  }

  JsonObject operation;
  operation.Set("nation", static_cast<int>(nationSlot));
  operation.Set("minor_nation", static_cast<int>(kMinorNationFirstSlot));
  operation.Set("resource", "steel");
  operation.Set("amount", 37);
  RuntimeActionResult started = transition.Begin(operation.Release());
  if (!started.Succeeded()) {
    return started;
  }

  nation->AddAmountToAidAllocationMatrixCellAndTotal(37, kResourceSteel, kMinorNationFirstSlot);
  return transition.Finish();
}

RuntimeActionResult RunDiplomacyGrantEntry(NativeTransition& transition) {
  const short activeNationSlot = g_pSimMgr->GetActiveNationId();
  const short targetNationSlot = 0;
  const short grantAmount = 10000;
  TGreatPower* nation = g_apNationStates[activeNationSlot];
  if (nation == 0 || activeNationSlot == targetNationSlot) {
    return RuntimeActionResult::Failure("the loaded player cannot make the grant-target check");
  }

  JsonObject operation;
  operation.Set("nation", static_cast<int>(activeNationSlot));
  operation.Set("target", static_cast<int>(targetNationSlot));
  operation.Set("amount", static_cast<int>(grantAmount));
  RuntimeActionResult started = transition.Begin(operation.Release());
  if (!started.Succeeded()) {
    return started;
  }

  const bool accepted =
      nation->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(targetNationSlot, grantAmount);
  return transition.Finish(accepted);
}

RuntimeActionResult RunDiplomacyReset(NativeTransition& transition) {
  const short activeNationSlot = g_pSimMgr->GetActiveNationId();
  TGreatPower* nation = g_apNationStates[activeNationSlot];
  if (nation == 0) {
    return RuntimeActionResult::Failure("the loaded player has no major-nation state");
  }

  const short policyTarget = OtherMajorNation(activeNationSlot, 1);
  const short oneTimeGrantTarget = OtherMajorNation(activeNationSlot, 2);
  const short recurringGrantTarget = OtherMajorNation(activeNationSlot, 3);
  const short oneTimeGrant = 1000;
  const short recurringGrant = 3000;
  const short kRecurringGrantFlag = 0x4000;
  const short recurringGrantEntry = static_cast<short>(recurringGrant | kRecurringGrantFlag);

  for (short targetNation = 0; targetNation < kNationSlotCount; ++targetNation) {
    if (!nation->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(targetNation, -1)) {
      return RuntimeActionResult::Failure("retail rejected clearing a diplomacy grant");
    }
  }

  nation->diplomacyPolicyByNation[policyTarget] = kDiplomacyProposalBuildConsulate;

  if (!nation->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(oneTimeGrantTarget, oneTimeGrant) ||
      !nation->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(recurringGrantTarget,
                                                                recurringGrantEntry)) {
    return RuntimeActionResult::Failure("retail rejected the seeded diplomacy grants");
  }

  JsonObject operation;
  operation.Set("nation", static_cast<int>(activeNationSlot));
  RuntimeActionResult started = transition.Begin(operation.Release());
  if (!started.Succeeded()) {
    return started;
  }

  nation->ResetDiplomacyPolicyAndGrantEntriesPreserveRecurringGrants();
  return transition.Finish();
}
