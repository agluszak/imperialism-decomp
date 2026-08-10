#include "JsonArray.h"
#include "JsonObject.h"
#include "RuntimeGameStateCapture.h"
#include "RuntimeDifferentialCapture.h"
#include "RuntimeRun.h"
#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "screens/OfferScreen.h"

#include "game/globals/shared_globals.h"
#include "game/nation/TGreatPower.h"
#include "game/nation/TMinor.h"
#include "game/turn_event_codes.h"
#include "game/ui_screens/TSimMgr.h"

#include "parson.h"

namespace {

enum { kSecondaryNationStateSlotCount = 36 };

bool HasFirstTurnNationSurvivalTopology() {
  if (g_pSimMgr->numMinorCountries != kNationSlotCount - kMinorNationFirstSlot) {
    return false;
  }
  for (int majorSlot = 0; majorSlot < kMajorNationCount; ++majorSlot) {
    TGreatPower* nation = g_apNationStates[majorSlot];
    if (nation == 0 || g_apTerrainTypeDescriptorTable[majorSlot] != nation ||
        nation->ownedRegionList == 0 || nation->ownedRegionList->GetSize() == 0) {
      return false;
    }
  }
  for (int minorSlot = kMinorNationFirstSlot; minorSlot < kNationSlotCount; ++minorSlot) {
    TMinor* nation = g_apSecondaryNationStateSlots[minorSlot];
    if (nation == 0 || g_apTerrainTypeDescriptorTable[minorSlot] != nation ||
        nation->ownedRegionList == 0 || nation->ownedRegionList->GetSize() == 0) {
      return false;
    }
  }
  for (int unusedSecondarySlot = kNationSlotCount;
       unusedSecondarySlot < kSecondaryNationStateSlotCount; ++unusedSecondarySlot) {
    if (g_apSecondaryNationStateSlots[unusedSecondarySlot] != 0) {
      return false;
    }
  }
  return true;
}

// Observe reconstructed phase 0x19 from the exact state produced by the recovered first-turn
// diplomacy, trade and military phases. Every nation still owns territory, so elimination
// advances directly to city and transport without dispatching a loss or victory event.
class FirstTurnEliminationPhaseTestCase : public LoadedMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();

    RT_DO("advance the first-turn elimination phase once", AdvanceEliminationPhaseOnce());
    RT_PASS();

    RT_END();
  }

private:
  RuntimeActionResult AdvanceEliminationPhaseOnce() {
    if (g_pSimMgr == 0 || g_pMapContextActionManager == 0 || g_pSimMgr->economicTurn != 1 ||
        g_pSimMgr->turnStateCode != 5) {
      return RuntimeActionResult::Failure("the loaded fixture is not at first-turn phase 5");
    }

    g_pSimMgr->turnStateCode = 6;
    const int expectedPhases[] = {7, 9, 10, 0x14, 0x15, 0x0d, 0x19};
    for (int index = 0; index < 7; ++index) {
      g_pSimMgr->AdvanceGlobalTurnStateMachine();
      if (g_pSimMgr->turnStateCode != expectedPhases[index]) {
        return RuntimeActionResult::Failure(
            "the prerequisite turn phases did not reach elimination");
      }
    }
    if (CurrentTurnEvent() != kTurnEventOfferSheet || !OfferScreen::IsCurrent()) {
      return RuntimeActionResult::Failure(
          "elimination did not begin from the retained offer sheet");
    }
    if (!HasFirstTurnNationSurvivalTopology()) {
      return RuntimeActionResult::Failure(
          "the beginning-save fixture has an unexpected nation survival topology");
    }

    TGreatPower* majorNationsBefore[kMajorNationCount];
    TMinor* minorNationsBefore[kNationSlotCount - kMinorNationFirstSlot];
    for (int beforeMajorSlot = 0; beforeMajorSlot < kMajorNationCount; ++beforeMajorSlot) {
      majorNationsBefore[beforeMajorSlot] = g_apNationStates[beforeMajorSlot];
    }
    for (int beforeMinorSlot = kMinorNationFirstSlot; beforeMinorSlot < kNationSlotCount;
         ++beforeMinorSlot) {
      minorNationsBefore[beforeMinorSlot - kMinorNationFirstSlot] =
          g_apSecondaryNationStateSlots[beforeMinorSlot];
    }

    RuntimeDifferentialCapture capture(RunState());
    RuntimeActionResult started = capture.Begin(json_value_init_null());
    if (!started.Succeeded()) {
      return started;
    }

    g_pSimMgr->AdvanceGlobalTurnStateMachine();
    if (g_pSimMgr->turnStateCode != 8) {
      return RuntimeActionResult::Failure("elimination did not advance to city and transport");
    }
    if (CurrentTurnEvent() != kTurnEventOfferSheet || !OfferScreen::IsCurrent()) {
      return RuntimeActionResult::Failure(
          "the no-elimination branch unexpectedly changed presentation");
    }
    if (!HasFirstTurnNationSurvivalTopology()) {
      return RuntimeActionResult::Failure("elimination unexpectedly removed a surviving nation");
    }
    for (int afterMajorSlot = 0; afterMajorSlot < kMajorNationCount; ++afterMajorSlot) {
      if (g_apNationStates[afterMajorSlot] != majorNationsBefore[afterMajorSlot]) {
        return RuntimeActionResult::Failure("elimination replaced a surviving major nation");
      }
    }
    for (int afterMinorSlot = kMinorNationFirstSlot; afterMinorSlot < kNationSlotCount;
         ++afterMinorSlot) {
      if (g_apSecondaryNationStateSlots[afterMinorSlot] !=
          minorNationsBefore[afterMinorSlot - kMinorNationFirstSlot]) {
        return RuntimeActionResult::Failure("elimination replaced a surviving minor nation");
      }
    }

    JsonArray effects;
    JsonObject result;
    result.Set("kind", "continues");
    result.Set("from", 0x19);
    result.Set("to", 8);
    result.Set("effects", effects.Release());
    return capture.Finish(result.Release());
  }
};

} // namespace

RUNTIME_TEST_FACTORY(FirstTurnEliminationPhaseTestCase, FirstTurnEliminationPhaseTest)
