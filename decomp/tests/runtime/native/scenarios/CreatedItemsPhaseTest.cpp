#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"

#include "game/city/TCity.h"
#include "game/globals/shared_globals.h"
#include "game/nation/TGreatPower.h"
#include "game/resource_domain_types.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

// Deliver the active nation's already allocated resources from the retail-produced
// beginning-of-game save. The Rust differential runner will replay this same
// city-and-transport settlement against the complete captured game state.
class CreatedItemsPhaseTestCase : public LoadedMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();

    RT_DO("deliver allocated city resources", AddCreatedItems());
    RT_PASS();

    RT_END();
  }

private:
  RuntimeActionResult AddCreatedItems() {
    const short nationSlot = g_pSimMgr->GetActiveNationId();
    TGreatPower* nation = g_apNationStates[nationSlot];
    if (nation == 0 || nation->city == 0) {
      return RuntimeActionResult::Failure("the loaded player has no city-and-transport state");
    }

    TCity* city = nation->city;
    short targets[kResourceKindCount];
    short previousStocks[kResourceKindCount];
    short resource;
    for (resource = 0; resource < kResourceKindCount; ++resource) {
      targets[resource] = nation->needTargetByType[resource];
      previousStocks[resource] = city->CityStockByType(resource);
    }
    const int expectedTreasury = nation->treasuryValue10 +
                                 static_cast<int>(targets[kResourceGems]) * 500 +
                                 static_cast<int>(targets[kResourceGold]) * 200;

    nation->AddCreatedItems();

    if (nation->treasuryValue10 != expectedTreasury) {
      return RuntimeActionResult::Failure("created-resource treasury settlement diverged");
    }

    for (resource = 0; resource < kResourceKindCount; ++resource) {
      short expectedStock = static_cast<short>(previousStocks[resource] + targets[resource]);
      if (resource == kResourceGems || resource == kResourceGold) {
        expectedStock = targets[resource];
      }
      if (nation->needTargetByType[resource] != targets[resource] ||
          city->CityStockByType(resource) != expectedStock) {
        return RuntimeActionResult::Failure("created-resource delivery diverged from target state");
      }
    }
    return RuntimeActionResult::Success();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(CreatedItemsPhaseTestCase, CreatedItemsPhaseTest)
