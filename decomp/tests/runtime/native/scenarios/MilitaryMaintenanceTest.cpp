#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "JsonObject.h"
#include "RuntimeGameStateCapture.h"
#include "RuntimeRun.h"

#include "game/globals/shared_globals.h"
#include "game/military/TMilitaryUnit.h"
#include "game/military_domain_types.h"
#include "game/nation/TGreatPower.h"
#include "game/navy/TShip.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

// Charge a deliberately small land-and-navy roster. The foreign entries prove that retail
// charges only the selected nation; the before/after game-state captures are the oracle.
class MilitaryMaintenanceTestCase : public LoadedMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();

    RT_DO("charge military maintenance", ChargeMilitaryMaintenance());
    RT_PASS();

    RT_END();
  }

private:
  RuntimeActionResult ChargeMilitaryMaintenance() {
    const NationSlot nationSlot = g_pSimMgr->GetActiveNationId();
    TGreatPower* nation = g_apNationStates[nationSlot];
    const NationSlot foreignNationSlot = nationSlot == 0 ? 1 : 0;
    TGreatPower* foreignNation = g_apNationStates[foreignNationSlot];
    if (nation == 0 || foreignNation == 0 || nation->militaryUnitList44 == 0 ||
        foreignNation->militaryUnitList44 == 0) {
      return RuntimeActionResult::Failure("the loaded game has no major-nation military state");
    }

    while (nation->militaryUnitList44->GetCount() != 0) {
      TMilitaryUnit* unit =
          static_cast<TMilitaryUnit*>(nation->militaryUnitList44->GetEntryByOrdinal(1));
      unit->DetachUnitOrderFromOwnerAndReset();
      unit->Free();
    }

    TMilitaryUnit* ownedMinutemen = new TMilitaryUnit();
    ownedMinutemen->IMilitaryUnit(EncodeMilitaryUnitKind(kMilitaryUnitMinutemen), -1, nationSlot);
    TMilitaryUnit* ownedArtillery = new TMilitaryUnit();
    ownedArtillery->IMilitaryUnit(EncodeMilitaryUnitKind(kMilitaryUnitLightArtillery), -1,
                                  nationSlot);
    TMilitaryUnit* ownedArmor = new TMilitaryUnit();
    ownedArmor->IMilitaryUnit(EncodeMilitaryUnitKind(kMilitaryUnitArmor), -1, nationSlot);
    TMilitaryUnit* foreignArmor = new TMilitaryUnit();
    foreignArmor->IMilitaryUnit(EncodeMilitaryUnitKind(kMilitaryUnitArmor), -1, foreignNationSlot);

    TShip* ownedSlot3 = new TShip();
    ownedSlot3->IShip(3, 0, nationSlot, "maintenance-owned-slot3");
    TShip* ownedSlot9 = new TShip();
    ownedSlot9->IShip(9, 0, nationSlot, "maintenance-owned-slot9");
    TShip* ownedSlot12 = new TShip();
    ownedSlot12->IShip(12, 0, nationSlot, "maintenance-owned-slot12");
    TShip* foreignSlot12 = new TShip();
    foreignSlot12->IShip(12, 0, foreignNationSlot, "maintenance-foreign-slot12");

    nation->treasuryValue10 = 10000;
    nation->militaryExpenses960 = 0;
    if (!CaptureGameState(RunState(), "before")) {
      return RuntimeActionResult::Failure("the before game-state capture is unavailable");
    }

    JsonObject caseCapture;
    caseCapture.Set("nation", static_cast<int>(nationSlot));
    RunState().SetCapture("case", caseCapture.Release());

    nation->PayForMilitary();

    if (!CaptureGameState(RunState(), "after")) {
      return RuntimeActionResult::Failure("the after game-state capture is unavailable");
    }
    return RuntimeActionResult::Success();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(MilitaryMaintenanceTestCase, MilitaryMaintenanceTest)
