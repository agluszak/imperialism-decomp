#include "NativeCases.h"
#include "JsonObject.h"

#include "game/city/TCity.h"
#include "game/city/TUnitOrder.h"
#include "game/globals/shared_globals.h"
#include "game/military/TMilitaryUnit.h"
#include "game/military_domain_types.h"
#include "game/nation/TGreatPower.h"
#include "game/navy/TShip.h"
#include "game/ui_screens/TSimMgr.h"

RuntimeActionResult RunSpecialistRecruitment(NativeTransition& transition) {
  const short nationSlot = g_pSimMgr->GetActiveNationId();
  TGreatPower* nation = g_apNationStates[nationSlot];
  if (nation == 0 || nation->city == 0 || nation->militaryUnitList44 == 0 ||
      nation->turnSummaryQueue == 0) {
    return RuntimeActionResult::Failure("the loaded player has no recruitment state");
  }

  JsonObject operation;
  operation.Set("nation", static_cast<int>(nationSlot));
  operation.Set("unit_kind", "sappers");
  operation.Set("quantity", 1);
  RuntimeActionResult started = transition.Begin(operation.Release());
  if (!started.Succeeded()) {
    return started;
  }

  TUnitOrder order;
  order.IUnitOrder(nation->city, 24, -1, 0, -1, 0, 0, kHighSkillWorkforceMode, 1);
  order.quantity = 1;
  order.Produce();
  return transition.Finish();
}

RuntimeActionResult RunMilitaryMaintenance(NativeTransition& transition) {
  const NationSlot nationSlot = g_pSimMgr->GetActiveNationId();
  TGreatPower* nation = g_apNationStates[nationSlot];
  const NationSlot foreignNationSlot = nationSlot == 0 ? 1 : 0;
  TGreatPower* foreignNation = g_apNationStates[foreignNationSlot];
  if (nation == 0 || foreignNation == 0 || nation->militaryUnitList44 == 0 ||
      foreignNation->militaryUnitList44 == 0 || g_pMapActionContextListHead == 0) {
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
  ownedSlot3->IShip(3, g_pMapActionContextListHead, nationSlot, "maintenance-owned-slot3");
  TShip* ownedSlot9 = new TShip();
  ownedSlot9->IShip(9, g_pMapActionContextListHead, nationSlot, "maintenance-owned-slot9");
  TShip* ownedSlot12 = new TShip();
  ownedSlot12->IShip(12, g_pMapActionContextListHead, nationSlot, "maintenance-owned-slot12");
  TShip* foreignSlot12 = new TShip();
  foreignSlot12->IShip(12, g_pMapActionContextListHead, foreignNationSlot,
                       "maintenance-foreign-slot12");

  nation->treasuryValue10 = 10000;
  nation->militaryExpenses960 = 0;

  JsonObject operation;
  operation.Set("nation", static_cast<int>(nationSlot));
  RuntimeActionResult started = transition.Begin(operation.Release());
  if (!started.Succeeded()) {
    return started;
  }

  nation->PayForMilitary();
  return transition.Finish();
}
