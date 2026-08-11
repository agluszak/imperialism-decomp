#include "NativeTransition.h"
#include "JsonObject.h"

#include "game/city/TCity.h"
#include "game/city_ui/TCityInteriorMinister.h"
#include "game/globals/shared_globals.h"
#include "game/nation/TGreatPower.h"
#include "game/resource_domain_types.h"
#include "game/ui_screens/TSimMgr.h"

RuntimeActionResult RunDirectTransport(NativeTransition& transition) {
  const short nationSlot = g_pSimMgr->GetActiveNationId();
  TGreatPower* nation = g_apNationStates[nationSlot];
  if (nation == 0 || nation->city == 0) {
    return RuntimeActionResult::Failure("the loaded player has no city-and-transport state");
  }

  TCity* city = nation->city;
  int resource;
  for (resource = 0; resource < kResourceKindCount; ++resource) {
    nation->needCurrentByType[resource] = 0;
    nation->needTargetByType[resource] = 0;
  }
  nation->needCurrentByType[kResourceCotton] = 7;
  nation->needTargetByType[kResourceCotton] = 7;
  nation->needCurrentByType[kResourceSteel] = 10;
  nation->needTargetByType[kResourceSteel] = 4;
  nation->transportCapacity = 15;
  nation->reservedTransportCapacity = 11;
  city->CityStockByType(kResourceSteel) = 2;

  JsonObject operation;
  operation.Set("nation", static_cast<int>(nationSlot));
  operation.Set("resource", "steel");
  operation.Set("requested", 9);
  RuntimeActionResult started = transition.Begin(operation.Release());
  if (!started.Succeeded()) {
    return started;
  }

  const short transported = city->DirectTransport(kResourceSteel, 9);
  return transition.Finish(static_cast<int>(transported));
}

RuntimeActionResult RunTransportNeedAllocation(NativeTransition& transition) {
  const short nationSlot = g_pSimMgr->GetActiveNationId();
  TGreatPower* nation = g_apNationStates[nationSlot];
  if (nation == 0 || nation->interiorMinister == 0) {
    return RuntimeActionResult::Failure("the loaded player has no interior minister");
  }

  JsonObject operation;
  operation.Set("nation", static_cast<int>(nationSlot));
  RuntimeActionResult started = transition.Begin(operation.Release());
  if (!started.Succeeded()) {
    return started;
  }

  nation->interiorMinister->SetCityPolicies();
  return transition.Finish();
}

RuntimeActionResult RunTransportedItemsPhase(NativeTransition& transition) {
  const short nationSlot = g_pSimMgr->GetActiveNationId();
  TGreatPower* nation = g_apNationStates[nationSlot];
  if (nation == 0 || nation->city == 0) {
    return RuntimeActionResult::Failure("the loaded player has no city-and-transport state");
  }

  TCity* city = nation->city;
  int resource;
  for (resource = 0; resource < kResourceKindCount; ++resource) {
    nation->transportedItemsByResource[resource] = 0;
  }
  city->CityStockByType(kResourceCotton) = 3;
  city->CityStockByType(kResourceWool) = 2;
  city->CityStockByType(kResourceGold) = 11;
  nation->transportedItemsByResource[kResourceCotton] = 5;
  nation->transportedItemsByResource[kResourceWool] = -7;
  nation->transportedItemsByResource[kResourceGold] = 4;

  JsonObject operation;
  operation.Set("nation", static_cast<int>(nationSlot));
  RuntimeActionResult started = transition.Begin(operation.Release());
  if (!started.Succeeded()) {
    return started;
  }

  nation->AddTransportedItems();
  return transition.Finish();
}

RuntimeActionResult RunRollingStockSuccess(NativeTransition& transition) {
  const short nationSlot = g_pSimMgr->GetActiveNationId();
  TGreatPower* nation = g_apNationStates[nationSlot];
  if (nation == 0 || nation->city == 0) {
    return RuntimeActionResult::Failure("the loaded player has no city-and-transport state");
  }

  TCity* city = nation->city;
  city->CityStockByType(kResourceLumber) = 1;
  city->CityStockByType(kResourceSteel) = 1;
  nation->transportCapacity = 15;

  JsonObject operation;
  operation.Set("nation", static_cast<int>(nationSlot));
  RuntimeActionResult started = transition.Begin(operation.Release());
  if (!started.Succeeded()) {
    return started;
  }

  const bool increased = nation->IncreaseRollingStock() != 0;
  return transition.Finish(increased);
}

RuntimeActionResult RunRollingStockInsufficient(NativeTransition& transition) {
  const short nationSlot = g_pSimMgr->GetActiveNationId();
  TGreatPower* nation = g_apNationStates[nationSlot];
  if (nation == 0 || nation->city == 0) {
    return RuntimeActionResult::Failure("the loaded player has no city-and-transport state");
  }

  TCity* city = nation->city;
  city->CityStockByType(kResourceLumber) = 0;
  city->CityStockByType(kResourceSteel) = 1;
  nation->transportCapacity = 15;

  JsonObject operation;
  operation.Set("nation", static_cast<int>(nationSlot));
  RuntimeActionResult started = transition.Begin(operation.Release());
  if (!started.Succeeded()) {
    return started;
  }

  const bool increased = nation->IncreaseRollingStock() != 0;
  return transition.Finish(increased);
}

RuntimeActionResult RunMerchantMarine(NativeTransition& transition) {
  const short nationSlot = g_pSimMgr->GetActiveNationId();
  TGreatPower* nation = g_apNationStates[nationSlot];
  if (nation == 0 || nation->city == 0) {
    return RuntimeActionResult::Failure("the loaded player has no city-and-merchant state");
  }

  TCity* city = nation->city;
  city->CityStockByType(kResourceLumber) = 3;
  city->CityStockByType(kResourceFabric) = 1;
  nation->merchantCapacity = 15;

  JsonObject operation;
  operation.Set("nation", static_cast<int>(nationSlot));
  RuntimeActionResult started = transition.Begin(operation.Release());
  if (!started.Succeeded()) {
    return started;
  }

  const bool increased = nation->IncreaseMerchantMarine() != 0;
  return transition.Finish(increased);
}
