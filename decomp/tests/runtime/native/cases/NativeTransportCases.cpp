#include "NativeCases.h"
#include "JsonObject.h"

#include "game/city/TCity.h"
#include "game/city_ui/TCityInteriorMinister.h"
#include "game/nation/TGreatPower.h"
#include "game/resource_domain_types.h"

RuntimeActionResult RunDirectTransport(NativeTransition& transition) {
  TGreatPower* nation = ActiveNation();
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

  JsonObject args;
  args.Set("nation", static_cast<int>(ActiveNationSlot()));
  args.Set("resource", "steel");
  args.Set("requested", 9);
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  const short transported = city->DirectTransport(kResourceSteel, 9);
  return transition.Finish(static_cast<int>(transported));
}

RuntimeActionResult RunTransportNeedAllocation(NativeTransition& transition) {
  TGreatPower* nation = ActiveNation();

  JsonObject args;
  args.Set("nation", static_cast<int>(ActiveNationSlot()));
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  nation->interiorMinister->SetCityPolicies();
  return transition.Finish();
}

RuntimeActionResult RunTransportedItemsPhase(NativeTransition& transition) {
  TGreatPower* nation = ActiveNation();
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

  JsonObject args;
  args.Set("nation", static_cast<int>(ActiveNationSlot()));
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  nation->AddTransportedItems();
  return transition.Finish();
}

RuntimeActionResult RunRollingStockSuccess(NativeTransition& transition) {
  TGreatPower* nation = ActiveNation();
  TCity* city = nation->city;
  city->CityStockByType(kResourceLumber) = 1;
  city->CityStockByType(kResourceSteel) = 1;
  nation->transportCapacity = 15;

  JsonObject args;
  args.Set("nation", static_cast<int>(ActiveNationSlot()));
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  const bool increased = nation->IncreaseRollingStock() != 0;
  return transition.Finish(increased);
}

RuntimeActionResult RunRollingStockInsufficient(NativeTransition& transition) {
  TGreatPower* nation = ActiveNation();
  TCity* city = nation->city;
  city->CityStockByType(kResourceLumber) = 0;
  city->CityStockByType(kResourceSteel) = 1;
  nation->transportCapacity = 15;

  JsonObject args;
  args.Set("nation", static_cast<int>(ActiveNationSlot()));
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  const bool increased = nation->IncreaseRollingStock() != 0;
  return transition.Finish(increased);
}

RuntimeActionResult RunMerchantMarine(NativeTransition& transition) {
  TGreatPower* nation = ActiveNation();
  TCity* city = nation->city;
  city->CityStockByType(kResourceLumber) = 3;
  city->CityStockByType(kResourceFabric) = 1;
  nation->merchantCapacity = 15;

  JsonObject args;
  args.Set("nation", static_cast<int>(ActiveNationSlot()));
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  const bool increased = nation->IncreaseMerchantMarine() != 0;
  return transition.Finish(increased);
}
