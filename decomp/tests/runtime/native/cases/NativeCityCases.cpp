#include "NativeCases.h"
#include "JsonObject.h"

#include "game/city/TCity.h"
#include "game/city/TItemOrder.h"
#include "game/nation/TGreatPower.h"
#include "game/resource_domain_types.h"

namespace {

TItemOrder* ClothingOrder(TGreatPower* nation) {
  return static_cast<TItemOrder*>(nation->city->orderSlotsE4[kResourceClothing]);
}

void SeedClothingInputs(TCity* city) {
  city->CityStockByType(kResourceFabric) = 2;
  city->productionOrderTable1dc[1] = 1;
  city->productionAccum1fc[1] = 1;
}

} // namespace

RuntimeActionResult RunCityItemOrderIncrease(NativeTransition& transition) {
  TGreatPower* nation = ActiveNation();
  TItemOrder* order = ClothingOrder(nation);
  SeedClothingInputs(nation->city);

  JsonObject args;
  args.Set("nation", static_cast<int>(ActiveNationSlot()));
  args.Set("output", "clothing");
  args.Set("quantity", 1);
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }
  return transition.Finish(order->SetQuantity(1));
}

RuntimeActionResult RunCityItemOrderDecrease(NativeTransition& transition) {
  TGreatPower* nation = ActiveNation();
  TItemOrder* order = ClothingOrder(nation);
  SeedClothingInputs(nation->city);
  order->SetQuantity(1);

  JsonObject args;
  args.Set("nation", static_cast<int>(ActiveNationSlot()));
  args.Set("output", "clothing");
  args.Set("quantity", 0);
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }
  return transition.Finish(order->SetQuantity(0));
}

RuntimeActionResult RunPowerPlantUpgrade(NativeTransition& transition) {
  TGreatPower* nation = ActiveNation();
  TCity* city = nation->city;
  city->powerPlantUpgradeQueuedFlag04 = 0;
  nation->treasuryValue10 = 10000;

  JsonObject args;
  args.Set("nation", static_cast<int>(ActiveNationSlot()));
  args.Set("enabled", true);
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  city->BuildPowerPlant(1);
  return transition.Finish();
}

RuntimeActionResult RunCreatedItemsPhase(NativeTransition& transition) {
  TGreatPower* nation = ActiveNation();

  JsonObject args;
  args.Set("nation", static_cast<int>(ActiveNationSlot()));
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  nation->AddCreatedItems();
  return transition.Finish();
}
