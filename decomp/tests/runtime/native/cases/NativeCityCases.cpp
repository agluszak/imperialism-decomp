#include "NativeCases.h"
#include "JsonObject.h"

#include "game/city/TCity.h"
#include "game/city/TItemOrder.h"
#include "game/city/TPopGrowthOrder.h"
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

RuntimeActionResult RunPopulationGrowthOrderIsOneShot(NativeTransition& transition) {
  TGreatPower* nation = ActiveNation();
  TCity* city = nation->city;
  TPopGrowthOrder* order = static_cast<TPopGrowthOrder*>(city->trailingOrderSlots1b0[9]);
  order->SetQuantity(0);
  city->cityStockFurnitureD2 = static_cast<short>(city->cityStockFurnitureD2 + 1);
  city->cityStockClothingD0 = static_cast<short>(city->cityStockClothingD0 + 1);
  city->cityStockCannedFoodC4 = static_cast<short>(city->cityStockCannedFoodC4 + 1);
  city->productionAccum1fc[0x0f] = static_cast<short>(city->productionAccum1fc[0x0f] + 1);
  if (!order->SetQuantity(1)) {
    return RuntimeActionResult::Failure("could not prepare a paid population-growth order");
  }

  JsonObject args;
  args.Set("nation", static_cast<int>(ActiveNationSlot()));
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  short populationBefore = city->productionSummary1d8->populationCount08;
  city->EndCityPhase();
  short populationAfterFirstPhase = city->productionSummary1d8->populationCount08;
  city->EndCityPhase();
  if (order->quantity != 0 || populationAfterFirstPhase != populationBefore + 1 ||
      city->productionSummary1d8->populationCount08 != populationAfterFirstPhase) {
    return RuntimeActionResult::Failure(
        "population-growth order was not consumed exactly once");
  }
  return transition.Finish();
}
