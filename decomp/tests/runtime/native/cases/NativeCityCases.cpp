#include "NativeTransition.h"
#include "JsonObject.h"

#include "game/city/TCity.h"
#include "game/city/TItemOrder.h"
#include "game/globals/shared_globals.h"
#include "game/nation/TGreatPower.h"
#include "game/resource_domain_types.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

RuntimeActionResult PrepareClothingOrder(TItemOrder** outOrder, short* outNationSlot,
                                         bool seedOne) {
  const short nationSlot = g_pSimMgr->GetActiveNationId();
  TGreatPower* nation = g_apNationStates[nationSlot];
  if (nation == 0 || nation->city == 0 || nation->city->productionSummary1d8 == 0) {
    return RuntimeActionResult::Failure("the loaded player has no complete city state");
  }

  TCity* city = nation->city;
  TProductionOrder* base = city->orderSlotsE4[kResourceClothing];
  if (base == 0) {
    return RuntimeActionResult::Failure("the clothing order is absent");
  }
  TItemOrder* order = static_cast<TItemOrder*>(base);
  if (order->ownerCity != city || order->productionSummary != city->productionSummary1d8 ||
      order->resourceTypeIndex != kResourceClothing ||
      order->primaryInputResourceId != kResourceFabric || order->secondaryInputResourceId != -1 ||
      order->productionSlot != 1 || order->quantity != 0 || order->requestedQuantity4c != 0 ||
      order->reservedWorkforce != 0) {
    return RuntimeActionResult::Failure("the retail fixture has an unexpected clothing order");
  }
  for (int resource = 0; resource < kResourceKindCount; ++resource) {
    if (order->trackingSlots[resource] != 0) {
      return RuntimeActionResult::Failure(
          "the retail fixture clothing order already tracks reserved resources");
    }
  }
  if (city->productionSummary1d8->strength < 2) {
    return RuntimeActionResult::Failure("the retail fixture has insufficient production labor");
  }

  city->CityStockByType(kResourceFabric) = 2;
  city->productionOrderTable1dc[1] = 1;
  city->productionAccum1fc[1] = 1;
  if (seedOne && !order->SetQuantity(1)) {
    return RuntimeActionResult::Failure("the seeded clothing order was rejected");
  }

  *outOrder = order;
  *outNationSlot = nationSlot;
  return RuntimeActionResult::Success();
}

} // namespace

RuntimeActionResult RunCityItemOrderIncrease(NativeTransition& transition) {
  TItemOrder* order = 0;
  short nationSlot = 0;
  RuntimeActionResult prepared = PrepareClothingOrder(&order, &nationSlot, false);
  if (!prepared.Succeeded()) {
    return prepared;
  }

  JsonObject operation;
  operation.Set("nation", static_cast<int>(nationSlot));
  operation.Set("output", "clothing");
  operation.Set("quantity", 1);
  RuntimeActionResult started = transition.Begin(operation.Release());
  if (!started.Succeeded()) {
    return started;
  }
  return transition.Finish(order->SetQuantity(1));
}

RuntimeActionResult RunCityItemOrderDecrease(NativeTransition& transition) {
  TItemOrder* order = 0;
  short nationSlot = 0;
  RuntimeActionResult prepared = PrepareClothingOrder(&order, &nationSlot, true);
  if (!prepared.Succeeded()) {
    return prepared;
  }

  JsonObject operation;
  operation.Set("nation", static_cast<int>(nationSlot));
  operation.Set("output", "clothing");
  operation.Set("quantity", 0);
  RuntimeActionResult started = transition.Begin(operation.Release());
  if (!started.Succeeded()) {
    return started;
  }
  return transition.Finish(order->SetQuantity(0));
}

RuntimeActionResult RunPowerPlantUpgrade(NativeTransition& transition) {
  const short nationSlot = g_pSimMgr->GetActiveNationId();
  TGreatPower* nation = g_apNationStates[nationSlot];
  if (nation == 0 || nation->city == 0) {
    return RuntimeActionResult::Failure("the loaded player has no city economy state");
  }

  TCity* city = nation->city;
  city->powerPlantUpgradeQueuedFlag04 = 0;
  nation->treasuryValue10 = 10000;

  JsonObject operation;
  operation.Set("nation", static_cast<int>(nationSlot));
  operation.Set("enabled", true);
  RuntimeActionResult started = transition.Begin(operation.Release());
  if (!started.Succeeded()) {
    return started;
  }

  city->BuildPowerPlant(1);
  return transition.Finish();
}

RuntimeActionResult RunCreatedItemsPhase(NativeTransition& transition) {
  const short nationSlot = g_pSimMgr->GetActiveNationId();
  TGreatPower* nation = g_apNationStates[nationSlot];
  if (nation == 0 || nation->city == 0) {
    return RuntimeActionResult::Failure("the loaded player has no city-and-transport state");
  }

  JsonObject operation;
  operation.Set("nation", static_cast<int>(nationSlot));
  RuntimeActionResult started = transition.Begin(operation.Release());
  if (!started.Succeeded()) {
    return started;
  }

  nation->AddCreatedItems();
  return transition.Finish();
}
