#include "NativeCases.h"
#include "JsonArray.h"
#include "JsonObject.h"

#include "game/city/TCity.h"
#include "game/globals/shared_globals.h"
#include "game/nation/TGreatPower.h"
#include "game/resource_domain_types.h"
#include "game/ui_widgets/TTradeMgr.h"

RuntimeActionResult RunMajorTradeSettlement(NativeTransition& transition) {
  TGreatPower* nation = ActiveNation();

  JsonArray settlements;
  JsonObject fabricBuy;
  fabricBuy.Set("resource", "fabric");
  fabricBuy.Set("amount", 3);
  fabricBuy.Set("price", 7);
  settlements.Add(fabricBuy.Release());

  JsonObject clothingSale;
  clothingSale.Set("resource", "clothing");
  clothingSale.Set("amount", -2);
  clothingSale.Set("price", 5);
  settlements.Add(clothingSale.Release());

  JsonObject fabricSale;
  fabricSale.Set("resource", "fabric");
  fabricSale.Set("amount", -1);
  fabricSale.Set("price", 4);
  settlements.Add(fabricSale.Release());

  JsonObject args;
  args.Set("nation", static_cast<int>(ActiveNationSlot()));
  args.Set("settlements", settlements.Release());
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  nation->PurchaseItem(kResourceFabric, 3, 7);
  nation->PurchaseItem(kResourceClothing, -2, 5);
  nation->PurchaseItem(kResourceFabric, -1, 4);
  return transition.Finish();
}

RuntimeActionResult RunPurchasedItemsPhase(NativeTransition& transition) {
  TGreatPower* nation = ActiveNation();
  nation->SetItemPotentials(kResourceFabric, -1);
  nation->SetItemPotentials(kResourceClothing, -1);

  JsonArray purchases;
  JsonObject fabricPurchase;
  fabricPurchase.Set("resource", "fabric");
  fabricPurchase.Set("amount", 3);
  fabricPurchase.Set("price", 7);
  purchases.Add(fabricPurchase.Release());

  JsonObject foodPurchase;
  foodPurchase.Set("resource", "food");
  foodPurchase.Set("amount", -30);
  foodPurchase.Set("price", 1);
  purchases.Add(foodPurchase.Release());

  JsonObject args;
  args.Set("nation", static_cast<int>(ActiveNationSlot()));
  args.Set("purchases", purchases.Release());
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  nation->RememberTradeBids();
  nation->PurchaseItem(kResourceFabric, 3, 7);
  nation->PurchaseItem(kResourceFood, -30, 1);
  nation->AddPurchasedItems();
  return transition.Finish();
}

RuntimeActionResult RunRecallTradeBids(NativeTransition& transition) {
  TGreatPower* nation = ActiveNation();
  TCity* city = nation->city;
  for (int resource = 0; resource < kResourceKindCount; ++resource) {
    nation->rememberedTradeOffersByResource[resource] = 0;
    nation->itemPotentials[resource] = 9;
  }
  city->CityStockByType(kResourceCotton) = 3;
  city->CityStockByType(kResourceWool) = 4;
  city->CityStockByType(kResourceTimber) = 5;
  nation->rememberedTradeOffersByResource[kResourceCotton] = 7;
  nation->rememberedTradeOffersByResource[kResourceWool] = -1;
  nation->rememberedTradeOffersByResource[kResourceTimber] = 2;

  nation->unfilledTradeOfferCount = 4;
  nation->budgetPoolBase = 600;
  nation->budgetPoolDelta = -140;
  nation->merchantCapacity = 19;
  nation->availableMerchantCapacity = 7;
  const int aidAllocationCount = static_cast<int>(sizeof(nation->aidAllocationMatrix) /
                                                  sizeof(nation->aidAllocationMatrix[0]));
  int matrixIndex;
  for (matrixIndex = 0; matrixIndex < aidAllocationCount; ++matrixIndex) {
    nation->aidAllocationMatrix[matrixIndex] = 0;
  }
  nation->aidAllocationMatrix[0] = 17;
  nation->aidAllocationMatrix[aidAllocationCount - 1] = -9;

  JsonObject args;
  args.Set("nation", static_cast<int>(ActiveNationSlot()));
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  nation->RecallTradeBids();
  return transition.Finish();
}

RuntimeActionResult RunPlayerTradePhaseReset(NativeTransition& transition) {
  TGreatPower* nation = ActiveNation();
  TCity* city = nation->city;
  for (int slot = 0; slot < kIndustryActionSlotCount; ++slot) {
    city->orderCountByType5c[slot] = 0;
  }
  city->orderCountByType5c[1] = 2;
  city->orderCountByType5c[5] = 1;
  city->orderCountByType5c[10] = 1;

  for (int resource = 0; resource < kResourceKindCount; ++resource) {
    nation->rememberedTradeOffersByResource[resource] = 0;
    nation->itemPotentials[resource] = 9;
  }
  city->CityStockByType(kResourceCotton) = 3;
  city->CityStockByType(kResourceWool) = 4;
  city->CityStockByType(kResourceTimber) = 5;
  nation->rememberedTradeOffersByResource[kResourceCotton] = 7;
  nation->rememberedTradeOffersByResource[kResourceWool] = -1;
  nation->rememberedTradeOffersByResource[kResourceTimber] = 2;

  nation->unfilledTradeOfferCount = 4;
  nation->budgetPoolBase = 600;
  nation->budgetPoolDelta = -140;
  nation->merchantCapacity = 19;
  nation->availableMerchantCapacity = 7;
  nation->AddAmountToAidAllocationMatrixCellAndTotal(37, kResourceSteel, kMinorNationFirstSlot);

  JsonObject args;
  args.Set("nation", static_cast<int>(ActiveNationSlot()));
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  nation->ResetDiplomacyNeedScoresAndClearAidAllocationMatrix();
  return transition.Finish();
}

RuntimeActionResult RunTradeCapacityRefresh(NativeTransition& transition) {
  TGreatPower* nation = ActiveNation();
  TCity* city = nation->city;
  for (int slot = 0; slot < kIndustryActionSlotCount; ++slot) {
    city->orderCountByType5c[slot] = 0;
  }
  city->orderCountByType5c[1] = 2;
  city->orderCountByType5c[5] = 1;
  city->orderCountByType5c[10] = 1;

  JsonObject args;
  args.Set("nation", static_cast<int>(ActiveNationSlot()));
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  nation->RecomputeDiplomacyAidBudgetScoreFromResourceWeights();
  return transition.Finish();
}

RuntimeActionResult RunTradeMarketPrice(NativeTransition& transition) {
  TTradeMgr* tradeManager = g_pTradeMgr;
  for (int resource = kResourceCotton; resource < kResourceManufacturedEnd; ++resource) {
    TTradeMgr::NationMetricCategoryRow& row = tradeManager->categoryRows[resource];
    row.previousPrice = static_cast<short>(100 + resource);
    row.price = static_cast<short>(400 + resource * 17);
    row.basePrice = static_cast<short>(200 + resource * 13);
    row.numRequests = static_cast<short>(20 + resource);
    row.numOffers = static_cast<short>(40 + resource);
    row.amountOffered = static_cast<short>(60 + resource);
    row.adjustedNumOffers = static_cast<double>(resource) + 0.5;
  }

  TTradeMgr::NationMetricCategoryRow& cotton = tradeManager->categoryRows[kResourceCotton];
  cotton.price = 1000;
  cotton.basePrice = 100;
  cotton.numRequests = 1;
  cotton.adjustedNumOffers = 4.5;

  TTradeMgr::NationMetricCategoryRow& wool = tradeManager->categoryRows[kResourceWool];
  wool.price = 50;
  wool.basePrice = 10;
  wool.numRequests = 20;
  wool.adjustedNumOffers = 10.0;

  TTradeMgr::NationMetricCategoryRow& timber = tradeManager->categoryRows[kResourceTimber];
  timber.price = 50;
  timber.basePrice = 1000;
  timber.numRequests = 0;
  timber.adjustedNumOffers = 100.0;

  TTradeMgr::NationMetricCategoryRow& coal = tradeManager->categoryRows[kResourceCoal];
  coal.price = 400;
  coal.basePrice = 100;
  coal.numRequests = 10;
  coal.adjustedNumOffers = 10.0;

  TTradeMgr::NationMetricCategoryRow& iron = tradeManager->categoryRows[kResourceIron];
  iron.price = 800;
  iron.basePrice = 100;
  iron.numRequests = 10;
  iron.adjustedNumOffers = 10.0;

  TTradeMgr::NationMetricCategoryRow& horses = tradeManager->categoryRows[kResourceHorses];
  horses.price = 720;
  horses.basePrice = 100;
  horses.numRequests = 14;
  horses.adjustedNumOffers = 10.5;

  TTradeMgr::NationMetricCategoryRow& oil = tradeManager->categoryRows[kResourceOil];
  oil.price = 20000;
  oil.basePrice = 200;
  oil.numRequests = 10;
  oil.adjustedNumOffers = 10.0;

  TTradeMgr::NationMetricCategoryRow& food = tradeManager->categoryRows[kResourceFood];
  food.price = 500;
  food.basePrice = 50;
  food.numRequests = 3;
  food.adjustedNumOffers = 11.0;

  TTradeMgr::NationMetricCategoryRow& clothing = tradeManager->categoryRows[kResourceClothing];
  clothing.price = 1700;
  clothing.basePrice = 800;
  clothing.numRequests = 19;
  clothing.adjustedNumOffers = 10.25;

  TTradeMgr::NationMetricCategoryRow& furniture = tradeManager->categoryRows[kResourceFurniture];
  furniture.price = 1850;
  furniture.basePrice = 900;
  furniture.numRequests = 5;
  furniture.adjustedNumOffers = 8.5;

  TTradeMgr::NationMetricCategoryRow& hardware = tradeManager->categoryRows[kResourceHardware];
  hardware.price = 900;
  hardware.basePrice = 600;
  hardware.numRequests = 100;
  hardware.adjustedNumOffers = 0.0;

  TTradeMgr::NationMetricCategoryRow& arms = tradeManager->categoryRows[kResourceArms];
  arms.price = 2222;
  arms.basePrice = 1000;
  arms.numRequests = 77;
  arms.adjustedNumOffers = 3.25;

  RuntimeActionResult started = transition.Begin(JsonNullValue());
  if (!started.Succeeded()) {
    return started;
  }

  tradeManager->CalculateNewWorldPrices();
  return transition.Finish();
}

RuntimeActionResult RunTradePolicySet(NativeTransition& transition) {
  const NationSlot sourceNationSlot = ActiveNationSlot();
  const NationSlot targetNationSlot =
      static_cast<NationSlot>((sourceNationSlot + 1) % kMajorNationCount);
  const short grantAmount = 1000;
  const short kBoycottPolicy = 300;
  TGreatPower* nation = ActiveNation();

  nation->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(targetNationSlot, grantAmount);

  JsonObject args;
  args.Set("nation", static_cast<int>(sourceNationSlot));
  args.Set("target", static_cast<int>(targetNationSlot));
  args.Set("policy", static_cast<int>(kBoycottPolicy));
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  nation->SetTradePolicyTo(targetNationSlot, kBoycottPolicy);
  return transition.Finish();
}

RuntimeActionResult RunTradePolicyStep(NativeTransition& transition) {
  const NationSlot sourceNationSlot = ActiveNationSlot();
  const NationSlot targetNationSlot = sourceNationSlot == 0 ? 1 : 0;
  TGreatPower* nation = ActiveNation();

  nation->needLevelByNation[targetNationSlot] = 75;
  nation->treasuryValue10 = 10001;

  JsonObject args;
  args.Set("source", static_cast<int>(sourceNationSlot));
  args.Set("target", static_cast<int>(targetNationSlot));
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  nation->DecrementNeedLevelByNationStep(targetNationSlot);
  return transition.Finish();
}
