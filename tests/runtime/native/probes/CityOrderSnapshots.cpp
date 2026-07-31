#include "CityOrderSnapshots.h"

#include "game/city/TCity.h"
#include "game/city/TItemOrder.h"
#include "game/city/TProductionOrder.h"
#include "game/city/TShipOrder.h"
#include "game/city/TTrainingOrder.h"
#include "game/city/TUnitOrder.h"
#include "game/nation/TGreatPower.h"
#include "game/resource_domain_types.h"

UnitOrderSnapshot::UnitOrderSnapshot()
    : quantity(0), primaryStock(0), secondaryStock(0), strength(0), populationCount(0),
      baselineLow(0), baselineMedium(0), baselineHigh(0), productionLow(0), productionMedium(0),
      productionHigh(0), treasury(0), populationFloat(0) {}

void UnitOrderSnapshot::CaptureFrom(TUnitOrder* order) {
  quantity = order->quantity;
  primaryStock = order->ownerCity->CityStockByType(order->primaryInputResourceId);
  // A secondary input is optional; -1 means the order has none, and 0 is the honest reading.
  secondaryStock = order->secondaryInputResourceId < 0
                       ? 0
                       : order->ownerCity->CityStockByType(order->secondaryInputResourceId);
  treasury = order->ownerCity->ownerNationAc->treasuryValue10;
  TPopulationMgr* population = order->productionSummary;
  strength = population->strength;
  populationCount = population->populationCount08;
  populationFloat = population->populationCountFloat0c;
  baselineLow = population->baselineSlots10->lowSkillCount04;
  baselineMedium = population->baselineSlots10->mediumSkillCount06;
  baselineHigh = population->baselineSlots10->highSkillCount08;
  productionLow = population->productionSlots14->lowSkillCount04;
  productionMedium = population->productionSlots14->mediumSkillCount06;
  productionHigh = population->productionSlots14->highSkillCount08;
}

ShipOrderSnapshot::ShipOrderSnapshot() : quantity(0), shipCount(0), merchantCapacity(0) {}

void ShipOrderSnapshot::CaptureFrom(TShipOrder* order) {
  quantity = order->quantity;
  shipCount = order->ownerCity->orderCountByType5c[order->resourceTypeIndex];
  // The capacity is derived, so it has to be recomputed before it can be read as a baseline.
  order->ownerCity->ownerNationAc->RecomputeDiplomacyAidBudgetScoreFromResourceWeights();
  merchantCapacity = order->ownerCity->ownerNationAc->merchantCapacity;
}

TrainingOrderSnapshot::TrainingOrderSnapshot()
    : quantity(0), paperStock(0), baselineLow(0), baselineMedium(0), treasury(0) {}

void TrainingOrderSnapshot::CaptureFrom(TTrainingOrder* order) {
  quantity = order->quantity;
  paperStock = order->ownerCity->cityStockPaperCA;
  treasury = order->ownerCity->ownerNationAc->treasuryValue10;
  baselineLow = order->productionSummary->baselineSlots10->lowSkillCount04;
  baselineMedium = order->productionSummary->baselineSlots10->mediumSkillCount06;
}

ItemOrderSnapshot::ItemOrderSnapshot()
    : quantity(0), requestedQuantity(0), primaryStock(0), primaryTracking(0), secondaryStock(0),
      secondaryTracking(0), reservedWorkforce(0), productionAccum(0), strength(0), treasury(0) {}

void ItemOrderSnapshot::CaptureFrom(TItemOrder* order) {
  quantity = order->quantity;
  requestedQuantity = order->requestedQuantity4c;
  primaryStock = order->ownerCity->CityStockByType(order->primaryInputResourceId);
  primaryTracking = order->trackingSlots[order->primaryInputResourceId];
  secondaryStock = order->secondaryInputResourceId < 0
                       ? 0
                       : order->ownerCity->CityStockByType(order->secondaryInputResourceId);
  secondaryTracking = order->secondaryInputResourceId < 0
                          ? 0
                          : order->trackingSlots[order->secondaryInputResourceId];
  strength = order->productionSummary->strength;
  reservedWorkforce = order->reservedWorkforce;
  productionAccum = order->ownerCity->productionAccum1fc[order->productionSlot];
}
