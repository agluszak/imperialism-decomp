#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "flows/CityBuildingFlow.h"
#include "screens/CityBuildingScreen.h"
#include "screens/CityScreen.h"
#include "screens/ModalScreen.h"
#include "screens/StrategicMapScreen.h"

#include "game/city/TCity.h"
#include "game/city/TItemOrder.h"
#include "game/city/TProductionOrder.h"
#include "game/city/TShipOrder.h"
#include "game/city/TTrainingOrder.h"
#include "game/city/TUnitOrder.h"
#include "game/city_ui/TCityProductionView.h"
#include "game/app/TTransFocusAnimation.h"
#include "game/core/global_data_tables.h"
#include "game/globals/shared_globals.h"
#include "game/map/TMapUberPicture.h"
#include "game/nation/TGreatPower.h"
#include "game/navy_order.h"
#include "game/turn_event_codes.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

// The city's building pages, in the order this scenario visits them. The slot numbers are the
// distance of each building's own turn event from the first, which is how the city view indexes
// its pages.
enum {
  kShipyardSlot = kTurnEventShipyard - kTurnEventTextileMill,
  kArmorySlot = kTurnEventArmory - kTurnEventTextileMill,
  kUniversitySlot = kTurnEventUniversity - kTurnEventTextileMill,
  kTradeSchoolSlot = kTurnEventSchool - kTurnEventTextileMill,
  kRailyardSlot = kTurnEventRailyard - kTurnEventTextileMill
};

// Training one tradesman costs a hundred from the treasury and one paper from the city.
const int kTrainingCashCost = 100;

// The city production screen, building by building.
//
// Each page is opened, checked against the orders behind it, driven up one unit and back down,
// and closed through its own window frame. What differs per building is which order the row
// stands for and what "one more unit" costs, which is what this scenario is really asserting:
// raising an order reserves exactly its inputs, and lowering it returns exactly them.
//
// The shipyard and the trade school do not lower again -- their orders are completed instead, so
// the assertions there are about what completion produces.
class CityScreenTestCase : public EasyMapScriptScenario {
public:
  CityScreenTestCase()
      : buildingSlot(kUniversitySlot), buildingKind(kCityBuildingUniversity), raisedRow(-1),
        industrySlot(-1), priorQuantity(0), priorRequestedQuantity(0), priorPrimaryStock(0),
        priorPrimaryTracking(0), priorSecondaryStock(0), priorSecondaryTracking(0),
        priorStrength(0), priorReservedWorkforce(0), priorProductionAccum(0),
        priorAnimationFrame(0), priorTreasury(0), priorPopulationCount(0), priorPopulationFloat(0),
        priorBaselineLow(0), priorBaselineMedium(0), priorBaselineHigh(0), priorProductionLow(0),
        priorProductionMedium(0), priorProductionHigh(0), priorShipCount(0),
        priorMerchantCapacity(0) {}

  bool RecordsGameFlow() const override {
    return true;
  }
  bool RequiresScenarioUiSnapshot() const override {
    return true;
  }
  void ObserveScenarioUiTree(int eventCode, TView* root) override {
    if (eventCode == kTurnEventCityProduction) {
      CaptureScenarioUiSnapshot(eventCode, root);
    }
  }

protected:
  void Script() override {
    RT_BEGIN();

    RT_REQUIRE_NOT_NULL(PlayerCity());
    RT_OPEN_SCREEN("open the city production screen", StrategicMap().OpenCity(),
                   TCityProductionView, kTurnEventCityProduction);
    RT_REQUIRE(City().HasProductionControls());
    RT_REQUIRE(City().SicknessPlacardsAreCleared());
    RT_AWAIT(HasScenarioUiSnapshot(), kObserveUiStateChanged);

    // One forced repaint has to settle the screen: anything still invalidated afterwards is a
    // paint that invalidates itself, which would spin the message loop forever.
    RT_ACTION("force one deterministic city paint", City().ForceOnePaint());
    RT_REQUIRE(!City().HasPendingPaint());

    // --- The university: recruiting one graduate reserves population and inputs. ---
    RT_RUN(OpenBuilding(kUniversitySlot, kCityBuildingUniversity, *this));
    RT_REQUIRE_NE(-1, Building().FirstRaisableRow());
    raisedRow = Building().FirstRaisableRow();
    CaptureUnitOrder(Building().UnitOrder(raisedRow));
    RT_ACTION("recruit one graduate", Building().RaiseRow(raisedRow));
    RT_REQUIRE(UnitOrderWasReserved());
    RT_STEP("confirm the university's counts", Building().VerifyLiveOrderState());
    RT_ACTION("cancel the recruitment", Building().LowerRow(raisedRow));
    RT_REQUIRE(UnitOrderWasRestored());
    RT_STEP("confirm the restored university counts", Building().VerifyLiveOrderState());
    RT_RUN(CloseBuilding(*this));

    // --- The armory: same shape, and its unit rows must each describe their own unit. ---
    SeedArmoryInputs();
    RT_RUN(OpenBuilding(kArmorySlot, kCityBuildingArmory, *this));
    RT_REQUIRE_NE(-1, Building().FirstRaisableRow());
    raisedRow = Building().FirstRaisableRow();
    CaptureUnitOrder(Building().UnitOrder(raisedRow));
    RT_ACTION("order one unit", Building().RaiseRow(raisedRow));
    RT_REQUIRE(UnitOrderWasReserved());
    RT_STEP("confirm the armory's state", Building().VerifyLiveOrderState());
    RT_ACTION("cancel the unit order", Building().LowerRow(raisedRow));
    RT_REQUIRE(UnitOrderWasRestored());
    RT_STEP("confirm the restored armory state", Building().VerifyLiveOrderState());
    RT_RUN(CloseBuilding(*this));

    // --- The shipyard: a completed ship reaches the fleet and the merchant marine. ---
    RT_RUN(OpenBuilding(kShipyardSlot, kCityBuildingShipyard, *this));
    RT_REQUIRE_NE(-1, Building().FirstRaisableRow());
    raisedRow = Building().FirstRaisableRow();
    CaptureShipOrder(Building().ShipOrder(raisedRow));
    RT_ACTION("order one ship", Building().RaiseRow(raisedRow));
    RT_REQUIRE_EQ(priorQuantity + 1, Building().ShipOrder(raisedRow)->quantity);
    RT_STEP("confirm the shipyard's counts", Building().VerifyLiveOrderState());
    RT_REQUIRE(CompletedShipOrderUpdatedTheFleet());
    RT_RUN(CloseBuilding(*this));

    // --- The railyard: opened only to confirm its count, which the open sequence does. It has no
    // order this scenario can raise. ---
    RT_RUN(OpenBuilding(kRailyardSlot, kCityBuildingRailyard, *this));
    RT_RUN(CloseBuilding(*this));

    // --- The trade school: a completed training moves one worker up a skill band. ---
    SeedTradeSchoolInputs();
    RT_RUN(OpenBuilding(kTradeSchoolSlot, kCityBuildingTradeSchool, *this));
    CaptureTrainingOrder(Building().TrainingOrder());
    RT_ACTION("enrol one trainee", Building().RaiseClusterOrder());
    RT_REQUIRE(TrainingOrderWasReserved());
    RT_STEP("confirm the trade school's state", Building().VerifyLiveOrderState());
    RT_REQUIRE(CompletedTrainingResetTheRow());
    RT_STEP("confirm the reset trade school row", Building().VerifyLiveOrderState());
    RT_RUN(CloseBuilding(*this));

    // --- An industry: its order animates the building while it is outstanding. ---
    industrySlot = FirstRaisableIndustrySlot();
    RT_REQUIRE_NE(-1, industrySlot);
    RT_RUN(OpenBuilding(industrySlot, kCityBuildingIndustry, *this));
    CaptureItemOrder(Building().ItemOrder());
    RT_REQUIRE(ProductionAnimationIsDormant());
    RT_ACTION("order one item", Building().RaiseClusterOrder());
    RT_REQUIRE(ItemOrderWasReserved());
    RT_STEP("confirm the industry's count", Building().VerifyLiveOrderState());
    RT_REQUIRE_NOT_NULL(Building().ProductionAnimation());
    RT_REQUIRE(Building().ProductionAnimation()->enabledFlag != 0);
    RT_AWAIT(Building().ProductionAnimation()->frameIndex != priorAnimationFrame,
             kObserveApplicationIdle | kObservePaintCompleted);
    RT_ACTION("cancel the item order", Building().LowerClusterOrder());
    RT_REQUIRE(ItemOrderWasRestored());
    RT_STEP("confirm the restored industry count", Building().VerifyLiveOrderState());
    // Cancelling the last outstanding order stops the building working again.
    RT_REQUIRE(Building().ProductionAnimation()->enabledFlag == 0);
    RT_RUN(CloseBuilding(*this));

    RT_CLOSE_TO_MAP("leave the city production screen", City().Close());
    RT_PASS();

    RT_END();
  }

private:
  CityBuildingScreen Building() const {
    return CityBuildingScreen(buildingSlot, buildingKind);
  }

  short ActiveNation() const {
    return g_pSimMgr->GetActiveNationId();
  }

  TGreatPower* Player() const {
    return g_apNationStates[ActiveNation()];
  }

  TCity* PlayerCity() const {
    TGreatPower* player = Player();
    return player != 0 ? player->city : 0;
  }

  // Opening a page: click the building, wait for its window, then check it is the page it claims
  // to be and wears the retail floating frame.
  RuntimeScriptStatus OpenBuilding(short slot, CityBuildingKind kind,
                                   RuntimeScriptScenario& scenario) {
    buildingSlot = slot;
    buildingKind = kind;
    return openBuilding.Open(slot, kind, scenario);
  }

  RuntimeScriptStatus CloseBuilding(RuntimeScriptScenario& scenario) {
    return closeBuilding.Close(buildingSlot, buildingKind, scenario);
  }

  // --- Model snapshots. These read the orders the page is showing, never the page itself. ---

  void CaptureUnitOrder(TUnitOrder* order) {
    unitOrder = order;
    priorQuantity = order->quantity;
    priorPrimaryStock = order->ownerCity->CityStockByType(order->primaryInputResourceId);
    priorSecondaryStock = order->secondaryInputResourceId < 0
                              ? 0
                              : order->ownerCity->CityStockByType(order->secondaryInputResourceId);
    priorTreasury = order->ownerCity->ownerNationAc->treasuryValue10;
    TPopulationMgr* population = order->productionSummary;
    priorStrength = population->strength;
    priorPopulationCount = population->populationCount08;
    priorPopulationFloat = population->populationCountFloat0c;
    priorBaselineLow = population->baselineSlots10->lowSkillCount04;
    priorBaselineMedium = population->baselineSlots10->mediumSkillCount06;
    priorBaselineHigh = population->baselineSlots10->highSkillCount08;
    priorProductionLow = population->productionSlots14->lowSkillCount04;
    priorProductionMedium = population->productionSlots14->mediumSkillCount06;
    priorProductionHigh = population->productionSlots14->highSkillCount08;
  }

  bool UnitOrderWasReserved() const {
    TUnitOrder* order = unitOrder;
    TPopulationMgr* population = order->productionSummary;
    // One more ordered, its inputs and its cash taken, and one person moved out of the pool.
    return order->quantity == priorQuantity + 1 &&
           order->ownerCity->CityStockByType(order->primaryInputResourceId) ==
               priorPrimaryStock - order->primaryInputPerUnit &&
           (order->secondaryInputResourceId < 0 ||
            order->ownerCity->CityStockByType(order->secondaryInputResourceId) ==
                priorSecondaryStock - order->secondaryInputPerUnit) &&
           order->ownerCity->ownerNationAc->treasuryValue10 ==
               priorTreasury - order->cashCostPerUnit &&
           population->populationCount08 == priorPopulationCount - 1 &&
           population->populationCountFloat0c == priorPopulationFloat - 1.0f &&
           population->strength < priorStrength;
  }

  bool UnitOrderWasRestored() const {
    TUnitOrder* order = unitOrder;
    TPopulationMgr* population = order->productionSummary;
    return order->quantity == priorQuantity &&
           order->ownerCity->CityStockByType(order->primaryInputResourceId) == priorPrimaryStock &&
           (order->secondaryInputResourceId < 0 ||
            order->ownerCity->CityStockByType(order->secondaryInputResourceId) ==
                priorSecondaryStock) &&
           order->ownerCity->ownerNationAc->treasuryValue10 == priorTreasury &&
           population->strength == priorStrength &&
           population->populationCount08 == priorPopulationCount &&
           population->populationCountFloat0c == priorPopulationFloat &&
           population->baselineSlots10->lowSkillCount04 == priorBaselineLow &&
           population->baselineSlots10->mediumSkillCount06 == priorBaselineMedium &&
           population->baselineSlots10->highSkillCount08 == priorBaselineHigh &&
           population->productionSlots14->lowSkillCount04 == priorProductionLow &&
           population->productionSlots14->mediumSkillCount06 == priorProductionMedium &&
           population->productionSlots14->highSkillCount08 == priorProductionHigh;
  }

  void CaptureShipOrder(TShipOrder* order) {
    shipOrder = order;
    priorQuantity = order->quantity;
    priorShipCount = order->ownerCity->orderCountByType5c[order->resourceTypeIndex];
    order->ownerCity->ownerNationAc->RecomputeDiplomacyAidBudgetScoreFromResourceWeights();
    priorMerchantCapacity = order->ownerCity->ownerNationAc->merchantCapacity;
  }

  // Completing the order is a model call, not a click: no control finishes a ship early. What is
  // asserted is what completion does -- the hulls reach the city and the merchant marine grows by
  // the ships' own weight.
  bool CompletedShipOrderUpdatedTheFleet() {
    const short completedQuantity = shipOrder->quantity;
    const short resourceType = shipOrder->resourceTypeIndex;
    TGreatPower* owner = shipOrder->ownerCity->ownerNationAc;
    shipOrder->Produce();
    owner->RecomputeDiplomacyAidBudgetScoreFromResourceWeights();
    const short expectedCapacity = static_cast<short>(
        priorMerchantCapacity +
        GetResourceDescriptorWeightWord0ByType(resourceType) * completedQuantity);
    return shipOrder->quantity == 0 &&
           shipOrder->ownerCity->orderCountByType5c[resourceType] ==
               priorShipCount + completedQuantity &&
           owner->merchantCapacity == expectedCapacity;
  }

  void CaptureTrainingOrder(TTrainingOrder* order) {
    trainingOrder = order;
    priorQuantity = order->quantity;
    priorPrimaryStock = order->ownerCity->cityStockPaperCA;
    priorTreasury = order->ownerCity->ownerNationAc->treasuryValue10;
    priorBaselineLow = order->productionSummary->baselineSlots10->lowSkillCount04;
    priorBaselineMedium = order->productionSummary->baselineSlots10->mediumSkillCount06;
  }

  bool TrainingOrderWasReserved() const {
    return trainingOrder->quantity == priorQuantity + 1 &&
           trainingOrder->ownerCity->cityStockPaperCA == priorPrimaryStock - 1 &&
           trainingOrder->ownerCity->ownerNationAc->treasuryValue10 ==
               priorTreasury - kTrainingCashCost;
  }

  // A finished training empties the row -- the bar has to follow the order back to zero, which is
  // what the completion path refreshes it for.
  bool CompletedTrainingResetTheRow() {
    trainingOrder->Produce();
    if (!Building().RefreshClusterAmount().Succeeded()) {
      return false;
    }
    return trainingOrder->quantity == 0 &&
           trainingOrder->productionSummary->baselineSlots10->lowSkillCount04 ==
               priorBaselineLow - 1 &&
           trainingOrder->productionSummary->baselineSlots10->mediumSkillCount06 ==
               priorBaselineMedium + 1;
  }

  void CaptureItemOrder(TItemOrder* order) {
    itemOrder = order;
    priorQuantity = order->quantity;
    priorRequestedQuantity = order->requestedQuantity4c;
    priorPrimaryStock = order->ownerCity->CityStockByType(order->primaryInputResourceId);
    priorPrimaryTracking = order->trackingSlots[order->primaryInputResourceId];
    priorSecondaryStock = order->secondaryInputResourceId < 0
                              ? 0
                              : order->ownerCity->CityStockByType(order->secondaryInputResourceId);
    priorSecondaryTracking = order->secondaryInputResourceId < 0
                                 ? 0
                                 : order->trackingSlots[order->secondaryInputResourceId];
    priorStrength = order->productionSummary->strength;
    priorReservedWorkforce = order->reservedWorkforce;
    priorProductionAccum = order->ownerCity->productionAccum1fc[order->productionSlot];
    TTransFocusAnimation* animation = Building().ProductionAnimation();
    priorAnimationFrame = animation != 0 ? animation->frameIndex : -1;
  }

  bool ProductionAnimationIsDormant() const {
    TTransFocusAnimation* animation = Building().ProductionAnimation();
    // Dormant but ready: it must already hold its frames and its surface, or "it started
    // animating" would only prove it was built late.
    return animation != 0 && animation->enabledFlag == 0 && animation->frameCount > 1 &&
           animation->insetBitmapSurface != 0;
  }

  bool ItemOrderWasReserved() const {
    TItemOrder* order = itemOrder;
    // A single-input item consumes two of it; a two-input item takes one of each.
    const short primaryAmount = order->secondaryInputResourceId < 0 ? 2 : 1;
    return order->quantity == priorQuantity + 1 && order->requestedQuantity4c == order->quantity &&
           order->ownerCity->CityStockByType(order->primaryInputResourceId) ==
               priorPrimaryStock - primaryAmount &&
           order->trackingSlots[order->primaryInputResourceId] ==
               priorPrimaryTracking + primaryAmount &&
           (order->secondaryInputResourceId < 0 ||
            (order->ownerCity->CityStockByType(order->secondaryInputResourceId) ==
                 priorSecondaryStock - 1 &&
             order->trackingSlots[order->secondaryInputResourceId] ==
                 priorSecondaryTracking + 1)) &&
           order->productionSummary->strength == priorStrength - 2 &&
           order->reservedWorkforce == priorReservedWorkforce + 2 &&
           order->ownerCity->productionAccum1fc[order->productionSlot] == priorProductionAccum - 1;
  }

  bool ItemOrderWasRestored() const {
    TItemOrder* order = itemOrder;
    return order->quantity == priorQuantity &&
           order->requestedQuantity4c == priorRequestedQuantity &&
           order->ownerCity->CityStockByType(order->primaryInputResourceId) == priorPrimaryStock &&
           order->trackingSlots[order->primaryInputResourceId] == priorPrimaryTracking &&
           (order->secondaryInputResourceId < 0 ||
            (order->ownerCity->CityStockByType(order->secondaryInputResourceId) ==
                 priorSecondaryStock &&
             order->trackingSlots[order->secondaryInputResourceId] == priorSecondaryTracking)) &&
           order->productionSummary->strength == priorStrength &&
           order->reservedWorkforce == priorReservedWorkforce &&
           order->ownerCity->productionAccum1fc[order->productionSlot] == priorProductionAccum;
  }

  // --- Seeding. A fresh Easy game does not always start with enough of everything to place one
  // more order, and this scenario is about the order mechanics rather than about the opening
  // stockpile. Each of these gives the city exactly the retail cost of the one order about to be
  // placed -- never a shortcut around the cost itself. ---

  void SeedArmoryInputs() {
    TCity* city = PlayerCity();
    TUnitOrder* firstOrder = city != 0 ? city->buildOrderSlots[0] : 0;
    if (firstOrder != 0) {
      city->CityStockByType(firstOrder->primaryInputResourceId) =
          static_cast<short>(firstOrder->primaryInputPerUnit * 2);
    }
  }

  void SeedTradeSchoolInputs() {
    TCity* city = PlayerCity();
    if (city == 0) {
      return;
    }
    if (city->cityStockPaperCA < 1) {
      city->cityStockPaperCA = 1;
    }
    if (city->ownerNationAc->ComputeAvailableDiplomacyBudget() < kTrainingCashCost) {
      city->ownerNationAc->treasuryValue10 += kTrainingCashCost;
    }
  }

  // An industry page whose building exists, whose order can still be raised, and which has an
  // animation to watch. Chosen before the page is opened, so it reads the city's orders rather
  // than the page's controls.
  short FirstRaisableIndustrySlot() const {
    TCity* city = PlayerCity();
    if (city == 0) {
      return -1;
    }
    for (short slot = 1; slot < kIndustryPageLimit; ++slot) {
      const short unitType = CityBuildingScreen::IndustryUnitTypeForSlot(slot);
      TProductionOrder* order = unitType >= 0 ? city->orderSlotsE4[unitType] : 0;
      if (city->GetBuildingType(slot) > 0 && order != 0 && order->MaxOrder() > order->quantity &&
          City().HasBuildingAnimation(slot)) {
        return slot;
      }
    }
    return -1;
  }

  enum { kIndustryPageLimit = 7 };

  OpenCityBuildingFlow openBuilding;
  CloseCityBuildingFlow closeBuilding;

  TUnitOrder* unitOrder;
  TShipOrder* shipOrder;
  TTrainingOrder* trainingOrder;
  TItemOrder* itemOrder;

  short buildingSlot;
  CityBuildingKind buildingKind;
  short raisedRow;
  short industrySlot;

  short priorQuantity;
  short priorRequestedQuantity;
  short priorPrimaryStock;
  short priorPrimaryTracking;
  short priorSecondaryStock;
  short priorSecondaryTracking;
  short priorStrength;
  short priorReservedWorkforce;
  short priorProductionAccum;
  short priorAnimationFrame;
  int priorTreasury;
  short priorPopulationCount;
  float priorPopulationFloat;
  short priorBaselineLow;
  short priorBaselineMedium;
  short priorBaselineHigh;
  short priorProductionLow;
  short priorProductionMedium;
  short priorProductionHigh;
  short priorShipCount;
  short priorMerchantCapacity;
};

} // namespace

RUNTIME_TEST_FACTORY(CityScreenTestCase, CityScreenTest)
