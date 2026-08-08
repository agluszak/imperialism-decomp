#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "probes/CityOrderSnapshots.h"
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
#include "game/app/TTransFocusAnimation.h"
#include "game/core/global_data_tables.h"
#include "game/globals/game_session_globals.h"
#include "game/globals/military_ui_globals.h"
#include "game/globals/nation_globals.h"
#include "game/globals/shared_globals.h"
#include "game/map/TZone.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/nation/TGreatPower.h"
#include "game/navy/TOcean.h"
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

// TCity's retail shipyard order layout: the first two entries are merchant hulls, while row four
// is the first navy hull and therefore enters the map's primary ship chain when completed.
const short kFirstNavyShipyardRow = 4;

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
        industrySlot(-1), priorAnimationFrame(0) {}

protected:
  void Script() override {
    RT_BEGIN();

    RT_REQUIRE_NOT_NULL(PlayerCity());
    RT_OPEN_TO("open the city production screen", StrategicMap().OpenCity(), CityScreen);
    RT_REQUIRE(City().HasProductionControls());
    RT_REQUIRE(City().SicknessPlacardsAreCleared());
    RT_AWAIT(HasScenarioUiSnapshot(), kObserveUiStateChanged);

    // One forced repaint has to settle the screen: anything still invalidated afterwards is a
    // paint that invalidates itself, which would spin the message loop forever.
    RT_DO("force one deterministic city paint", City().ForceOnePaint());
    RT_REQUIRE(!City().HasPendingPaint());

    // --- The university: recruiting one graduate reserves population and inputs. ---
    RT_RUN(OpenBuilding(kUniversitySlot, kCityBuildingUniversity, *this));
    RT_REQUIRE_NE(-1, Building().FirstRaisableRow());
    raisedRow = Building().FirstRaisableRow();
    CaptureUnitOrder(Building().UnitOrder(raisedRow));
    RT_DO("recruit one graduate", Building().RaiseRow(raisedRow));
    RT_REQUIRE(UnitOrderWasReserved());
    RT_DO("confirm the university's counts", Building().VerifyLiveOrderState());
    RT_DO("cancel the recruitment", Building().LowerRow(raisedRow));
    RT_REQUIRE(UnitOrderWasRestored());
    RT_DO("confirm the restored university counts", Building().VerifyLiveOrderState());
    RT_RUN(CloseBuilding(*this));

    // --- The armory: same shape, and its unit rows must each describe their own unit. ---
    SeedArmoryInputs();
    RT_RUN(OpenBuilding(kArmorySlot, kCityBuildingArmory, *this));
    RT_REQUIRE_NE(-1, Building().FirstRaisableRow());
    raisedRow = Building().FirstRaisableRow();
    CaptureUnitOrder(Building().UnitOrder(raisedRow));
    RT_DO("order one unit", Building().RaiseRow(raisedRow));
    RT_REQUIRE(UnitOrderWasReserved());
    RT_DO("confirm the armory's state", Building().VerifyLiveOrderState());
    RT_DO("cancel the unit order", Building().LowerRow(raisedRow));
    RT_REQUIRE(UnitOrderWasRestored());
    RT_DO("confirm the restored armory state", Building().VerifyLiveOrderState());
    RT_RUN(CloseBuilding(*this));

    // --- The shipyard: a completed ship reaches the fleet and the merchant marine. ---
    RT_RUN(OpenBuilding(kShipyardSlot, kCityBuildingShipyard, *this));
    RT_REQUIRE_NE(-1, Building().FirstRaisableRow());
    raisedRow = Building().FirstRaisableRow();
    CaptureShipOrder(Building().ShipOrder(raisedRow));
    RT_DO("order one ship", Building().RaiseRow(raisedRow));
    RT_REQUIRE_EQ(shipBefore.quantity + 1, Building().ShipOrder(raisedRow)->quantity);
    RT_DO("confirm the shipyard's counts", Building().VerifyLiveOrderState());
    RT_REQUIRE(CompletedShipOrderUpdatedTheFleet());

    raisedRow = kFirstNavyShipyardRow;
    CaptureShipOrder(Building().ShipOrder(raisedRow));
    RT_DO("order one navy ship", Building().RaiseRow(raisedRow));
    RT_REQUIRE_EQ(shipBefore.quantity + 1, Building().ShipOrder(raisedRow)->quantity);
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
    RT_DO("enrol one trainee", Building().RaiseClusterOrder());
    RT_REQUIRE(TrainingOrderWasReserved());
    RT_DO("confirm the trade school's state", Building().VerifyLiveOrderState());
    RT_REQUIRE(CompletedTrainingResetTheRow());
    RT_DO("confirm the reset trade school row", Building().VerifyLiveOrderState());
    RT_RUN(CloseBuilding(*this));

    // --- An industry: its order animates the building while it is outstanding. ---
    industrySlot = FirstRaisableIndustrySlot();
    RT_REQUIRE_NE(-1, industrySlot);
    RT_RUN(OpenBuilding(industrySlot, kCityBuildingIndustry, *this));
    CaptureItemOrder(Building().ItemOrder());
    RT_REQUIRE(ProductionAnimationIsDormant());
    RT_DO("order one item", Building().RaiseClusterOrder());
    RT_REQUIRE(ItemOrderWasReserved());
    RT_DO("confirm the industry's count", Building().VerifyLiveOrderState());
    RT_REQUIRE_NOT_NULL(Building().ProductionAnimation());
    RT_REQUIRE(Building().ProductionAnimation()->enabledFlag != 0);
    RT_AWAIT(Building().ProductionAnimation()->frameIndex != priorAnimationFrame,
             kObserveApplicationIdle | kObservePaintCompleted);
    RT_DO("cancel the item order", Building().LowerClusterOrder());
    RT_REQUIRE(ItemOrderWasRestored());
    RT_DO("confirm the restored industry count", Building().VerifyLiveOrderState());
    // Cancelling the last outstanding order stops the building working again.
    RT_REQUIRE(Building().ProductionAnimation()->enabledFlag == 0);
    RT_RUN(CloseBuilding(*this));

    RT_CLOSE_TO_MAP("leave the city production screen", City().Close());
    g_pActiveMapOrderContext->RefreshMapActionContextNationOverlaysAndOrderRanks();
    RT_REQUIRE(LiveZoneMasksCountOnlyNationsAtWar());
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
    unitBefore.CaptureFrom(order);
  }

  bool UnitOrderWasReserved() const {
    TUnitOrder* order = unitOrder;
    TPopulationMgr* population = order->productionSummary;
    // One more ordered, its inputs and its cash taken, and one person moved out of the pool.
    return order->quantity == unitBefore.quantity + 1 &&
           order->ownerCity->CityStockByType(order->primaryInputResourceId) ==
               unitBefore.primaryStock - order->primaryInputPerUnit &&
           (order->secondaryInputResourceId < 0 ||
            order->ownerCity->CityStockByType(order->secondaryInputResourceId) ==
                unitBefore.secondaryStock - order->secondaryInputPerUnit) &&
           order->ownerCity->ownerNationAc->treasuryValue10 ==
               unitBefore.treasury - order->cashCostPerUnit &&
           population->populationCount08 == unitBefore.populationCount - 1 &&
           population->populationCountFloat0c == unitBefore.populationFloat - 1.0f &&
           population->strength < unitBefore.strength;
  }

  bool UnitOrderWasRestored() const {
    TUnitOrder* order = unitOrder;
    TPopulationMgr* population = order->productionSummary;
    return order->quantity == unitBefore.quantity &&
           order->ownerCity->CityStockByType(order->primaryInputResourceId) ==
               unitBefore.primaryStock &&
           (order->secondaryInputResourceId < 0 ||
            order->ownerCity->CityStockByType(order->secondaryInputResourceId) ==
                unitBefore.secondaryStock) &&
           order->ownerCity->ownerNationAc->treasuryValue10 == unitBefore.treasury &&
           population->strength == unitBefore.strength &&
           population->populationCount08 == unitBefore.populationCount &&
           population->populationCountFloat0c == unitBefore.populationFloat &&
           population->baselineSlots10->lowSkillCount04 == unitBefore.baselineLow &&
           population->baselineSlots10->mediumSkillCount06 == unitBefore.baselineMedium &&
           population->baselineSlots10->highSkillCount08 == unitBefore.baselineHigh &&
           population->productionSlots14->lowSkillCount04 == unitBefore.productionLow &&
           population->productionSlots14->mediumSkillCount06 == unitBefore.productionMedium &&
           population->productionSlots14->highSkillCount08 == unitBefore.productionHigh;
  }

  void CaptureShipOrder(TShipOrder* order) {
    shipOrder = order;
    shipBefore.CaptureFrom(order);
  }

  // Completing the order is a model call, not a click: no control finishes a ship early. What is
  // asserted is what completion does -- the hulls reach the city, the navy's arms grow by their
  // industry weight, and the merchant marine grows by their cargo weight.
  bool CompletedShipOrderUpdatedTheFleet() {
    const short completedQuantity = shipOrder->quantity;
    const short resourceType = shipOrder->resourceTypeIndex;
    TGreatPower* owner = shipOrder->ownerCity->ownerNationAc;
    shipOrder->Produce();
    owner->RecomputeDiplomacyAidBudgetScoreFromResourceWeights();
    const short expectedCapacity = static_cast<short>(
        shipBefore.merchantCapacity +
        GetResourceDescriptorWeightWord0ByType(resourceType) * completedQuantity);
    const int expectedArms =
        shipBefore.armsInNavy +
        GetIndustryActionCostWeightByResourceType(resourceType) * completedQuantity;
    return shipOrder->quantity == 0 &&
           shipOrder->ownerCity->orderCountByType5c[resourceType] ==
               shipBefore.shipCount + completedQuantity &&
           owner->merchantCapacity == expectedCapacity && owner->GetArmsInNavy() == expectedArms;
  }

  void CaptureTrainingOrder(TTrainingOrder* order) {
    trainingOrder = order;
    trainingBefore.CaptureFrom(order);
  }

  bool TrainingOrderWasReserved() const {
    return trainingOrder->quantity == trainingBefore.quantity + 1 &&
           trainingOrder->ownerCity->cityStockPaperCA == trainingBefore.paperStock - 1 &&
           trainingOrder->ownerCity->ownerNationAc->treasuryValue10 ==
               trainingBefore.treasury - kTrainingCashCost;
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
               trainingBefore.baselineLow - 1 &&
           trainingOrder->productionSummary->baselineSlots10->mediumSkillCount06 ==
               trainingBefore.baselineMedium + 1;
  }

  void CaptureItemOrder(TItemOrder* order) {
    itemOrder = order;
    itemBefore.CaptureFrom(order);
    TTransFocusAnimation* animation = Building().ProductionAnimation();
    // A view reading, not a model one, so it stays here rather than in the snapshot.
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
    return order->quantity == itemBefore.quantity + 1 &&
           order->requestedQuantity4c == order->quantity &&
           order->ownerCity->CityStockByType(order->primaryInputResourceId) ==
               itemBefore.primaryStock - primaryAmount &&
           order->trackingSlots[order->primaryInputResourceId] ==
               itemBefore.primaryTracking + primaryAmount &&
           (order->secondaryInputResourceId < 0 ||
            (order->ownerCity->CityStockByType(order->secondaryInputResourceId) ==
                 itemBefore.secondaryStock - 1 &&
             order->trackingSlots[order->secondaryInputResourceId] ==
                 itemBefore.secondaryTracking + 1)) &&
           order->productionSummary->strength == itemBefore.strength - 2 &&
           order->reservedWorkforce == itemBefore.reservedWorkforce + 2 &&
           order->ownerCity->productionAccum1fc[order->productionSlot] ==
               itemBefore.productionAccum - 1;
  }

  bool ItemOrderWasRestored() const {
    TItemOrder* order = itemOrder;
    return order->quantity == itemBefore.quantity &&
           order->requestedQuantity4c == itemBefore.requestedQuantity &&
           order->ownerCity->CityStockByType(order->primaryInputResourceId) ==
               itemBefore.primaryStock &&
           order->trackingSlots[order->primaryInputResourceId] == itemBefore.primaryTracking &&
           (order->secondaryInputResourceId < 0 ||
            (order->ownerCity->CityStockByType(order->secondaryInputResourceId) ==
                 itemBefore.secondaryStock &&
             order->trackingSlots[order->secondaryInputResourceId] ==
                 itemBefore.secondaryTracking)) &&
           order->productionSummary->strength == itemBefore.strength &&
           order->reservedWorkforce == itemBefore.reservedWorkforce &&
           order->ownerCity->productionAccum1fc[order->productionSlot] ==
               itemBefore.productionAccum;
  }

  // --- Seeding. A fresh Easy game does not always start with enough of everything to place one
  // more order, and this scenario is about the order mechanics rather than about the opening
  // stockpile. Each of these gives the city exactly the retail cost of the one order about to be
  // placed -- never a shortcut around the cost itself. ---

  void SeedArmoryInputs() {
    TCity* city = PlayerCity();
    TUnitOrder* firstOrder = city != 0 ? city->buildOrderSlots148[0] : 0;
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

  bool LiveZoneMasksCountOnlyNationsAtWar() const {
    int examinedRelations = 0;
    for (TZone* zone = g_pMapActionContextListHead; zone != 0; zone = zone->prev18) {
      for (int nation = 0; nation < 7; ++nation) {
        int expected = 0;
        for (int slot = 0; slot < 7; ++slot) {
          if (g_apTerrainTypeDescriptorTable[slot] != 0 &&
              (zone->nationKeyMask10 & (1 << slot)) != 0) {
            ++examinedRelations;
            if (g_pDiplomacyTurnStateManager->IsNationPairAtWar(nation, slot)) {
              ++expected;
            }
          }
        }
        if (zone->CountDiplomaticallyRelatedNationsInKeyMask(nation) != expected) {
          return false;
        }
      }
    }
    return examinedRelations != 0;
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

  // One snapshot per order family, so a field cannot be read as another family's (see
  // probes/CityOrderSnapshots.h). priorAnimationFrame is a *view* reading and stays here.
  UnitOrderSnapshot unitBefore;
  ShipOrderSnapshot shipBefore;
  TrainingOrderSnapshot trainingBefore;
  ItemOrderSnapshot itemBefore;
  short priorAnimationFrame;
};

} // namespace

RUNTIME_TEST_FACTORY(CityScreenTestCase, CityScreenTest)
