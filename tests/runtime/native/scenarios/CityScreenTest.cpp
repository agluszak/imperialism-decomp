#include "RuntimeScenario.h"
#include "flows/RandomGameFlow.h"
#include "RuntimeUiDriver.h"
#include "screens/StrategicMapDriver.h"

#include "game/city/TCity.h"
#include "game/city/TItemOrder.h"
#include "game/city/TProductionOrder.h"
#include "game/city/TShipOrder.h"
#include "game/city/TUnitOrder.h"
#include "game/city_ui/TArmoryView.h"
#include "game/city_ui/TBuildingView.h"
#include "game/city_ui/TCityProductionView.h"
#include "game/city_ui/TIndustryView.h"
#include "game/city_ui/TShipyardView.h"
#include "game/city_ui/TUniversityView.h"
#include "game/globals/prelude.h"
#include "game/globals/city_ui_globals.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"
#include "game/gfx/TModuleLibraryCacheTableStateB.h"
#include "game/map/TMapUberPicture.h"
#include "game/nation/TGreatPower.h"
#include "game/turn_event_codes.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_core/TWindow.h"
#include "game/ui_core/TNumberText.h"
#include "game/ui_core/TStaticText.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/ui_tags_city.h"
#include "game/ui_tags_common.h"
#include "game/ui_widgets/TIndustryCluster.h"
#include "game/ui_widgets/TPlacard.h"
#include "game/ui_widgets/TRailCluster.h"
#include "game/ui_widgets/TCivilianButton.h"

namespace {

class CityScreenTestCase : public RandomGameScenario {
public:
  CityScreenTestCase()
      : phase(kActivateCityScreen), activeBuildingSlot(kUniversityBuildingSlot),
        interactionComplete(false), interactionKind(kNoInteraction), interactionUnitOrder(0),
        interactionItemOrder(0), interactionShipOrder(0), interactionRowTag(0) {}
  int DifficultyLevel() const override {
    return 1;
  }
  bool RecordsGameFlow() const override {
    return true;
  }
  bool RequiresScenarioUiSnapshot() const override {
    return true;
  }

  void OnMapReadyWithoutCapitalSelection() override {
    phase = kActivateCityScreen;
    EnterScenarioStep("activating_city_screen", "easy_combined_map_ready_for_city_screen");
    RequestScenarioTick();
  }

  void TickScenario() override {
    if (phase == kActivateCityScreen) {
      ActivateCityScreen();
    } else if (phase == kWaitForCityScreen) {
      WaitForCityScreen();
    } else if (phase == kActivateBuilding) {
      ActivateBuilding();
    } else if (phase == kWaitForBuilding) {
      WaitForBuilding();
    } else if (phase == kWaitForOrderIncrease) {
      WaitForOrderIncrease();
    } else if (phase == kWaitForOrderRestore) {
      WaitForOrderRestore();
    } else if (phase == kWaitForBuildingClose) {
      WaitForBuildingClose();
    } else if (phase == kReturnToMap) {
      ReturnToMap();
    } else {
      WaitForMap();
    }
  }

  void ObserveScenarioUiTree(int eventCode, TView* root) override {
    if (eventCode == kTurnEventCityProduction) {
      CaptureScenarioUiSnapshot(eventCode, root);
    }
  }

private:
  enum Phase {
    kActivateCityScreen,
    kWaitForCityScreen,
    kActivateBuilding,
    kWaitForBuilding,
    kWaitForOrderIncrease,
    kWaitForOrderRestore,
    kWaitForBuildingClose,
    kReturnToMap,
    kWaitForMap
  };

  enum {
    kShipyardBuildingSlot = kTurnEventShipyard - kTurnEventTextileMill,
    kArmoryBuildingSlot = kTurnEventArmory - kTurnEventTextileMill,
    kUniversityBuildingSlot = kTurnEventUniversity - kTurnEventTextileMill,
    kRailyardBuildingSlot = kTurnEventRailyard - kTurnEventTextileMill
  };

  enum InteractionKind {
    kNoInteraction,
    kUniversityInteraction,
    kArmoryInteraction,
    kShipyardInteraction,
    kItemInteraction
  };

  void ActivateCityScreen() {
    if (ScenarioPhaseTicks() < 60) {
      RequestScenarioTick();
      return;
    }
    TView* mainView = CurrentMainView();
    if (g_pUiRuntimeContext->currentTurnEventCode != kTurnEventStrategicMap || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TMapUberPicture)) == 0 || !g_ModalViewStack.IsEmpty()) {
      WaitForScenarioTick("\"combined map was not idle before opening the city screen\"");
      return;
    }
    TGreatPower* activeNation = g_apNationStates[g_pSimMgr->GetActiveNationId()];
    if (activeNation == 0 || activeNation->city == 0) {
      FailScenario("\"active nation has no city state before opening the city screen\"");
      return;
    }
    phase = kWaitForCityScreen;
    EnterScenarioStep("waiting_for_city_screen", "activate_city_toolbar_control");
    StrategicMapDriver map(mainView);
    if (!map.ActivateCitySemantically()) {
      FailScenario("\"city toolbar control is missing or disabled\"");
      return;
    }
    RequestScenarioTick();
  }

  void WaitForCityScreen() {
    TView* mainView = CurrentMainView();
    if (g_pUiRuntimeContext->currentTurnEventCode != kTurnEventCityProduction || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TCityProductionView)) == 0) {
      WaitForScenarioTick("\"city toolbar action did not activate the city production view\"");
      return;
    }
    if (!g_ModalViewStack.IsEmpty()) {
      RecordUnexpectedModalView(static_cast<TView*>(g_ModalViewStack.GetHead()));
      FailScenario("\"city toolbar action opened an unexpected modal\"");
      return;
    }
    TCityProductionView* cityView = static_cast<TCityProductionView*>(mainView);
    if (cityView->ResolveControlByTag(kControlTagLabP) == 0 ||
        cityView->ResolveControlByTag(kControlTagMeat) == 0) {
      FailScenario("\"city production view is missing required production controls\"");
      return;
    }
    TPlacard* sickPlacard = static_cast<TPlacard*>(cityView->ResolveControlByTag(kControlTagSick));
    TPlacard* deadPlacard = static_cast<TPlacard*>(
        cityView->ResolveControlByTag(IMPERIALISM_FOURCC('d', 'e', 'a', 'd')));
    if (sickPlacard == 0 || deadPlacard == 0) {
      FailScenario("\"city production view is missing sickness status placards\"");
      return;
    }
    if (sickPlacard->glyph90 != 0 || sickPlacard->field04 != 0 || deadPlacard->glyph90 != 0 ||
        deadPlacard->field04 != 0) {
      FailScenario("\"zero-count sickness status placards remained visible\"");
      return;
    }
    if (!HasScenarioUiSnapshot()) {
      WaitForScenarioTick("\"city production UI tree was not captured\"");
      return;
    }
    // Keep the production view live long enough to expose repaint/invalidation loops.
    // A tick-only wait completes in a few milliseconds because the driver posts its
    // own messages, which previously let TPlacard::Draw self-invalidation escape.
    if (ScenarioPhaseTicks() < 20 || ScenarioPhaseElapsedMs() < 1000) {
      RequestScenarioTick();
      return;
    }
    phase = kActivateBuilding;
    EnterScenarioStep("activating_city_building", "activate_university_building_slot");
    RequestScenarioTick();
  }

  void ActivateBuilding() {
    TView* mainView = CurrentMainView();
    if (g_pUiRuntimeContext->currentTurnEventCode != kTurnEventCityProduction || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TCityProductionView)) == 0) {
      FailScenario("\"city production view disappeared before building activation\"");
      return;
    }
    TCityProductionView* cityView = static_cast<TCityProductionView*>(mainView);
    interactionComplete = false;
    interactionKind = kNoInteraction;
    phase = kWaitForBuilding;
    EnterScenarioStep("waiting_for_city_building", "activate_city_building_hit_region");
    if (!cityView->ActivateBuildingSlotForRuntimeTest(activeBuildingSlot)) {
      FailScenario("\"city production building hit region is missing or inactive\"");
      return;
    }
    RequestScenarioTick();
  }

  bool HasCorrectNumberTextPresentationState(TNumberText* numberText, short fontSize,
                                             COLORREF textColor) {
    return numberText->field04 == 0 && numberText->field08 != 0 &&
           numberText->stylePayload48 == 0 && numberText->textStyle78.fontFamily == 3 &&
           numberText->textStyle78.fontStyleFlags == 0 &&
           numberText->textStyle78.fontSize == fontSize &&
           numberText->textStyle78.textColor == textColor &&
           numberText->absoluteX == numberText->ownerContext->absoluteX + numberText->ownerLocalX &&
           numberText->absoluteY == numberText->ownerContext->absoluteY + numberText->ownerLocalY &&
           numberText->frameWidth34 > 0 && numberText->frameHeight38 > 0;
  }

  bool ValidateUniversityQuantities(TBuildingView* buildingView) {
    if (buildingView->IsKindOf(RUNTIME_CLASS(TUniversityView)) == 0) {
      FailScenario("\"university building control opened the wrong view class\"");
      return false;
    }
    bool foundLiveRecruitmentCount = false;
    for (short category = 0; category < 9; ++category) {
      if (category == 6 || category == 7) {
        continue;
      }
      TView* recruitmentRow = buildingView->ResolveControlByTag(kControlTagClu0 + category);
      TNumberText* recruitmentQuantity =
          recruitmentRow == 0
              ? 0
              : static_cast<TNumberText*>(recruitmentRow->ResolveControlByTag(kControlTagNumb));
      if (recruitmentQuantity == 0) {
        FailScenario("\"university recruitment count control is missing\"");
        return false;
      }
      if (recruitmentQuantity->textStyle78.textColor != PALETTEINDEX(0xd2)) {
        continue;
      }
      foundLiveRecruitmentCount = true;
      TUnitOrder* order = buildingView->city94->buildOrderSlots[category + 9];
      CString quantityText;
      CString expectedText;
      recruitmentQuantity->GetCurrentText(&quantityText);
      expectedText.Format("%d", order->quantityField04);
      if (quantityText != expectedText || recruitmentQuantity->value != order->quantityField04 ||
          !HasCorrectNumberTextPresentationState(recruitmentQuantity, 10, PALETTEINDEX(0xd2))) {
        FailScenario("\"university recruitment count state does not match its live order\"");
        return false;
      }
    }
    if (!foundLiveRecruitmentCount) {
      FailScenario("\"university has no styled live recruitment count\"");
      return false;
    }
    return true;
  }

  bool ValidateArmoryState(TBuildingView* buildingView) {
    if (buildingView->IsKindOf(RUNTIME_CLASS(TArmoryView)) == 0) {
      FailScenario("\"armory building control opened the wrong view class\"");
      return false;
    }
    TArmoryView* armory = static_cast<TArmoryView*>(buildingView);
    short nationSlot = g_pSimMgr->GetActiveNationId();
    bool foundActionableOrder = false;
    short firstPictureId = -1;
    bool foundDifferentPicture = false;
    for (short category = 0; category < 8; ++category) {
      TUnitOrder* order = buildingView->city94->buildOrderSlots[category];
      TView* quantityRow = buildingView->ResolveControlByTag(kControlTagNum0 + category);
      TNumberText* quantity =
          quantityRow == 0
              ? 0
              : static_cast<TNumberText*>(quantityRow->ResolveControlByTag(kControlTagNumb));
      TCivilianButton* button = static_cast<TCivilianButton*>(
          buildingView->ResolveControlByTag(kControlTagCiv0 + category));
      if (order == 0 || quantity == 0 || button == 0) {
        FailScenario("\"armory unit row is missing its order, quantity, or picture control\"");
        return false;
      }

      short unitType = order->resourceTypeIndex48;
      if (g_awTacticalUnitCategoryCodeBySlot[unitType] != category + 1 ||
          g_pCityOrderCapabilityState->nationCapRows1e8[nationSlot].slots[category + 1] !=
              unitType ||
          g_pCityOrderCapabilityState->abilityActiveRows395[nationSlot]
                  .abilityActiveById[unitType] == 0) {
        CString failure;
        failure.Format(
            "\"armory row %d profile mismatch: type=%d category=%d selected=%d "
            "active=%d\"",
            category, unitType, g_awTacticalUnitCategoryCodeBySlot[unitType],
            g_pCityOrderCapabilityState->nationCapRows1e8[nationSlot].slots[category + 1],
            g_pCityOrderCapabilityState->abilityActiveRows395[nationSlot]
                .abilityActiveById[unitType]);
        FailScenario(failure);
        return false;
      }

      short pictureVariant;
      if (category == 7) {
        pictureVariant = unitType == 0x18 ? 8 : (unitType == 0x19 ? 0x10 : 0x18);
      } else {
        pictureVariant = unitType;
      }
      short expectedPictureId = static_cast<short>(0x1d60 + pictureVariant * 2);
      short actualPictureBase = static_cast<short>(button->glyphBase84 & ~1);
      if (actualPictureBase != expectedPictureId) {
        CString failure;
        failure.Format("\"armory row %d picture mismatch: type=%d actual=%d expected=%d\"",
                       category, unitType, actualPictureBase, expectedPictureId);
        FailScenario(failure);
        return false;
      }
      if (category == 0) {
        firstPictureId = actualPictureBase;
      } else if (actualPictureBase != firstPictureId) {
        foundDifferentPicture = true;
      }

      CString quantityText;
      CString expectedQuantityText;
      quantity->GetCurrentText(&quantityText);
      expectedQuantityText.Format("%d", order->quantityField04);
      if (quantityText != expectedQuantityText || quantity->value != order->quantityField04 ||
          !HasCorrectNumberTextPresentationState(quantity, 10, PALETTEINDEX(0xd2))) {
        FailScenario("\"armory recruitment count state does not match its live order\"");
        return false;
      }
      TView* purchaseRow = buildingView->ResolveControlByTag(kControlTagClu0 + category);
      TView* plus = purchaseRow == 0 ? 0 : purchaseRow->ResolveControlByTag(kControlTagPlus);
      if (plus != 0 && plus->IsActionable() != 0 && order->MaxOrder() > order->quantityField04) {
        foundActionableOrder = true;
      }
    }
    if (!foundDifferentPicture) {
      FailScenario("\"armory unit rows all use the same picture\"");
      return false;
    }
    if (!foundActionableOrder) {
      TUnitOrder* firstOrder = buildingView->city94->buildOrderSlots[0];
      TView* firstRow = buildingView->ResolveControlByTag(kControlTagClu0);
      TView* firstPlus = firstRow == 0 ? 0 : firstRow->ResolveControlByTag(kControlTagPlus);
      CString failure;
      failure.Format("\"armory has no actionable unit order: plus=%d enabled=%d actionable=%d "
                     "quantity=%d max=%d primary_stock=%d treasury=%d\"",
                     firstPlus != 0, firstPlus == 0 ? -1 : firstPlus->IsEnabled(),
                     firstPlus == 0 ? -1 : firstPlus->IsActionable(), firstOrder->quantityField04,
                     firstOrder->MaxOrder(),
                     buildingView->city94->CityStockByType(firstOrder->primaryInputResourceId),
                     buildingView->city94->ownerNationAc->treasuryValue10);
      FailScenario(failure);
      return false;
    }
    if (armory->selectedUnitOrderA8 == 0) {
      FailScenario("\"armory has no selected unit order\"");
      return false;
    }

    short selectedUnitType = armory->selectedUnitOrderA8->resourceTypeIndex48;
    TStaticText* unitName =
        static_cast<TStaticText*>(buildingView->ResolveControlByTag(kControlTagUnit));
    TNumberText* firepower =
        static_cast<TNumberText*>(buildingView->ResolveControlByTag(kControlTagSta0));
    int expectedFirepower = static_cast<int>(g_afArmoryUnitFirepowerByType[selectedUnitType] *
                                             g_fArmoryFirepowerDisplayScale);
    CString expectedUnitName;
    g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(
        &expectedUnitName, 0x2717, static_cast<short>(selectedUnitType + 1));
    if (unitName == 0 || unitName->text == 0 || unitName->text->IsEmpty() ||
        *unitName->text != expectedUnitName) {
      CString failure;
      failure.Format("\"armory selected unit name mismatch: control=%d text=%d empty=%d type=%d\"",
                     unitName != 0, unitName != 0 && unitName->text != 0,
                     unitName == 0 || unitName->text == 0 ? -1 : unitName->text->IsEmpty(),
                     selectedUnitType);
      FailScenario(failure);
      return false;
    }
    if (firepower == 0 || firepower->value != expectedFirepower || firepower->value == 999) {
      FailScenario("\"armory selected unit firepower does not match the retail data table\"");
      return false;
    }
    return true;
  }

  bool ValidateShipyardQuantities(TBuildingView* buildingView) {
    if (buildingView->IsKindOf(RUNTIME_CLASS(TShipyardView)) == 0) {
      FailScenario("\"shipyard building control opened the wrong view class\"");
      return false;
    }
    bool foundLiveShipOrder = false;
    for (short queueIndex = 0; queueIndex < 8; ++queueIndex) {
      TShipOrder* order = buildingView->city94->shipOrderSlots[queueIndex];
      if (order == 0 || order->resourceTypeIndex48 == 0) {
        continue;
      }
      TView* queueRow = buildingView->ResolveControlByTag(kControlTagClu0 + queueIndex);
      TNumberText* quantity =
          queueRow == 0 ? 0
                        : static_cast<TNumberText*>(queueRow->ResolveControlByTag(kControlTagNumb));
      if (quantity == 0) {
        FailScenario("\"shipyard build-queue count control is missing\"");
        return false;
      }
      foundLiveShipOrder = true;
      CString quantityText;
      CString expectedText;
      quantity->GetCurrentText(&quantityText);
      expectedText.Format("%d", order->quantityField04);
      if (quantityText != expectedText || quantity->value != order->quantityField04 ||
          !HasCorrectNumberTextPresentationState(quantity, 10, PALETTEINDEX(0xd2))) {
        FailScenario("\"shipyard build-queue count does not match its live order\"");
        return false;
      }
    }
    if (!foundLiveShipOrder) {
      FailScenario("\"shipyard has no live ship order\"");
      return false;
    }
    return true;
  }

  bool ValidateRailyardQuantity(TBuildingView* buildingView) {
    if (buildingView->IsKindOf(RUNTIME_CLASS(TIndustryView)) == 0) {
      FailScenario("\"railyard building control opened the wrong view class\"");
      return false;
    }
    TRailCluster* railCluster =
        static_cast<TRailCluster*>(buildingView->ResolveControlByTag(kSummaryTagRail));
    TNumberText* railQuantity =
        railCluster == 0
            ? 0
            : static_cast<TNumberText*>(railCluster->ResolveControlByTag(kControlTagMove));
    if (railQuantity == 0 || railCluster->selectedMetricOrder == 0) {
      FailScenario("\"railyard production count control is missing\"");
      return false;
    }
    CString quantityText;
    CString expectedText;
    railQuantity->GetCurrentText(&quantityText);
    expectedText.Format("%d", railCluster->selectedMetricOrder->quantityField04);
    if (quantityText != expectedText ||
        railQuantity->value != railCluster->selectedMetricOrder->quantityField04 ||
        !HasCorrectNumberTextPresentationState(railQuantity, 10, PALETTEINDEX(0))) {
      FailScenario("\"railyard production count state does not match its live order\"");
      return false;
    }
    return true;
  }

  short IndustryUnitTypeForBuilding(short buildingSlot) {
    static const short kIndustryUnitTypesByPage[7] = {8, 13, 11, 15, 9, 14, 12};
    return buildingSlot >= 0 && buildingSlot < 7 ? kIndustryUnitTypesByPage[buildingSlot] : -1;
  }

  TIndustryCluster* ResolveItemIndustryCluster(TBuildingView* buildingView) {
    short unitType = IndustryUnitTypeForBuilding(activeBuildingSlot);
    if (unitType < 0) {
      return 0;
    }
    return static_cast<TIndustryCluster*>(
        buildingView->ResolveControlByTag(g_pTradeSummarySelectionMap[unitType]));
  }

  bool ValidateItemQuantity(TBuildingView* buildingView) {
    if (buildingView->IsKindOf(RUNTIME_CLASS(TIndustryView)) == 0) {
      FailScenario("\"industry building control opened the wrong view class\"");
      return false;
    }
    short unitType = IndustryUnitTypeForBuilding(activeBuildingSlot);
    TIndustryCluster* industryCluster = ResolveItemIndustryCluster(buildingView);
    TNumberText* quantity =
        industryCluster == 0
            ? 0
            : static_cast<TNumberText*>(industryCluster->ResolveControlByTag(kControlTagMove));
    TProductionOrder* order = unitType < 0 ? 0 : buildingView->city94->orderSlotsE4[unitType];
    if (quantity == 0 || order == 0 || industryCluster->selectedMetricOrder != order) {
      FailScenario("\"industry production count control is missing or has the wrong order\"");
      return false;
    }
    CString quantityText;
    CString expectedText;
    quantity->GetCurrentText(&quantityText);
    expectedText.Format("%d", order->quantityField04);
    if (quantityText != expectedText || quantity->value != order->quantityField04 ||
        !HasCorrectNumberTextPresentationState(quantity, 10, PALETTEINDEX(0))) {
      FailScenario("\"industry production count state does not match its live item order\"");
      return false;
    }
    return true;
  }

  TBuildingView* ActiveBuildingView() {
    TView* mainView = CurrentMainView();
    if (g_pUiRuntimeContext->currentTurnEventCode != kTurnEventCityProduction || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TCityProductionView)) == 0) {
      return 0;
    }
    return static_cast<TCityProductionView*>(mainView)->BuildingViewForRuntimeTest(
        activeBuildingSlot);
  }

  void CaptureUnitOrderState(TUnitOrder* order) {
    interactionKind = kUniversityInteraction;
    interactionUnitOrder = order;
    interactionItemOrder = 0;
    interactionShipOrder = 0;
    priorQuantity = order->quantityField04;
    priorPrimaryStock = order->cityField08->CityStockByType(order->primaryInputResourceId);
    priorSecondaryStock =
        order->secondaryInputResourceId < 0
            ? 0
            : order->cityField08->CityStockByType(order->secondaryInputResourceId);
    priorTreasury = order->cityField08->ownerNationAc->treasuryValue10;
    TPopulationMgr* population = order->summaryField0c;
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

  void CaptureItemOrderState(TItemOrder* order) {
    interactionKind = kItemInteraction;
    interactionUnitOrder = 0;
    interactionItemOrder = order;
    interactionShipOrder = 0;
    priorQuantity = order->quantityField04;
    priorRequestedQuantity = order->requestedQuantity4c;
    priorPrimaryStock = order->cityField08->CityStockByType(order->primaryInputResourceId);
    priorPrimaryTracking = order->trackingSlots10[order->primaryInputResourceId];
    priorSecondaryStock =
        order->secondaryInputResourceId < 0
            ? 0
            : order->cityField08->CityStockByType(order->secondaryInputResourceId);
    priorSecondaryTracking = order->secondaryInputResourceId < 0
                                 ? 0
                                 : order->trackingSlots10[order->secondaryInputResourceId];
    priorStrength = order->summaryField0c->strength;
    priorField3e = order->field3e;
    priorProductionAccum = order->cityField08->productionAccum1fc[order->productionSlot];
  }

  void CaptureShipOrderState(TShipOrder* order) {
    interactionKind = kShipyardInteraction;
    interactionUnitOrder = 0;
    interactionItemOrder = 0;
    interactionShipOrder = order;
    priorQuantity = order->quantityField04;
  }

  bool BeginUniversityInteraction(TBuildingView* buildingView) {
    for (short category = 0; category < 9; ++category) {
      if (category == 6 || category == 7) {
        continue;
      }
      TView* row = buildingView->ResolveControlByTag(kControlTagClu0 + category);
      TView* plus = row == 0 ? 0 : row->ResolveControlByTag(kControlTagPlus);
      TUnitOrder* order = buildingView->city94->buildOrderSlots[category + 9];
      if (plus == 0 || plus->IsActionable() == 0 || order == 0 ||
          order->MaxOrder() <= order->quantityField04) {
        continue;
      }
      CaptureUnitOrderState(order);
      interactionRowTag = kControlTagClu0 + category;
      phase = kWaitForOrderIncrease;
      EnterScenarioStep("waiting_for_university_order_increase", "activate_university_plus_arrow");
      if (!RuntimeUiDriver::ActivateControlSemantically(row, kControlTagPlus)) {
        FailScenario("\"university plus arrow could not be activated\"");
        return false;
      }
      RequestScenarioTick();
      return true;
    }
    FailScenario("\"university has no actionable production-order plus arrow\"");
    return false;
  }

  bool BeginArmoryInteraction(TBuildingView* buildingView) {
    for (short category = 0; category < 8; ++category) {
      TView* row = buildingView->ResolveControlByTag(kControlTagClu0 + category);
      TView* plus = row == 0 ? 0 : row->ResolveControlByTag(kControlTagPlus);
      TUnitOrder* order = buildingView->city94->buildOrderSlots[category];
      if (plus == 0 || plus->IsActionable() == 0 || order == 0 ||
          order->MaxOrder() <= order->quantityField04) {
        continue;
      }
      CaptureUnitOrderState(order);
      interactionKind = kArmoryInteraction;
      interactionRowTag = kControlTagClu0 + category;
      phase = kWaitForOrderIncrease;
      EnterScenarioStep("waiting_for_armory_order_increase", "activate_armory_plus_arrow");
      if (!RuntimeUiDriver::ActivateControlSemantically(row, kControlTagPlus)) {
        FailScenario("\"armory plus arrow could not be activated\"");
        return false;
      }
      RequestScenarioTick();
      return true;
    }
    FailScenario("\"armory has no actionable production-order plus arrow\"");
    return false;
  }

  bool BeginShipyardInteraction(TBuildingView* buildingView) {
    for (short queueIndex = 0; queueIndex < 8; ++queueIndex) {
      TShipOrder* order = buildingView->city94->shipOrderSlots[queueIndex];
      TView* queueRow = buildingView->ResolveControlByTag(kControlTagClu0 + queueIndex);
      TView* plus = queueRow == 0 ? 0 : queueRow->ResolveControlByTag(kControlTagPlus);
      if (order == 0 || order->resourceTypeIndex48 == 0 || plus == 0 || plus->IsActionable() == 0 ||
          order->MaxOrder() <= order->quantityField04) {
        continue;
      }
      CaptureShipOrderState(order);
      interactionRowTag = kControlTagClu0 + queueIndex;
      phase = kWaitForOrderIncrease;
      EnterScenarioStep("waiting_for_ship_order_increase", "activate_shipyard_plus_arrow");
      if (!RuntimeUiDriver::ActivateControlSemantically(queueRow, kControlTagPlus)) {
        FailScenario("\"shipyard plus arrow could not be activated\"");
        return false;
      }
      RequestScenarioTick();
      return true;
    }
    FailScenario("\"shipyard has no actionable build-order plus arrow\"");
    return false;
  }

  bool BeginItemInteraction(TBuildingView* buildingView) {
    TIndustryCluster* cluster = ResolveItemIndustryCluster(buildingView);
    TView* rightArrow = cluster == 0 ? 0 : cluster->ResolveControlByTag(kControlTagRght);
    TItemOrder* order = cluster == 0 ? 0 : static_cast<TItemOrder*>(cluster->selectedMetricOrder);
    if (rightArrow == 0 || rightArrow->IsActionable() == 0 || order == 0 ||
        order->MaxOrder() <= order->quantityField04) {
      FailScenario("\"industry item order has no actionable right arrow\"");
      return false;
    }
    CaptureItemOrderState(order);
    phase = kWaitForOrderIncrease;
    EnterScenarioStep("waiting_for_industry_order_increase", "activate_industry_right_arrow");
    rightArrow->HandleEvent(100, rightArrow, 0);
    RequestScenarioTick();
    return true;
  }

  bool UnitOrderStateWasReserved() {
    TUnitOrder* order = interactionUnitOrder;
    TPopulationMgr* population = order->summaryField0c;
    if (order->quantityField04 != priorQuantity + 1 ||
        order->cityField08->CityStockByType(order->primaryInputResourceId) !=
            priorPrimaryStock - order->primaryInputPerUnit ||
        (order->secondaryInputResourceId >= 0 &&
         order->cityField08->CityStockByType(order->secondaryInputResourceId) !=
             priorSecondaryStock - order->secondaryInputPerUnit) ||
        order->cityField08->ownerNationAc->treasuryValue10 !=
            priorTreasury - order->cashCostPerUnit ||
        population->populationCount08 != priorPopulationCount - 1 ||
        population->populationCountFloat0c != priorPopulationFloat - 1.0f ||
        population->strength >= priorStrength) {
      return false;
    }
    return true;
  }

  bool ItemOrderStateWasReserved() {
    TItemOrder* order = interactionItemOrder;
    short primaryAmount = order->secondaryInputResourceId < 0 ? 2 : 1;
    if (order->quantityField04 != priorQuantity + 1 ||
        order->requestedQuantity4c != order->quantityField04 ||
        order->cityField08->CityStockByType(order->primaryInputResourceId) !=
            priorPrimaryStock - primaryAmount ||
        order->trackingSlots10[order->primaryInputResourceId] !=
            priorPrimaryTracking + primaryAmount ||
        (order->secondaryInputResourceId >= 0 &&
         (order->cityField08->CityStockByType(order->secondaryInputResourceId) !=
              priorSecondaryStock - 1 ||
          order->trackingSlots10[order->secondaryInputResourceId] != priorSecondaryTracking + 1)) ||
        order->summaryField0c->strength != priorStrength - 2 ||
        order->field3e != priorField3e + 2 ||
        order->cityField08->productionAccum1fc[order->productionSlot] != priorProductionAccum - 1) {
      return false;
    }
    return true;
  }

  bool UnitOrderStateWasRestored() {
    TUnitOrder* order = interactionUnitOrder;
    TPopulationMgr* population = order->summaryField0c;
    return order->quantityField04 == priorQuantity &&
           order->cityField08->CityStockByType(order->primaryInputResourceId) ==
               priorPrimaryStock &&
           (order->secondaryInputResourceId < 0 ||
            order->cityField08->CityStockByType(order->secondaryInputResourceId) ==
                priorSecondaryStock) &&
           order->cityField08->ownerNationAc->treasuryValue10 == priorTreasury &&
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

  bool ItemOrderStateWasRestored() {
    TItemOrder* order = interactionItemOrder;
    return order->quantityField04 == priorQuantity &&
           order->requestedQuantity4c == priorRequestedQuantity &&
           order->cityField08->CityStockByType(order->primaryInputResourceId) ==
               priorPrimaryStock &&
           order->trackingSlots10[order->primaryInputResourceId] == priorPrimaryTracking &&
           (order->secondaryInputResourceId < 0 ||
            (order->cityField08->CityStockByType(order->secondaryInputResourceId) ==
                 priorSecondaryStock &&
             order->trackingSlots10[order->secondaryInputResourceId] == priorSecondaryTracking)) &&
           order->summaryField0c->strength == priorStrength && order->field3e == priorField3e &&
           order->cityField08->productionAccum1fc[order->productionSlot] == priorProductionAccum;
  }

  bool ShipOrderStateWasReserved() {
    return interactionShipOrder->quantityField04 == priorQuantity + 1;
  }

  bool ShipOrderStateWasRestored() {
    return interactionShipOrder->quantityField04 == priorQuantity;
  }

  void WaitForOrderIncrease() {
    TBuildingView* buildingView = ActiveBuildingView();
    if (buildingView == 0) {
      FailScenario("\"city building view disappeared during order interaction\"");
      return;
    }
    bool stateIsCorrect =
        interactionKind == kUniversityInteraction || interactionKind == kArmoryInteraction
            ? UnitOrderStateWasReserved()
        : interactionKind == kShipyardInteraction ? ShipOrderStateWasReserved()
                                                  : ItemOrderStateWasReserved();
    bool uiIsCorrect =
        interactionKind == kUniversityInteraction ? ValidateUniversityQuantities(buildingView)
        : interactionKind == kArmoryInteraction   ? ValidateArmoryState(buildingView)
        : interactionKind == kShipyardInteraction ? ValidateShipyardQuantities(buildingView)
                                                  : ValidateItemQuantity(buildingView);
    if (!stateIsCorrect || !uiIsCorrect) {
      FailScenario("\"city production increase did not reserve model state and refresh UI\"");
      return;
    }

    TView* interactionRoot;
    int controlTag;
    int commandId;
    if (interactionKind == kUniversityInteraction || interactionKind == kArmoryInteraction ||
        interactionKind == kShipyardInteraction) {
      interactionRoot = buildingView->ResolveControlByTag(interactionRowTag);
      controlTag = kControlTagMinu;
      commandId = 0;
    } else {
      interactionRoot = ResolveItemIndustryCluster(buildingView);
      controlTag = kControlTagLeft;
      commandId = 101;
    }
    TView* control = interactionRoot == 0 ? 0 : interactionRoot->ResolveControlByTag(controlTag);
    if (control == 0 || control->IsActionable() == 0) {
      FailScenario("\"city production decrease control is missing or disabled\"");
      return;
    }

    phase = kWaitForOrderRestore;
    EnterScenarioStep("waiting_for_city_order_restore", "activate_city_order_decrease");
    if (interactionKind == kUniversityInteraction || interactionKind == kArmoryInteraction ||
        interactionKind == kShipyardInteraction) {
      if (!RuntimeUiDriver::ActivateControlSemantically(interactionRoot, controlTag)) {
        FailScenario("\"city production minus arrow could not be activated\"");
        return;
      }
    } else {
      control->HandleEvent(commandId, control, 0);
    }
    RequestScenarioTick();
  }

  void WaitForOrderRestore() {
    TBuildingView* buildingView = ActiveBuildingView();
    if (buildingView == 0) {
      FailScenario("\"city building view disappeared while restoring order state\"");
      return;
    }
    bool stateIsCorrect =
        interactionKind == kUniversityInteraction || interactionKind == kArmoryInteraction
            ? UnitOrderStateWasRestored()
        : interactionKind == kShipyardInteraction ? ShipOrderStateWasRestored()
                                                  : ItemOrderStateWasRestored();
    bool uiIsCorrect =
        interactionKind == kUniversityInteraction ? ValidateUniversityQuantities(buildingView)
        : interactionKind == kArmoryInteraction   ? ValidateArmoryState(buildingView)
        : interactionKind == kShipyardInteraction ? ValidateShipyardQuantities(buildingView)
                                                  : ValidateItemQuantity(buildingView);
    if (!stateIsCorrect || !uiIsCorrect) {
      FailScenario("\"city production decrease did not restore model state and refresh UI\"");
      return;
    }
    interactionComplete = true;
    phase = kWaitForBuilding;
    EnterScenarioStep("verified_city_order_interaction", "close_verified_city_building");
    RequestScenarioTick();
  }

  void WaitForBuilding() {
    TView* mainView = CurrentMainView();
    if (g_pUiRuntimeContext->currentTurnEventCode != kTurnEventCityProduction || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TCityProductionView)) == 0) {
      FailScenario("\"city production view disappeared after building activation\"");
      return;
    }
    TCityProductionView* cityView = static_cast<TCityProductionView*>(mainView);
    TBuildingView* buildingView = cityView->BuildingViewForRuntimeTest(activeBuildingSlot);
    if (buildingView == 0) {
      WaitForScenarioTick("\"city building control did not open its production view\"");
      return;
    }
    TGreatPower* activeNation = g_apNationStates[g_pSimMgr->GetActiveNationId()];
    if (activeNation == 0 || buildingView->city94 != activeNation->city ||
        buildingView->isEmbeddedPage9C || buildingView->embeddedPageIndex9E != activeBuildingSlot) {
      FailScenario("\"city building control opened the wrong production slot\"");
      return;
    }
    bool quantitiesAreValid;
    if (activeBuildingSlot == kUniversityBuildingSlot) {
      quantitiesAreValid = ValidateUniversityQuantities(buildingView);
    } else if (activeBuildingSlot == kArmoryBuildingSlot) {
      quantitiesAreValid = ValidateArmoryState(buildingView);
    } else if (activeBuildingSlot == kShipyardBuildingSlot) {
      quantitiesAreValid = ValidateShipyardQuantities(buildingView);
    } else if (activeBuildingSlot == kRailyardBuildingSlot) {
      quantitiesAreValid = ValidateRailyardQuantity(buildingView);
    } else {
      quantitiesAreValid = ValidateItemQuantity(buildingView);
    }
    if (!quantitiesAreValid) {
      return;
    }
    TWindow* buildingWindow = buildingView->GetWindow();
    if (buildingWindow == 0 || buildingWindow->nativeWindow50 == 0 ||
        buildingWindow->nativeWindow50->m_hWnd == 0) {
      FailScenario("\"city building production view has no native window\"");
      return;
    }
    HWND buildingHwnd = buildingWindow->nativeWindow50->m_hWnd;
    LONG style = GetWindowLongA(buildingHwnd, GWL_STYLE);
    LONG extendedStyle = GetWindowLongA(buildingHwnd, GWL_EXSTYLE);
    if (buildingWindow->windowStyleType != 0x1f40 || buildingWindow->windowFlags != 0x80 ||
        !buildingWindow->useCaptionedFrameFlag6d || !buildingWindow->topmostFlag70 ||
        (style & (WS_CAPTION | WS_SYSMENU)) != (WS_CAPTION | WS_SYSMENU) ||
        (extendedStyle & WS_EX_TOOLWINDOW) == 0) {
      CString failure;
      failure.Format("\"city building native window is missing its retail floating frame: "
                     "descriptor_style=0x%x descriptor_flags=0x%x caption=%d topmost=%d "
                     "style=0x%lx exstyle=0x%lx\"",
                     buildingWindow->windowStyleType, buildingWindow->windowFlags,
                     buildingWindow->useCaptionedFrameFlag6d, buildingWindow->topmostFlag70, style,
                     extendedStyle);
      FailScenario(failure);
      return;
    }
    CWnd* mainWindow = AfxGetMainWnd();
    if (mainWindow == 0 || GetParent(buildingHwnd) != mainWindow->m_hWnd) {
      FailScenario("\"city building native window is not owned by the main game window\"");
      return;
    }
    RECT windowRect;
    POINT clientOrigin;
    clientOrigin.x = 0;
    clientOrigin.y = 0;
    if (!GetWindowRect(buildingHwnd, &windowRect) || !ClientToScreen(buildingHwnd, &clientOrigin) ||
        clientOrigin.y <= windowRect.top) {
      FailScenario("\"city building native window has no non-client caption area\"");
      return;
    }
    POINT captionPoint;
    captionPoint.x = (windowRect.left + windowRect.right) / 2;
    captionPoint.y = (windowRect.top + clientOrigin.y) / 2;
    LPARAM hitPoint =
        MAKELPARAM(static_cast<short>(captionPoint.x), static_cast<short>(captionPoint.y));
    if (SendMessageA(buildingHwnd, WM_NCHITTEST, 0, hitPoint) != HTCAPTION) {
      FailScenario("\"city building native frame does not expose a movable caption\"");
      return;
    }
    if (ScenarioPhaseTicks() < 5) {
      RequestScenarioTick();
      return;
    }
    if (!interactionComplete && activeBuildingSlot == kUniversityBuildingSlot) {
      BeginUniversityInteraction(buildingView);
      return;
    }
    if (!interactionComplete && activeBuildingSlot == kArmoryBuildingSlot) {
      BeginArmoryInteraction(buildingView);
      return;
    }
    if (!interactionComplete && activeBuildingSlot == kShipyardBuildingSlot) {
      BeginShipyardInteraction(buildingView);
      return;
    }
    if (!interactionComplete && activeBuildingSlot != kRailyardBuildingSlot) {
      BeginItemInteraction(buildingView);
      return;
    }
    phase = kWaitForBuildingClose;
    EnterScenarioStep("closing_city_building", "activate_native_system_close");
    SendMessageA(buildingHwnd, WM_SYSCOMMAND, SC_CLOSE, 0);
    RequestScenarioTick();
  }

  void WaitForBuildingClose() {
    TView* mainView = CurrentMainView();
    if (g_pUiRuntimeContext->currentTurnEventCode != kTurnEventCityProduction || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TCityProductionView)) == 0) {
      FailScenario("\"city production view disappeared while closing a building window\"");
      return;
    }
    TCityProductionView* cityView = static_cast<TCityProductionView*>(mainView);
    if (cityView->BuildingViewForRuntimeTest(activeBuildingSlot) != 0) {
      WaitForScenarioTick("\"native system close did not close the city building window\"");
      return;
    }
    if (activeBuildingSlot == kUniversityBuildingSlot) {
      TGreatPower* activeNation = g_apNationStates[g_pSimMgr->GetActiveNationId()];
      TUnitOrder* armoryOrder = activeNation->city->buildOrderSlots[0];
      activeNation->city->CityStockByType(armoryOrder->primaryInputResourceId) =
          static_cast<short>(armoryOrder->primaryInputPerUnit * 2);
      activeBuildingSlot = kArmoryBuildingSlot;
      phase = kActivateBuilding;
      EnterScenarioStep("activating_armory_building", "activate_armory_building_slot");
      RequestScenarioTick();
      return;
    }
    if (activeBuildingSlot == kArmoryBuildingSlot) {
      activeBuildingSlot = kShipyardBuildingSlot;
      phase = kActivateBuilding;
      EnterScenarioStep("activating_shipyard_building", "activate_shipyard_building_slot");
      RequestScenarioTick();
      return;
    }
    if (activeBuildingSlot == kShipyardBuildingSlot) {
      activeBuildingSlot = kRailyardBuildingSlot;
      phase = kActivateBuilding;
      EnterScenarioStep("activating_railyard_building", "activate_railyard_building_slot");
      RequestScenarioTick();
      return;
    }
    if (activeBuildingSlot == kRailyardBuildingSlot) {
      TGreatPower* activeNation = g_apNationStates[g_pSimMgr->GetActiveNationId()];
      if (activeNation == 0 || activeNation->city == 0) {
        FailScenario("\"active nation lost its city before industry interaction\"");
        return;
      }
      short itemBuildingSlot = -1;
      for (short buildingSlot = 1; buildingSlot < 7; ++buildingSlot) {
        short unitType = IndustryUnitTypeForBuilding(buildingSlot);
        TProductionOrder* order = activeNation->city->orderSlotsE4[unitType];
        if (activeNation->city->GetBuildingType(buildingSlot) > 0 && order != 0 &&
            order->MaxOrder() > order->quantityField04) {
          itemBuildingSlot = buildingSlot;
          break;
        }
      }
      if (itemBuildingSlot < 0) {
        FailScenario("\"city has no actionable TItemOrder-backed industry building\"");
        return;
      }
      activeBuildingSlot = itemBuildingSlot;
      phase = kActivateBuilding;
      EnterScenarioStep("activating_item_industry_building", "activate_item_industry_slot");
      RequestScenarioTick();
      return;
    }
    phase = kReturnToMap;
    EnterScenarioStep("returning_to_strategic_map", "click_city_end_control");
    RequestScenarioTick();
  }

  void ReturnToMap() {
    TView* mainView = CurrentMainView();
    if (mainView == 0 || mainView->IsKindOf(RUNTIME_CLASS(TCityProductionView)) == 0) {
      FailScenario("\"city production view disappeared before back navigation\"");
      return;
    }
    phase = kWaitForMap;
    EnterScenarioStep("waiting_for_strategic_map_return", "activate_city_end_control");
    if (!RuntimeUiDriver::ClickControlThroughNativeMessages(mainView, kControlTagEnd)) {
      FailScenario("\"city back control is missing or cannot receive native input\"");
      return;
    }
    RequestScenarioTick();
  }

  void WaitForMap() {
    TView* mainView = CurrentMainView();
    if (g_pUiRuntimeContext->currentTurnEventCode != kTurnEventStrategicMap || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TMapUberPicture)) == 0) {
      WaitForScenarioTick("\"city back control did not restore the strategic map\"");
      return;
    }
    if (!g_ModalViewStack.IsEmpty()) {
      RecordUnexpectedModalView(static_cast<TView*>(g_ModalViewStack.GetHead()));
      FailScenario("\"city back navigation left an unexpected modal\"");
      return;
    }
    if (ScenarioPhaseTicks() < 20) {
      RequestScenarioTick();
      return;
    }
    Pass();
  }

  Phase phase;
  short activeBuildingSlot;
  bool interactionComplete;
  InteractionKind interactionKind;
  TUnitOrder* interactionUnitOrder;
  TItemOrder* interactionItemOrder;
  TShipOrder* interactionShipOrder;
  int interactionRowTag;
  short priorQuantity;
  short priorRequestedQuantity;
  short priorPrimaryStock;
  short priorPrimaryTracking;
  short priorSecondaryStock;
  short priorSecondaryTracking;
  short priorStrength;
  short priorField3e;
  short priorProductionAccum;
  int priorTreasury;
  short priorPopulationCount;
  float priorPopulationFloat;
  short priorBaselineLow;
  short priorBaselineMedium;
  short priorBaselineHigh;
  short priorProductionLow;
  short priorProductionMedium;
  short priorProductionHigh;
};

CityScreenTestCase g_test;

} // namespace

RuntimeTestCase* CityScreenTest() {
  return &g_test;
}
