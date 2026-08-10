#include "NativeCases.h"

#include "flows/LoadGameFlow.h"
#include "scenarios/RuntimeScenario.h"
#include "scenarios/RuntimeTestFactory.h"

#include <stdlib.h>
#include <string.h>

namespace {

class NativeTransitionOracleCase : public RuntimeScenario {
public:
  bool RequiresFixture() const {
    return true;
  }

protected:
  RuntimeFlow* NavigationFlow() {
    return &loadGameFlow;
  }

  void OnCombinedMapReady() {
    const char* name = getenv("IMPERIALISM_NATIVE_CASE");
    if (name == 0 || name[0] == '\0') {
      FailScenario("IMPERIALISM_NATIVE_CASE is unset");
      return;
    }

    NativeTransition transition(RunState());
    const NativeCase* nativeCase = FindNativeCase(name);
    if (nativeCase == 0) {
      FailScenario("unknown native transition case");
      return;
    }

    RuntimeActionResult result = nativeCase->run(transition);
    if (!result.Succeeded()) {
      FailScenarioText((LPCSTR)result.FailureMessage());
      return;
    }

    Pass();
  }

private:
  LoadGameFlow loadGameFlow;
};

} // namespace

namespace {

const NativeCase kCases[] = {
    {"city_item_order_increase", RunCityItemOrderIncrease},
    {"city_item_order_decrease", RunCityItemOrderDecrease},
    {"power_plant_upgrade", RunPowerPlantUpgrade},
    {"created_items_phase", RunCreatedItemsPhase},
    {"direct_transport", RunDirectTransport},
    {"transport_need_allocation", RunTransportNeedAllocation},
    {"transported_items_phase", RunTransportedItemsPhase},
    {"rolling_stock", RunRollingStockSuccess},
    {"rolling_stock_insufficient_resources", RunRollingStockInsufficient},
    {"merchant_marine", RunMerchantMarine},
    {"major_trade_settlement", RunMajorTradeSettlement},
    {"purchased_items_phase", RunPurchasedItemsPhase},
    {"recall_trade_bids", RunRecallTradeBids},
    {"player_trade_phase_reset", RunPlayerTradePhaseReset},
    {"trade_capacity_refresh", RunTradeCapacityRefresh},
    {"trade_market_price", RunTradeMarketPrice},
    {"trade_policy_set", RunTradePolicySet},
    {"trade_policy_step", RunTradePolicyStep},
    {"aid_allocation", RunAidAllocation},
    {"diplomacy_grant_entry_updates_treasury", RunDiplomacyGrantEntry},
    {"diplomacy_reset_preserves_recurring_grants", RunDiplomacyReset},
    {"first_turn_alert_phase", RunFirstTurnAlertPhase},
    {"first_turn_diplomacy_phase", RunFirstTurnDiplomacyPhase},
    {"first_turn_trade_phase", RunFirstTurnTradePhase},
    {"first_turn_civilian_phase", RunFirstTurnCivilianPhase},
    {"first_turn_military_phase", RunFirstTurnMilitaryPhase},
    {"first_turn_combat_movement_phase", RunFirstTurnCombatMovementPhase},
    {"first_turn_military_cleanup_phase", RunFirstTurnMilitaryCleanupPhase},
    {"first_turn_diplomacy_offer_phase", RunFirstTurnDiplomacyOfferPhase},
    {"first_turn_elimination_phase", RunFirstTurnEliminationPhase},
    {"first_turn_city_transport_phase", RunFirstTurnCityTransportPhase},
    {"first_turn_great_power_pressure_phase", RunFirstTurnGreatPowerPressurePhase},
    {"first_turn_deal_book_phase", RunFirstTurnDealBookPhase},
    {"first_turn_quarter_gate_phase", RunFirstTurnQuarterGatePhase},
    {"first_turn_season_advance_phase", RunFirstTurnSeasonAdvancePhase},
    {"first_turn_technology_advances_phase", RunFirstTurnTechnologyAdvancesPhase},
    {"first_turn_newspaper_phase", RunFirstTurnNewspaperPhase},
    {"first_turn_return_to_map_phase", RunFirstTurnReturnToMapPhase},
    {"nation_resource_yield_rebuild", RunNationResourceYieldRebuild},
    {"ai_nation_resource_yield_rebuild_clamps_targets",
     RunAiNationResourceYieldRebuildClampsTargets},
    {"specialist_recruitment", RunSpecialistRecruitment},
    {"military_maintenance", RunMilitaryMaintenance},
    {"completed_rail_section", RunCompletedRailSection},
    {"completed_resource_development", RunCompletedResourceDevelopment},
};

} // namespace

const NativeCase* FindNativeCase(const char* name) {
  if (name == 0) {
    return 0;
  }
  for (int index = 0; index < (int)(sizeof(kCases) / sizeof(kCases[0])); ++index) {
    if (strcmp(kCases[index].name, name) == 0) {
      return &kCases[index];
    }
  }
  return 0;
}

RUNTIME_TEST_FACTORY(NativeTransitionOracleCase, NativeTransitionOracle)
