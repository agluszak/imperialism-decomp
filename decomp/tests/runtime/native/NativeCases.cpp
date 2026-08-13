#include "NativeCases.h"

#include "game/globals/shared_globals.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TSimMgr.h"

#include <string.h>

RuntimeActionResult RunCityItemOrderIncrease(NativeTransition& transition);
RuntimeActionResult RunCityItemOrderDecrease(NativeTransition& transition);
RuntimeActionResult RunPowerPlantUpgrade(NativeTransition& transition);
RuntimeActionResult RunCreatedItemsPhase(NativeTransition& transition);

RuntimeActionResult RunDirectTransport(NativeTransition& transition);
RuntimeActionResult RunTransportNeedAllocation(NativeTransition& transition);
RuntimeActionResult RunTransportedItemsPhase(NativeTransition& transition);
RuntimeActionResult RunRollingStockSuccess(NativeTransition& transition);
RuntimeActionResult RunRollingStockInsufficient(NativeTransition& transition);
RuntimeActionResult RunMerchantMarine(NativeTransition& transition);

RuntimeActionResult RunMajorTradeSettlement(NativeTransition& transition);
RuntimeActionResult RunPurchasedItemsPhase(NativeTransition& transition);
RuntimeActionResult RunRecallTradeBids(NativeTransition& transition);
RuntimeActionResult RunPlayerTradePhaseReset(NativeTransition& transition);
RuntimeActionResult RunTradeCapacityRefresh(NativeTransition& transition);
RuntimeActionResult RunTradeMarketPrice(NativeTransition& transition);
RuntimeActionResult RunTradePolicySet(NativeTransition& transition);
RuntimeActionResult RunTradePolicyStep(NativeTransition& transition);
RuntimeActionResult RunTradePhase(NativeTransition& transition);
RuntimeActionResult RunTradePhaseSellOnly(NativeTransition& transition);

RuntimeActionResult RunAidAllocation(NativeTransition& transition);
RuntimeActionResult RunDiplomacyGrantEntry(NativeTransition& transition);
RuntimeActionResult RunDiplomacyReset(NativeTransition& transition);
RuntimeActionResult RunDiplomacyPhase(NativeTransition& transition);

RuntimeActionResult RunNationResourceYieldRebuild(NativeTransition& transition);
RuntimeActionResult RunAiNationResourceYieldRebuildClampsTargets(NativeTransition& transition);
RuntimeActionResult RunNationResourceYieldRebuildMultipleTowns(NativeTransition& transition);

RuntimeActionResult RunSpecialistRecruitment(NativeTransition& transition);
RuntimeActionResult RunMilitaryMaintenance(NativeTransition& transition);

RuntimeActionResult RunCompletedRailSection(NativeTransition& transition);
RuntimeActionResult RunIssuedRailSection(NativeTransition& transition);
RuntimeActionResult RunCompletedResourceDevelopment(NativeTransition& transition);
RuntimeActionResult RunOwnedRegionDevelopment(NativeTransition& transition);
RuntimeActionResult RunCityAndTransportPhase(NativeTransition& transition);
RuntimeActionResult RunNavyGrowthPending(NativeTransition& transition);
RuntimeActionResult RunCiviliansPhase(NativeTransition& transition);
RuntimeActionResult RunProvinceLossWithStationedUnit(NativeTransition& transition);
RuntimeActionResult RunProvinceOwnerOceanContext(NativeTransition& transition);

RuntimeActionResult RunCheckTechnologyAdvances(NativeTransition& transition);
RuntimeActionResult RunCheckTechnologyAdvancesAiPurchase(NativeTransition& transition);
RuntimeActionResult RunConstructNewspaperPage(NativeTransition& transition);
RuntimeActionResult RunConstructNewspaperPageMiscEvent(NativeTransition& transition);

RuntimeActionResult RunGreatPowerPressureHumanDebt(NativeTransition& transition);
RuntimeActionResult RunGreatPowerPressureAiNoop(NativeTransition& transition);
RuntimeActionResult RunSeasonAdvanceClearsStatusFlags(NativeTransition& transition);
RuntimeActionResult RunTurnAlertsSkipFirstEconomicTurn(NativeTransition& transition);
RuntimeActionResult RunDiplomacyOfferGate(NativeTransition& transition);
RuntimeActionResult RunQuarterGateOffDecade(NativeTransition& transition);
RuntimeActionResult RunReturnToMapClearsNoticeQueues(NativeTransition& transition);
RuntimeActionResult RunEliminationPhaseWithLandedGreatPowers(NativeTransition& transition);

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
    {"trade_phase", RunTradePhase},
    {"trade_phase_sell_only", RunTradePhaseSellOnly},
    {"aid_allocation", RunAidAllocation},
    {"diplomacy_grant_entry_updates_treasury", RunDiplomacyGrantEntry},
    {"diplomacy_reset_preserves_recurring_grants", RunDiplomacyReset},
    {"diplomacy_phase_applies_grant_and_consulate", RunDiplomacyPhase},
    {"nation_resource_yield_rebuild", RunNationResourceYieldRebuild},
    {"ai_nation_resource_yield_rebuild_clamps_targets",
     RunAiNationResourceYieldRebuildClampsTargets},
    {"nation_resource_yield_rebuild_multiple_towns", RunNationResourceYieldRebuildMultipleTowns},
    {"specialist_recruitment", RunSpecialistRecruitment},
    {"military_maintenance", RunMilitaryMaintenance},
    {"completed_rail_section", RunCompletedRailSection},
    {"issued_rail_section", RunIssuedRailSection},
    {"completed_resource_development", RunCompletedResourceDevelopment},
    {"owned_region_development", RunOwnedRegionDevelopment},
    {"city_and_transport_phase", RunCityAndTransportPhase},
    {"navy_growth_pending", RunNavyGrowthPending},
    {"civilians_phase", RunCiviliansPhase},
    {"province_loss_with_stationed_unit", RunProvinceLossWithStationedUnit},
    {"province_owner_ocean_context", RunProvinceOwnerOceanContext},
    {"check_technology_advances", RunCheckTechnologyAdvances},
    {"check_technology_advances_ai_purchase", RunCheckTechnologyAdvancesAiPurchase},
    {"construct_newspaper_page", RunConstructNewspaperPage},
    {"construct_newspaper_page_misc_event", RunConstructNewspaperPageMiscEvent},
    {"great_power_pressure_human_debt", RunGreatPowerPressureHumanDebt},
    {"great_power_pressure_ai_noop", RunGreatPowerPressureAiNoop},
    {"season_advance_clears_status_flags", RunSeasonAdvanceClearsStatusFlags},
    {"turn_alerts_skip_first_economic_turn", RunTurnAlertsSkipFirstEconomicTurn},
    {"diplomacy_offer_gate", RunDiplomacyOfferGate},
    {"quarter_gate_off_decade", RunQuarterGateOffDecade},
    {"return_to_map_clears_notice_queues", RunReturnToMapClearsNoticeQueues},
    {"elimination_phase_with_landed_great_powers", RunEliminationPhaseWithLandedGreatPowers},
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

TGreatPower* ActiveNation() {
  return g_apNationStates[g_pSimMgr->GetActiveNationId()];
}

short ActiveNationSlot() {
  return g_pSimMgr->GetActiveNationId();
}
