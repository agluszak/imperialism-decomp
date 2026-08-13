#include "NativeCases.h"

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

RuntimeActionResult RunAidAllocation(NativeTransition& transition);
RuntimeActionResult RunDiplomacyGrantEntry(NativeTransition& transition);
RuntimeActionResult RunDiplomacyReset(NativeTransition& transition);

RuntimeActionResult RunNationResourceYieldRebuild(NativeTransition& transition);
RuntimeActionResult RunAiNationResourceYieldRebuildClampsTargets(NativeTransition& transition);
RuntimeActionResult RunNationResourceYieldRebuildMultipleTowns(NativeTransition& transition);

RuntimeActionResult RunSpecialistRecruitment(NativeTransition& transition);
RuntimeActionResult RunMilitaryMaintenance(NativeTransition& transition);

RuntimeActionResult RunCompletedRailSection(NativeTransition& transition);
RuntimeActionResult RunIssuedRailSection(NativeTransition& transition);
RuntimeActionResult RunCompletedResourceDevelopment(NativeTransition& transition);

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
    {"nation_resource_yield_rebuild", RunNationResourceYieldRebuild},
    {"ai_nation_resource_yield_rebuild_clamps_targets",
     RunAiNationResourceYieldRebuildClampsTargets},
    {"nation_resource_yield_rebuild_multiple_towns",
     RunNationResourceYieldRebuildMultipleTowns},
    {"specialist_recruitment", RunSpecialistRecruitment},
    {"military_maintenance", RunMilitaryMaintenance},
    {"completed_rail_section", RunCompletedRailSection},
    {"issued_rail_section", RunIssuedRailSection},
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
