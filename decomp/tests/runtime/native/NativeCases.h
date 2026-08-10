#ifndef IMPERIALISM_NATIVE_CASES_H
#define IMPERIALISM_NATIVE_CASES_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error NativeCases is test-only and must not be included in the production build
#endif

#include "NativeTransition.h"

struct NativeCase {
  const char* name;
  RuntimeActionResult (*run)(NativeTransition&);
};

const NativeCase* FindNativeCase(const char* name);

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

RuntimeActionResult RunFirstTurnAlertPhase(NativeTransition& transition);
RuntimeActionResult RunFirstTurnDiplomacyPhase(NativeTransition& transition);
RuntimeActionResult RunFirstTurnTradePhase(NativeTransition& transition);
RuntimeActionResult RunFirstTurnCivilianPhase(NativeTransition& transition);
RuntimeActionResult RunFirstTurnMilitaryPhase(NativeTransition& transition);
RuntimeActionResult RunFirstTurnCombatMovementPhase(NativeTransition& transition);
RuntimeActionResult RunFirstTurnMilitaryCleanupPhase(NativeTransition& transition);
RuntimeActionResult RunFirstTurnDiplomacyOfferPhase(NativeTransition& transition);
RuntimeActionResult RunFirstTurnEliminationPhase(NativeTransition& transition);
RuntimeActionResult RunFirstTurnCityTransportPhase(NativeTransition& transition);

RuntimeActionResult RunFirstTurnGreatPowerPressurePhase(NativeTransition& transition);
RuntimeActionResult RunFirstTurnDealBookPhase(NativeTransition& transition);
RuntimeActionResult RunFirstTurnQuarterGatePhase(NativeTransition& transition);
RuntimeActionResult RunFirstTurnSeasonAdvancePhase(NativeTransition& transition);
RuntimeActionResult RunFirstTurnTechnologyAdvancesPhase(NativeTransition& transition);
RuntimeActionResult RunFirstTurnNewspaperPhase(NativeTransition& transition);
RuntimeActionResult RunFirstTurnReturnToMapPhase(NativeTransition& transition);

RuntimeActionResult RunNationResourceYieldRebuild(NativeTransition& transition);
RuntimeActionResult RunAiNationResourceYieldRebuildClampsTargets(NativeTransition& transition);

RuntimeActionResult RunSpecialistRecruitment(NativeTransition& transition);
RuntimeActionResult RunMilitaryMaintenance(NativeTransition& transition);

RuntimeActionResult RunCompletedRailSection(NativeTransition& transition);
RuntimeActionResult RunCompletedResourceDevelopment(NativeTransition& transition);

#endif
