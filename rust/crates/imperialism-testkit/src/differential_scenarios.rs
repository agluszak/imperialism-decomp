//! Rust halves of the process-isolated semantic differential scenarios.
//!
//! Each scenario keeps its native name, decoded case, semantic result, and
//! direct Rust operation together. The native runtime remains responsible for
//! constructing the case and observing the C++ result.

use crate::{EvidenceKind, RuntimeResultExpectations};

const DIFFERENTIAL_CAPTURES: &[&str] = &["before", "case", "after", "result"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScenarioMeta {
    pub name: &'static str,
    pub seed: u32,
    pub evidence_kind: EvidenceKind,
}

impl ScenarioMeta {
    pub const fn expectations(self) -> RuntimeResultExpectations<'static> {
        RuntimeResultExpectations {
            name: self.name,
            seed: self.seed,
            evidence_kind: self.evidence_kind,
            required_captures: DIFFERENTIAL_CAPTURES,
        }
    }
}

#[cfg(test)]
mod scenarios {
    use super::ScenarioMeta;
    use crate::EvidenceKind;
    use imperialism_core::*;
    use serde::Deserialize;

    const fn retail_fixture(name: &'static str) -> ScenarioMeta {
        ScenarioMeta {
            name,
            seed: 1,
            evidence_kind: EvidenceKind::RetailFixtureOracle,
        }
    }

    #[derive(Debug, Deserialize)]
    struct NationCase {
        nation: MajorNationId,
    }

    #[derive(Debug, Deserialize)]
    struct TradeSettlement {
        resource: ResourceKind,
        amount: i16,
        price: i16,
    }

    #[derive(Debug, Deserialize)]
    struct MajorTradeSettlementCase {
        nation: MajorNationId,
        settlements: Vec<TradeSettlement>,
    }

    const MAJOR_TRADE_SETTLEMENT: ScenarioMeta = retail_fixture("major_trade_settlement");

    fn apply_major_trade_settlement(state: &mut GameState, case: MajorTradeSettlementCase) {
        for settlement in case.settlements {
            state.purchase_item(
                case.nation,
                settlement.resource,
                settlement.amount,
                settlement.price,
            );
        }
    }

    const PURCHASED_ITEMS_PHASE: ScenarioMeta = retail_fixture("purchased_items_phase");

    #[derive(Debug, Deserialize)]
    struct PurchasedItemsPhaseCase {
        nation: MajorNationId,
        purchases: Vec<TradeSettlement>,
    }

    fn apply_purchased_items_phase(state: &mut GameState, case: PurchasedItemsPhaseCase) {
        state.remember_trade_bids(case.nation);
        for purchase in case.purchases {
            state.purchase_item(
                case.nation,
                purchase.resource,
                purchase.amount,
                purchase.price,
            );
        }
        state.commit_purchased_items(case.nation);
    }

    const CREATED_ITEMS_PHASE: ScenarioMeta = retail_fixture("created_items_phase");

    fn apply_created_items_phase(state: &mut GameState, case: NationCase) {
        state.add_created_items(case.nation);
    }

    const FIRST_TURN_ALERT_PHASE: ScenarioMeta = retail_fixture("first_turn_alert_phase");

    fn apply_first_turn_alert_phase(state: &mut GameState, (): ()) {
        let _ = state.advance_turn_step();
    }

    const FIRST_TURN_DIPLOMACY_PHASE: ScenarioMeta = retail_fixture("first_turn_diplomacy_phase");

    fn apply_first_turn_diplomacy_phase(
        state: &mut GameState,
        (): (),
    ) -> imperialism_core::AdvanceTurnOutcome {
        state.advance_turn_step()
    }

    const FIRST_TURN_TRADE_PHASE: ScenarioMeta = retail_fixture("first_turn_trade_phase");

    fn apply_first_turn_trade_phase(
        state: &mut GameState,
        (): (),
    ) -> imperialism_core::AdvanceTurnOutcome {
        state.advance_turn_step()
    }

    const FIRST_TURN_CIVILIAN_PHASE: ScenarioMeta = retail_fixture("first_turn_civilian_phase");

    fn apply_first_turn_civilian_phase(
        state: &mut GameState,
        (): (),
    ) -> imperialism_core::AdvanceTurnOutcome {
        state.advance_turn_step()
    }

    const FIRST_TURN_MILITARY_PHASE: ScenarioMeta = retail_fixture("first_turn_military_phase");

    fn apply_first_turn_military_phase(
        state: &mut GameState,
        (): (),
    ) -> imperialism_core::AdvanceTurnOutcome {
        state.advance_turn_step()
    }

    const FIRST_TURN_COMBAT_MOVEMENT_PHASE: ScenarioMeta =
        retail_fixture("first_turn_combat_movement_phase");

    fn apply_first_turn_combat_movement_phase(
        state: &mut GameState,
        (): (),
    ) -> imperialism_core::AdvanceTurnOutcome {
        state.advance_turn_step()
    }

    const FIRST_TURN_MILITARY_CLEANUP_PHASE: ScenarioMeta =
        retail_fixture("first_turn_military_cleanup_phase");

    fn apply_first_turn_military_cleanup_phase(
        state: &mut GameState,
        (): (),
    ) -> imperialism_core::AdvanceTurnOutcome {
        state.advance_turn_step()
    }

    const FIRST_TURN_DIPLOMACY_OFFER_PHASE: ScenarioMeta =
        retail_fixture("first_turn_diplomacy_offer_phase");

    fn apply_first_turn_diplomacy_offer_phase(
        state: &mut GameState,
        (): (),
    ) -> imperialism_core::AdvanceTurnOutcome {
        state.advance_turn_step()
    }

    const FIRST_TURN_ELIMINATION_PHASE: ScenarioMeta =
        retail_fixture("first_turn_elimination_phase");

    fn apply_first_turn_elimination_phase(
        state: &mut GameState,
        (): (),
    ) -> imperialism_core::AdvanceTurnOutcome {
        state.advance_turn_step()
    }

    const FIRST_TURN_CITY_TRANSPORT_PHASE: ScenarioMeta =
        retail_fixture("first_turn_city_transport_phase");

    fn apply_first_turn_city_transport_phase(
        state: &mut GameState,
        (): (),
    ) -> imperialism_core::AdvanceTurnOutcome {
        state.advance_turn_step()
    }

    const FIRST_TURN_GREAT_POWER_PRESSURE_PHASE: ScenarioMeta =
        retail_fixture("first_turn_great_power_pressure_phase");

    fn apply_first_turn_great_power_pressure_phase(
        state: &mut GameState,
        (): (),
    ) -> imperialism_core::AdvanceTurnOutcome {
        state.advance_turn_step()
    }

    const FIRST_TURN_DEAL_BOOK_PHASE: ScenarioMeta = retail_fixture("first_turn_deal_book_phase");

    fn apply_first_turn_deal_book_phase(
        state: &mut GameState,
        (): (),
    ) -> imperialism_core::AdvanceTurnOutcome {
        state.advance_turn_step()
    }

    const FIRST_TURN_QUARTER_GATE_PHASE: ScenarioMeta =
        retail_fixture("first_turn_quarter_gate_phase");

    fn apply_first_turn_quarter_gate_phase(
        state: &mut GameState,
        (): (),
    ) -> imperialism_core::AdvanceTurnOutcome {
        state.advance_turn_step()
    }

    const FIRST_TURN_SEASON_ADVANCE_PHASE: ScenarioMeta =
        retail_fixture("first_turn_season_advance_phase");

    fn apply_first_turn_season_advance_phase(
        state: &mut GameState,
        (): (),
    ) -> imperialism_core::AdvanceTurnOutcome {
        state.advance_turn_step()
    }

    const FIRST_TURN_TECHNOLOGY_ADVANCES_PHASE: ScenarioMeta =
        retail_fixture("first_turn_technology_advances_phase");

    fn apply_first_turn_technology_advances_phase(
        state: &mut GameState,
        (): (),
    ) -> imperialism_core::AdvanceTurnOutcome {
        state.advance_turn_step()
    }

    const FIRST_TURN_NEWSPAPER_PHASE: ScenarioMeta = retail_fixture("first_turn_newspaper_phase");

    fn apply_first_turn_newspaper_phase(
        state: &mut GameState,
        (): (),
    ) -> imperialism_core::AdvanceTurnOutcome {
        state.advance_turn_step()
    }

    const FIRST_TURN_RETURN_TO_MAP_PHASE: ScenarioMeta =
        retail_fixture("first_turn_return_to_map_phase");

    fn apply_first_turn_return_to_map_phase(
        state: &mut GameState,
        (): (),
    ) -> imperialism_core::AdvanceTurnOutcome {
        state.advance_turn_step()
    }

    const EASY_TURN_FROM_SAVE: ScenarioMeta = retail_fixture("easy_turn_from_save");

    #[derive(Debug, Deserialize)]
    struct EasyTurnFromSaveCase {
        reject_offers: bool,
        expect_exactly_one_turn: bool,
    }

    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    enum EasyTurnFromSaveResult {
        Completed {
            from_turn: i32,
            to_turn: i32,
            gates: Vec<UiGate>,
        },
    }

    fn apply_easy_turn_from_save(
        state: &mut GameState,
        case: EasyTurnFromSaveCase,
    ) -> EasyTurnFromSaveResult {
        assert!(case.reject_offers);
        assert!(case.expect_exactly_one_turn);
        let from_turn = state.turn.economic_turn;

        let first = state.finish_player_orders();
        assert!(matches!(
            first,
            AdvanceTurnOutcome::Blocked {
                block: TurnBlock::Ui {
                    gate: UiGate::DealBook
                },
                ..
            }
        ));

        let second = state.resume_after_ui(UiGate::DealBook);
        assert!(matches!(
            second,
            AdvanceTurnOutcome::Blocked {
                block: TurnBlock::Ui {
                    gate: UiGate::Newspaper
                },
                ..
            }
        ));

        let third = state.resume_after_ui(UiGate::Newspaper);
        assert!(matches!(
            third,
            AdvanceTurnOutcome::Blocked {
                block: TurnBlock::PlayerOrders,
                ..
            }
        ));
        assert_eq!(state.turn.economic_turn, from_turn + 1);

        EasyTurnFromSaveResult::Completed {
            from_turn,
            to_turn: state.turn.economic_turn,
            gates: vec![UiGate::DealBook, UiGate::Newspaper],
        }
    }

    const TRANSPORTED_ITEMS_PHASE: ScenarioMeta = retail_fixture("transported_items_phase");

    fn apply_transported_items_phase(state: &mut GameState, case: NationCase) {
        state.settle_transported_items(case.nation);
    }

    #[derive(Debug, Deserialize)]
    struct DiplomacyGrantCase {
        nation: MajorNationId,
        target: NationId,
        amount: i32,
    }

    const DIPLOMACY_GRANT_ENTRY: ScenarioMeta =
        retail_fixture("diplomacy_grant_entry_updates_treasury");

    fn apply_diplomacy_grant_entry(state: &mut GameState, case: DiplomacyGrantCase) -> bool {
        state.set_diplomacy_grant(
            case.nation,
            case.target,
            Some(DiplomacyGrant {
                amount: case.amount,
                recurring: false,
            }),
        )
    }

    const DIPLOMACY_RESET: ScenarioMeta =
        retail_fixture("diplomacy_reset_preserves_recurring_grants");

    fn apply_diplomacy_reset(state: &mut GameState, case: NationCase) {
        state.reset_diplomacy_commitments(case.nation);
    }

    #[derive(Debug, Deserialize)]
    struct AidAllocationCase {
        nation: MajorNationId,
        minor_nation: MinorNationId,
        resource: ResourceKind,
        amount: i32,
    }

    const AID_ALLOCATION: ScenarioMeta = retail_fixture("aid_allocation");

    fn apply_aid_allocation(state: &mut GameState, case: AidAllocationCase) {
        state.add_aid_allocation(case.nation, case.minor_nation, case.resource, case.amount);
    }

    #[derive(Debug, Deserialize)]
    struct DirectTransportCase {
        nation: MajorNationId,
        resource: ResourceKind,
        requested: i16,
    }

    const DIRECT_TRANSPORT: ScenarioMeta = retail_fixture("direct_transport");

    fn apply_direct_transport(state: &mut GameState, case: DirectTransportCase) -> i16 {
        state.direct_transport(case.nation, case.resource, case.requested)
    }

    const ROLLING_STOCK_SUCCESS: ScenarioMeta = retail_fixture("rolling_stock");
    const ROLLING_STOCK_INSUFFICIENT: ScenarioMeta = ScenarioMeta {
        name: "rolling_stock_insufficient_resources",
        seed: 1,
        evidence_kind: EvidenceKind::RetailFixtureOracle,
    };
    const ROLLING_STOCK_CORPUS: &[ScenarioMeta] =
        &[ROLLING_STOCK_SUCCESS, ROLLING_STOCK_INSUFFICIENT];

    fn apply_rolling_stock(state: &mut GameState, case: NationCase) -> bool {
        state.increase_rolling_stock(case.nation)
    }

    const MERCHANT_MARINE: ScenarioMeta = retail_fixture("merchant_marine");

    fn apply_merchant_marine(state: &mut GameState, case: NationCase) -> bool {
        state.increase_merchant_marine(case.nation)
    }

    #[derive(Debug, Deserialize)]
    struct CityItemOrderCase {
        nation: MajorNationId,
        output: ResourceKind,
        quantity: i16,
    }

    const CITY_ITEM_ORDER_INCREASE: ScenarioMeta = retail_fixture("city_item_order_increase");
    const CITY_ITEM_ORDER_DECREASE: ScenarioMeta = retail_fixture("city_item_order_decrease");

    fn apply_city_item_order(state: &mut GameState, case: CityItemOrderCase) -> bool {
        state.set_city_order_quantity(case.nation, CityOrderId::Item(case.output), case.quantity)
    }

    #[derive(Debug, Deserialize)]
    struct PowerPlantUpgradeCase {
        nation: MajorNationId,
        enabled: bool,
    }

    const POWER_PLANT_UPGRADE: ScenarioMeta = retail_fixture("power_plant_upgrade");

    fn apply_power_plant_upgrade(state: &mut GameState, case: PowerPlantUpgradeCase) {
        state.set_power_plant_upgrade(case.nation, case.enabled);
    }

    #[derive(Debug, Deserialize)]
    struct TradePolicyStepCase {
        source: MajorNationId,
        target: NationId,
    }

    const TRADE_POLICY_STEP: ScenarioMeta = retail_fixture("trade_policy_step");

    fn apply_trade_policy_step(state: &mut GameState, case: TradePolicyStepCase) {
        state.decrement_trade_policy_score(case.source, case.target);
    }

    #[derive(Debug, Deserialize)]
    struct TradePolicySetCase {
        nation: MajorNationId,
        target: NationId,
        policy: TradePolicyScore,
    }

    const TRADE_POLICY_SET: ScenarioMeta = retail_fixture("trade_policy_set");

    fn apply_trade_policy_set(state: &mut GameState, case: TradePolicySetCase) {
        state.set_trade_policy(case.nation, case.target, case.policy);
    }

    const TRADE_CAPACITY_REFRESH: ScenarioMeta = retail_fixture("trade_capacity_refresh");

    fn apply_trade_capacity_refresh(state: &mut GameState, case: NationCase) {
        state.refresh_merchant_capacity(case.nation);
    }

    const RECALL_TRADE_BIDS: ScenarioMeta = retail_fixture("recall_trade_bids");

    fn apply_recall_trade_bids(state: &mut GameState, case: NationCase) {
        state.recall_trade_bids(case.nation);
    }

    const TRANSPORT_NEED_ALLOCATION: ScenarioMeta = retail_fixture("transport_need_allocation");

    fn apply_transport_need_allocation(state: &mut GameState, case: NationCase) {
        state.allocate_transport_needs(case.nation);
    }

    const NATION_RESOURCE_YIELD_REBUILD: ScenarioMeta =
        retail_fixture("nation_resource_yield_rebuild");
    const AI_NATION_RESOURCE_YIELD_REBUILD_CLAMPS_TARGETS: ScenarioMeta =
        retail_fixture("ai_nation_resource_yield_rebuild_clamps_targets");
    const NATION_RESOURCE_YIELD_REBUILD_CORPUS: &[ScenarioMeta] = &[
        NATION_RESOURCE_YIELD_REBUILD,
        AI_NATION_RESOURCE_YIELD_REBUILD_CLAMPS_TARGETS,
    ];

    fn apply_nation_resource_yield_rebuild(state: &mut GameState, case: NationCase) {
        state.rebuild_nation_resource_yields(case.nation);
    }

    const PLAYER_TRADE_PHASE_RESET: ScenarioMeta = retail_fixture("player_trade_phase_reset");

    fn apply_player_trade_phase_reset(state: &mut GameState, case: NationCase) {
        state.reset_player_trade_phase(case.nation);
    }

    const TRADE_MARKET_PRICE: ScenarioMeta = retail_fixture("trade_market_price");

    fn apply_trade_market_price(state: &mut GameState, (): ()) {
        state.recalculate_trade_prices();
    }

    const MILITARY_MAINTENANCE: ScenarioMeta = retail_fixture("military_maintenance");

    fn apply_military_maintenance(state: &mut GameState, case: NationCase) {
        state.pay_for_military(case.nation);
    }

    #[derive(Debug, Deserialize)]
    struct ResourceDevelopmentCase {
        extractive_worker: CivilianUnitId,
        surface_worker: CivilianUnitId,
    }

    const COMPLETED_RESOURCE_DEVELOPMENT: ScenarioMeta =
        retail_fixture("completed_resource_development");

    fn apply_completed_resource_development(state: &mut GameState, case: ResourceDevelopmentCase) {
        state.advance_civilian_work(case.extractive_worker);
        state.advance_civilian_work(case.surface_worker);
    }

    #[derive(Debug, Deserialize)]
    struct RailConstructionCase {
        civilian: CivilianUnitId,
    }

    const COMPLETED_RAIL_SECTION: ScenarioMeta = retail_fixture("completed_rail_section");

    fn apply_completed_rail_section(state: &mut GameState, case: RailConstructionCase) {
        state.advance_civilian_work(case.civilian);
    }

    #[derive(Debug, Deserialize)]
    struct SpecialistRecruitmentCase {
        nation: MajorNationId,
        unit_kind: MilitaryUnitKind,
        quantity: i16,
    }

    const SPECIALIST_RECRUITMENT: ScenarioMeta = retail_fixture("specialist_recruitment");

    fn apply_specialist_recruitment(state: &mut GameState, case: SpecialistRecruitmentCase) {
        state.produce_military_recruits(case.nation, case.unit_kind, case.quantity);
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::differential;

        macro_rules! differential_test {
            ($test:ident, $scenario:expr, $apply:expr) => {
                #[test]
                #[ignore = "requires the native C++ runtime oracle (just runtime-run)"]
                fn $test() {
                    differential($scenario, $apply).unwrap();
                }
            };
        }

        differential_test!(
            major_trade_settlement,
            MAJOR_TRADE_SETTLEMENT,
            apply_major_trade_settlement
        );
        differential_test!(
            purchased_items_phase,
            PURCHASED_ITEMS_PHASE,
            apply_purchased_items_phase
        );
        differential_test!(
            created_items_phase,
            CREATED_ITEMS_PHASE,
            apply_created_items_phase
        );
        differential_test!(
            first_turn_alert_phase,
            FIRST_TURN_ALERT_PHASE,
            apply_first_turn_alert_phase
        );
        differential_test!(
            first_turn_diplomacy_phase,
            FIRST_TURN_DIPLOMACY_PHASE,
            apply_first_turn_diplomacy_phase
        );
        differential_test!(
            first_turn_trade_phase,
            FIRST_TURN_TRADE_PHASE,
            apply_first_turn_trade_phase
        );
        differential_test!(
            first_turn_civilian_phase,
            FIRST_TURN_CIVILIAN_PHASE,
            apply_first_turn_civilian_phase
        );
        differential_test!(
            first_turn_military_phase,
            FIRST_TURN_MILITARY_PHASE,
            apply_first_turn_military_phase
        );
        differential_test!(
            first_turn_combat_movement_phase,
            FIRST_TURN_COMBAT_MOVEMENT_PHASE,
            apply_first_turn_combat_movement_phase
        );
        differential_test!(
            first_turn_military_cleanup_phase,
            FIRST_TURN_MILITARY_CLEANUP_PHASE,
            apply_first_turn_military_cleanup_phase
        );
        differential_test!(
            first_turn_diplomacy_offer_phase,
            FIRST_TURN_DIPLOMACY_OFFER_PHASE,
            apply_first_turn_diplomacy_offer_phase
        );
        differential_test!(
            first_turn_elimination_phase,
            FIRST_TURN_ELIMINATION_PHASE,
            apply_first_turn_elimination_phase
        );
        differential_test!(
            first_turn_city_transport_phase,
            FIRST_TURN_CITY_TRANSPORT_PHASE,
            apply_first_turn_city_transport_phase
        );
        differential_test!(
            first_turn_great_power_pressure_phase,
            FIRST_TURN_GREAT_POWER_PRESSURE_PHASE,
            apply_first_turn_great_power_pressure_phase
        );
        differential_test!(
            first_turn_deal_book_phase,
            FIRST_TURN_DEAL_BOOK_PHASE,
            apply_first_turn_deal_book_phase
        );
        differential_test!(
            first_turn_quarter_gate_phase,
            FIRST_TURN_QUARTER_GATE_PHASE,
            apply_first_turn_quarter_gate_phase
        );
        differential_test!(
            first_turn_season_advance_phase,
            FIRST_TURN_SEASON_ADVANCE_PHASE,
            apply_first_turn_season_advance_phase
        );
        differential_test!(
            first_turn_technology_advances_phase,
            FIRST_TURN_TECHNOLOGY_ADVANCES_PHASE,
            apply_first_turn_technology_advances_phase
        );
        differential_test!(
            first_turn_newspaper_phase,
            FIRST_TURN_NEWSPAPER_PHASE,
            apply_first_turn_newspaper_phase
        );
        differential_test!(
            first_turn_return_to_map_phase,
            FIRST_TURN_RETURN_TO_MAP_PHASE,
            apply_first_turn_return_to_map_phase
        );
        differential_test!(
            easy_turn_from_save,
            EASY_TURN_FROM_SAVE,
            apply_easy_turn_from_save
        );
        differential_test!(
            transported_items_phase,
            TRANSPORTED_ITEMS_PHASE,
            apply_transported_items_phase
        );
        differential_test!(
            diplomacy_grant_entry,
            DIPLOMACY_GRANT_ENTRY,
            apply_diplomacy_grant_entry
        );
        differential_test!(diplomacy_reset, DIPLOMACY_RESET, apply_diplomacy_reset);
        differential_test!(aid_allocation, AID_ALLOCATION, apply_aid_allocation);
        differential_test!(direct_transport, DIRECT_TRANSPORT, apply_direct_transport);
        differential_test!(merchant_marine, MERCHANT_MARINE, apply_merchant_marine);
        differential_test!(
            city_item_order_increase,
            CITY_ITEM_ORDER_INCREASE,
            apply_city_item_order
        );
        differential_test!(
            city_item_order_decrease,
            CITY_ITEM_ORDER_DECREASE,
            apply_city_item_order
        );
        differential_test!(
            power_plant_upgrade,
            POWER_PLANT_UPGRADE,
            apply_power_plant_upgrade
        );
        differential_test!(
            trade_policy_step,
            TRADE_POLICY_STEP,
            apply_trade_policy_step
        );
        differential_test!(trade_policy_set, TRADE_POLICY_SET, apply_trade_policy_set);
        differential_test!(
            trade_capacity_refresh,
            TRADE_CAPACITY_REFRESH,
            apply_trade_capacity_refresh
        );
        differential_test!(
            recall_trade_bids,
            RECALL_TRADE_BIDS,
            apply_recall_trade_bids
        );
        differential_test!(
            transport_need_allocation,
            TRANSPORT_NEED_ALLOCATION,
            apply_transport_need_allocation
        );
        #[test]
        #[ignore = "requires the native C++ runtime oracle (just runtime-run)"]
        fn nation_resource_yield_rebuild_corpus() {
            for scenario in NATION_RESOURCE_YIELD_REBUILD_CORPUS {
                differential(*scenario, apply_nation_resource_yield_rebuild).unwrap();
            }
        }
        differential_test!(
            player_trade_phase_reset,
            PLAYER_TRADE_PHASE_RESET,
            apply_player_trade_phase_reset
        );
        differential_test!(
            trade_market_price,
            TRADE_MARKET_PRICE,
            apply_trade_market_price
        );
        differential_test!(
            military_maintenance,
            MILITARY_MAINTENANCE,
            apply_military_maintenance
        );
        differential_test!(
            completed_resource_development,
            COMPLETED_RESOURCE_DEVELOPMENT,
            apply_completed_resource_development
        );
        differential_test!(
            completed_rail_section,
            COMPLETED_RAIL_SECTION,
            apply_completed_rail_section
        );
        differential_test!(
            specialist_recruitment,
            SPECIALIST_RECRUITMENT,
            apply_specialist_recruitment
        );

        #[test]
        #[ignore = "requires the native C++ runtime oracle (just runtime-run)"]
        fn rolling_stock_corpus() {
            for scenario in ROLLING_STOCK_CORPUS {
                differential(*scenario, apply_rolling_stock).unwrap();
            }
        }

        #[test]
        fn rolling_stock_corpus_names_deliberate_success_and_rejection_cases() {
            assert_eq!(ROLLING_STOCK_CORPUS.len(), 2);
            assert_eq!(ROLLING_STOCK_CORPUS[0].name, "rolling_stock");
            assert_eq!(
                ROLLING_STOCK_CORPUS[1].name,
                "rolling_stock_insufficient_resources"
            );
            assert!(
                ROLLING_STOCK_CORPUS
                    .iter()
                    .all(|scenario| scenario.evidence_kind == EvidenceKind::RetailFixtureOracle)
            );
        }
    }
}
