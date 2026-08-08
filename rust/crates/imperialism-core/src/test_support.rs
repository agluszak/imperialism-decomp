//! Shared constructors for `imperialism-core` unit tests.
//!
//! These build a canonical, correlated [`GameState`]/[`MajorNation`]/[`CityState`]
//! so individual tests override only the fields they exercise instead of pasting
//! full struct literals.

use crate::{
    CityState, CivilianUnitTable, Difficulty, GameState, IndustryActionTable, LaborPool,
    MajorNation, MajorNationId, MajorNationState, MajorNationTable, MilitaryUnitTable,
    MinorNationTable, NationCapacities, NationCommonState, NationId, NationPendingWork,
    NationTable, Nations, PendingActionTable, PendingWorkState, PopulationState, ProductionTable,
    ResourceTable, RetailCrtRng, RetailLcg, RngState, TileId, TradeMarketState, TurnState,
    WorldState,
};

/// A minimal city with a small three-band population and no stock.
pub(crate) fn city() -> CityState {
    CityState {
        power_plant_upgrade_queued: false,
        food_substitution_count: 0,
        starvation_population_loss: 0,
        serialized_state: 0,
        phase_counter: 0,
        military_recruit_count_by_kind: MilitaryUnitTable::default(),
        civilian_recruit_count_by_kind: CivilianUnitTable::default(),
        order_count_by_type: IndustryActionTable::default(),
        rolling_item_production_score: 0,
        low_production: false,
        low_stock: false,
        reserved_by_type: ResourceTable::default(),
        home_town_tile: Some(TileId::new(1)),
        power_available: 0,
        stock_by_type: ResourceTable::default(),
        production_orders: ProductionTable::default(),
        production_accum: ProductionTable::default(),
        production_flags: ProductionTable::default(),
        production_current: ProductionTable::default(),
        production_progress: ProductionTable::default(),
        population_growth_penalty_ticks: 0,
        unmet_resource_retries: ResourceTable::default(),
        consumed_production_input_by_type: ResourceTable::default(),
        population: PopulationState {
            count: 7,
            count_float_bits: 7.0_f32.to_bits(),
            strength: 12,
            extra: 0,
            phase_value: 0,
            baseline_labor: LaborPool::new(4, 2, 1),
            production_labor: LaborPool::new(4, 2, 1),
            pending_labor_delta: LaborPool::default(),
            predicted_need_by_resource: ResourceTable::default(),
        },
    }
}

/// A neutral major-nation rule state with default tables and capacities.
pub(crate) fn major_nation_state() -> MajorNationState {
    MajorNationState {
        diplomacy_eligible: true,
        capacities: NationCapacities::default(),
        grant_total_cost: 0,
        unfilled_trade_offer_count: 0,
        diplomacy_policy_by_nation: NationTable::default(),
        diplomacy_grants_by_nation: NationTable::default(),
        need_current_by_type: ResourceTable::default(),
        need_target_by_type: ResourceTable::default(),
        relation_delta_current: ResourceTable::default(),
        purchased_items_by_resource: ResourceTable::default(),
        item_potentials: ResourceTable::default(),
        unfilled_trade_turns_by_resource: ResourceTable::default(),
        transported_items_by_resource: ResourceTable::default(),
        remembered_trade_offers_by_resource: ResourceTable::default(),
        aid_allocation_by_minor_nation: MinorNationTable::default(),
        budget_pool_base: 0,
        budget_pool_delta: 0,
        special_resource_trade_balance: 0,
        candidate_nation_flags: NationTable::default(),
        scenario_initialized: false,
        turn_finished: false,
        pending_action_status: PendingActionTable::default(),
        pending_action_payload_by_action: PendingActionTable::default(),
        diplomacy_budget_base: 0,
        escalation_counter: 0,
        pending_commitment_cost: 0,
        pressure_counter: 0,
        aid_allocation_total: 0,
        colony_boycott_flags: NationTable::default(),
        military_expenses: 0,
    }
}

/// A present major nation with common state, rule state, and a city.
pub(crate) fn major_nation() -> MajorNation {
    MajorNation {
        common: NationCommonState {
            treasury: 1_000,
            home_tile: Some(TileId::new(0)),
            trade_policy_by_nation: NationTable::default(),
        },
        state: major_nation_state(),
        city: Some(city()),
    }
}

/// A game state with a single present major nation (slot 0) and empty world.
pub(crate) fn game_state() -> GameState {
    let mut majors = MajorNationTable::default();
    majors[MajorNationId::new(0)] = Some(major_nation());
    GameState {
        turn: TurnState {
            scenario_map_index_plus_one: 0,
            economic_turn: 1,
            phase_code: 5,
            difficulty: Difficulty::Easy,
            active_nation: NationId::new(0),
            selected_nation: NationId::new(0),
        },
        persistent_unit_id_counter: 0,
        world: WorldState {
            wraps_horizontally: false,
            tiles: Vec::new(),
        },
        rng: RngState {
            crt_rand: RetailCrtRng::from_state(1),
            map_generation: RetailLcg::from_state(1),
            zone_status: RetailLcg::from_state(1),
        },
        market: TradeMarketState::default(),
        nations: Nations {
            majors,
            minors: MinorNationTable::default(),
        },
        military_units: Vec::new(),
        civilian_units: Vec::new(),
        ships: Vec::new(),
        task_forces: Vec::new(),
        missions: Vec::new(),
        pending: PendingWorkState {
            nations: MajorNationTable::from_fn(|_nation| NationPendingWork {
                turn_events: Vec::new(),
                proposals: Vec::new(),
                turn_summary: Vec::new(),
                turn_start_events: Vec::new(),
            }),
            war_transitions: Vec::new(),
        },
    }
}
