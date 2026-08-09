//! Shared constructors for `imperialism-core` unit tests.
//!
//! These build a canonical, correlated [`GameState`]/[`MajorNation`]/[`CityState`]
//! so individual tests override only the fields they exercise instead of pasting
//! full struct literals.

use crate::{
    CityState, CivilianUnitTable, Difficulty, GameState, GreatPowerState, LaborPool, MajorNation,
    MajorNationTable, MilitaryUnitTable, MinorNationTable, NationCapacities, NationCommonState,
    NationId, NationTable, Nations, PendingActionTable, PopulationState, ProductionTable,
    ResourceTable, RetailCrtRng, RetailLcg, RngState, ShipTypeTable, StrategicMap, TileId,
    TradeMarketState, TurnState,
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
        ship_order_count_by_type: ShipTypeTable::default(),
        rolling_item_production_score: 0,
        low_production: false,
        low_stock: false,
        reserved_by_type: ResourceTable::default(),
        home_town_tile: Some(TileId::new(1)),
        power_available: 0,
        stockpile: crate::Stockpile::default(),
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
            accumulator: crate::PopulationAccumulator::from_bits(7.0_f32.to_bits()),
            strength: 12,
            extra: 0,
            strike_phase: crate::StrikePhase::default(),
            baseline_labor: LaborPool::new(4, 2, 1),
            production_labor: LaborPool::new(4, 2, 1),
            pending_labor_delta: LaborPool::default(),
            predicted_need_by_resource: ResourceTable::default(),
        },
    }
}

/// A neutral major-nation rule state with default tables and capacities.
pub(crate) fn great_power_state() -> GreatPowerState {
    GreatPowerState {
        controller: crate::MajorNationController::Human,
        foreign_minister_personality: crate::ForeignMinisterPersonality::Base,
        foreign_minister_skill_index: 0,
        development_grant_by_nation: NationTable::default(),
        defense_minister_skill_index: 0,
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
        pending_actions: PendingActionTable::default(),
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
        economy: great_power_state(),
        city: city(),
    }
}

/// A game state with seven valid major nations and an empty world.
pub(crate) fn game_state() -> GameState {
    let mut diplomacy_rng = RetailCrtRng::from_state(1);
    GameState {
        turn: TurnState {
            scenario_map: None,
            economic_turn: 1,
            phase: crate::PhaseCode::STRATEGIC_MAP,
            difficulty: Difficulty::Easy,
            active_nation: NationId::new(0),
            selected_nation: NationId::new(0),
        },
        unit_ids: crate::UnitIdAllocator::default(),
        world: StrategicMap::new(
            crate::MapTopology::Bounded,
            vec![crate::TileState::default(); crate::STRATEGIC_TILE_COUNT],
        )
        .unwrap(),
        rng: RngState {
            crt_rand: RetailCrtRng::from_state(1),
            map_generation: RetailLcg::from_state(1),
            zone_status: RetailLcg::from_state(1),
        },
        market: TradeMarketState::default(),
        diplomacy: crate::DiplomacyState::for_random_start(
            crate::MajorNationId::new(0),
            Difficulty::Normal,
            &mut diplomacy_rng,
        ),
        nations: Nations {
            majors: MajorNationTable::from_fn(|_nation| major_nation()),
            minors: MinorNationTable::default(),
        },
        military_units: Vec::new(),
        civilian_units: Vec::new(),
        ships: Vec::new(),
        task_forces: Vec::new(),
        missions: Vec::new(),
        pending: crate::PendingWorkState::default(),
    }
}
