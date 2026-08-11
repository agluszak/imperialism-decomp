//! Shared constructors for `imperialism-core` unit tests.
//!
//! These build a canonical, correlated [`GameState`]/[`MajorNation`]/[`CityState`]
//! so individual tests override only the fields they exercise instead of pasting
//! full struct literals.

use crate::*;

pub(crate) fn random_game_names() -> RandomGameNames {
    let mut localized_nation_names = NationTable::default();
    let mut province_names_by_nation = NationTable::default();
    for nation in NationId::all() {
        localized_nation_names[nation] = format!("N{}", nation.get());
        let count = if MajorNationId::from_nation(nation).is_some() {
            8
        } else {
            4
        };
        province_names_by_nation[nation] = (0..count)
            .map(|ordinal| format!("N{}P{}", nation.get(), ordinal + 1))
            .collect();
    }
    RandomGameNames {
        localized_nation_names,
        province_names_by_nation,
        zone_headline_templates: (0..24).map(|status| format!("S{status} [1]")).collect(),
        fallback_ocean_names: (0..37).map(|index| format!("Ocean{index}")).collect(),
    }
}

/// A minimal city with a small three-band population and no stock.
pub(crate) fn city() -> CityState {
    CityState {
        orders: Box::default(),
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
        ai_zone_targets: None,
        ai_province_targets: None,
        foreign_minister_personality: crate::ForeignMinisterPersonality::Base,
        foreign_minister_skill_index: 0,
        foreign_trade: crate::ForeignTradeState::for_random_start(
            crate::ForeignMinisterPersonality::Base,
        ),
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
        deal_book: crate::TradeCommodityTable::default(),
        pending_ship: None,
        interior_civilian: Box::default(),
        ai_trade: None,
        ai_development_pressure: None,
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
        army_movement_budget: 0,
        aid_allocation_total: 0,
        colony_boycott_flags: NationTable::default(),
        military_expenses: 0,
    }
}

/// A present major nation with common state, rule state, and a city.
pub(crate) fn major_nation() -> MajorNation {
    MajorNation {
        kind: MajorNationKind::GreatPower,
        common: NationCommonState::from_parts(
            String::new(),
            crate::CountryStatus::Independent,
            Vec::new(),
            1_000,
            Some(TileId::new(1)),
            NationTable::default(),
        ),
        economy: great_power_state(),
        city: city(),
        towns: vec![TownState::for_frog_city(TileId::new(1), NationId::new(0))],
    }
}

/// A game state with seven valid major nations and an empty world.
pub(crate) fn game_state() -> GameState {
    let mut diplomacy_rng = RetailCrtRng::from_state(1);
    GameState {
        turn: TurnState {
            scenario_map: None,
            economic_turn: 1,
            diplomacy_year_term_raw: 1914,
            phase: crate::PhaseCode::STRATEGIC_MAP,
            turn_flow_status_flags: 0,
            quarter_gate_by_decade: [0, 1, 1, 1, 1, 1, 1, 1, 1, 1],
            difficulty: Difficulty::Easy,
            active_nation: NationId::new(0),
            selected_nation: NationId::new(0),
        },
        unit_ids: crate::UnitIdAllocator::default(),
        map: MapMgr::new(
            crate::MapTopology::Bounded,
            vec![crate::TileState::default(); crate::STRATEGIC_TILE_COUNT],
        )
        .unwrap(),
        ocean: Ocean::default(),
        rng: RngState {
            crt_rand: RetailCrtRng::from_state(1),
            map_generation: RetailLcg::from_state(1),
            zone_status: RetailLcg::from_state(1),
        },
        market: TradeMarketState::default(),
        technology: crate::TechnologyState::default(),
        diplomacy: crate::DiplomacyState::for_random_start(
            crate::MajorNationId::new(0),
            Difficulty::Normal,
            &mut diplomacy_rng,
        ),
        nations: Nations::new(
            MajorNationTable::from_fn(|_nation| major_nation()),
            MinorNationTable::default(),
        ),
        military_units: Vec::new(),
        civilian_units: Vec::new(),
        ships: Vec::new(),
        task_forces: Vec::new(),
        missions: Vec::new(),
        news: crate::NewsState::default(),
        pending: crate::PendingWorkState::default(),
    }
}
