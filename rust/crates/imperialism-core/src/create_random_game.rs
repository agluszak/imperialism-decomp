use crate::{
    AidAllocationTable, CityState, Difficulty, GameState, GeneratedTerrainTile, LaborPool,
    MAJOR_NATION_COUNT, MajorNationId, MajorNationState, MajorNationTable, NATION_COUNT,
    NationCommonState, NationData, NationId, NationPendingWork, NationState, NationTable,
    PendingWorkState, PopulationState, ProductionSlot, ProductionTable, RandomSetupPreview,
    ResourceTable, RetailTopologyByte, RngState, STRATEGIC_TILE_COUNT, TileState, TurnState,
    WorldState, all_resources,
};

/// Inputs committed when Accept/Okay is pressed on the random-game setup screen.
///
/// The retained [`RandomSetupPreview`] already owns the accepted terrain map; this
/// draft only carries the player-facing options applied by `StartGame`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RandomGameDraft {
    pub topology: RetailTopologyByte,
    pub nation: MajorNationId,
    pub country_name: String,
    pub difficulty: Difficulty,
    pub localized_names: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CreateRandomGameError {
    #[error("preview map has {actual} tiles, expected {STRATEGIC_TILE_COUNT}")]
    InvalidTileCount { actual: usize },
}

/// Starting treasury by difficulty for human majors (`g_anNationStartingTreasuryByLocale`).
///
/// AI majors force 10000 after construction regardless of this table.
const STARTING_TREASURY_BY_DIFFICULTY: [i32; 5] = [50_000, 10_000, 10_000, 5_000, 5_000];

/// Scenario city stock presets (`g_Rebuild_Primary_Nation_Value_00653570`).
///
/// Row index is the difficulty for human majors, or forced Normal for AI majors.
const CITY_STOCK_PRESET_BY_LEVEL: [[i16; 23]; 5] = [
    [
        20, 20, 40, 30, 30, 10, 0, 20, 20, 20, 20, 20, 0, 10, 10, 10, 10, 10, 5, 0, 5, 0, 0,
    ],
    [
        5, 5, 10, 5, 5, 2, 0, 20, 10, 15, 8, 10, 0, 5, 5, 0, 0, 10, 5, 0, 5, 0, 0,
    ],
    [
        0, 0, 0, 0, 0, 0, 0, 20, 10, 24, 8, 19, 0, 5, 5, 0, 0, 0, 0, 0, 0, 0, 0,
    ],
    [
        0, 0, 0, 0, 0, 0, 0, 15, 6, 16, 6, 12, 0, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0,
    ],
    [
        0, 0, 0, 0, 0, 0, 0, 15, 6, 16, 6, 12, 0, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0,
    ],
];

/// Production-order slots forced to 999 by `ApplyScenarioRelationPresetAndSpawnFrogCity`.
const SCENARIO_FORCED_PRODUCTION_SLOTS: [u8; 6] = [7, 8, 9, 10, 13, 14];

/// Builds the Normal start-boundary [`GameState`] from a setup draft and retained preview.
///
/// Retail Accept does not regenerate the map. It commits setup options and rebuilds
/// nation/city state on top of the preview already produced by the setup screen.
/// The returned state matches the capital-selection-ready boundary for Normal+
/// (`phase_code = 2`, human capital not yet placed).
pub fn create_random_game(
    draft: &RandomGameDraft,
    preview: &RandomSetupPreview,
) -> Result<GameState, CreateRandomGameError> {
    if preview.map.tiles.len() != STRATEGIC_TILE_COUNT {
        return Err(CreateRandomGameError::InvalidTileCount {
            actual: preview.map.tiles.len(),
        });
    }

    let _ = (&draft.country_name, draft.localized_names);

    Ok(GameState {
        turn: TurnState {
            scenario_map_index_plus_one: 0,
            economic_turn: 0,
            phase_code: 2,
            difficulty: draft.difficulty,
            active_nation: draft.nation.nation(),
            selected_nation: draft.nation.nation(),
        },
        persistent_unit_id_counter: 0,
        world: WorldState {
            wraps_horizontally: draft.topology.wraps_horizontally(),
            tiles: preview
                .map
                .tiles
                .iter()
                .copied()
                .map(tile_from_generated)
                .collect(),
        },
        rng: RngState {
            // CRT/zone advance during later bootstrap; map_generation stays at the
            // retained preview until tile post-passes and capital placement consume it.
            crt_rand: 0,
            map_generation: preview.final_map_lcg,
            zone_status: 0,
        },
        nations: bootstrap_nations(draft),
        cities: bootstrap_cities(draft),
        military_units: Vec::new(),
        civilian_units: Vec::new(),
        ships: Vec::new(),
        task_forces: Vec::new(),
        missions: Vec::new(),
        pending: PendingWorkState {
            turn_flow_status_flags: 0,
            nations: MajorNationTable::from_fn(|_nation| NationPendingWork {
                turn_events: Vec::new(),
                proposals: Vec::new(),
                turn_summary: Vec::new(),
                turn_start_events: Vec::new(),
            }),
            war_transitions: Vec::new(),
        },
    })
}

fn tile_from_generated(tile: GeneratedTerrainTile) -> TileState {
    let owner = (tile.owner_nation >= 0).then_some(tile.owner_nation);
    TileState {
        terrain_kind: tile.terrain_kind,
        owner_nation: owner,
        // Retail stamps former owners from the generation owners before Accept.
        former_owner_nation: owner,
        province: (tile.province_index >= 0).then_some(tile.province_index),
        development_classes: 0,
        edge_resources: [None, None],
        rail_flags: 0,
        // Map tiles default to "no action" (-1) after generation.
        action_state: -1,
        active_flags: 0,
    }
}

fn bootstrap_nations(draft: &RandomGameDraft) -> NationTable<Option<NationState>> {
    let mut nations = NationTable::default();
    for slot in 0..NATION_COUNT as u8 {
        let nation = NationId::new(slot);
        if slot < MAJOR_NATION_COUNT as u8 {
            let human = slot == draft.nation.get();
            nations[nation] = Some(major_nation_state(nation, draft.difficulty, human));
        } else {
            nations[nation] = Some(minor_nation_state(nation));
        }
    }
    nations
}

fn major_nation_state(nation: NationId, difficulty: Difficulty, human: bool) -> NationState {
    let treasury = if human {
        STARTING_TREASURY_BY_DIFFICULTY[difficulty.index()]
    } else {
        // IAutoGreatPower forces treasury to 10000 after IGreatPower.
        10_000
    };
    NationState {
        common: NationCommonState {
            // InitializeNationStateIdentityAndOwnedRegionList sets -1; DecodeOwnerNationSlot
            // then reports the nation's own slot.
            encoded_nation_slot: -1,
            owner_nation: i16::from(nation.get()),
            treasury,
            // Human Normal+ keeps home_tile at -1 until capital selection. AI homes are
            // chosen later by SelectBestSecondaryHomeTileByFrogCityScore (needs tile
            // post-passes).
            home_tile: -1,
            need_level_by_nation: NationTable::from_array([100; NATION_COUNT]),
        },
        data: NationData::Major(MajorNationState {
            diplomacy_eligible: human,
            // Capacities after IGreatPower / IAutoGreatPower construction.
            capacities: [0, 0, 0x0f, 0],
            grant_total_cost: 0,
            unfilled_trade_offer_count: 0,
            diplomacy_policy_by_nation: NationTable::default(),
            diplomacy_grant_by_nation: NationTable::default(),
            need_current_by_type: ResourceTable::default(),
            need_target_by_type: ResourceTable::default(),
            relation_delta_current: ResourceTable::default(),
            purchased_items_by_resource: ResourceTable::default(),
            item_potentials: ResourceTable::default(),
            unfilled_trade_turns_by_resource: ResourceTable::default(),
            transported_items_by_resource: ResourceTable::default(),
            remembered_trade_offers_by_resource: ResourceTable::default(),
            aid_allocation_matrix: AidAllocationTable::default(),
            budget_pool_base: 0,
            budget_pool_delta: 0,
            special_resource_trade_balance: 0,
            candidate_nation_flags: NationTable::default(),
            scenario_initialized: false,
            turn_finished: true,
            pending_action_status: crate::PendingActionTable::default(),
            pending_action_payload_by_action: crate::PendingActionTable::default(),
            diplomacy_budget_base: 20_000,
            escalation_counter: 0,
            pending_commitment_cost: 0,
            pressure_counter: 0,
            aid_allocation_total: 0,
            colony_boycott_flags: NationTable::default(),
            military_expenses: 0,
        }),
    }
}

fn minor_nation_state(nation: NationId) -> NationState {
    NationState {
        common: NationCommonState {
            encoded_nation_slot: -1,
            owner_nation: i16::from(nation.get()),
            treasury: 5_000,
            home_tile: -1,
            need_level_by_nation: NationTable::from_array([100; NATION_COUNT]),
        },
        data: NationData::Minor,
    }
}

fn bootstrap_cities(draft: &RandomGameDraft) -> MajorNationTable<Option<CityState>> {
    MajorNationTable::from_fn(|nation| {
        let human = nation.get() == draft.nation.get();
        let preset_level = if human {
            draft.difficulty.index()
        } else {
            // AI majors always use the Normal preset row.
            Difficulty::Normal.index()
        };
        Some(scenario_city(preset_level, human))
    })
}

fn scenario_city(preset_level: usize, human: bool) -> CityState {
    let stock_row = CITY_STOCK_PRESET_BY_LEVEL[preset_level];
    let mut stock_by_type = ResourceTable::default();
    for (index, resource) in all_resources().enumerate() {
        stock_by_type[resource] = stock_row[index];
    }

    let mut production_orders = ProductionTable::default();
    let mut production_accum = ProductionTable::default();
    for slot in SCENARIO_FORCED_PRODUCTION_SLOTS {
        let slot = ProductionSlot::new(slot).expect("forced production slot is in range");
        production_accum[slot] = 999;
        production_orders[slot] = 999;
    }

    // Intro (preset 0) uses SetPopulation(2, 3, 2); every other level uses (4, 2, 1).
    let labor = if preset_level == 0 {
        LaborPool::new(2, 3, 2)
    } else {
        LaborPool::new(4, 2, 1)
    };
    let count = labor
        .low
        .wrapping_add(labor.medium)
        .wrapping_add(labor.high);

    CityState {
        power_plant_upgrade_queued: false,
        food_substitution_count: 0,
        starvation_population_loss: 0,
        serialized_state: 0,
        phase_counter: 0,
        military_recruit_count_by_kind: crate::MilitaryUnitTable::default(),
        civilian_recruit_count_by_kind: crate::CivilianUnitTable::default(),
        order_count_by_type: [0; 14],
        rolling_item_production_score: 0,
        low_production: false,
        low_stock: false,
        reserved_by_type: ResourceTable::default(),
        // Human Frog City marker sits at tile 0 without PlaceCity. AI capitals are
        // placed later once tile post-passes and frog-city scoring land.
        home_town_tile: if human { 0 } else { -1 },
        power_available: 0,
        stock_by_type,
        production_orders,
        production_accum,
        production_flags: ProductionTable::default(),
        production_current: ProductionTable::default(),
        production_progress: ProductionTable::default(),
        population_growth_penalty_ticks: 0,
        unmet_resource_retries: ResourceTable::default(),
        consumed_production_input_by_type: ResourceTable::default(),
        population: PopulationState {
            count,
            count_float_bits: f32::from(count).to_bits(),
            strength: labor.strength(),
            extra: 0,
            phase_value: 0,
            baseline_labor: Some(labor),
            production_labor: Some(labor),
            pending_labor_delta: Some(LaborPool::default()),
            predicted_need_by_resource: ResourceTable::default(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Difficulty, ResourceKind, RetailTopologyByte, generate_random_setup_preview_with_clock_seed,
    };

    #[test]
    fn creates_a_normal_start_boundary_from_the_retained_preview() {
        let preview = generate_random_setup_preview_with_clock_seed(
            b"Woopnist",
            RetailTopologyByte::from_wraps_horizontally(true),
            1,
        );
        let state = create_random_game(
            &RandomGameDraft {
                topology: RetailTopologyByte::from_wraps_horizontally(true),
                nation: MajorNationId::new(6),
                country_name: "Testland".to_owned(),
                difficulty: Difficulty::Normal,
                localized_names: true,
            },
            &preview,
        )
        .unwrap();

        assert_eq!(state.turn.phase_code, 2);
        assert_eq!(state.turn.difficulty, Difficulty::Normal);
        assert_eq!(state.turn.selected_nation, NationId::new(6));
        assert_eq!(state.rng.map_generation, preview.final_map_lcg);
        assert_eq!(state.world.tiles.len(), STRATEGIC_TILE_COUNT);
        assert_eq!(
            state.world.tiles[0].terrain_kind,
            preview.map.tiles[0].terrain_kind
        );
        assert_eq!(
            state.world.tiles[0].former_owner_nation,
            state.world.tiles[0].owner_nation
        );

        let human = state.nations[NationId::new(6)].as_ref().unwrap();
        assert_eq!(human.common.treasury, 10_000);
        assert_eq!(human.common.home_tile, -1);
        assert!(human.major().unwrap().diplomacy_eligible);

        let ai = state.nations[NationId::new(0)].as_ref().unwrap();
        assert_eq!(ai.common.treasury, 10_000);
        assert!(!ai.major().unwrap().diplomacy_eligible);

        assert_eq!(state.nations.iter().flatten().count(), NATION_COUNT);
        assert_eq!(state.cities.iter().flatten().count(), MAJOR_NATION_COUNT);
        assert_eq!(
            state.cities[MajorNationId::new(6)]
                .as_ref()
                .unwrap()
                .home_town_tile,
            0
        );
        assert_eq!(
            state.cities[MajorNationId::new(6)]
                .as_ref()
                .unwrap()
                .stock_by_type[ResourceKind::Food],
            20
        );
    }
}
