use crate::{
    CityState, Difficulty, GameState, GeneratedTerrainTile, LaborPool, MajorNation, MajorNationId,
    MajorNationTable, MinorNation, MinorNationTable, NationCommonState, NationPendingWork,
    NationTable, Nations, PendingWorkState, ProductionTable, ProvinceId, RandomSetupPreview,
    ResourceTable, RetailCrtRng, RetailLcg, RngState, TileOwnerTag, TileState, TradeMarketState,
    TurnState, WorldState,
};
use enum_map::EnumMap;

/// Starting treasury by difficulty for human majors (`g_anNationStartingTreasuryByLocale`).
///
/// AI majors force 10000 after construction regardless of this table.
const STARTING_TREASURY_BY_DIFFICULTY: EnumMap<Difficulty, i32> =
    EnumMap::from_array([50_000, 10_000, 10_000, 5_000, 5_000]);

/// Scenario city stock presets (`g_Rebuild_Primary_Nation_Value_00653570`).
///
/// Row index is the difficulty for human majors, or forced Normal for AI majors.
const CITY_STOCK_PRESET_BY_DIFFICULTY: EnumMap<Difficulty, ResourceTable<i16>> =
    EnumMap::from_array([
        ResourceTable::from_array([
            20, 20, 40, 30, 30, 10, 0, 20, 20, 20, 20, 20, 0, 10, 10, 10, 10, 10, 5, 0, 5, 0, 0,
        ]),
        ResourceTable::from_array([
            5, 5, 10, 5, 5, 2, 0, 20, 10, 15, 8, 10, 0, 5, 5, 0, 0, 10, 5, 0, 5, 0, 0,
        ]),
        ResourceTable::from_array([
            0, 0, 0, 0, 0, 0, 0, 20, 10, 24, 8, 19, 0, 5, 5, 0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        ResourceTable::from_array([
            0, 0, 0, 0, 0, 0, 0, 15, 6, 16, 6, 12, 0, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        ResourceTable::from_array([
            0, 0, 0, 0, 0, 0, 0, 15, 6, 16, 6, 12, 0, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0,
        ]),
    ]);

/// Production-order values forced by `ApplyScenarioRelationPresetAndSpawnFrogCity`.
const SCENARIO_FORCED_PRODUCTION: ProductionTable<i16> =
    ProductionTable::from_array([0, 0, 0, 0, 0, 0, 0, 999, 999, 999, 999, 0, 0, 999, 999, 0]);

/// Builds the Normal start-boundary [`GameState`] from the retained preview.
///
/// Retail Accept does not regenerate the map. It commits setup options and rebuilds
/// nation/city state on top of the preview already produced by the setup screen.
/// The returned state matches the capital-selection-ready boundary for Normal+
/// (`phase_code = 2`, human capital not yet placed).
pub fn create_random_game(
    preview: &RandomSetupPreview,
    human_nation: MajorNationId,
    difficulty: Difficulty,
) -> GameState {
    GameState {
        turn: TurnState {
            scenario_map_index_plus_one: 0,
            economic_turn: 0,
            phase_code: 2,
            difficulty,
            active_nation: human_nation.nation(),
            selected_nation: human_nation.nation(),
        },
        persistent_unit_id_counter: 0,
        world: WorldState {
            wraps_horizontally: preview.topology.wraps_horizontally(),
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
            crt_rand: RetailCrtRng::from_state(0),
            map_generation: RetailLcg::from_state(preview.final_map_lcg),
            zone_status: RetailLcg::from_state(0),
        },
        market: TradeMarketState::default(),
        nations: bootstrap_nations(human_nation, difficulty),
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

fn tile_from_generated(tile: GeneratedTerrainTile) -> TileState {
    let owner = u8::try_from(tile.owner_nation).ok().map(TileOwnerTag::new);
    TileState {
        terrain_kind: tile.terrain_kind,
        owner_nation: owner,
        // Retail stamps former owners from the generation owners before Accept.
        former_owner_nation: owner,
        province: u16::try_from(tile.province_index).ok().map(ProvinceId::new),
        development: Default::default(),
        edge_resources: [None, None],
        transport_links: Default::default(),
        pending_rail_links: Default::default(),
        // Map tiles default to "no action" (-1) after generation.
        action_state: -1,
        active_flags: 0,
        region_marker: -1,
        river_sprite_code: tile.river_sprite_code,
    }
}

fn bootstrap_nations(human_nation: MajorNationId, difficulty: Difficulty) -> Nations {
    Nations {
        majors: MajorNationTable::from_fn(|nation| {
            Some(major_nation(difficulty, nation == human_nation))
        }),
        minors: MinorNationTable::from_fn(|_nation| Some(minor_nation())),
    }
}

fn major_nation(difficulty: Difficulty, human: bool) -> MajorNation {
    let treasury = if human {
        STARTING_TREASURY_BY_DIFFICULTY[difficulty]
    } else {
        // IAutoGreatPower forces treasury to 10000 after IGreatPower.
        10_000
    };
    // AI majors always use the Normal preset row for their scenario city.
    let preset_difficulty = if human {
        difficulty
    } else {
        Difficulty::Normal
    };
    MajorNation::for_random_start(treasury, human, scenario_city(preset_difficulty, human))
}

fn minor_nation() -> MinorNation {
    MinorNation {
        common: NationCommonState {
            treasury: 5_000,
            home_tile: None,
            trade_policy_by_nation: NationTable::default(),
        },
    }
}

fn scenario_city(difficulty: Difficulty, human: bool) -> CityState {
    // Intro (preset 0) uses SetPopulation(2, 3, 2); every other level uses (4, 2, 1).
    let labor = if difficulty == Difficulty::Introductory {
        LaborPool::new(2, 3, 2)
    } else {
        LaborPool::new(4, 2, 1)
    };
    CityState::for_random_start(
        CITY_STOCK_PRESET_BY_DIFFICULTY[difficulty],
        SCENARIO_FORCED_PRODUCTION,
        labor,
        human,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Difficulty, NationId, ResourceKind, RetailTopologyByte, TileId,
        generate_random_setup_preview_with_clock_seed,
    };

    #[test]
    fn creates_a_normal_start_boundary_from_the_retained_preview() {
        let preview = generate_random_setup_preview_with_clock_seed(
            b"Woopnist",
            RetailTopologyByte::from_wraps_horizontally(true),
            1,
        );
        let state = create_random_game(&preview, MajorNationId::new(6), Difficulty::Normal);

        assert_eq!(state.turn.phase_code, 2);
        assert_eq!(state.turn.difficulty, Difficulty::Normal);
        assert_eq!(state.turn.selected_nation, NationId::new(6));
        assert_eq!(
            state.rng.map_generation,
            RetailLcg::from_state(preview.final_map_lcg)
        );
        assert_eq!(state.world.tiles.len(), crate::STRATEGIC_TILE_COUNT);
        assert_eq!(
            state.world.tiles[0].terrain_kind,
            preview.map.tiles[0].terrain_kind
        );
        assert_eq!(
            state.world.tiles[0].former_owner_nation,
            state.world.tiles[0].owner_nation
        );

        let human = state.nations.major(MajorNationId::new(6)).unwrap();
        assert_eq!(human.common.treasury, 10_000);
        assert_eq!(human.common.home_tile, None);
        assert!(human.state.diplomacy_eligible);

        let ai = state.nations.major(MajorNationId::new(0)).unwrap();
        assert_eq!(ai.common.treasury, 10_000);
        assert!(!ai.state.diplomacy_eligible);

        assert_eq!(
            state.nations.majors.iter().flatten().count(),
            crate::MAJOR_NATION_COUNT
        );
        assert_eq!(
            state.nations.minors.iter().flatten().count(),
            crate::MINOR_NATION_COUNT
        );
        let human_city = state.nations.city(MajorNationId::new(6)).unwrap();
        assert_eq!(human_city.home_town_tile, Some(TileId::new(0)));
        assert_eq!(human_city.stock_by_type[ResourceKind::Food], 20);
    }
}
