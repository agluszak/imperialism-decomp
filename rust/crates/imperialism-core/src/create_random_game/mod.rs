use crate::*;
use enum_map::{Enum, EnumMap};

mod city_placement;
mod map_post_pass;
mod map_render;
mod missions;
mod nation_setup;
mod sea_zones;
#[cfg(test)]
mod tests;

use city_placement::*;
use map_post_pass::*;
use map_render::*;
use missions::*;
use nation_setup::*;
use sea_zones::*;

/// `g_fScatteredShipsMissionDefaultScore` (0.001f) as IEEE-754 bits.
const SCATTERED_SHIPS_IMPORTANCE_BITS: u32 = 981_668_463;

/// `kMapTileActionStateAnchor`.
const ACTION_STATE_ANCHOR: i16 = 3;

const ACTION_STATE_ZONE_CENTER: i16 = -16;

const ACTION_STATE_ZONE_NORTH_WEST: i16 = -18;

const ACTION_STATE_ZONE_NORTH_EAST: i16 = -20;

/// Water-region owner tags are biased by this amount (`label + 0x17`).
const SEA_OWNER_BIAS: u8 = 0x17;

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

/// `TCity::ICity` starter capacity retained by human Introductory/Easy cities
/// before `ApplyScenarioRelationPresetAndSpawnFrogCity` forces the other slots.
const LOW_DIFFICULTY_HUMAN_PRODUCTION: ProductionTable<i16> =
    ProductionTable::from_array([2, 1, 2, 1, 2, 1, 0, 999, 999, 999, 999, 0, 0, 999, 999, 0]);

/// Builds the Normal start-boundary [`GameState`] from the retained preview.
///
/// Retail Accept does not regenerate the map. It commits setup options and rebuilds
/// nation/city state on top of the preview already produced by the setup screen.
/// The returned state matches the capital-selection-ready boundary for Normal+
/// (`phase_code = 2`, human capital not yet placed).
///
/// Random-map display-name generation and localized-name selection are separate
/// setup operations that are not yet ported. Nation display names therefore remain
/// empty here rather than inventing values at this construction boundary.
pub fn create_random_game(
    preview: &RandomSetupPreview,
    human_nation: MajorNationId,
    difficulty: Difficulty,
    runtime_seed: u32,
) -> GameState {
    let mut map_lcg = RetailLcg::from_state(preview.final_map_lcg);
    let mut post = apply_tile_post_passes(&preview.map, preview.topology, &mut map_lcg);
    let foreign_ministers = choose_foreign_ministers(&preview.map, human_nation);
    let mut nations = bootstrap_nations(human_nation, difficulty, foreign_ministers);
    let technology = TechnologyState::default();
    let mut world = StrategicMap::from_generated_tiles(preview.topology, post.tiles);
    initialize_sea_zone_map_markers(&mut world, preview.sea_zone_marker_crt);
    // Fresh-map construction ends by reseeding CRT from the clock. Setup/bootstrap consumes one
    // draw from that reseeded stream before the first random minor-home selection.
    let mut crt_rand = RetailCrtRng::from_state(runtime_seed);
    let _ = crt_rand.next_rand();

    // Sea-zone ordinals are `owner_tag - 0x17` after water-region assign (and, in retail,
    // after border/merge/compact). Port zones continue that ordinal space.
    let mut port_zones = PortZoneTable::new(sea_zone_count(&world));
    let mut mission_queues: MajorNationTable<Vec<MissionState>> =
        MajorNationTable::from_fn(|_| Vec::new());

    // Accept bootstrap (`RebuildPrimaryNationStateForSlot` 6→0): AI majors PlaceCity +
    // `QueueMapActionMissionsForPortZoneCandidates`; human Normal+ only attaches Frog City.
    place_ai_frog_cities(
        &mut world,
        &mut post.gate_flags,
        &mut post.province_capitals,
        &mut nations,
        human_nation,
        &technology,
        &mut port_zones,
        &mut mission_queues,
    );

    let mut military_units = Vec::new();
    let mut unit_ids = UnitIdAllocator::default();
    // `TMinor::IMinor` snapshots these map resource counts before choosing and
    // resetting each minor's home tile.
    initialize_minor_trade_state(&world, &post.gate_flags, &mut nations);
    // `RebuildSecondaryNationStateForSlot` for minors 7..22.
    bootstrap_minors(
        &mut world,
        &mut post.gate_flags,
        &mut post.province_capitals,
        &mut nations,
        &mut crt_rand,
        &mut military_units,
        &mut unit_ids,
        difficulty,
        &mut port_zones,
    );
    for (index, &subtype) in post.gate_flags.iter().enumerate() {
        world
            .tile_mut(TileId::new(index as u16))
            .region_tile_subtype = RegionTileSubtype::from_retail(subtype);
    }
    if requires_capital_site_selection(difficulty) {
        initialize_capital_selection_view_origin(&mut world, human_nation);
    }
    let diplomacy = DiplomacyState::for_random_start(human_nation, difficulty, &mut crt_rand);

    initialize_ai_targets(&mut nations, &mission_queues, port_zones.next_ordinal);
    let port_zone_owners = port_zones
        .ports
        .iter()
        .map(|port| PortZoneOwner {
            zone: port.ordinal,
            former_owner: port.former_owner,
        })
        .collect();
    let missions = flatten_mission_queues(&mut mission_queues);
    let provinces =
        build_province_state(&preview.map, &world, &post.province_capitals, &mut nations);
    let mut pending = PendingWorkState::default();
    pending.queue_newspaper_event(PendingNewspaperEvent::Miscellaneous {
        audience: None,
        story_code: 1,
    });
    pending.queue_newspaper_event(PendingNewspaperEvent::Miscellaneous {
        audience: None,
        story_code: 2,
    });

    let state = GameState {
        turn: TurnState {
            scenario_map: None,
            economic_turn: 0,
            diplomacy_year_term_raw: 1914,
            phase: crate::PhaseCode::CAPITAL_SELECTION,
            turn_flow_status_flags: 0,
            quarter_gate_by_decade: [0, 1, 1, 1, 1, 1, 1, 1, 1, 1],
            difficulty,
            active_nation: human_nation.nation(),
            selected_nation: human_nation.nation(),
        },
        unit_ids,
        world,
        provinces,
        port_zone_owners,
        rng: RngState {
            crt_rand,
            map_generation: RetailLcg::from_state(map_lcg.state()),
            // `GenerateProvinceNames` hashes the scenario tag then reseeds zone status from
            // `ClockDerivedPrngSeed()` (= runtime seed under the test harness).
            zone_status: RetailLcg::from_state(runtime_seed),
        },
        market: TradeMarketState::default(),
        technology,
        diplomacy,
        nations,
        military_units,
        civilian_units: Vec::new(),
        ships: Vec::new(),
        task_forces: Vec::new(),
        missions,
        news: NewsState::default(),
        pending,
    };
    state
        .validate_territory_index()
        .expect("random-game setup must build one consistent territory index");
    state
}
