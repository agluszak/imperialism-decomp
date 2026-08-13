use crate::*;
use enum_map::EnumMap;

mod city_placement;
mod map_post_pass;
mod map_render;
mod missions;
mod nation_setup;
mod sea_zones;
#[cfg(test)]
mod tests;

use city_placement::*;
pub(crate) use city_placement::{
    name_units_for_nation, resource_capability_level, resource_capability_requirement_level,
};
use map_post_pass::*;
use map_render::*;
use missions::*;
use nation_setup::*;
use sea_zones::*;

/// `g_fScatteredShipsMissionDefaultScore` (0.001f) as IEEE-754 bits.
const SCATTERED_SHIPS_IMPORTANCE_BITS: u32 = 981_668_463;

/// `kMapTileActionStateAnchor`.
const ACTION_STATE_ANCHOR: i16 = 3;

const ACTION_STATE_PORT_ZONE_MARKER: i16 = -14;

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

/// Localized retail strings consumed while an accepted random map becomes a game.
///
/// Nation names are the localized `0x2715` table in slot order. Province entries start
/// with the first name assigned by `GenerateProvinceNames`; each nation's separate
/// capital-city name is not part of this operation. Zone templates and fallback names
/// retain their direct C++ table order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RandomGameNames {
    pub localized_nation_names: NationTable<String>,
    pub province_names_by_nation: NationTable<Vec<String>>,
    pub zone_headline_templates: Vec<String>,
    pub fallback_ocean_names: Vec<String>,
}

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
    country_name: &str,
    localized_names: bool,
    runtime_seed: u32,
    names: &RandomGameNames,
) -> GameState {
    let mut map_lcg = RetailLcg::from_state(preview.final_map_lcg);
    let mut post = apply_tile_post_passes(&preview.map, preview.topology, &mut map_lcg);
    let foreign_ministers = choose_foreign_ministers(&preview.map, human_nation);
    let mut nations = bootstrap_nations(
        &preview.map,
        human_nation,
        difficulty,
        foreign_ministers,
        country_name,
        localized_names.then_some(&names.localized_nation_names),
    );
    let technology = TechnologyState::for_random_start(runtime_seed);
    let mut world = MapMgr::new(preview.topology, post.tiles);
    for (index, generated) in preview.map.provinces().iter().enumerate() {
        world.provinces[ProvinceId::new(index as u16)].region_class = Some(generated.region_class);
    }
    world.map_data_ready = true;
    world.recruit_search_active = true;
    world.scenario_tag = preview.scenario_tag.clone();
    world.pending_river_mouth_tile = post.pending_river_mouth_tile;
    // Fresh-map BuildOrLoadGlobalMapStateForSession runs this mode-0 cache pass
    // once, in tile order, immediately after its final AssignPictToTile pass.
    for index in 0..TileId::COUNT {
        world.update_tile_neighbor_border_influence_counters(TileId::new(index), 0);
    }
    let mut ocean_zones = initialize_sea_zone_map_markers(&mut world, preview.sea_zone_marker_crt);
    initialize_sea_zone_neighbors(&mut ocean_zones, &world, &preview.map.ocean_zone_links);
    generate_base_zone_status_codes(
        &mut ocean_zones,
        preview.scenario_tag.as_bytes(),
        runtime_seed,
    );
    // Fresh-map construction ends by reseeding CRT from the clock. Setup/bootstrap consumes one
    // draw from that reseeded stream before the first random minor-home selection.
    let mut crt_rand = RetailCrtRng::from_state(runtime_seed);
    let _ = crt_rand.next_rand();

    // Sea-zone ordinals are `owner_tag - 0x17` after water-region assign (and, in retail,
    // after border/merge/compact). Port zones continue that ordinal space.
    let mut port_zones = PortZoneTable::new(sea_zone_count(&world));
    let mut mission_queues: MajorNationTable<Vec<MissionState>> =
        MajorNationTable::from_fn(|_| Vec::new());

    // Accept bootstrap (`RebuildPrimaryNationStateForSlot` 6→0): every AI major and the
    // Introductory/Easy human place Frog City. Human Normal+ keeps the tile-0 marker until the
    // capital-selection screen confirms a site.
    place_initial_frog_cities(
        &mut world,
        &mut post.province_capitals,
        &mut nations,
        human_nation,
        &technology,
        &mut port_zones,
        &ocean_zones,
        &mut mission_queues,
        difficulty,
    );

    let mut military_units = Vec::new();
    let mut unit_ids = UnitIdAllocator::default();
    // `TMinor::IMinor` snapshots these map resource counts before choosing and
    // resetting each minor's home tile.
    initialize_minor_trade_state(&world, &mut nations);
    // `RebuildSecondaryNationStateForSlot` for minors 7..22.
    bootstrap_minors(
        &mut world,
        &mut post.province_capitals,
        &mut nations,
        &mut crt_rand,
        &mut military_units,
        &mut unit_ids,
        difficulty,
        &mut port_zones,
    );
    let map_view_origin = if requires_capital_site_selection(difficulty) {
        world.seed_valid_city_site_candidate_tiles_for_nation(human_nation);
        capital_selection_view_origin(&world, human_nation)
    } else {
        TileId::new(1)
    };
    let diplomacy = DiplomacyState::for_random_start(human_nation, difficulty, &mut crt_rand);

    initialize_ai_targets(&mut nations, &mission_queues, port_zones.next_ordinal);
    let mut port_status_rng = RetailLcg::from_state(runtime_seed);
    for port in port_zones.ports.iter().rev() {
        debug_assert_eq!(usize::from(port.ordinal.get()), ocean_zones.len());
        if let Some(neighbor) = port.primary_neighbor {
            let neighbor = &mut ocean_zones[usize::from(neighbor.get())];
            let neighbor = match neighbor {
                ZoneKind::Zone(zone) => zone,
                ZoneKind::PortZone(port) => &mut port.zone,
            };
            if !neighbor.primary_neighbors.contains(&port.ordinal) {
                neighbor.primary_neighbors.push(port.ordinal);
            }
        }
        ocean_zones.push(ZoneKind::PortZone(PortZone {
            zone: Zone {
                display_name: String::new(),
                status_code: Some(20 + (port_status_rng.next_sample_15() & 3) as i16),
                target_tile: Some(port.sea_tile),
                seed_owner: Some(port.seed_owner),
                active_tile: port.active_tile,
                primary_neighbors: port.primary_neighbor.into_iter().collect(),
                secondary_neighbors: Vec::new(),
            },
            port_tile: port.port_tile,
        }));
    }
    let mut ocean = Ocean {
        zones: ocean_zones,
        routes: preview.map.ocean_routes.clone(),
    };
    let missions = flatten_mission_queues(&mut mission_queues);
    let mut provinces = build_province_state(
        &preview.map,
        &world,
        &post.province_capitals,
        &post.province_resource_presence_masks,
        &mut nations,
    );
    generate_province_names(&mut provinces, names);
    world.provinces = provinces;
    generate_zone_display_names(
        &mut ocean.zones,
        &world,
        preview.scenario_tag.as_bytes(),
        runtime_seed,
        names,
    );
    let mut pending = PendingWorkState::default();
    pending.queue_newspaper_event(PendingNewspaperEvent::Miscellaneous {
        audience: None,
        story_code: 1,
    });
    pending.queue_newspaper_event(PendingNewspaperEvent::Miscellaneous {
        audience: None,
        story_code: 2,
    });

    GameState {
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
            last_turn_alert_tick: 0,
        },
        unit_ids,
        map: world,
        map_view_origin,
        ocean,
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
        admirals: Vec::new(),
        task_forces: Vec::new(),
        missions,
        news: NewsState::default(),
        pending,
        trade_session: None,
    }
}
