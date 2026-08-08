use crate::{
    ArmyMissionState, CityState, DevelopmentLevel, Difficulty, GameState, GeneratedMap,
    GeneratedTerrainTile, HexDirection, LaborPool, MajorNation, MajorNationId, MajorNationTable,
    MapGeometry, MilitaryUnitId, MilitaryUnitKind, MilitaryUnitState, MinorNation, MinorNationId,
    MinorNationTable, MissionData, MissionState, NationCommonState, NationId, NationPendingWork,
    NationTable, Nations, NavyMissionState, PendingWorkState, ProductionTable, ProvinceId,
    RandomSetupPreview, ResourceKind, ResourceTable, RetailCrtRng, RetailLcg, RngState,
    STRATEGIC_MAP_WIDTH, STRATEGIC_TILE_COUNT, TileId, TileOwnerTag, TileState, TradeMarketState,
    TurnState, WorldState, is_valid_secondary_nation_home_tile_candidate, place_city,
    supports_city_site_terrain,
};
use enum_map::{Enum, EnumMap};

/// `g_fScatteredShipsMissionDefaultScore` (0.001f) as IEEE-754 bits.
const SCATTERED_SHIPS_IMPORTANCE_BITS: u32 = 981_668_463;
/// `kMapTileActionStateAnchor`.
const ACTION_STATE_ANCHOR: i16 = 3;
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

const WATER: i8 = 5;
const PLAINS: i8 = 0;
const FOREST: i8 = 1;
const HILLS: i8 = 2;
const MOUNTAIN: i8 = 3;
const SWAMP: i8 = 4;
const DESERT: i8 = 6;
const FARMLAND: i8 = 7;

/// Builds the Normal start-boundary [`GameState`] from the retained preview.
///
/// Retail Accept does not regenerate the map. It commits setup options and rebuilds
/// nation/city state on top of the preview already produced by the setup screen.
/// The returned state matches the capital-selection-ready boundary for Normal+
/// (`phase_code = 2`, human capital not yet placed).
///
/// Country display name / localized-name policy are intentionally not inputs here:
/// retail stores them on `TCountry` identity strings and `TSimMgr::useLocalizedNameTables68`,
/// outside the semantic `GameState` capture. Wire them only when those fields exist in
/// authoritative state.
pub fn create_random_game(
    preview: &RandomSetupPreview,
    human_nation: MajorNationId,
    difficulty: Difficulty,
    runtime_seed: u32,
) -> GameState {
    let mut map_lcg = RetailLcg::from_state(preview.final_map_lcg);
    let wraps = preview.topology.wraps_horizontally();
    let mut post = apply_tile_post_passes(&preview.map, wraps, &mut map_lcg);
    let mut nations = bootstrap_nations(human_nation, difficulty);
    let mut world = WorldState {
        wraps_horizontally: wraps,
        tiles: post.tiles,
    };
    // Runtime-test / Accept entry: map build ends in `srand(runtime_seed)`, then setup
    // `DoPostCreate` draws one `rand() % 7` for the initial nation when the slot was -1.
    let mut crt_rand = RetailCrtRng::from_state(runtime_seed);
    let _ = crt_rand.next_rand();

    // Sea-zone ordinals are `owner_tag - 0x17` after water-region assign (and, in retail,
    // after border/merge/compact). Port zones continue that ordinal space.
    let mut port_zones = PortZoneTable::new(sea_zone_count(&world.tiles));
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
        &mut port_zones,
        &mut mission_queues,
    );

    let mut military_units = Vec::new();
    let mut persistent_unit_id_counter = 0i32;
    // `RebuildSecondaryNationStateForSlot` for minors 7..22.
    bootstrap_minors(
        &mut world,
        &mut post.gate_flags,
        &mut post.province_capitals,
        &mut nations,
        &mut crt_rand,
        &mut military_units,
        &mut persistent_unit_id_counter,
        difficulty,
        &mut port_zones,
    );

    let missions = flatten_mission_queues(&mission_queues);

    GameState {
        turn: TurnState {
            scenario_map_index_plus_one: 0,
            economic_turn: 0,
            phase_code: 2,
            difficulty,
            active_nation: human_nation.nation(),
            selected_nation: human_nation.nation(),
        },
        persistent_unit_id_counter,
        world,
        rng: RngState {
            crt_rand,
            map_generation: RetailLcg::from_state(map_lcg.state()),
            // `GenerateProvinceNames` hashes the scenario tag then reseeds zone status from
            // `ClockDerivedPrngSeed()` (= runtime seed under the test harness).
            zone_status: RetailLcg::from_state(runtime_seed),
        },
        market: TradeMarketState::default(),
        nations,
        military_units,
        civilian_units: Vec::new(),
        ships: Vec::new(),
        task_forces: Vec::new(),
        missions,
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

struct TilePostPassState {
    tiles: Vec<TileState>,
    gate_flags: Vec<i8>,
    province_capitals: Vec<Option<usize>>,
}

/// Province-capital marker written by `RebuildTileOwnerNeighborCachesAndFallbackAssignments`.
const PROVINCE_CAPITAL_ACTIVE_FLAGS: u16 = 0x22;

/// Preview-time tile post-passes from `TMapMgr::BuildOrLoadGlobalMapStateForSession`:
/// icon-variant/edge-resource stamping, former-owner snapshot, province fallback capitals,
/// and `GuaranteeResources`.
fn apply_tile_post_passes(
    map: &GeneratedMap,
    wraps_horizontally: bool,
    map_lcg: &mut RetailLcg,
) -> TilePostPassState {
    let geometry = MapGeometry::new(wraps_horizontally);
    let mut tiles: Vec<TileState> = map.tiles.iter().copied().map(tile_from_generated).collect();
    let mut gate_flags: Vec<i8> = map.tiles.iter().map(|tile| tile.gate_flag).collect();

    for index in 0..tiles.len() {
        update_strategic_map_tile_icon_variant_state(
            &mut tiles,
            &mut gate_flags,
            geometry,
            index,
            map.tiles[index].owner_nation,
            map_lcg,
        );
    }

    // Retail runs this between icon variants and GuaranteeResources; it advances the map
    // LCG once per occupied province and stamps capital `active_flags`.
    let province_capitals =
        assign_province_fallback_capitals(&mut tiles, &mut gate_flags, geometry, map_lcg);

    guarantee_resources(&mut tiles, &mut gate_flags, map_lcg);
    TilePostPassState {
        tiles,
        gate_flags,
        province_capitals,
    }
}

/// Capital-tile pick + stamp from `TMapMgr::RebuildTileOwnerNeighborCachesAndFallbackAssignments`
/// (0x0050f860). Adjacent-province bookkeeping and transport-mask side effects that are not
/// represented on [`TileState`] are omitted.
fn assign_province_fallback_capitals(
    tiles: &mut [TileState],
    gate_flags: &mut [i8],
    geometry: MapGeometry,
    map_lcg: &mut RetailLcg,
) -> Vec<Option<usize>> {
    let province_count = tiles
        .iter()
        .filter_map(|tile| {
            tile.province
                .map(|province| usize::from(province.get()) + 1)
        })
        .max()
        .unwrap_or(0);
    let mut linked_by_province: Vec<Vec<usize>> = vec![Vec::new(); province_count];
    let mut province_capitals = vec![None; province_count];
    for (index, tile) in tiles.iter().enumerate() {
        if tile.terrain_kind == WATER {
            continue;
        }
        let Some(province) = tile.province else {
            continue;
        };
        linked_by_province[usize::from(province.get())].push(index);
    }

    for (province_index, linked) in linked_by_province.iter().enumerate() {
        if linked.is_empty() {
            continue;
        }

        let mut interior = Vec::new();
        for &tile_index in linked {
            let tile_id = TileId::new(tile_index as u16);
            let has_foreign_neighbor =
                geometry
                    .neighbors(tile_id)
                    .into_iter()
                    .flatten()
                    .any(|neighbor| {
                        let neighbor_tile = &tiles[usize::from(neighbor.get())];
                        match neighbor_tile.province {
                            Some(province) => usize::from(province.get()) != province_index,
                            None => false,
                        }
                    });
            if !has_foreign_neighbor {
                interior.push(tile_index);
            }
        }

        let chosen = if interior.is_empty() {
            let sample = map_lcg.next_sample_15() as usize;
            linked[sample % linked.len()]
        } else {
            let flat: Vec<usize> = interior
                .iter()
                .copied()
                .filter(|&index| matches!(tiles[index].terrain_kind, PLAINS | FARMLAND))
                .collect();
            if !flat.is_empty() {
                let sample = map_lcg.next_sample_15() as usize;
                flat[sample % flat.len()]
            } else {
                let sample = map_lcg.next_sample_15() as usize;
                interior[sample % interior.len()]
            }
        };

        initialize_tile_neighbor_connection_mask_if_needed(tiles, gate_flags, chosen);
        tiles[chosen].active_flags = PROVINCE_CAPITAL_ACTIVE_FLAGS;
        province_capitals[province_index] = Some(chosen);
    }
    province_capitals
}

/// `TMapMgr::InitializeTileNeighborConnectionMaskIfNeeded` (0x005107e0).
///
/// Neighbor `adjacencyMaskA0a` edits are omitted; they are not part of [`TileState`].
fn initialize_tile_neighbor_connection_mask_if_needed(
    tiles: &mut [TileState],
    gate_flags: &mut [i8],
    index: usize,
) {
    if gate_flags[index] == 1 {
        return;
    }
    tiles[index].terrain_kind = PLAINS;
    tiles[index].edge_resources = [Some(0x11), None];
    gate_flags[index] = resolve_region_tile_subtype_code(tiles, gate_flags, index);
}

/// `TMapMgr::PlaceCity` active flags after Accept AI / human capital confirmation.
const PLACE_CITY_ACTIVE_FLAGS: u16 = 0x37;

/// `g_abUniversityRequirementLevelById` — yield lookup by resource and development/tech index.
const UNIVERSITY_REQUIREMENT_LEVEL: [[u8; 4]; 24] = [
    [1, 2, 3, 4],
    [1, 2, 3, 4],
    [1, 2, 3, 4],
    [0, 2, 4, 6],
    [0, 2, 4, 6],
    [1, 1, 1, 1],
    [0, 2, 4, 6],
    [0, 0, 0, 0],
    [0, 0, 0, 0],
    [0, 0, 0, 0],
    [0, 0, 0, 0],
    [0, 0, 0, 0],
    [0, 0, 0, 0],
    [0, 0, 0, 0],
    [0, 0, 0, 0],
    [0, 0, 0, 0],
    [0, 0, 0, 0],
    [1, 2, 3, 4],
    [1, 2, 3, 4],
    [1, 2, 3, 4],
    [1, 2, 3, 4],
    [0, 1, 2, 3],
    [0, 1, 2, 3],
    [0, 0, 0, 0],
];

/// `g_abResourceTypeUsesHighNibbleFlag` — nonzero means extractive nibble / tech override.
const RESOURCE_USES_HIGH_NIBBLE: [u8; 24] = [
    0, 0, 0, 1, 1, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0,
];

/// `g_abGateFlagQualifies` — farmland auto-development gate check in `PlaceCity`.
const GATE_FLAG_QUALIFIES: [u8; 24] = [
    0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

const RESOURCE_GRAIN: i8 = 17;
const RESOURCE_FRUIT: i8 = 18;

/// AI home placement from `CreateFrogCityAtHomeRegionAndAttach` for setup mode 2 majors.
fn place_ai_frog_cities(
    world: &mut WorldState,
    gate_flags: &mut [i8],
    province_capitals: &mut [Option<usize>],
    nations: &mut Nations,
    human_nation: MajorNationId,
    port_zones: &mut PortZoneTable,
    mission_queues: &mut MajorNationTable<Vec<MissionState>>,
) {
    let province_adjacency = build_province_adjacency(world);
    for slot in (0..MajorNationId::COUNT).rev() {
        let nation = MajorNationId::new(slot);
        if nation == human_nation {
            continue;
        }
        let Some(home) = select_best_secondary_home_tile(world, gate_flags, nation) else {
            continue;
        };
        place_ai_capital(world, gate_flags, province_capitals, home, nation);
        ensure_port_zone_for_tile(world, port_zones, usize::from(home.get()));
        if let Some(major) = nations.major_mut(nation) {
            major.common.home_tile = Some(home);
            if let Some(city) = major.city.as_mut() {
                city.home_town_tile = Some(home);
            }
        }
        // `QueueMapActionMissionsForPortZoneCandidates` runs only for setup-mode-2 AI.
        mission_queues[nation] = queue_map_action_missions_for_port_zone_candidates(
            world,
            province_capitals,
            &province_adjacency,
            port_zones,
            nation,
        );
    }
}

/// Minor capital marker from `TMapMgr::ResetTileToBaseTransportFlag` (`1 | 0x20`).
const MINOR_HOME_ACTIVE_FLAGS: u16 = 0x21;

const LAND_UNIT_TYPE_NAMES: [&str; 8] = [
    "Minutemen",
    "Skirmishers",
    "Regulars",
    "Grenadiers",
    "Hussars",
    "Cuirassiers",
    "Light Artillery",
    "Artillery",
];

/// `RebuildSecondaryNationStateForSlot` for minors: home pick, militia, trailing Regulars.
#[allow(clippy::too_many_arguments)]
fn bootstrap_minors(
    world: &mut WorldState,
    gate_flags: &mut [i8],
    province_capitals: &mut [Option<usize>],
    nations: &mut Nations,
    crt: &mut RetailCrtRng,
    military_units: &mut Vec<MilitaryUnitState>,
    persistent_unit_id_counter: &mut i32,
    difficulty: Difficulty,
    port_zones: &mut PortZoneTable,
) {
    for minor_id in MinorNationId::all() {
        let owner = TileOwnerTag::new(minor_id.nation().get());
        let Some(home) = select_minor_home_tile(world, owner, crt) else {
            continue;
        };
        reset_tile_to_base_transport_flag(world, gate_flags, province_capitals, home);
        // Retail calls `EnsurePortZoneForTile` after the minor home stamp.
        ensure_port_zone_for_tile(world, port_zones, home);
        if let Some(minor) = nations.minors[minor_id].as_mut() {
            minor.common.home_tile = Some(TileId::new(home as u16));
        }

        let mut name_ordinals = [1i16; MilitaryUnitKind::LENGTH];
        let mut next_roster_id = 1i16;
        let owned = owned_province_ids(world, province_capitals, owner);
        spawn_initial_militia_for_minor(
            world,
            province_capitals,
            minor_id,
            &owned,
            difficulty,
            military_units,
            persistent_unit_id_counter,
            &mut name_ordinals,
            &mut next_roster_id,
        );
        // RebuildSecondaryNationStateForSlot trailing pair after InitialMilitia.
        let home_province = world.tiles[home]
            .province
            .map(|province| i16::try_from(province.get()).expect("province fits i16"))
            .unwrap_or(-1);
        for _ in 0..2 {
            push_military_unit(
                military_units,
                persistent_unit_id_counter,
                minor_id.nation(),
                MilitaryUnitKind::Regulars,
                home_province,
                2,
            );
        }
        name_units_for_nation(
            military_units,
            minor_id.nation(),
            &mut name_ordinals,
            &mut next_roster_id,
        );
    }
}

fn select_minor_home_tile(
    world: &WorldState,
    owner: TileOwnerTag,
    crt: &mut RetailCrtRng,
) -> Option<usize> {
    let mut selected = None;
    let mut candidates = Vec::new();
    for (index, tile) in world.tiles.iter().enumerate() {
        if tile.owner_nation != Some(owner) {
            continue;
        }
        if (tile.active_flags & 1) != 0 {
            selected = Some(index);
        }
        let tile_id = TileId::new(index as u16);
        if is_valid_secondary_nation_home_tile_candidate(world, tile_id).unwrap_or(false) {
            candidates.push(index);
        }
    }
    if selected.is_some() {
        return selected;
    }
    if candidates.is_empty() {
        return None;
    }
    // `At(rand() % count + 1)` on a 1-based list ≡ zero-based `rand() % count`.
    let pick = (crt.next_rand() as usize) % candidates.len();
    Some(candidates[pick])
}

/// `TMapMgr::ResetTileToBaseTransportFlag` (0x00518990).
fn reset_tile_to_base_transport_flag(
    world: &mut WorldState,
    gate_flags: &mut [i8],
    province_capitals: &mut [Option<usize>],
    tile: usize,
) {
    set_region_tile_subtype_and_refresh_neighbor_flags(world, gate_flags, province_capitals, tile);
    world.tiles[tile].active_flags = MINOR_HOME_ACTIVE_FLAGS;
    initialize_tile_neighbor_connection_mask_if_needed(&mut world.tiles, gate_flags, tile);
}

fn owned_province_ids(
    world: &WorldState,
    province_capitals: &[Option<usize>],
    owner: TileOwnerTag,
) -> Vec<u16> {
    let mut owned = Vec::new();
    for (province_index, capital) in province_capitals.iter().enumerate() {
        let Some(capital) = *capital else {
            continue;
        };
        if world.tiles[capital].owner_nation == Some(owner) {
            owned.push(province_index as u16);
        }
    }
    owned
}

/// `TCountry::InitialMilitia` for random-map minors at the pre-capital boundary.
#[allow(clippy::too_many_arguments)]
fn spawn_initial_militia_for_minor(
    world: &mut WorldState,
    province_capitals: &[Option<usize>],
    minor_id: MinorNationId,
    owned_provinces: &[u16],
    difficulty: Difficulty,
    military_units: &mut Vec<MilitaryUnitState>,
    persistent_unit_id_counter: &mut i32,
    name_ordinals: &mut [i16],
    next_roster_id: &mut i16,
) {
    let nation = minor_id.nation();
    let set_garrison_orders = matches!(difficulty, Difficulty::Introductory | Difficulty::Easy);
    for &province in owned_provinces {
        let capital = province_capitals
            .get(usize::from(province))
            .copied()
            .flatten();
        let capital_flags = capital
            .map(|index| world.tiles[index].active_flags)
            .unwrap_or(0);
        if (capital_flags & 1) != 0 {
            let order = if set_garrison_orders { 2 } else { 0 };
            push_military_unit(
                military_units,
                persistent_unit_id_counter,
                nation,
                MilitaryUnitKind::Regulars,
                province as i16,
                order,
            );
            push_military_unit(
                military_units,
                persistent_unit_id_counter,
                nation,
                MilitaryUnitKind::Regulars,
                province as i16,
                order,
            );
            push_military_unit(
                military_units,
                persistent_unit_id_counter,
                nation,
                MilitaryUnitKind::Artillery,
                province as i16,
                order,
            );
            if let Some(capital) = capital {
                world.tiles[capital].active_flags |= 8;
            }
        }
        // `AddMilitia` ×3 (minors always spawn type 0 / Minutemen with order 2).
        for _ in 0..3 {
            push_military_unit(
                military_units,
                persistent_unit_id_counter,
                nation,
                MilitaryUnitKind::Minutemen,
                province as i16,
                2,
            );
        }
        if matches!(difficulty, Difficulty::Hard | Difficulty::NighOnImpossible) {
            push_military_unit(
                military_units,
                persistent_unit_id_counter,
                nation,
                MilitaryUnitKind::Minutemen,
                province as i16,
                2,
            );
            push_military_unit(
                military_units,
                persistent_unit_id_counter,
                nation,
                MilitaryUnitKind::Artillery,
                province as i16,
                0,
            );
        }
    }
    name_units_for_nation(military_units, nation, name_ordinals, next_roster_id);
}

fn push_military_unit(
    military_units: &mut Vec<MilitaryUnitState>,
    persistent_unit_id_counter: &mut i32,
    nation: NationId,
    unit_type: MilitaryUnitKind,
    stationed_province: i16,
    order: i32,
) {
    *persistent_unit_id_counter += 1;
    military_units.push(MilitaryUnitState {
        id: MilitaryUnitId::new(*persistent_unit_id_counter),
        nation,
        unit_type,
        stationed_province,
        order,
        order_target: -1,
        owner_nation: nation,
        roster_id: 0,
        registered: true,
        order_target_tiles: [stationed_province; 3],
        order_target_mirrors: [stationed_province; 3],
        name: String::new(),
        strength: 500,
        era: unit_type.spawn_era(),
        experience: 0,
        battle_flags: 0,
    });
}

/// `TCountry::NameUnits` for non-general land units (English STR# 0x2717 / 0x275f).
fn name_units_for_nation(
    military_units: &mut [MilitaryUnitState],
    nation: NationId,
    name_ordinals: &mut [i16],
    next_roster_id: &mut i16,
) {
    for unit in military_units
        .iter_mut()
        .filter(|unit| unit.nation == nation)
    {
        if unit.roster_id != 0 {
            continue;
        }
        let kind = unit.unit_type.index() as usize;
        if kind >= MilitaryUnitKind::GeneralEra1 as usize {
            continue;
        }
        let ordinal = name_ordinals[kind];
        let type_name = LAND_UNIT_TYPE_NAMES.get(kind).copied().unwrap_or("Unit");
        unit.name = format!("{} {}", english_ordinal(ordinal), type_name);
        unit.roster_id = *next_roster_id;
        *next_roster_id += 1;
        name_ordinals[kind] = ordinal + 1;
    }
}

fn english_ordinal(value: i16) -> String {
    let value = i32::from(value);
    let suffix = match value % 10 {
        1 if value != 11 => "st",
        2 if value != 12 => "nd",
        3 if value != 13 => "rd",
        _ => "th",
    };
    format!("{value}{suffix}")
}

/// `TCityInteriorMinister::SelectBestSecondaryHomeTileByFrogCityScore` (0x004c11c0).
fn select_best_secondary_home_tile(
    world: &WorldState,
    gate_flags: &[i8],
    nation: MajorNationId,
) -> Option<TileId> {
    let owner = TileOwnerTag::new(nation.get());
    let mut best_score: i32 = -1;
    let mut best_tile: Option<TileId> = None;
    for index in 0..STRATEGIC_TILE_COUNT {
        let tile = TileId::new(index as u16);
        let state = &world.tiles[index];
        if state.owner_nation != Some(owner) {
            continue;
        }
        if !is_valid_secondary_nation_home_tile_candidate(world, tile).unwrap_or(false) {
            continue;
        }
        if !supports_city_site_terrain(state.terrain_kind) {
            continue;
        }
        let yields = calculate_city_resources(world, gate_flags, tile, nation);
        let mut score = frog_city_score(&yields);
        if (state.active_flags & 1) != 0 {
            score = 32_000;
        }
        if (best_score as i16) < (score as i16) {
            best_score = score;
            best_tile = Some(tile);
        }
    }
    best_tile
}

fn frog_city_score(yields: &[i16; ResourceKind::LENGTH]) -> i32 {
    let grain = yields[ResourceKind::Grain as usize];
    let fruit = yields[ResourceKind::Fruit as usize];
    let clamped_grain = grain.clamp(0, 6);
    let clamped_fruit = fruit.clamp(0, 2);
    let grain_surplus = (grain - 6).clamp(0, 3);
    let fruit_surplus = (fruit * 2 - 4).clamp(0, 4);
    let food_bonus =
        ((yields[ResourceKind::Fish as usize] + yields[ResourceKind::Livestock as usize]) * 2)
            .clamp(0, 4);
    let raw_material = (yields[ResourceKind::Timber as usize] * 2).clamp(0, 12);
    let soft = i32::from(yields[ResourceKind::Cotton as usize])
        + i32::from(yields[ResourceKind::Wool as usize])
        + i32::from(yields[ResourceKind::Gold as usize]);
    soft * 3
        + i32::from(yields[ResourceKind::Coal as usize])
        + i32::from(yields[ResourceKind::Iron as usize])
        + i32::from(raw_material)
        + i32::from(clamped_grain) * 1000
        + i32::from(clamped_fruit) * 1000
        + i32::from(grain_surplus)
        + i32::from(fruit_surplus)
        + i32::from(food_bonus)
}

/// `TTown::CalculateCityResources` (0x005b73e0) for an enabled Frog City marker.
fn calculate_city_resources(
    world: &WorldState,
    gate_flags: &[i8],
    home: TileId,
    nation: MajorNationId,
) -> [i16; ResourceKind::LENGTH] {
    let geometry = MapGeometry::new(world.wraps_horizontally);
    let owner = TileOwnerTag::new(nation.get());
    let mut yields = [0i16; ResourceKind::LENGTH];
    // Directions 0..5 are hex neighbors; 6 is the home tile itself (`TownNeighborTile`).
    for tile in geometry
        .neighbors(home)
        .into_iter()
        .chain(std::iter::once(Some(home)))
        .flatten()
    {
        let index = usize::from(tile.get());
        let state = &world.tiles[index];
        if state.owner_nation != Some(owner) && state.terrain_kind != WATER {
            continue;
        }
        for resource in 0..ResourceKind::LENGTH {
            let mut amount = i16::from(resource_capability_level_by_type(
                state,
                gate_flags[index],
                resource as u8,
            ));
            if amount != 0 {
                let gate = gate_flags[index];
                if (0..24).contains(&gate) && RESOURCE_USES_HIGH_NIBBLE[gate as usize] != 0 {
                    let capability = starting_tech_capability(resource);
                    amount = i16::from(UNIVERSITY_REQUIREMENT_LEVEL[resource][capability]);
                }
            }
            yields[resource] = yields[resource].saturating_add(amount);
        }
        if state.river_sprite_code != 0 {
            yields[ResourceKind::Fish as usize] =
                yields[ResourceKind::Fish as usize].saturating_add(1);
        }
    }
    yields
}

fn resource_capability_level_by_type(tile: &TileState, _gate_flag: i8, resource: u8) -> u8 {
    for edge in 0..2 {
        if tile.edge_resources[edge] == Some(resource as i8) {
            return resource_capability_level(tile, edge);
        }
    }
    0
}

fn resource_capability_level(tile: &TileState, edge: usize) -> u8 {
    let Some(resource) = tile.edge_resources[edge] else {
        return 0;
    };
    let resource = resource as usize;
    if resource >= UNIVERSITY_REQUIREMENT_LEVEL.len() {
        return 0;
    }
    let packed = (tile.development.extractive.get() << 4) | tile.development.surface.get();
    let index = if RESOURCE_USES_HIGH_NIBBLE[resource] != 0 {
        packed >> 4
    } else {
        packed & 0x0f
    };
    UNIVERSITY_REQUIREMENT_LEVEL[resource][usize::from(index.min(3))]
}

fn starting_tech_capability(resource: usize) -> usize {
    match resource {
        0x12 | 0x11 | 0x15 | 4 | 3 | 0x16 => 1,
        _ => 0,
    }
}

/// Accept-time AI `PlaceCity`: province capital rewrite, flags, flood-fill, farmland nibble.
fn place_ai_capital(
    world: &mut WorldState,
    gate_flags: &mut [i8],
    province_capitals: &mut [Option<usize>],
    tile: TileId,
    nation: MajorNationId,
) {
    let index = usize::from(tile.get());
    set_region_tile_subtype_and_refresh_neighbor_flags(world, gate_flags, province_capitals, index);
    let owner = TileOwnerTag::new(nation.get());
    let _ = place_city(world, tile, owner);
    debug_assert_eq!(world.tiles[index].active_flags, PLACE_CITY_ACTIVE_FLAGS);

    let origin_marker = world.tiles[index].region_marker;
    for neighbor in place_city_harvest_tiles(index).into_iter().flatten() {
        if world.tiles[neighbor].region_marker != origin_marker {
            continue;
        }
        let gate = gate_flags[neighbor];
        let qualifies = (0..24).contains(&gate) && GATE_FLAG_QUALIFIES[gate as usize] != 0;
        if !qualifies {
            continue;
        }
        let eligible = world.tiles[neighbor]
            .edge_resources
            .iter()
            .any(|edge| matches!(edge, Some(RESOURCE_GRAIN) | Some(RESOURCE_FRUIT)));
        if eligible {
            world.tiles[neighbor].development.surface = DevelopmentLevel::new(1);
        }
    }
    gate_flags[index] = resolve_region_tile_subtype_code(&world.tiles, gate_flags, index);
}

/// `TMapMgr::SetRegionTileSubtypeAndRefreshNeighborFlags` (0x00515f80) tile mutations.
fn set_region_tile_subtype_and_refresh_neighbor_flags(
    world: &mut WorldState,
    gate_flags: &mut [i8],
    province_capitals: &mut [Option<usize>],
    new_tile: usize,
) {
    let Some(province) = world.tiles[new_tile].province else {
        return;
    };
    let province_index = usize::from(province.get());
    if province_index >= province_capitals.len() {
        return;
    }
    if let Some(old_tile) = province_capitals[province_index] {
        world.tiles[old_tile].active_flags = 0;
        world.tiles[old_tile].edge_resources[0] = Some(0x11);
        gate_flags[old_tile] = resolve_region_tile_subtype_code(&world.tiles, gate_flags, old_tile);
    }
    world.tiles[new_tile].active_flags = PROVINCE_CAPITAL_ACTIVE_FLAGS;
    province_capitals[province_index] = Some(new_tile);
    gate_flags[new_tile] = resolve_region_tile_subtype_code(&world.tiles, gate_flags, new_tile);

    for (index, tile) in world.tiles.iter_mut().enumerate() {
        if index != new_tile && tile.province == Some(province) && (tile.active_flags & 0x20) != 0 {
            tile.active_flags &= !0x20;
        }
    }
}

/// Harvest ring from `TMapMgr::PlaceCity` (directions 0..5 via hex-area deltas, 6 = self).
fn place_city_harvest_tiles(tile_index: usize) -> [Option<usize>; 7] {
    const COL_DELTA: [i32; 6] = [1, 2, 1, -1, -2, -1];
    const ROW_DELTA: [i32; 6] = [-1, 0, 1, 1, 0, -1];
    let mut out = [None; 7];
    let width = i32::from(STRATEGIC_MAP_WIDTH);
    let row = (tile_index as i32) / width;
    let col = (tile_index as i32) % width;
    for direction in 0..6 {
        let mut scaled = row % 2 + col * 2 + COL_DELTA[direction];
        let mut neighbor_row = row + ROW_DELTA[direction];
        if scaled < 0 {
            scaled += 0xd8;
        } else if scaled >= 0xd8 {
            scaled -= 0xd9;
        }
        neighbor_row = neighbor_row.clamp(0, 0x3b);
        let neighbor = scaled / 2 + neighbor_row * width;
        if neighbor >= 0 && (neighbor as usize) < STRATEGIC_TILE_COUNT {
            out[direction] = Some(neighbor as usize);
        }
    }
    out[6] = Some(tile_index);
    out
}

/// Special-purpose Accept-time port-zone table (no full `TZone` graph).
///
/// Sea-zone ordinals are `water_owner - 0x17`. Port zones allocate the next ordinals in
/// creation order. `ports` is newest-first so `FindFirstPortZone*` walks match retail's
/// `g_pMapActionContextListHead`/`prev18` chain.
struct PortZoneTable {
    next_ordinal: i16,
    ports: Vec<PortZone>,
}

#[derive(Clone, Copy, Debug)]
struct PortZone {
    ordinal: i16,
    port_tile: usize,
    sea_tile: usize,
    /// `primaryNeighbors[0]` ordinal (sea zone or another port).
    primary_neighbor: Option<i16>,
    former_owner: u8,
}

impl PortZoneTable {
    fn new(sea_zone_count: i16) -> Self {
        Self {
            next_ordinal: sea_zone_count.max(0),
            ports: Vec::new(),
        }
    }

    fn find_port_by_tile(&self, tile: usize) -> Option<&PortZone> {
        self.ports
            .iter()
            .find(|port| port.port_tile == tile || port.sea_tile == tile)
    }

    fn find_first_port_for_nation(&self, nation: u8) -> Option<&PortZone> {
        self.ports
            .iter()
            .find(|port| port.former_owner == nation)
    }
}

fn sea_zone_count(tiles: &[TileState]) -> i16 {
    let mut max_ordinal = -1_i16;
    for tile in tiles {
        if tile.terrain_kind != WATER {
            continue;
        }
        let Some(owner) = tile.owner_nation else {
            continue;
        };
        let tag = i16::from(owner.get());
        if tag >= i16::from(SEA_OWNER_BIAS) {
            max_ordinal = max_ordinal.max(tag - i16::from(SEA_OWNER_BIAS));
        }
    }
    max_ordinal + 1
}

/// `TOcean::EnsurePortZoneForTile` side effects needed for Accept missions / tile action state.
fn ensure_port_zone_for_tile(world: &mut WorldState, ports: &mut PortZoneTable, tile_index: usize) {
    if tile_index >= world.tiles.len() {
        return;
    }
    if (world.tiles[tile_index].active_flags & 1) == 0 {
        return;
    }
    if ports.find_port_by_tile(tile_index).is_some() {
        return;
    }
    let Some(nation_seed) = world.tiles[tile_index].owner_nation.map(|owner| owner.get()) else {
        return;
    };
    let former_owner = world.tiles[tile_index]
        .former_owner_nation
        .map(|owner| owner.get())
        .unwrap_or(nation_seed);

    let geometry = MapGeometry::new(world.wraps_horizontally);
    let Some(best_sea) = select_port_sea_tile(world, geometry, tile_index, nation_seed) else {
        return;
    };

    let primary_neighbor = if world.tiles[best_sea].action_state == ACTION_STATE_ANCHOR
        || world.tiles[best_sea].action_state == 14
    {
        ports
            .find_port_by_tile(best_sea)
            .map(|port| port.ordinal)
    } else {
        world.tiles[best_sea]
            .owner_nation
            .map(|owner| owner.get())
            .filter(|&tag| tag >= SEA_OWNER_BIAS)
            .map(|tag| i16::from(tag - SEA_OWNER_BIAS))
    };

    let ordinal = ports.next_ordinal;
    ports.next_ordinal = ports.next_ordinal.saturating_add(1);
    ports.ports.insert(
        0,
        PortZone {
            ordinal,
            port_tile: tile_index,
            sea_tile: best_sea,
            primary_neighbor,
            former_owner,
        },
    );
    world.tiles[best_sea].action_state = ACTION_STATE_ANCHOR;
}

fn select_port_sea_tile(
    world: &WorldState,
    geometry: MapGeometry,
    tile_index: usize,
    nation_seed: u8,
) -> Option<usize> {
    let tile_id = TileId::new(tile_index as u16);
    for offset in 0..6 {
        let direction = HexDirection::ALL[(tile_index + offset) % 6];
        let Some(candidate) = geometry.neighbor(tile_id, direction) else {
            continue;
        };
        let candidate_index = usize::from(candidate.get());
        if world.tiles[candidate_index].terrain_kind != WATER {
            continue;
        }
        let all_neighbors_qualify = geometry
            .neighbors(candidate)
            .into_iter()
            .flatten()
            .all(|neighbor| {
                let neighbor_owner = world.tiles[usize::from(neighbor.get())].owner_nation;
                !matches!(
                    neighbor_owner,
                    Some(owner) if owner.get() < SEA_OWNER_BIAS && owner.get() != nation_seed
                )
            });
        if all_neighbors_qualify {
            return Some(candidate_index);
        }
    }
    // Fallback: any adjacent water tile (skips the full river-flow tracer).
    geometry
        .neighbors(tile_id)
        .into_iter()
        .flatten()
        .map(|neighbor| usize::from(neighbor.get()))
        .find(|&index| world.tiles[index].terrain_kind == WATER)
}

/// Province adjacency lists used by the defend-province availability gate.
fn build_province_adjacency(world: &WorldState) -> Vec<Vec<u16>> {
    let province_count = world
        .tiles
        .iter()
        .filter_map(|tile| tile.province.map(|province| usize::from(province.get()) + 1))
        .max()
        .unwrap_or(0);
    let mut adjacency = vec![Vec::new(); province_count];
    let geometry = MapGeometry::new(world.wraps_horizontally);
    for (index, tile) in world.tiles.iter().enumerate() {
        let Some(province) = tile.province else {
            continue;
        };
        let province_index = usize::from(province.get());
        for neighbor in geometry
            .neighbors(TileId::new(index as u16))
            .into_iter()
            .flatten()
        {
            let Some(neighbor_province) = world.tiles[usize::from(neighbor.get())].province else {
                continue;
            };
            if neighbor_province == province {
                continue;
            }
            let neighbor_index = neighbor_province.get();
            if !adjacency[province_index].contains(&neighbor_index) {
                adjacency[province_index].push(neighbor_index);
            }
        }
    }
    adjacency
}

/// `IsNodeTypeLinkUnavailableAndNoActiveMapActionContext` for Accept-time owned provinces.
///
/// Without the sea-zone secondary-neighbor graph, coastal isolation falls back to "has any
/// adjacent province". The second-degree retail quirk (owned province with a neighbor that
/// itself has neighbors) is preserved.
fn province_mission_available(
    province: u16,
    nation: TileOwnerTag,
    world: &WorldState,
    province_capitals: &[Option<usize>],
    adjacency: &[Vec<u16>],
) -> bool {
    let province_usize = usize::from(province);
    let neighbors = adjacency.get(province_usize).map(Vec::as_slice).unwrap_or(&[]);
    for &adjacent in neighbors {
        let Some(capital) = province_capitals.get(usize::from(adjacent)).copied().flatten() else {
            continue;
        };
        if world.tiles[capital].owner_nation == Some(nation) {
            return true;
        }
    }
    // CollectSecondDegreeLinksMatchingNodeType: if this owned province has any neighbor that
    // itself has neighbors, treat as available.
    if !neighbors.is_empty() {
        for &adjacent in neighbors {
            if adjacency
                .get(usize::from(adjacent))
                .is_some_and(|list| !list.is_empty())
            {
                return true;
            }
        }
    }
    false
}

/// `TAutoGreatPower::QueueMapActionMissionsForPortZoneCandidates`.
fn queue_map_action_missions_for_port_zone_candidates(
    world: &WorldState,
    province_capitals: &[Option<usize>],
    adjacency: &[Vec<u16>],
    ports: &PortZoneTable,
    nation: MajorNationId,
) -> Vec<MissionState> {
    let owner = TileOwnerTag::new(nation.get());
    let owned = owned_province_ids(world, province_capitals, owner);
    let mut missions = Vec::new();
    let mut queue_index = 0u32;

    for &province in &owned {
        if !province_mission_available(province, owner, world, province_capitals, adjacency) {
            continue;
        }
        missions.push(mission_state(
            nation,
            queue_index,
            MissionData::DefendProvince(ArmyMissionState {
                present_location: province as i16,
                required_equipage_bits: [0; 5],
                units: Vec::new(),
            }),
            0,
        ));
        queue_index += 1;
    }

    let Some(port) = ports.find_first_port_for_nation(nation.get()) else {
        return missions;
    };
    let Some(sea_or_neighbor) = port.primary_neighbor else {
        return missions;
    };

    // Factory: zone != nation's first port → ControlSeaZone; port itself → Escort.
    missions.push(mission_state(
        nation,
        queue_index,
        MissionData::ControlSeaZone(empty_navy_mission(sea_or_neighbor, -1)),
        0,
    ));
    queue_index += 1;
    missions.push(mission_state(
        nation,
        queue_index,
        MissionData::Escort(empty_navy_mission(port.ordinal, port.ordinal)),
        0,
    ));
    queue_index += 1;
    missions.push(mission_state(
        nation,
        queue_index,
        MissionData::ScatteredShips(empty_navy_mission(-1, -1)),
        SCATTERED_SHIPS_IMPORTANCE_BITS,
    ));
    missions
}

fn empty_navy_mission(target_zone: i16, resolved_port_zone: i16) -> NavyMissionState {
    NavyMissionState {
        target_zone,
        resolved_port_zone,
        selected_ship: None,
        task_force: None,
        state: 0,
        required_equipage_bits: [0; 4],
        ships: Vec::new(),
    }
}

fn mission_state(
    nation: MajorNationId,
    queue_index: u32,
    data: MissionData,
    importance_bits: u32,
) -> MissionState {
    MissionState {
        nation: nation.nation(),
        queue_index,
        data,
        source_nation: i16::from(nation.get()),
        path_marker: -1,
        state: 2,
        importance_bits,
        marker: 0,
    }
}

fn flatten_mission_queues(queues: &MajorNationTable<Vec<MissionState>>) -> Vec<MissionState> {
    let mut missions = Vec::new();
    for nation in MajorNationId::all() {
        missions.extend(queues[nation].iter().cloned());
    }
    missions
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

/// `TMapMgr::UpdateStrategicMapTileIconVariantState` (0x00511610).
fn update_strategic_map_tile_icon_variant_state(
    tiles: &mut [TileState],
    gate_flags: &mut [i8],
    geometry: MapGeometry,
    index: usize,
    owner_nation_tag: i8,
    map_lcg: &mut RetailLcg,
) {
    let terrain = tiles[index].terrain_kind;
    match terrain {
        WATER => {
            let tile_id = TileId::new(index as u16);
            let found_land = geometry
                .neighbors(tile_id)
                .into_iter()
                .flatten()
                .any(|neighbor| tiles[usize::from(neighbor.get())].terrain_kind != WATER);
            if found_land {
                tiles[index].edge_resources[0] = Some(0x13);
            }
        }
        PLAINS => {
            let roll = map_lcg.next_sample_15();
            if roll % 100 < 10 {
                tiles[index].edge_resources[0] = Some(0);
            } else {
                let roll = map_lcg.next_sample_15();
                if roll % 100 < 5 && owner_nation_tag < 7 {
                    tiles[index].edge_resources[0] = Some(5);
                } else {
                    let roll = map_lcg.next_sample_15();
                    tiles[index].edge_resources[0] =
                        Some(if roll % 100 < 0x24 { 0x14 } else { 0x11 });
                }
            }
        }
        FARMLAND => {
            let roll = map_lcg.next_sample_15();
            tiles[index].edge_resources[0] = Some(if roll % 100 < 0x37 { 0x11 } else { 0x12 });
        }
        FOREST => {
            tiles[index].edge_resources[0] = Some(2);
        }
        SWAMP | DESERT => {
            let roll = map_lcg.next_sample_15();
            if roll % 100 < 0xf {
                tiles[index].edge_resources[0] = Some(6);
            }
        }
        HILLS => {
            let roll = map_lcg.next_sample_15();
            if roll % 100 < 0xc {
                tiles[index].edge_resources[0] = Some(1);
            } else {
                let roll = map_lcg.next_sample_15();
                if roll % 100 < 0x14 {
                    let roll = map_lcg.next_sample_15();
                    tiles[index].edge_resources[0] = Some(if roll % 100 < 0x32 { 3 } else { 4 });
                }
            }
        }
        MOUNTAIN => {
            let mut edge_index = 0usize;
            let roll = map_lcg.next_sample_15();
            if roll % 100 < 0x14 {
                let roll = map_lcg.next_sample_15();
                tiles[index].edge_resources[0] = Some(if roll % 100 < 0x32 { 3 } else { 4 });
                edge_index = 1;
            }
            if owner_nation_tag < 7 {
                let roll = map_lcg.next_sample_15();
                if roll % 100 < 0xf {
                    tiles[index].edge_resources[edge_index] = Some(0x16);
                }
            } else {
                let roll = map_lcg.next_sample_15();
                if roll % 100 < 0xa {
                    tiles[index].edge_resources[edge_index] = Some(0x15);
                } else {
                    let roll = map_lcg.next_sample_15();
                    if roll % 100 < 0xf {
                        tiles[index].edge_resources[edge_index] = Some(0x16);
                    }
                }
            }
        }
        _ => {}
    }
    gate_flags[index] = resolve_region_tile_subtype_code(tiles, gate_flags, index);
}

/// `TMapMgr::ResolveRegionTileSubtypeCodeForTileIndex` (0x00514210).
fn resolve_region_tile_subtype_code(tiles: &[TileState], gate_flags: &[i8], index: usize) -> i8 {
    let tile = &tiles[index];
    let edge0 = tile.edge_resources[0];
    match tile.terrain_kind {
        PLAINS => match edge0 {
            Some(0) => 2,
            Some(5) => 4,
            Some(0x14) => 3,
            _ if (tile.active_flags & 2) != 0 => 0xe,
            _ => 1,
        },
        FOREST => {
            if gate_flags[index] == -1 {
                0xd
            } else {
                gate_flags[index]
            }
        }
        HILLS => i8::from(edge0 != Some(1)) + 7,
        MOUNTAIN => 9,
        SWAMP => 0xa,
        DESERT => {
            if gate_flags[index] != -1 {
                gate_flags[index]
            } else {
                let row = index / usize::from(STRATEGIC_MAP_WIDTH);
                if !(0xf..=0x2d).contains(&row) {
                    0xc
                } else {
                    0xb
                }
            }
        }
        FARMLAND => i8::from(edge0 != Some(0x11)) + 5,
        _ => 0,
    }
}

/// `TMapMgr::GuaranteeResources` (0x00511a70).
fn guarantee_resources(tiles: &mut [TileState], gate_flags: &mut [i8], map_lcg: &mut RetailLcg) {
    for nation_tag in 0i8..=6 {
        let linked: Vec<usize> = tiles
            .iter()
            .enumerate()
            .filter_map(|(index, tile)| {
                let owner = tile.owner_nation?;
                (owner.get() == nation_tag as u8).then_some(index)
            })
            .collect();
        if linked.is_empty() {
            continue;
        }

        let mut resource_tally = [0i16; 24];
        for &index in &linked {
            for edge in 0..2 {
                if let Some(resource) = tiles[index].edge_resources[edge] {
                    let slot = usize::try_from(resource).unwrap_or(0);
                    if slot < resource_tally.len() {
                        resource_tally[slot] += 1;
                    }
                }
            }
        }

        if resource_tally[3] == 0 {
            place_guaranteed_resource(tiles, gate_flags, &linked, map_lcg, 3);
        }
        if resource_tally[4] == 0 {
            let mut target_index: isize = -1;
            let mut found = false;
            let mut gate_flag;
            loop {
                target_index += 1;
                let index = linked[target_index as usize];
                gate_flag = gate_flags[index];
                if (gate_flag == 9 || gate_flag == 8) && tiles[index].edge_resources[0].is_none() {
                    found = true;
                }
                if (target_index as usize) >= linked.len() - 1 || found {
                    break;
                }
            }

            if found {
                let index = linked[target_index as usize];
                tiles[index].edge_resources[0] = Some(4);
                if gate_flag == 9 {
                    tiles[index].edge_resources[1] = None;
                    gate_flags[index] = resolve_region_tile_subtype_code(tiles, gate_flags, index);
                    continue;
                }
            } else {
                let mut picked;
                loop {
                    loop {
                        let sample = map_lcg.next_sample_15();
                        picked = (sample as usize) % linked.len();
                        gate_flag = gate_flags[linked[picked]];
                        if gate_flag != 8 {
                            break;
                        }
                    }
                    if gate_flag != 9 {
                        break;
                    }
                }
                let index = linked[picked];
                gate_flags[index] = 8;
                tiles[index].edge_resources[0] = Some(4);
                target_index = picked as isize;
            }
            let index = linked[target_index as usize];
            tiles[index].edge_resources[1] = None;
            gate_flags[index] = resolve_region_tile_subtype_code(tiles, gate_flags, index);
        }
    }
}

fn place_guaranteed_resource(
    tiles: &mut [TileState],
    gate_flags: &mut [i8],
    linked: &[usize],
    map_lcg: &mut RetailLcg,
    resource: i8,
) {
    let mut target_index: isize = -1;
    let mut found = false;
    loop {
        target_index += 1;
        let index = linked[target_index as usize];
        let gate_flag = gate_flags[index];
        if (gate_flag == 9 || gate_flag == 8) && tiles[index].edge_resources[0].is_none() {
            found = true;
        }
        if (target_index as usize) >= linked.len() - 1 || found {
            break;
        }
    }

    if found {
        tiles[linked[target_index as usize]].edge_resources[0] = Some(resource);
    } else {
        let mut picked;
        loop {
            loop {
                let sample = map_lcg.next_sample_15();
                picked = (sample as usize) % linked.len();
                let gate_flag = gate_flags[linked[picked]];
                if gate_flag != 8 {
                    break;
                }
            }
            if gate_flags[linked[picked]] != 9 {
                break;
            }
        }
        let index = linked[picked];
        gate_flags[index] = 8;
        tiles[index].edge_resources[0] = Some(resource);
        target_index = picked as isize;
    }
    let index = linked[target_index as usize];
    tiles[index].edge_resources[1] = None;
    gate_flags[index] = resolve_region_tile_subtype_code(tiles, gate_flags, index);
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
        let state = create_random_game(&preview, MajorNationId::new(6), Difficulty::Normal, 1);

        assert_eq!(state.turn.phase_code, 2);
        assert_eq!(state.turn.difficulty, Difficulty::Normal);
        assert_eq!(state.turn.selected_nation, NationId::new(6));
        assert_ne!(
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
        assert!(
            state
                .world
                .tiles
                .iter()
                .any(|tile| tile.edge_resources[0].is_some()),
            "post-passes must stamp some edge resources"
        );
        assert!(
            state
                .world
                .tiles
                .iter()
                .any(|tile| tile.active_flags == PROVINCE_CAPITAL_ACTIVE_FLAGS),
            "untouched provinces keep fallback capital active_flags=0x22"
        );
        assert!(
            state
                .world
                .tiles
                .iter()
                .any(|tile| tile.active_flags == PLACE_CITY_ACTIVE_FLAGS),
            "AI PlaceCity must stamp active_flags=0x37"
        );

        let human = state.nations.major(MajorNationId::new(6)).unwrap();
        assert_eq!(human.common.treasury, 10_000);
        assert_eq!(human.common.home_tile, None);
        assert!(human.state.diplomacy_eligible);

        let ai = state.nations.major(MajorNationId::new(0)).unwrap();
        assert_eq!(ai.common.treasury, 10_000);
        assert!(!ai.state.diplomacy_eligible);
        assert!(ai.common.home_tile.is_some(), "AI majors place a capital");
        assert_eq!(
            state
                .nations
                .city(MajorNationId::new(0))
                .unwrap()
                .home_town_tile,
            ai.common.home_tile
        );
        let ai_home = ai.common.home_tile.unwrap();
        assert_eq!(
            state.world.tiles[usize::from(ai_home.get())].active_flags,
            PLACE_CITY_ACTIVE_FLAGS
        );
        assert!(
            state.world.tiles[usize::from(ai_home.get())].region_marker >= 1,
            "retail region markers start at 1"
        );
        assert_eq!(state.rng.zone_status, RetailLcg::from_state(1));

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

        let placed_minors = state
            .nations
            .minors
            .iter()
            .flatten()
            .filter(|minor| minor.common.home_tile.is_some())
            .count();
        assert!(placed_minors > 0, "minors receive home tiles");
        assert!(
            state.world.tiles.iter().any(
                |tile| (tile.active_flags & MINOR_HOME_ACTIVE_FLAGS) == MINOR_HOME_ACTIVE_FLAGS
            ),
            "minor homes stamp active_flags with bit0|0x20"
        );
        assert!(
            !state.military_units.is_empty(),
            "minor InitialMilitia produces military units"
        );
        assert!(
            state
                .military_units
                .iter()
                .all(|unit| unit.nation.get() >= MinorNationId::FIRST),
            "pre-capital military units are minor-owned only"
        );
        assert!(
            state
                .military_units
                .iter()
                .any(|unit| unit.name.starts_with("1st ")),
            "NameUnits assigns English ordinal names"
        );
        assert_ne!(
            state.rng.crt_rand,
            RetailCrtRng::from_state(1),
            "minor home selection advances CRT rand"
        );
        assert!(
            !state.missions.is_empty(),
            "AI QueueMapActionMissions fills the Accept mission queues"
        );
        assert!(
            state.missions.iter().any(|mission| {
                matches!(mission.data, MissionData::ScatteredShips(_))
                    && mission.importance_bits == SCATTERED_SHIPS_IMPORTANCE_BITS
            }),
            "each AI queue ends with ScatteredShips at 0.001f"
        );
        assert!(
            state.missions.iter().any(|mission| {
                matches!(mission.data, MissionData::DefendProvince(_))
            }),
            "AI queues include DefendProvince for owned regions"
        );
        assert!(
            state
                .world
                .tiles
                .iter()
                .any(|tile| tile.action_state == ACTION_STATE_ANCHOR),
            "EnsurePortZone stamps Anchor action_state on linked sea tiles"
        );
        assert!(
            state
                .missions
                .iter()
                .all(|mission| mission.nation.get() != 6),
            "human Normal+ majors do not receive Accept mission queues"
        );
    }
}
