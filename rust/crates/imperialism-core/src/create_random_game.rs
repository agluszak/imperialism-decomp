use crate::*;
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
    let mut post = apply_tile_post_passes(&preview.map, preview.topology, &mut map_lcg);
    let foreign_ministers = choose_foreign_ministers(&preview.map, human_nation);
    let mut nations = bootstrap_nations(human_nation, difficulty, foreign_ministers);
    let mut world = StrategicMap::from_generated_tiles(preview.topology, post.tiles);
    // Runtime-test / Accept entry: map build ends in `srand(runtime_seed)`, then setup
    // `DoPostCreate` draws one `rand() % 7` for the initial nation when the slot was -1.
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
        &mut port_zones,
        &mut mission_queues,
    );

    let mut military_units = Vec::new();
    let mut unit_ids = UnitIdAllocator::default();
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
    let diplomacy = DiplomacyState::for_random_start(human_nation, difficulty, &mut crt_rand);

    initialize_ai_zone_targets(&mut nations, &mission_queues, port_zones.next_ordinal);
    let port_zone_owners = port_zones
        .ports
        .iter()
        .map(|port| PortZoneOwner {
            zone: port.ordinal,
            former_owner: port.former_owner,
        })
        .collect();
    let missions = flatten_mission_queues(&mut mission_queues);
    let provinces = build_province_state(&preview.map, &world, &mut nations);
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
        technology: crate::TechnologyState::default(),
        diplomacy,
        nations,
        military_units,
        civilian_units: Vec::new(),
        ships: Vec::new(),
        task_forces: Vec::new(),
        missions,
        pending,
    }
}

struct TilePostPassState {
    tiles: Box<[TileState]>,
    gate_flags: Vec<i8>,
    province_capitals: Vec<Option<TileId>>,
}

/// Preview-time tile post-passes from `TMapMgr::BuildOrLoadGlobalMapStateForSession`:
/// icon-variant/edge-resource stamping, former-owner snapshot, province fallback capitals,
/// `GuaranteeResources`, and the final picture-assignment RNG pass.
fn apply_tile_post_passes(
    map: &GeneratedMap,
    topology: MapTopology,
    map_lcg: &mut RetailLcg,
) -> TilePostPassState {
    let geometry = MapGeometry::new(topology);
    let mut tiles: Vec<TileState> = map
        .tiles()
        .iter()
        .copied()
        .map(tile_from_generated)
        .collect();
    let mut gate_flags: Vec<i8> = map
        .tiles()
        .iter()
        .map(|tile| {
            tile.gate
                .map_or(-1, crate::random_map_terrain::GenerationGate::code)
        })
        .collect();

    for index in 0..tiles.len() {
        update_strategic_map_tile_icon_variant_state(
            &mut tiles,
            &mut gate_flags,
            geometry,
            index,
            map_lcg,
        );
    }

    // Retail runs this between icon variants and GuaranteeResources; it advances the map
    // LCG once per occupied province and records its fallback capital.
    let province_capitals =
        assign_province_fallback_capitals(&mut tiles, &mut gate_flags, geometry, map_lcg);

    guarantee_resources(&mut tiles, &mut gate_flags, map_lcg);
    consume_fresh_map_picture_assignment_rng(&tiles, geometry, map_lcg);
    TilePostPassState {
        tiles: tiles.into_boxed_slice(),
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
) -> Vec<Option<TileId>> {
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
        if tile.terrain == TerrainKind::Water {
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
                .filter(|&index| {
                    matches!(
                        tiles[index].terrain,
                        TerrainKind::Plains | TerrainKind::Farmland
                    )
                })
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
        tiles[chosen].flags = TileFlags::PROVINCE_ANCHOR_STATE;
        province_capitals[province_index] = Some(TileId::new(chosen as u16));
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
    tiles[index].terrain = TerrainKind::Plains;
    tiles[index].edge_resources = [Some(ResourceKind::Grain), None];
    gate_flags[index] = resolve_region_tile_subtype_code(tiles, gate_flags, index);
}

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

/// AI home placement from `CreateFrogCityAtHomeRegionAndAttach` for setup mode 2 majors.
fn place_ai_frog_cities(
    world: &mut StrategicMap,
    gate_flags: &mut [i8],
    province_capitals: &mut [Option<TileId>],
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
        ensure_port_zone_for_tile(world, port_zones, home);
        let major = nations.major_mut(nation);
        major.common.home_tile = Some(home);
        major.city.home_town_tile = Some(home);
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
    world: &mut StrategicMap,
    gate_flags: &mut [i8],
    province_capitals: &mut [Option<TileId>],
    nations: &mut Nations,
    crt: &mut RetailCrtRng,
    military_units: &mut Vec<MilitaryUnitState>,
    unit_ids: &mut UnitIdAllocator,
    difficulty: Difficulty,
    port_zones: &mut PortZoneTable,
) {
    for minor_id in (MinorNationId::FIRST..NationId::COUNT).map(MinorNationId::new) {
        let owner = TileOwnerTag::from_nation(minor_id.nation());
        let Some(home) = select_minor_home_tile(world, owner, crt) else {
            continue;
        };
        reset_tile_to_base_transport_flag(world, gate_flags, province_capitals, home);
        // Retail calls `EnsurePortZoneForTile` after the minor home stamp.
        ensure_port_zone_for_tile(world, port_zones, home);
        if let Some(minor) = nations.minors[minor_id].as_mut() {
            minor.common.home_tile = Some(home);
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
            unit_ids,
            &mut name_ordinals,
            &mut next_roster_id,
        );
        // RebuildSecondaryNationStateForSlot trailing pair after InitialMilitia.
        let home_province = world[home].province;
        for _ in 0..2 {
            push_military_unit(
                military_units,
                unit_ids,
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
    world: &StrategicMap,
    owner: TileOwnerTag,
    crt: &mut RetailCrtRng,
) -> Option<TileId> {
    let mut selected = None;
    let mut candidates = Vec::new();
    for (index, tile) in world.iter().enumerate() {
        if tile.owner_nation != Some(owner) {
            continue;
        }
        if tile.flags.has_base_transport() {
            selected = Some(TileId::new(index as u16));
        }
        let tile_id = TileId::new(index as u16);
        if is_valid_secondary_nation_home_tile_candidate(world, tile_id) {
            candidates.push(tile_id);
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
    world: &mut StrategicMap,
    gate_flags: &mut [i8],
    province_capitals: &mut [Option<TileId>],
    tile: TileId,
) {
    set_region_tile_subtype_and_refresh_neighbor_flags(world, gate_flags, province_capitals, tile);
    world[tile].flags = TileFlags::MINOR_HOME_STATE;
    initialize_world_tile_neighbor_connection_mask_if_needed(world, gate_flags, tile);
}

fn owned_province_ids(
    world: &StrategicMap,
    province_capitals: &[Option<TileId>],
    owner: TileOwnerTag,
) -> Vec<ProvinceId> {
    let mut owned = Vec::new();
    for (province_index, capital) in province_capitals.iter().enumerate() {
        let Some(capital) = *capital else {
            continue;
        };
        if world[capital].owner_nation == Some(owner) {
            owned.push(ProvinceId::new(province_index as u16));
        }
    }
    owned
}

/// `TCountry::InitialMilitia` for random-map minors at the pre-capital boundary.
#[allow(clippy::too_many_arguments)]
fn spawn_initial_militia_for_minor(
    world: &mut StrategicMap,
    province_capitals: &[Option<TileId>],
    minor_id: MinorNationId,
    owned_provinces: &[ProvinceId],
    difficulty: Difficulty,
    military_units: &mut Vec<MilitaryUnitState>,
    unit_ids: &mut UnitIdAllocator,
    name_ordinals: &mut [i16],
    next_roster_id: &mut i16,
) {
    let nation = minor_id.nation();
    let set_garrison_orders = matches!(difficulty, Difficulty::Introductory | Difficulty::Easy);
    for &province in owned_provinces {
        let capital = province_capitals[usize::from(province.get())];
        if let Some(capital) = capital
            && world[capital].flags.has_base_transport()
        {
            let order = if set_garrison_orders { 2 } else { 0 };
            push_military_unit(
                military_units,
                unit_ids,
                nation,
                MilitaryUnitKind::Regulars,
                Some(province),
                order,
            );
            push_military_unit(
                military_units,
                unit_ids,
                nation,
                MilitaryUnitKind::Regulars,
                Some(province),
                order,
            );
            push_military_unit(
                military_units,
                unit_ids,
                nation,
                MilitaryUnitKind::Artillery,
                Some(province),
                order,
            );
            world[capital]
                .flags
                .insert(TileFlags::PROVINCE_CAPITAL_FORTIFICATION);
        }
        // `AddMilitia` ×3 (minors always spawn type 0 / Minutemen with order 2).
        for _ in 0..3 {
            push_military_unit(
                military_units,
                unit_ids,
                nation,
                MilitaryUnitKind::Minutemen,
                Some(province),
                2,
            );
        }
        if matches!(difficulty, Difficulty::Hard | Difficulty::NighOnImpossible) {
            push_military_unit(
                military_units,
                unit_ids,
                nation,
                MilitaryUnitKind::Minutemen,
                Some(province),
                2,
            );
            push_military_unit(
                military_units,
                unit_ids,
                nation,
                MilitaryUnitKind::Artillery,
                Some(province),
                0,
            );
        }
    }
    name_units_for_nation(military_units, nation, name_ordinals, next_roster_id);
}

fn push_military_unit(
    military_units: &mut Vec<MilitaryUnitState>,
    unit_ids: &mut UnitIdAllocator,
    nation: NationId,
    unit_type: MilitaryUnitKind,
    stationed_province: Option<ProvinceId>,
    order: i32,
) {
    let targets = [stationed_province; 3];
    let order = if order == 0 {
        MilitaryOrder::idle(targets, targets)
    } else {
        MilitaryOrder::retail(
            MilitaryOrderCode::from_retail(order),
            None,
            targets,
            targets,
        )
    };
    military_units.push(MilitaryUnitState::new(
        unit_ids.next_military(),
        nation,
        unit_type,
        stationed_province,
        order,
        nation,
        0,
        true,
        String::new(),
        500,
        unit_type.spawn_era(),
        0,
        0,
    ));
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
        if unit.unit_type >= MilitaryUnitKind::GeneralEra1 {
            continue;
        }
        let kind = unit.unit_type as usize;
        let ordinal = name_ordinals[kind];
        let type_name = LAND_UNIT_TYPE_NAMES[kind];
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
    world: &StrategicMap,
    gate_flags: &[i8],
    nation: MajorNationId,
) -> Option<TileId> {
    let owner = TileOwnerTag::from_nation(nation.nation());
    let mut best_score: i32 = -1;
    let mut best_tile: Option<TileId> = None;
    for index in 0..STRATEGIC_TILE_COUNT {
        let tile = TileId::new(index as u16);
        let state = &world[tile];
        if state.owner_nation != Some(owner) {
            continue;
        }
        if !is_valid_secondary_nation_home_tile_candidate(world, tile) {
            continue;
        }
        if !supports_city_site_terrain(state.terrain) {
            continue;
        }
        let yields = calculate_city_resources(world, gate_flags, tile, nation);
        let mut score = frog_city_score(&yields);
        if state.flags.has_base_transport() {
            score = 32_000;
        }
        if (best_score as i16) < (score as i16) {
            best_score = score;
            best_tile = Some(tile);
        }
    }
    best_tile
}

fn frog_city_score(yields: &ResourceTable<i16>) -> i32 {
    let grain = yields[ResourceKind::Grain];
    let fruit = yields[ResourceKind::Fruit];
    let clamped_grain = grain.clamp(0, 6);
    let clamped_fruit = fruit.clamp(0, 2);
    let grain_surplus = (grain - 6).clamp(0, 3);
    let fruit_surplus = (fruit * 2 - 4).clamp(0, 4);
    let food_bonus =
        ((yields[ResourceKind::Fish] + yields[ResourceKind::Livestock]) * 2).clamp(0, 4);
    let raw_material = (yields[ResourceKind::Timber] * 2).clamp(0, 12);
    let soft = i32::from(yields[ResourceKind::Cotton])
        + i32::from(yields[ResourceKind::Wool])
        + i32::from(yields[ResourceKind::Gold]);
    soft * 3
        + i32::from(yields[ResourceKind::Coal])
        + i32::from(yields[ResourceKind::Iron])
        + i32::from(raw_material)
        + i32::from(clamped_grain) * 1000
        + i32::from(clamped_fruit) * 1000
        + i32::from(grain_surplus)
        + i32::from(fruit_surplus)
        + i32::from(food_bonus)
}

/// `TTown::CalculateCityResources` (0x005b73e0) for an enabled Frog City marker.
fn calculate_city_resources(
    world: &StrategicMap,
    gate_flags: &[i8],
    home: TileId,
    nation: MajorNationId,
) -> ResourceTable<i16> {
    let geometry = world.geometry();
    let owner = TileOwnerTag::from_nation(nation.nation());
    let mut yields = ResourceTable::default();
    // Directions 0..5 are hex neighbors; 6 is the home tile itself (`TownNeighborTile`).
    for tile in geometry
        .neighbors(home)
        .into_iter()
        .chain(std::iter::once(Some(home)))
        .flatten()
    {
        let index = usize::from(tile.get());
        let state = &world[tile];
        if state.owner_nation != Some(owner) && state.terrain != TerrainKind::Water {
            continue;
        }
        for resource in crate::all_resources() {
            let resource_index = resource as usize;
            let mut amount = i16::from(resource_capability_level(state, resource));
            if amount != 0 {
                let gate = gate_flags[index];
                if (0..24).contains(&gate) && RESOURCE_USES_HIGH_NIBBLE[gate as usize] != 0 {
                    let capability = starting_tech_capability(resource);
                    amount = i16::from(UNIVERSITY_REQUIREMENT_LEVEL[resource_index][capability]);
                }
            }
            yields[resource] += amount;
        }
        if state.river.is_some() {
            yields[ResourceKind::Fish] += 1;
        }
    }
    yields
}

fn resource_capability_level(tile: &TileState, resource: ResourceKind) -> u8 {
    if !tile.edge_resources.contains(&Some(resource)) {
        return 0;
    }
    let resource = resource as usize;
    let packed = (tile.development.extractive.get() << 4) | tile.development.surface.get();
    let index = if RESOURCE_USES_HIGH_NIBBLE[resource] != 0 {
        packed >> 4
    } else {
        packed & 0x0f
    };
    UNIVERSITY_REQUIREMENT_LEVEL[resource][usize::from(index.min(3))]
}

fn starting_tech_capability(resource: ResourceKind) -> usize {
    match resource {
        ResourceKind::Fruit
        | ResourceKind::Grain
        | ResourceKind::Gems
        | ResourceKind::Iron
        | ResourceKind::Coal
        | ResourceKind::Gold => 1,
        _ => 0,
    }
}

/// Accept-time AI `PlaceCity`: province capital rewrite, flags, flood-fill, farmland nibble.
fn place_ai_capital(
    world: &mut StrategicMap,
    gate_flags: &mut [i8],
    province_capitals: &mut [Option<TileId>],
    tile: TileId,
    nation: MajorNationId,
) {
    let index = usize::from(tile.get());
    set_region_tile_subtype_and_refresh_neighbor_flags(world, gate_flags, province_capitals, tile);
    let owner = TileOwnerTag::from_nation(nation.nation());
    place_city(world, tile, owner);

    let origin_marker = world[tile].region;
    for neighbor in place_city_harvest_tiles(index).into_iter().flatten() {
        let neighbor = TileId::new(neighbor as u16);
        if world[neighbor].region != origin_marker {
            continue;
        }
        let neighbor_index = usize::from(neighbor.get());
        let gate = gate_flags[neighbor_index];
        let qualifies = (0..24).contains(&gate) && GATE_FLAG_QUALIFIES[gate as usize] != 0;
        if !qualifies {
            continue;
        }
        let eligible = world[neighbor]
            .edge_resources
            .iter()
            .any(|edge| matches!(edge, Some(ResourceKind::Grain) | Some(ResourceKind::Fruit)));
        if eligible {
            world[neighbor].development.surface = DevelopmentLevel::new(1);
        }
    }
    gate_flags[index] =
        resolve_region_tile_subtype_code_for_state(&world[tile], gate_flags[index], index);
}

/// `TMapMgr::SetRegionTileSubtypeAndRefreshNeighborFlags` (0x00515f80) tile mutations.
fn set_region_tile_subtype_and_refresh_neighbor_flags(
    world: &mut StrategicMap,
    gate_flags: &mut [i8],
    province_capitals: &mut [Option<TileId>],
    new_tile: TileId,
) {
    let Some(province) = world[new_tile].province else {
        return;
    };
    let province_index = usize::from(province.get());
    if let Some(old_tile) = province_capitals[province_index] {
        let old_index = usize::from(old_tile.get());
        world[old_tile].flags = TileFlags::empty();
        world[old_tile].edge_resources[0] = Some(ResourceKind::Grain);
        gate_flags[old_index] = resolve_region_tile_subtype_code_for_state(
            &world[old_tile],
            gate_flags[old_index],
            old_index,
        );
    }
    let new_index = usize::from(new_tile.get());
    world[new_tile].flags = TileFlags::PROVINCE_ANCHOR_STATE;
    province_capitals[province_index] = Some(new_tile);
    gate_flags[new_index] = resolve_region_tile_subtype_code_for_state(
        &world[new_tile],
        gate_flags[new_index],
        new_index,
    );

    for index in 0..STRATEGIC_TILE_COUNT {
        let tile_id = TileId::new(index as u16);
        if tile_id != new_tile && world[tile_id].province == Some(province) {
            world[tile_id].flags.clear_city_marker();
        }
    }
}

fn initialize_world_tile_neighbor_connection_mask_if_needed(
    world: &mut StrategicMap,
    gate_flags: &mut [i8],
    tile: TileId,
) {
    let index = usize::from(tile.get());
    if gate_flags[index] == 1 {
        return;
    }
    world[tile].terrain = TerrainKind::Plains;
    world[tile].edge_resources = [Some(ResourceKind::Grain), None];
    gate_flags[index] =
        resolve_region_tile_subtype_code_for_state(&world[tile], gate_flags[index], index);
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
    next_ordinal: u16,
    ports: Vec<PortZone>,
}

#[derive(Clone, Copy, Debug)]
struct PortZone {
    ordinal: OceanZoneId,
    port_tile: TileId,
    sea_tile: TileId,
    /// `primaryNeighbors[0]` ordinal (sea zone or another port).
    primary_neighbor: Option<OceanZoneId>,
    former_owner: NationId,
}

impl PortZoneTable {
    fn new(sea_zone_count: u16) -> Self {
        Self {
            next_ordinal: sea_zone_count,
            ports: Vec::new(),
        }
    }

    fn find_port_by_tile(&self, tile: TileId) -> Option<&PortZone> {
        self.ports
            .iter()
            .find(|port| port.port_tile == tile || port.sea_tile == tile)
    }

    fn find_first_port_for_nation(&self, nation: NationId) -> Option<&PortZone> {
        self.ports.iter().find(|port| port.former_owner == nation)
    }
}

fn sea_zone_count(world: &StrategicMap) -> u16 {
    world
        .iter()
        .filter(|tile| tile.terrain == TerrainKind::Water)
        .filter_map(|tile| tile.owner_nation)
        .map(TileOwnerTag::get)
        .filter(|&tag| tag >= SEA_OWNER_BIAS)
        .map(|tag| u16::from(tag - SEA_OWNER_BIAS) + 1)
        .max()
        .unwrap_or(0)
}

/// `TOcean::EnsurePortZoneForTile` side effects needed for Accept missions / tile action state.
fn ensure_port_zone_for_tile(world: &mut StrategicMap, ports: &mut PortZoneTable, tile: TileId) {
    if !world[tile].flags.has_base_transport() {
        return;
    }
    if ports.find_port_by_tile(tile).is_some() {
        return;
    }
    let Some(owner) = world[tile].owner_nation.and_then(TileOwnerTag::nation) else {
        return;
    };
    let nation_seed = owner.get();
    let former_owner = world[tile]
        .former_owner_nation
        .and_then(TileOwnerTag::nation)
        .unwrap_or(owner);

    let geometry = world.geometry();
    let Some(best_sea) = select_port_sea_tile(world, geometry, tile, nation_seed) else {
        return;
    };

    let primary_neighbor = if world[best_sea]
        .action
        .is_some_and(|action| matches!(action.retail(), ACTION_STATE_ANCHOR | 14))
    {
        ports.find_port_by_tile(best_sea).map(|port| port.ordinal)
    } else {
        world[best_sea]
            .owner_nation
            .map(|owner| owner.get())
            .filter(|&tag| tag >= SEA_OWNER_BIAS)
            .map(|tag| OceanZoneId::new(u16::from(tag - SEA_OWNER_BIAS)))
    };

    let ordinal = OceanZoneId::new(ports.next_ordinal);
    ports.next_ordinal += 1;
    ports.ports.insert(
        0,
        PortZone {
            ordinal,
            port_tile: tile,
            sea_tile: best_sea,
            primary_neighbor,
            former_owner,
        },
    );
    world[best_sea].action = TileAction::try_from_retail(ACTION_STATE_ANCHOR);
}

fn select_port_sea_tile(
    world: &StrategicMap,
    geometry: MapGeometry,
    tile: TileId,
    nation_seed: u8,
) -> Option<TileId> {
    let tile_index = usize::from(tile.get());
    for offset in 0..6 {
        let direction = HexDirection::ALL[(tile_index + offset) % 6];
        let Some(candidate) = geometry.neighbor(tile, direction) else {
            continue;
        };
        if world[candidate].terrain != TerrainKind::Water {
            continue;
        }
        let all_neighbors_qualify =
            geometry
                .neighbors(candidate)
                .into_iter()
                .flatten()
                .all(|neighbor| {
                    let neighbor_owner = world[neighbor].owner_nation;
                    !matches!(
                        neighbor_owner,
                        Some(owner) if owner.get() < SEA_OWNER_BIAS && owner.get() != nation_seed
                    )
                });
        if all_neighbors_qualify {
            return Some(candidate);
        }
    }
    // Fallback: any adjacent water tile (skips the full river-flow tracer).
    geometry
        .neighbors(tile)
        .into_iter()
        .flatten()
        .find(|&neighbor| world[neighbor].terrain == TerrainKind::Water)
}

/// Province adjacency lists used by the defend-province availability gate.
fn build_province_adjacency(world: &StrategicMap) -> Vec<Vec<ProvinceId>> {
    let province_count = world
        .iter()
        .filter_map(|tile| {
            tile.province
                .map(|province| usize::from(province.get()) + 1)
        })
        .max()
        .unwrap_or(0);
    let mut adjacency = vec![Vec::new(); province_count];
    let geometry = world.geometry();
    for (index, tile) in world.iter().enumerate() {
        let Some(province) = tile.province else {
            continue;
        };
        let province_index = usize::from(province.get());
        for neighbor in geometry
            .neighbors(TileId::new(index as u16))
            .into_iter()
            .flatten()
        {
            let Some(neighbor_province) = world[neighbor].province else {
                continue;
            };
            if neighbor_province == province {
                continue;
            }
            if !adjacency[province_index].contains(&neighbor_province) {
                adjacency[province_index].push(neighbor_province);
            }
        }
    }
    adjacency
}

/// Materializes the fixed province table and each country's ordered region list.
/// Generated province IDs are already compact and are visited in ascending retail
/// table order, matching the append order used by map setup.
fn build_province_state(
    map: &GeneratedMap,
    world: &StrategicMap,
    nations: &mut Nations,
) -> ProvinceTable<ProvinceState> {
    let adjacency = build_province_adjacency(world);
    let mut provinces = ProvinceTable::default();
    for (index, generated) in map.provinces().iter().enumerate() {
        let province = ProvinceId::new(index as u16);
        let owner = generated
            .owner
            .nation()
            .expect("accepted generated provinces have nation owners");
        provinces[province] = ProvinceState::new(
            Some(owner),
            Some(owner),
            adjacency[index].clone(),
            Some(generated.terrain.retail() as u8),
        )
        .expect("generated province state fits the retail province record");
        nations
            .common_mut(owner)
            .expect("accepted generated province owner is present")
            .owned_regions
            .push(province);
    }
    provinces
}

/// `IsNodeTypeLinkUnavailableAndNoActiveMapActionContext` for Accept-time owned provinces.
///
/// Without the sea-zone secondary-neighbor graph, coastal isolation falls back to "has any
/// adjacent province". The second-degree retail quirk (owned province with a neighbor that
/// itself has neighbors) is preserved.
fn province_mission_available(
    province: ProvinceId,
    nation: TileOwnerTag,
    world: &StrategicMap,
    province_capitals: &[Option<TileId>],
    adjacency: &[Vec<ProvinceId>],
) -> bool {
    let province_usize = usize::from(province.get());
    let neighbors = &adjacency[province_usize];
    for &adjacent in neighbors {
        let Some(capital) = province_capitals[usize::from(adjacent.get())] else {
            continue;
        };
        if world[capital].owner_nation == Some(nation) {
            return true;
        }
    }
    // CollectSecondDegreeLinksMatchingNodeType: if this owned province has any neighbor that
    // itself has neighbors, treat as available.
    if !neighbors.is_empty() {
        for &adjacent in neighbors {
            if !adjacency[usize::from(adjacent.get())].is_empty() {
                return true;
            }
        }
    }
    false
}

/// `TAutoGreatPower::QueueMapActionMissionsForPortZoneCandidates`.
fn queue_map_action_missions_for_port_zone_candidates(
    world: &StrategicMap,
    province_capitals: &[Option<TileId>],
    adjacency: &[Vec<ProvinceId>],
    ports: &PortZoneTable,
    nation: MajorNationId,
) -> Vec<MissionState> {
    let owner = TileOwnerTag::from_nation(nation.nation());
    let owned = owned_province_ids(world, province_capitals, owner);
    let mut missions = Vec::new();

    for &province in &owned {
        if !province_mission_available(province, owner, world, province_capitals, adjacency) {
            continue;
        }
        missions.push(mission_state(
            nation,
            MissionData::DefendProvince {
                province,
                army: ArmyMissionState {
                    required_equipage_bits: [0; 5],
                    units: Vec::new(),
                },
            },
            0,
        ));
    }

    let Some(port) = ports.find_first_port_for_nation(nation.nation()) else {
        return missions;
    };
    let Some(sea_or_neighbor) = port.primary_neighbor else {
        return missions;
    };

    // Factory: zone != nation's first port → ControlSeaZone; port itself → Escort.
    missions.push(mission_state(
        nation,
        MissionData::ControlSeaZone(empty_navy_mission(Some(sea_or_neighbor), None)),
        0,
    ));
    missions.push(mission_state(
        nation,
        MissionData::Escort(empty_navy_mission(Some(port.ordinal), Some(port.ordinal))),
        0,
    ));
    missions.push(mission_state(
        nation,
        MissionData::ScatteredShips(empty_navy_mission(None, None)),
        SCATTERED_SHIPS_IMPORTANCE_BITS,
    ));
    missions
}

fn initialize_ai_zone_targets(
    nations: &mut Nations,
    mission_queues: &MajorNationTable<Vec<MissionState>>,
    live_zone_count: u16,
) {
    for nation in (0..MajorNationId::COUNT).map(MajorNationId::new) {
        let economy = &mut nations.major_mut(nation).economy;
        let Some(targets) = economy.ai_zone_targets.as_mut() else {
            continue;
        };
        targets.resize(usize::from(live_zone_count), AiZoneTargetState::Unmarked);
        for mission in &mission_queues[nation] {
            let target = match &mission.data {
                MissionData::ControlSeaZone(navy) | MissionData::Escort(navy) => navy.target_zone,
                _ => None,
            };
            if let Some(target) = target {
                targets[usize::from(target.get())] = AiZoneTargetState::MissionQueued;
            }
        }
    }
}

fn empty_navy_mission(
    target_zone: Option<OceanZoneId>,
    resolved_port_zone: Option<OceanZoneId>,
) -> NavyMissionState {
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

fn mission_state(nation: MajorNationId, data: MissionData, importance_bits: u32) -> MissionState {
    MissionState {
        nation: nation.nation(),
        data,
        path_nation: None,
        state: 2,
        importance_bits,
        marker: 0,
    }
}

fn flatten_mission_queues(queues: &mut MajorNationTable<Vec<MissionState>>) -> Vec<MissionState> {
    let mut missions = Vec::new();
    for nation in (0..MajorNationId::COUNT).map(MajorNationId::new) {
        missions.append(&mut queues[nation]);
    }
    missions
}

fn tile_from_generated(tile: GeneratedTerrainTile) -> TileState {
    let owner = tile.owner;
    TileState {
        terrain: tile.terrain,
        owner_nation: owner,
        // Retail stamps former owners from the generation owners before Accept.
        former_owner_nation: owner,
        province: tile.province,
        development: Default::default(),
        edge_resources: [None, None],
        transport_links: Default::default(),
        pending_rail_links: Default::default(),
        // Map tiles default to "no action" (-1) after generation.
        action: None,
        flags: TileFlags::empty(),
        region: None,
        river: tile.river,
    }
}

/// `TMapMgr::UpdateStrategicMapTileIconVariantState` (0x00511610).
fn update_strategic_map_tile_icon_variant_state(
    tiles: &mut [TileState],
    gate_flags: &mut [i8],
    geometry: MapGeometry,
    index: usize,
    map_lcg: &mut RetailLcg,
) {
    let terrain = tiles[index].terrain;
    let major_owner = tiles[index]
        .owner_nation
        .and_then(TileOwnerTag::nation)
        .and_then(MajorNationId::from_nation)
        .is_some();
    match terrain {
        TerrainKind::Water => {
            let tile_id = TileId::new(index as u16);
            let found_land = geometry
                .neighbors(tile_id)
                .into_iter()
                .flatten()
                .any(|neighbor| tiles[usize::from(neighbor.get())].terrain != TerrainKind::Water);
            if found_land {
                tiles[index].edge_resources[0] = Some(ResourceKind::Fish);
            }
        }
        TerrainKind::Plains => {
            let roll = map_lcg.next_sample_15();
            if roll % 100 < 10 {
                tiles[index].edge_resources[0] = Some(ResourceKind::Cotton);
            } else {
                let roll = map_lcg.next_sample_15();
                if roll % 100 < 5 && major_owner {
                    tiles[index].edge_resources[0] = Some(ResourceKind::Horses);
                } else {
                    let roll = map_lcg.next_sample_15();
                    tiles[index].edge_resources[0] = Some(if roll % 100 < 0x24 {
                        ResourceKind::Livestock
                    } else {
                        ResourceKind::Grain
                    });
                }
            }
        }
        TerrainKind::Farmland => {
            let roll = map_lcg.next_sample_15();
            tiles[index].edge_resources[0] = Some(if roll % 100 < 0x37 {
                ResourceKind::Grain
            } else {
                ResourceKind::Fruit
            });
        }
        TerrainKind::Forest => {
            tiles[index].edge_resources[0] = Some(ResourceKind::Timber);
        }
        TerrainKind::Swamp | TerrainKind::Desert => {
            let roll = map_lcg.next_sample_15();
            if roll % 100 < 0xf {
                tiles[index].edge_resources[0] = Some(ResourceKind::Oil);
            }
        }
        TerrainKind::Hills => {
            let roll = map_lcg.next_sample_15();
            if roll % 100 < 0xc {
                tiles[index].edge_resources[0] = Some(ResourceKind::Wool);
            } else {
                let roll = map_lcg.next_sample_15();
                if roll % 100 < 0x14 {
                    let roll = map_lcg.next_sample_15();
                    tiles[index].edge_resources[0] = Some(if roll % 100 < 0x32 {
                        ResourceKind::Coal
                    } else {
                        ResourceKind::Iron
                    });
                }
            }
        }
        TerrainKind::Mountain => {
            let mut edge_index = 0usize;
            let roll = map_lcg.next_sample_15();
            if roll % 100 < 0x14 {
                let roll = map_lcg.next_sample_15();
                tiles[index].edge_resources[0] = Some(if roll % 100 < 0x32 {
                    ResourceKind::Coal
                } else {
                    ResourceKind::Iron
                });
                edge_index = 1;
            }
            if major_owner {
                let roll = map_lcg.next_sample_15();
                if roll % 100 < 0xf {
                    tiles[index].edge_resources[edge_index] = Some(ResourceKind::Gold);
                }
            } else {
                let roll = map_lcg.next_sample_15();
                if roll % 100 < 0xa {
                    tiles[index].edge_resources[edge_index] = Some(ResourceKind::Gems);
                } else {
                    let roll = map_lcg.next_sample_15();
                    if roll % 100 < 0xf {
                        tiles[index].edge_resources[edge_index] = Some(ResourceKind::Gold);
                    }
                }
            }
        }
    }
    gate_flags[index] = resolve_region_tile_subtype_code(tiles, gate_flags, index);
}

/// `TMapMgr::ResolveRegionTileSubtypeCodeForTileIndex` (0x00514210).
fn resolve_region_tile_subtype_code(tiles: &[TileState], gate_flags: &[i8], index: usize) -> i8 {
    resolve_region_tile_subtype_code_for_state(&tiles[index], gate_flags[index], index)
}

fn resolve_region_tile_subtype_code_for_state(tile: &TileState, gate_flag: i8, index: usize) -> i8 {
    let edge0 = tile.edge_resources[0];
    match tile.terrain {
        TerrainKind::Plains => match edge0 {
            Some(ResourceKind::Cotton) => 2,
            Some(ResourceKind::Horses) => 4,
            Some(ResourceKind::Livestock) => 3,
            _ if tile.flags.contains(TileFlags::RECRUITMENT_RESERVED) => 0xe,
            _ => 1,
        },
        TerrainKind::Forest => {
            if gate_flag == -1 {
                0xd
            } else {
                gate_flag
            }
        }
        TerrainKind::Hills => i8::from(edge0 != Some(ResourceKind::Wool)) + 7,
        TerrainKind::Mountain => 9,
        TerrainKind::Swamp => 0xa,
        TerrainKind::Desert => {
            if gate_flag != -1 {
                gate_flag
            } else {
                let row = index / usize::from(STRATEGIC_MAP_WIDTH);
                if !(0xf..=0x2d).contains(&row) {
                    0xc
                } else {
                    0xb
                }
            }
        }
        TerrainKind::Farmland => i8::from(edge0 != Some(ResourceKind::Grain)) + 5,
        TerrainKind::Water => 0,
    }
}

/// `TMapMgr::GuaranteeResources` (0x00511a70).
fn guarantee_resources(tiles: &mut [TileState], gate_flags: &mut [i8], map_lcg: &mut RetailLcg) {
    for nation in (0..MajorNationId::COUNT).map(MajorNationId::new) {
        let owner = TileOwnerTag::from_nation(nation.nation());
        let linked: Vec<usize> = tiles
            .iter()
            .enumerate()
            .filter_map(|(index, tile)| (tile.owner_nation == Some(owner)).then_some(index))
            .collect();
        if linked.is_empty() {
            continue;
        }

        let mut resource_tally: ResourceTable<i16> = ResourceTable::default();
        for &index in &linked {
            for edge in 0..2 {
                if let Some(resource) = tiles[index].edge_resources[edge] {
                    resource_tally[resource] += 1;
                }
            }
        }

        if resource_tally[ResourceKind::Coal] == 0 {
            place_guaranteed_resource(tiles, gate_flags, &linked, map_lcg, ResourceKind::Coal);
        }
        if resource_tally[ResourceKind::Iron] == 0 {
            let index = if let Some(index) = linked.iter().copied().find(|&index| {
                matches!(gate_flags[index], 8 | 9) && tiles[index].edge_resources[0].is_none()
            }) {
                tiles[index].edge_resources[0] = Some(ResourceKind::Iron);
                if gate_flags[index] == 9 {
                    tiles[index].edge_resources[1] = None;
                    gate_flags[index] = resolve_region_tile_subtype_code(tiles, gate_flags, index);
                    continue;
                }
                index
            } else {
                let mut picked;
                let mut gate_flag;
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
                tiles[index].edge_resources[0] = Some(ResourceKind::Iron);
                index
            };
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
    resource: ResourceKind,
) {
    let index = if let Some(index) = linked.iter().copied().find(|&index| {
        matches!(gate_flags[index], 8 | 9) && tiles[index].edge_resources[0].is_none()
    }) {
        tiles[index].edge_resources[0] = Some(resource);
        index
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
        index
    };
    tiles[index].edge_resources[1] = None;
    gate_flags[index] = resolve_region_tile_subtype_code(tiles, gate_flags, index);
}

/// Fresh-map `TMapMgr::AssignPictToTile` pass after `GuaranteeResources`.
///
/// Retail stores the mountain/coast/open-water variants and resolved river sprites in its
/// presentation-shaped terrain records. Those values are not authoritative game state, but the
/// pass consumes the shared map LCG. Keep the temporary presentation values just long enough to
/// preserve later tiles' branch decisions and retain canonical river connection codes on
/// [`TileState`].
fn consume_fresh_map_picture_assignment_rng(
    tiles: &[TileState],
    geometry: MapGeometry,
    map_lcg: &mut RetailLcg,
) {
    let mut sprite_variants = vec![0u8; tiles.len()];
    let mut river_sprite_codes: Vec<u8> = tiles
        .iter()
        .map(|tile| tile.river.map_or(0, RiverSegment::connection_code))
        .collect();

    for index in 0..tiles.len() {
        assign_picture_to_tile_for_rng(
            tiles,
            geometry,
            index,
            &mut sprite_variants,
            &mut river_sprite_codes,
            map_lcg,
        );
    }
}

fn assign_picture_to_tile_for_rng(
    tiles: &[TileState],
    geometry: MapGeometry,
    index: usize,
    sprite_variants: &mut [u8],
    river_sprite_codes: &mut [u8],
    map_lcg: &mut RetailLcg,
) {
    if tiles[index].terrain != TerrainKind::Water {
        if tiles[index].terrain == TerrainKind::Mountain && map_lcg.next_sample_15() & 1 != 0 {
            sprite_variants[index] = 1;
        }

        if river_sprite_codes[index] != 0 {
            river_sprite_codes[index] =
                resolve_picture_river_sprite(tiles, index, river_sprite_codes, map_lcg);
            if (0x1b..0x2b).contains(&river_sprite_codes[index]) {
                river_sprite_codes[index] -= 0x10;
            }
        }
        return;
    }

    let tile = TileId::new(index as u16);
    let neighbors = geometry.neighbors(tile);
    let mut has_land_neighbor = false;
    for (direction, neighbor) in HexDirection::ALL.into_iter().zip(neighbors) {
        if neighbor.is_some_and(|neighbor| {
            tiles[usize::from(neighbor.get())].terrain != TerrainKind::Water
        }) {
            has_land_neighbor = true;
            if map_lcg.next_sample_15() & 1 != 0 {
                sprite_variants[index] |= 1 << direction as u8;
            }
        }
    }

    if has_land_neighbor {
        if river_sprite_codes[index] != 0 {
            river_sprite_codes[index] =
                resolve_picture_river_sprite(tiles, index, river_sprite_codes, map_lcg);
        }
        return;
    }

    let west = neighbors[HexDirection::West as usize].map(|tile| usize::from(tile.get()));
    let Some(west) = west else {
        return;
    };
    if sprite_variants[west] != 0 {
        return;
    }

    let north_west =
        neighbors[HexDirection::NorthWest as usize].map(|tile| usize::from(tile.get()));
    let north_east =
        neighbors[HexDirection::NorthEast as usize].map(|tile| usize::from(tile.get()));
    let north_west_variant = north_west.map_or(0, |neighbor| sprite_variants[neighbor]);
    let north_east_variant = north_east.map_or(0, |neighbor| sprite_variants[neighbor]);

    if north_west_variant == 0 && north_east_variant == 0 {
        if map_lcg.next_sample_15() % 100 <= 3 {
            sprite_variants[index] = (map_lcg.next_sample_15() & 3) as u8 + 1;
        }
        return;
    }

    if map_lcg.next_sample_15() % 100 > 7 {
        return;
    }
    if north_west_variant != 0 {
        sprite_variants[index] = if north_west_variant < 4 {
            north_west_variant + 1
        } else {
            1
        };
    } else {
        sprite_variants[index] = if north_east_variant < 4 {
            north_east_variant + 1
        } else {
            1
        };
    }
}

fn resolve_picture_river_sprite(
    tiles: &[TileState],
    index: usize,
    river_sprite_codes: &[u8],
    map_lcg: &mut RetailLcg,
) -> u8 {
    let code = river_sprite_codes[index];
    let last_column =
        index % usize::from(STRATEGIC_MAP_WIDTH) == usize::from(STRATEGIC_MAP_WIDTH) - 1;
    let west_code = || {
        river_sprite_codes[index
            .checked_sub(1)
            .expect("fresh-map river does not cross the raw west boundary")]
    };
    let north_run_code = || {
        river_sprite_codes[index
            .checked_sub(usize::from(STRATEGIC_MAP_WIDTH) - 1)
            .expect("fresh-map river north-run lookup is in bounds")]
    };
    let random_bit = |rng: &mut RetailLcg| (rng.next_sample_15() & 1) as u8;

    if tiles[index].terrain == TerrainKind::Water {
        return match code {
            0x10 => 0x37,
            0x11 if variant_set_a(west_code()) => 0x38,
            0x11 if !variant_set_b(west_code()) => 0x38 + random_bit(map_lcg),
            0x11 => 0x39,
            0x12 => 0x3a,
            0x13 => 0x33,
            0x14 if !last_column => 0x35 - random_bit(map_lcg),
            0x14 if variant_set_c(north_run_code()) => 0x34,
            0x14 if variant_set_d(north_run_code()) => 0x35,
            0x14 => 0x34 + random_bit(map_lcg),
            0x15 => 0x36,
            _ => 0,
        };
    }

    match code {
        1 => 0x0b,
        2 => 0x0c,
        3 if variant_set_a(west_code()) => 0x0d,
        3 if !variant_set_b(west_code()) => 0x0d + random_bit(map_lcg),
        3 => 0x0e,
        4 if !last_column => 0x10 - random_bit(map_lcg),
        4 if variant_set_c(north_run_code()) => 0x0f,
        4 if variant_set_d(north_run_code()) => 0x10,
        4 => 0x0f + random_bit(map_lcg),
        5 if variant_set_a(west_code()) && !last_column => 0x12 - random_bit(map_lcg),
        5 if variant_set_a(west_code()) && variant_set_c(north_run_code()) => 0x11,
        5 if variant_set_a(west_code()) => 0x12,
        5 if !last_column => 0x14 - random_bit(map_lcg),
        5 if variant_set_c(north_run_code()) => 0x13,
        5 => 0x14,
        6 if !last_column => 0x16 - random_bit(map_lcg),
        6 if variant_set_c(north_run_code()) => 0x15,
        6 if variant_set_d(north_run_code()) => 0x16,
        6 => 0x15 + random_bit(map_lcg),
        7 if variant_set_a(west_code()) => 0x17,
        7 if !variant_set_b(west_code()) => 0x17 + random_bit(map_lcg),
        7 => 0x18,
        8 => 0x19,
        9 => 0x1a,
        0x0a => 0x2b,
        0x0b if !last_column => 0x2d - random_bit(map_lcg),
        0x0b if variant_set_c(north_run_code()) => 0x2c,
        0x0b if variant_set_d(north_run_code()) => 0x2d,
        0x0b => 0x2c + random_bit(map_lcg),
        0x0c => 0x2e,
        0x0d => 0x2f,
        0x0e if variant_set_a(west_code()) => 0x30,
        0x0e if !variant_set_b(west_code()) => 0x30 + random_bit(map_lcg),
        0x0e => 0x31,
        0x0f => 0x32,
        _ => 0,
    }
}

const fn variant_set_a(code: u8) -> bool {
    matches!(
        code,
        0x0f | 0x1f | 0x11 | 0x21 | 0x13 | 0x23 | 0x15 | 0x25 | 0x2c | 0x34
    )
}

const fn variant_set_b(code: u8) -> bool {
    matches!(
        code,
        0x10 | 0x20 | 0x12 | 0x22 | 0x14 | 0x24 | 0x16 | 0x26 | 0x2d | 0x35
    )
}

const fn variant_set_c(code: u8) -> bool {
    matches!(
        code,
        0x0d | 0x1d | 0x11 | 0x21 | 0x12 | 0x22 | 0x17 | 0x27 | 0x30 | 0x38
    )
}

const fn variant_set_d(code: u8) -> bool {
    matches!(
        code,
        0x0e | 0x1e | 0x13 | 0x23 | 0x14 | 0x24 | 0x18 | 0x28 | 0x31 | 0x39
    )
}

fn bootstrap_nations(
    human_nation: MajorNationId,
    difficulty: Difficulty,
    foreign_ministers: MajorNationTable<ForeignMinisterPersonality>,
) -> Nations {
    Nations::new(
        MajorNationTable::from_fn(|nation| {
            major_nation(
                difficulty,
                nation == human_nation,
                foreign_ministers[nation],
            )
        }),
        MinorNationTable::from_fn(|nation| Some(minor_nation(nation))),
    )
}

fn major_nation(
    difficulty: Difficulty,
    human: bool,
    foreign_minister: ForeignMinisterPersonality,
) -> MajorNation {
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
    MajorNation::for_random_start(
        treasury,
        human,
        foreign_minister,
        scenario_city(preset_difficulty, human),
    )
}

/// `TMapMgr::ChooseNationSetupProfilesForOpenSlots` followed by the foreign-minister
/// column of `g_aDefaultNationSetupPolicyProfiles`.
fn choose_foreign_ministers(
    map: &GeneratedMap,
    human_nation: MajorNationId,
) -> MajorNationTable<ForeignMinisterPersonality> {
    const PROFILE_ORDER: [usize; 7] = [1, 5, 4, 6, 2, 3, 3];
    const PREFERRED_ISOLATION_BY_PROFILE: [[u8; 3]; 7] = [
        [0, 1, 2],
        [2, 1, 0],
        [0, 1, 2],
        [0, 1, 2],
        [1, 2, 0],
        [1, 2, 0],
        [0, 1, 2],
    ];
    const FOREIGN_MINISTER_BY_PROFILE: [ForeignMinisterPersonality; 7] = [
        ForeignMinisterPersonality::Diplomat,
        ForeignMinisterPersonality::Ted,
        ForeignMinisterPersonality::Bill,
        ForeignMinisterPersonality::Diplomat,
        ForeignMinisterPersonality::Textile,
        ForeignMinisterPersonality::Trader,
        ForeignMinisterPersonality::Bill,
    ];

    let mut region_class_by_nation = [None; NATION_COUNT];
    for province in map.provinces() {
        region_class_by_nation[usize::from(province.owner.get())] = Some(province.terrain);
    }

    let major_count = usize::from(MajorNationId::COUNT);
    let isolation_by_major = MajorNationTable::from_fn(|nation| {
        let class = region_class_by_nation[usize::from(nation.get())]
            .expect("accepted random maps assign a region class to every major nation");
        if (0..major_count).any(|other| {
            other != usize::from(nation.get()) && region_class_by_nation[other] == Some(class)
        }) {
            0
        } else if (major_count..NATION_COUNT)
            .any(|other| region_class_by_nation[other] == Some(class))
        {
            1
        } else {
            2
        }
    });

    let mut profile_by_major = MajorNationTable::from_fn(|_| None);
    for &profile in PROFILE_ORDER.iter().take(major_count - 1) {
        let nation = PREFERRED_ISOLATION_BY_PROFILE[profile]
            .iter()
            .find_map(|&isolation| {
                (0..major_count).find_map(|slot| {
                    let nation = MajorNationId::new(slot as u8);
                    (nation != human_nation
                        && profile_by_major[nation].is_none()
                        && isolation_by_major[nation] == isolation)
                        .then_some(nation)
                })
            })
            .expect("each generated-map AI profile has an eligible open nation slot");
        profile_by_major[nation] = Some(profile);
    }

    MajorNationTable::from_fn(|nation| {
        if nation == human_nation {
            ForeignMinisterPersonality::Base
        } else {
            let profile =
                profile_by_major[nation].expect("every AI nation receives a setup profile");
            FOREIGN_MINISTER_BY_PROFILE[profile]
        }
    })
}

fn minor_nation(nation: MinorNationId) -> MinorNation {
    let first_member = MinorNationId::FIRST + (nation.get() - MinorNationId::FIRST) / 4 * 4;
    MinorNation {
        common: NationCommonState {
            status: CountryStatus::Independent,
            owned_regions: Vec::new(),
            treasury: 5_000,
            home_tile: None,
            trade_policy_by_nation: NationTable::default(),
        },
        consortium_members: std::array::from_fn(|offset| {
            MinorNationId::new(first_member + offset as u8)
        }),
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

    #[test]
    fn picture_assignment_consumes_ordered_mountain_and_river_draws_without_rewriting_rivers() {
        let geometry = MapGeometry::new(MapTopology::Bounded);
        let mut tiles = vec![TileState::default(); STRATEGIC_TILE_COUNT];
        tiles[0].terrain = TerrainKind::Mountain;
        let first_river = geometry.tile(10, 10).unwrap();
        let second_river = geometry.neighbor(first_river, HexDirection::East).unwrap();
        tiles[usize::from(first_river.get())].river = RiverSegment::from_connection_code(4);
        tiles[usize::from(second_river.get())].river = RiverSegment::from_connection_code(3);
        let original_rivers: Vec<_> = tiles.iter().map(|tile| tile.river).collect();

        let mut rng = RetailLcg::from_state(1);
        consume_fresh_map_picture_assignment_rng(&tiles, geometry, &mut rng);

        let mut expected_rng = RetailLcg::from_state(1);
        expected_rng.advance(); // mountain variant
        expected_rng.advance(); // first river resolves to a set-A or set-B west continuation
        assert_eq!(rng, expected_rng);
        assert_eq!(
            tiles.iter().map(|tile| tile.river).collect::<Vec<_>>(),
            original_rivers
        );
    }

    #[test]
    fn picture_assignment_draws_in_direction_order_for_each_land_edge_on_water() {
        let geometry = MapGeometry::new(MapTopology::Bounded);
        let target = geometry.tile(10, 10).unwrap();
        let mut tiles = vec![TileState::default(); STRATEGIC_TILE_COUNT];
        for tile in &mut tiles {
            tile.terrain = TerrainKind::Water;
        }
        for direction in [HexDirection::NorthEast, HexDirection::SouthWest] {
            let neighbor = geometry.neighbor(target, direction).unwrap();
            tiles[usize::from(neighbor.get())].terrain = TerrainKind::Plains;
        }
        let mut sprite_variants = vec![0; STRATEGIC_TILE_COUNT];
        let mut river_sprite_codes = vec![0; STRATEGIC_TILE_COUNT];
        let mut rng = RetailLcg::from_state(3);

        assign_picture_to_tile_for_rng(
            &tiles,
            geometry,
            usize::from(target.get()),
            &mut sprite_variants,
            &mut river_sprite_codes,
            &mut rng,
        );

        assert_eq!(rng.state(), 0x7ed3_5321);
        assert_eq!(
            sprite_variants[usize::from(target.get())],
            1 << HexDirection::SouthWest as u8
        );
    }

    #[test]
    fn open_water_variant_draws_depend_on_already_processed_northern_tiles() {
        let geometry = MapGeometry::new(MapTopology::Bounded);
        let target = geometry.tile(10, 10).unwrap();
        let north_west = geometry.neighbor(target, HexDirection::NorthWest).unwrap();
        let tiles = vec![
            TileState {
                terrain: TerrainKind::Water,
                ..TileState::default()
            };
            STRATEGIC_TILE_COUNT
        ];
        let mut river_sprite_codes = vec![0; STRATEGIC_TILE_COUNT];

        let mut propagated_variants = vec![0; STRATEGIC_TILE_COUNT];
        propagated_variants[usize::from(north_west.get())] = 4;
        let mut propagation_rng = RetailLcg::from_state(5);
        assign_picture_to_tile_for_rng(
            &tiles,
            geometry,
            usize::from(target.get()),
            &mut propagated_variants,
            &mut river_sprite_codes,
            &mut propagation_rng,
        );
        assert_eq!(propagation_rng.state(), 0x06c3_870a);
        assert_eq!(propagated_variants[usize::from(target.get())], 1);

        let mut isolated_variants = vec![0; STRATEGIC_TILE_COUNT];
        let mut isolated_rng = RetailLcg::from_state(50);
        assign_picture_to_tile_for_rng(
            &tiles,
            geometry,
            usize::from(target.get()),
            &mut isolated_variants,
            &mut river_sprite_codes,
            &mut isolated_rng,
        );
        assert_eq!(isolated_rng.state(), 0xd73b_4ad8);
        assert_eq!(isolated_variants[usize::from(target.get())], 1);
    }

    #[test]
    fn fallback_capital_stamps_the_province_anchor_state() {
        let tile = TileId::new(0);
        let mut tiles = vec![TileState::default(); STRATEGIC_TILE_COUNT];
        tiles[usize::from(tile.get())].province = Some(ProvinceId::new(0));
        let mut gate_flags = vec![1; STRATEGIC_TILE_COUNT];
        let capitals = assign_province_fallback_capitals(
            &mut tiles,
            &mut gate_flags,
            MapGeometry::new(MapTopology::Bounded),
            &mut RetailLcg::from_state(1),
        );

        assert_eq!(capitals, vec![Some(tile)]);
        assert_eq!(
            tiles[usize::from(tile.get())].flags,
            TileFlags::PROVINCE_ANCHOR_STATE
        );
    }

    #[test]
    fn reanchoring_resets_the_old_tile_and_only_clears_sibling_city_markers() {
        let province = ProvinceId::new(0);
        let old_tile = TileId::new(0);
        let new_tile = TileId::new(1);
        let sibling = TileId::new(2);
        let mut world = StrategicMap::new(
            MapTopology::Bounded,
            vec![TileState::default(); STRATEGIC_TILE_COUNT],
        )
        .unwrap();
        for tile in [old_tile, new_tile, sibling] {
            world[tile].province = Some(province);
        }
        world[old_tile].flags = TileFlags::PLACED_CITY_STATE;
        let sibling_flags =
            TileFlags::PLACED_CITY_STATE | TileFlags::PROVINCE_CAPITAL_FORTIFICATION;
        world[sibling].flags = sibling_flags;
        let mut gate_flags = vec![1; STRATEGIC_TILE_COUNT];
        let mut capitals = vec![Some(old_tile)];

        set_region_tile_subtype_and_refresh_neighbor_flags(
            &mut world,
            &mut gate_flags,
            &mut capitals,
            new_tile,
        );

        assert_eq!(world[old_tile].flags, TileFlags::empty());
        assert_eq!(world[new_tile].flags, TileFlags::PROVINCE_ANCHOR_STATE);
        assert_eq!(capitals, vec![Some(new_tile)]);
        let mut expected_sibling_flags = sibling_flags;
        expected_sibling_flags.clear_city_marker();
        assert_eq!(world[sibling].flags, expected_sibling_flags);
    }

    #[test]
    fn minor_home_garrison_preserves_the_base_state_and_marks_the_capital() {
        let province = ProvinceId::new(0);
        let tile = TileId::new(0);
        let mut world = StrategicMap::new(
            MapTopology::Bounded,
            vec![TileState::default(); STRATEGIC_TILE_COUNT],
        )
        .unwrap();
        world[tile].province = Some(province);
        let mut gate_flags = vec![1; STRATEGIC_TILE_COUNT];
        let mut capitals = vec![None];

        reset_tile_to_base_transport_flag(&mut world, &mut gate_flags, &mut capitals, tile);
        assert_eq!(world[tile].flags, TileFlags::MINOR_HOME_STATE);

        let mut units = Vec::new();
        let mut unit_ids = UnitIdAllocator::default();
        let mut name_ordinals = [1; MilitaryUnitKind::LENGTH];
        let mut next_roster_id = 1;
        spawn_initial_militia_for_minor(
            &mut world,
            &capitals,
            MinorNationId::new(MinorNationId::FIRST),
            &[province],
            Difficulty::Normal,
            &mut units,
            &mut unit_ids,
            &mut name_ordinals,
            &mut next_roster_id,
        );

        assert_eq!(
            units.len(),
            6,
            "three garrison units and three militia units"
        );
        assert_eq!(
            world[tile].flags,
            TileFlags::MINOR_HOME_STATE | TileFlags::PROVINCE_CAPITAL_FORTIFICATION
        );
    }

    #[test]
    fn normal_random_start_marks_only_queued_ai_navy_zone_targets() {
        let human_nation = MajorNationId::new(6);
        let preview =
            generate_random_setup_preview_with_clock_seed(b"Woopnist", MapTopology::Wrapping, 1);
        let state = create_random_game(&preview, human_nation, Difficulty::Normal, 1);
        let live_zone_count =
            usize::from(sea_zone_count(&state.world)) + state.port_zone_owners.len();

        assert!(
            state
                .port_zone_owners
                .windows(2)
                .all(|pair| pair[0].zone.get() > pair[1].zone.get()),
            "port owners preserve the newest-to-oldest port chain"
        );

        for nation in (0..MajorNationId::COUNT).map(MajorNationId::new) {
            let economy = &state.nations.majors[nation].economy;
            if nation == human_nation {
                assert_eq!(economy.ai_zone_targets, None);
                continue;
            }

            let mut expected = vec![AiZoneTargetState::Unmarked; live_zone_count];
            let mut queued_navy_target_count = 0;
            for mission in state
                .missions
                .iter()
                .filter(|mission| mission.nation == nation.nation())
            {
                let target = match &mission.data {
                    MissionData::ControlSeaZone(navy) => navy.target_zone,
                    MissionData::Escort(navy) => {
                        let port = state
                            .port_zone_owners
                            .iter()
                            .find(|port| port.former_owner == nation.nation())
                            .expect("an Escort mission resolves the nation's first port");
                        assert_eq!(navy.target_zone, Some(port.zone));
                        assert_eq!(navy.resolved_port_zone, Some(port.zone));
                        navy.target_zone
                    }
                    _ => None,
                };
                if let Some(target) = target {
                    expected[usize::from(target.get())] = AiZoneTargetState::MissionQueued;
                    queued_navy_target_count += 1;
                }
            }

            let actual = economy
                .ai_zone_targets
                .as_ref()
                .expect("computer majors own AI zone-target state");
            assert_eq!(actual, &expected);
            assert_eq!(
                actual
                    .iter()
                    .filter(|&&target| target == AiZoneTargetState::MissionQueued)
                    .count(),
                queued_navy_target_count
            );
            assert!(!actual.contains(&AiZoneTargetState::Candidate));
        }
    }

    #[test]
    fn creates_a_normal_start_boundary_from_the_retained_preview() {
        let preview =
            generate_random_setup_preview_with_clock_seed(b"Woopnist", MapTopology::Wrapping, 1);
        let state = create_random_game(&preview, MajorNationId::new(6), Difficulty::Normal, 1);

        assert_eq!(
            state
                .nations
                .majors
                .iter()
                .map(|nation| nation.economy.foreign_minister_personality)
                .collect::<Vec<_>>(),
            [
                ForeignMinisterPersonality::Trader,
                ForeignMinisterPersonality::Bill,
                ForeignMinisterPersonality::Bill,
                ForeignMinisterPersonality::Diplomat,
                ForeignMinisterPersonality::Textile,
                ForeignMinisterPersonality::Ted,
                ForeignMinisterPersonality::Base,
            ]
        );
        assert_eq!(
            state
                .nations
                .majors
                .iter()
                .map(|nation| nation.economy.foreign_minister_skill_index)
                .collect::<Vec<_>>(),
            [1, 4, 4, 3, 2, 5, 0]
        );
        assert!(state.nations.majors.iter().all(|nation| {
            nation.economy.development_grant_by_nation == NationTable::default()
                && nation.economy.defense_minister_skill_index == 0
        }));

        let expected_adjacency = build_province_adjacency(&state.world);
        for (index, generated) in preview.map.provinces().iter().enumerate() {
            let province = ProvinceId::new(index as u16);
            let owner = generated.owner.nation().unwrap();
            assert_eq!(state.provinces[province].owner(), Some(owner));
            assert_eq!(state.provinces[province].former_owner(), Some(owner));
            assert_eq!(
                state.provinces[province].adjacency(),
                expected_adjacency[index]
            );
            assert_eq!(
                state.provinces[province].region_class(),
                Some(generated.terrain.retail() as u8)
            );
        }
        for index in preview.map.provinces().len()..crate::PROVINCE_COUNT {
            assert_eq!(
                state.provinces[ProvinceId::new(index as u16)],
                ProvinceState::default()
            );
        }
        for nation in NationId::all() {
            let expected = preview
                .map
                .provinces()
                .iter()
                .enumerate()
                .filter_map(|(index, province)| {
                    (province.owner.nation() == Some(nation))
                        .then_some(ProvinceId::new(index as u16))
                })
                .collect::<Vec<_>>();
            let common = state.nations.common(nation).unwrap();
            assert_eq!(common.status, CountryStatus::Independent);
            assert_eq!(common.owned_regions, expected);
        }

        assert_eq!(state.turn.phase, crate::PhaseCode::CAPITAL_SELECTION);
        assert_eq!(state.turn.difficulty, Difficulty::Normal);
        assert_eq!(state.turn.selected_nation, NationId::new(6));
        assert_ne!(
            state.rng.map_generation,
            RetailLcg::from_state(preview.final_map_lcg)
        );
        assert_eq!(
            state.world[TileId::new(0)].terrain,
            preview.map.tile(TileId::new(0)).terrain
        );
        assert_eq!(
            state.world[TileId::new(0)].former_owner_nation,
            state.world[TileId::new(0)].owner_nation
        );
        assert!(
            state
                .world
                .iter()
                .any(|tile| tile.edge_resources[0].is_some()),
            "post-passes must stamp some edge resources"
        );
        assert!(
            state.world.iter().any(|tile| tile.flags.is_city()),
            "AI PlaceCity must mark a city tile"
        );

        let human = &state.nations.majors[MajorNationId::new(6)];
        assert_eq!(human.common.treasury, 10_000);
        assert_eq!(human.common.home_tile, None);
        assert!(human.economy.controller.is_human());

        let ai = &state.nations.majors[MajorNationId::new(0)];
        assert_eq!(ai.common.treasury, 10_000);
        assert!(!ai.economy.controller.is_human());
        assert!(ai.common.home_tile.is_some(), "AI majors place a capital");
        assert_eq!(
            state.nations.majors[MajorNationId::new(0)]
                .city
                .home_town_tile,
            ai.common.home_tile
        );
        let ai_home = ai.common.home_tile.unwrap();
        assert!(
            state.world[ai_home].flags.is_city(),
            "AI PlaceCity marks the selected capital as a city"
        );
        assert!(
            state.world[ai_home].region.is_some(),
            "retail region markers start at 1"
        );
        assert_eq!(state.rng.zone_status, RetailLcg::from_state(1));

        assert_eq!(state.nations.minor_count(), crate::MINOR_NATION_COUNT);
        let human_city = &state.nations.majors[MajorNationId::new(6)].city;
        assert_eq!(human_city.home_town_tile, Some(TileId::new(0)));
        assert_eq!(human_city.stockpile[ResourceKind::Food], 20);

        let placed_minors = state
            .nations
            .minors
            .iter()
            .flatten()
            .filter(|minor| minor.common.home_tile.is_some())
            .count();
        assert!(placed_minors > 0, "minors receive home tiles");
        assert!(state.nations.minors.iter().flatten().all(|minor| {
            minor.common.home_tile.is_none_or(|home| {
                let flags = state.world[home].flags;
                flags.is_city()
                    && flags.has_base_transport()
                    && flags.contains(TileFlags::PROVINCE_CAPITAL_FORTIFICATION)
            })
        }));
        assert!(
            !state.military_units.is_empty(),
            "minor InitialMilitia produces military units"
        );
        assert!(
            state
                .military_units
                .iter()
                .all(|unit| unit.nation().get() >= MinorNationId::FIRST),
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
            state
                .missions
                .iter()
                .any(|mission| matches!(mission.data, MissionData::DefendProvince { .. })),
            "AI queues include DefendProvince for owned regions"
        );
        assert!(
            state.world.iter().any(|tile| {
                tile.action
                    .is_some_and(|action| action.retail() == ACTION_STATE_ANCHOR)
            }),
            "EnsurePortZone stamps Anchor on linked sea tiles"
        );
        assert!(
            state
                .missions
                .iter()
                .all(|mission| mission.nation.get() != 6),
            "human Normal+ majors do not receive Accept mission queues"
        );
        assert_eq!(
            state.unit_ids.current(),
            state.military_units.len() as i32,
            "field_64 tracks each spawned TUnit"
        );
        assert_eq!(state.market, TradeMarketState::default());
        assert!(state.civilian_units.is_empty());
        assert!(
            state
                .pending
                .nations
                .iter()
                .all(|work| work.turn_summary.is_empty())
        );
        assert_eq!(
            state.pending.newspaper_events,
            [
                PendingNewspaperEvent::Miscellaneous {
                    audience: None,
                    story_code: 2,
                },
                PendingNewspaperEvent::Miscellaneous {
                    audience: None,
                    story_code: 1,
                },
            ]
        );
    }
}
