use crate::{
    CityState, Difficulty, GameState, GeneratedMap, GeneratedTerrainTile, LaborPool, MajorNation,
    MajorNationId, MajorNationTable, MapGeometry, MinorNation, MinorNationTable, NationCommonState,
    NationPendingWork, NationTable, Nations, PendingWorkState, ProductionTable, ProvinceId,
    RandomSetupPreview, ResourceTable, RetailCrtRng, RetailLcg, RngState, STRATEGIC_MAP_WIDTH,
    TileId, TileOwnerTag, TileState, TradeMarketState, TurnState, WorldState,
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
) -> GameState {
    let mut map_lcg = RetailLcg::from_state(preview.final_map_lcg);
    let tiles = apply_tile_post_passes(
        &preview.map,
        preview.topology.wraps_horizontally(),
        &mut map_lcg,
    );
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
            tiles,
        },
        rng: RngState {
            // CRT/zone advance during later Accept bootstrap; map_generation continues
            // through the preview post-passes that stamp edge resources.
            crt_rand: RetailCrtRng::from_state(0),
            map_generation: RetailLcg::from_state(map_lcg.state()),
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

/// Province-capital marker written by `RebuildTileOwnerNeighborCachesAndFallbackAssignments`.
const PROVINCE_CAPITAL_ACTIVE_FLAGS: u16 = 0x22;

/// Preview-time tile post-passes from `TMapMgr::BuildOrLoadGlobalMapStateForSession`:
/// icon-variant/edge-resource stamping, former-owner snapshot, province fallback capitals,
/// and `GuaranteeResources`.
fn apply_tile_post_passes(
    map: &GeneratedMap,
    wraps_horizontally: bool,
    map_lcg: &mut RetailLcg,
) -> Vec<TileState> {
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
    assign_province_fallback_capitals(&mut tiles, &mut gate_flags, geometry, map_lcg);

    guarantee_resources(&mut tiles, &mut gate_flags, map_lcg);
    tiles
}

/// Capital-tile pick + stamp from `TMapMgr::RebuildTileOwnerNeighborCachesAndFallbackAssignments`
/// (0x0050f860). Adjacent-province bookkeeping and transport-mask side effects that are not
/// represented on [`TileState`] are omitted.
fn assign_province_fallback_capitals(
    tiles: &mut [TileState],
    gate_flags: &mut [i8],
    geometry: MapGeometry,
    map_lcg: &mut RetailLcg,
) {
    let province_count = tiles
        .iter()
        .filter_map(|tile| {
            tile.province
                .map(|province| usize::from(province.get()) + 1)
        })
        .max()
        .unwrap_or(0);
    let mut linked_by_province: Vec<Vec<usize>> = vec![Vec::new(); province_count];
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
    }
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
        let state = create_random_game(&preview, MajorNationId::new(6), Difficulty::Normal);

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
        let province_capitals = state
            .world
            .tiles
            .iter()
            .filter(|tile| tile.active_flags == PROVINCE_CAPITAL_ACTIVE_FLAGS)
            .count();
        assert!(
            province_capitals > 0,
            "province fallback capitals must stamp active_flags=0x22"
        );
        assert_eq!(
            province_capitals,
            state
                .world
                .tiles
                .iter()
                .filter_map(|tile| tile.province)
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            "one fallback capital per occupied province"
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
