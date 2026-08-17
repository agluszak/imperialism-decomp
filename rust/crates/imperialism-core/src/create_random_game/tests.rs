use super::*;

fn initial_seed_one_preview() -> RandomSetupPreview {
    let mut sea_zone_marker_crt = RetailCrtRng::from_state(1);
    let _ = sea_zone_marker_crt.next_rand();
    generate_random_setup_preview_with_clock_seed(
        b"Woopnist",
        MapTopology::Wrapping,
        1,
        sea_zone_marker_crt,
    )
}

#[test]
fn picture_assignment_consumes_ordered_mountain_and_river_draws_without_rewriting_rivers() {
    let geometry = MapGeometry::new(MapTopology::Bounded);
    let mut tiles = vec![TileState::default(); STRATEGIC_TILE_COUNT];
    tiles[0].terrain = TerrainKind::Mountain;
    let first_river = geometry.tile(10, 10).unwrap();
    let second_river = geometry.neighbor(first_river, HexDirection::East).unwrap();
    let mut river_connections = vec![0u8; STRATEGIC_TILE_COUNT];
    river_connections[usize::from(first_river.get())] = 4;
    river_connections[usize::from(second_river.get())] = 3;
    let original_connections = river_connections.clone();
    let mut rng = RetailLcg::from_state(1);
    assign_fresh_map_pictures(&mut tiles, &mut river_connections, geometry, &mut rng);

    let mut expected_rng = RetailLcg::from_state(1);
    expected_rng.advance(); // mountain variant
    expected_rng.advance(); // first river resolves to a set-A or set-B west continuation
    assert_eq!(rng, expected_rng);
    assert_eq!(
        tiles
            .iter()
            .map(|tile| tile.river().map(RiverSegment::connection_code).unwrap_or(0))
            .collect::<Vec<_>>(),
        original_connections
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
    let mut tiles = vec![
        TileState {
            gate: 1,
            ..TileState::default()
        };
        STRATEGIC_TILE_COUNT
    ];
    tiles[usize::from(tile.get())].province = Some(ProvinceId::new(0));
    let capitals = assign_province_fallback_capitals(
        &mut tiles,
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
    let mut world = MapMgr::new(
        MapTopology::Bounded,
        vec![
            TileState {
                gate: 1,
                ..TileState::default()
            };
            STRATEGIC_TILE_COUNT
        ],
    );
    for tile in [old_tile, new_tile, sibling] {
        world[tile].province = Some(province);
    }
    world[old_tile].flags = TileFlags::PLACED_CITY_STATE;
    let sibling_flags = TileFlags::PLACED_CITY_STATE | TileFlags::PROVINCE_CAPITAL_FORTIFICATION;
    world[sibling].flags = sibling_flags;
    let mut capitals = vec![Some(old_tile)];

    set_region_tile_subtype_and_refresh_neighbor_flags(&mut world, &mut capitals, new_tile);

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
    let mut world = MapMgr::new(
        MapTopology::Bounded,
        vec![
            TileState {
                gate: 1,
                ..TileState::default()
            };
            STRATEGIC_TILE_COUNT
        ],
    );
    world[tile].province = Some(province);
    let mut capitals = vec![None];

    reset_tile_to_base_transport_flag(&mut world, &mut capitals, tile);
    assert_eq!(world[tile].flags, TileFlags::MINOR_HOME_STATE);

    let mut units = indexmap::IndexMap::new();
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

fn normal_start() -> GameState {
    create_random_game(
        &initial_seed_one_preview(),
        MajorNationId::new(6),
        Difficulty::Normal,
        "Testland",
        true,
        1,
        &crate::test_support::random_game_names(),
    )
}

#[test]
fn normal_random_start_reaches_capital_selection() {
    let human = MajorNationId::new(6);
    let state = normal_start();

    assert_eq!(state.turn.selected_nation, human.nation());
    assert_eq!(state.turn.phase, crate::PhaseCode::CAPITAL_SELECTION);
    assert_eq!(state.turn.difficulty, Difficulty::Normal);
    assert!(state.map.map_data_ready);
    assert!(state.nations.majors[human].auto.is_none());
    assert!(
        state.nations.majors[human].common.home_tile.is_none(),
        "human capital awaits selection"
    );

    for nation in MajorNationId::all().filter(|&nation| nation != human) {
        assert!(
            state.nations.majors[nation].common.home_tile.is_some(),
            "AI majors place a capital before capital selection"
        );
        assert!(state.nations.majors[nation].is_auto());
    }

    assert!(state.nations.minor_count() > 0);
    assert!(
        !state.military_units.is_empty(),
        "minor InitialMilitia produces military units"
    );
    assert!(
        state
            .military_units
            .values()
            .all(|unit| unit.nation().get() >= MinorNationId::FIRST),
        "pre-capital military units are minor-owned only"
    );
    assert!(
        !state.missions.is_empty(),
        "AI QueueMapActionMissions fills the Accept mission queues"
    );
    assert!(
        state
            .missions
            .values()
            .all(|mission| mission.nation != human.nation()),
        "human Normal+ majors do not receive Accept mission queues"
    );
}

#[test]
fn normal_random_start_marks_only_queued_ai_map_targets() {
    let human = MajorNationId::new(6);
    let state = normal_start();
    let live_zone_count = state.ocean.zones.len();

    for nation in MajorNationId::all() {
        let major = &state.nations.majors[nation];
        if nation == human {
            assert!(major.auto.is_none());
            continue;
        }

        let mut expected = vec![AiTargetState::Unmarked; live_zone_count];
        let mut expected_provinces = ProvinceTable::default();
        for mission in state
            .missions
            .values()
            .filter(|mission| mission.nation == nation.nation())
        {
            match &mission.data {
                MissionData::DefendProvince { province, .. } => {
                    expected_provinces[province] = AiTargetState::MissionQueued;
                }
                MissionData::ControlSeaZone(navy) | MissionData::Escort(navy) => {
                    if let Some(target) = navy.target_zone {
                        expected[usize::from(target.get())] = AiTargetState::MissionQueued;
                    }
                }
                _ => {}
            }
        }

        let auto = major
            .auto
            .as_ref()
            .expect("computer majors own AutoGreatPower state");
        assert_eq!(&auto.zone_targets, &expected);
        assert_eq!(auto.province_targets, expected_provinces);
        assert!(
            !auto.zone_targets.contains(&AiTargetState::Candidate),
            "start-of-game AI targets are queued missions, never candidates"
        );
    }
}
