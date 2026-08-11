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
fn normal_random_start_marks_only_queued_ai_map_targets() {
    let human_nation = MajorNationId::new(6);
    let preview = initial_seed_one_preview();
    let state = create_random_game(
        &preview,
        human_nation,
        Difficulty::Normal,
        "Testland",
        true,
        1,
        &crate::test_support::random_game_names(),
    );
    assert_eq!(state.map.provinces[ProvinceId::new(0)].name, "N9P1");
    assert_eq!(state.map.provinces[ProvinceId::new(1)].name, "N9P2");
    assert_eq!(state.map.provinces[ProvinceId::new(2)].name, "N12P1");
    assert!(state.ocean.zones.iter().all(|zone| match zone {
        ZoneKind::Zone(zone) => !zone.display_name.is_empty(),
        ZoneKind::PortZone(port) => !port.zone.display_name.is_empty(),
    }));
    assert_eq!(
        state.nations.majors[human_nation].towns[0].name,
        "Frog City"
    );
    for nation in (0..MajorNationId::COUNT - 1).map(MajorNationId::new) {
        assert_eq!(state.nations.majors[nation].towns[0].name, "FrogCity");
    }
    let live_zone_count = state.ocean.zones.len();
    assert_eq!(state.ocean.routes, preview.map.ocean_routes);
    assert_eq!(state.map.scenario_tag, "Woopnist");
    assert_eq!(
        state
            .ocean
            .zones
            .iter()
            .filter(|zone| matches!(zone, ZoneKind::Zone(_)))
            .count(),
        usize::from(sea_zone_count(&state.map))
    );
    assert_eq!(
        state
            .ocean
            .zones
            .iter()
            .filter_map(|zone| match zone {
                ZoneKind::Zone(zone) => zone.status_code,
                ZoneKind::PortZone(_) => None,
            })
            .collect::<Vec<_>>(),
        [
            16, 12, 12, 12, 17, 16, 5, 15, 14, 13, 14, 11, 17, 15, 13, 14, 19, 13, 8, 12, 17, 17,
            14, 10, 18, 12, 15, 14, 9, 18, 13, 12, 14, 14, 12, 12, 12, 12, 8, 14, 12, 13, 15, 12,
            9, 14, 12, 16, 14, 15, 10, 14, 16, 13, 13, 15, 16,
        ]
    );
    assert_eq!(
        state
            .ocean
            .zones
            .iter()
            .filter_map(|zone| match zone {
                ZoneKind::Zone(_) => None,
                ZoneKind::PortZone(port) => port.zone.status_code,
            })
            .collect::<Vec<_>>(),
        [
            20, 22, 20, 20, 21, 20, 23, 23, 22, 23, 22, 23, 20, 22, 20, 23, 23, 20, 22, 21, 22, 23,
        ]
    );

    assert!(
        state
            .ocean
            .zones
            .iter()
            .enumerate()
            .filter_map(|(ordinal, zone)| {
                matches!(zone, ZoneKind::PortZone(_)).then_some(ordinal)
            })
            .collect::<Vec<_>>()
            .windows(2)
            .all(|pair| pair[0] < pair[1]),
        "port zones preserve their ordinal positions"
    );

    for nation in (0..MajorNationId::COUNT).map(MajorNationId::new) {
        let economy = &state.nations.majors[nation].economy;
        assert_eq!(economy.army_movement_budget, 15);
        if nation == human_nation {
            assert_eq!(economy.ai_zone_targets, None);
            assert_eq!(economy.ai_province_targets, None);
            continue;
        }

        let mut expected = vec![AiTargetState::Unmarked; live_zone_count];
        let mut expected_provinces = ProvinceTable::default();
        let mut queued_navy_target_count = 0;
        for mission in state
            .missions
            .iter()
            .filter(|mission| mission.nation == nation.nation())
        {
            let target = match &mission.data {
                MissionData::DefendProvince { province, .. } => {
                    expected_provinces[*province] = AiTargetState::MissionQueued;
                    None
                }
                MissionData::ControlSeaZone(navy) => navy.target_zone,
                MissionData::Escort(navy) => {
                    let (ordinal, _) = state
                        .ocean
                        .zones
                        .iter()
                        .enumerate()
                        .find_map(|(ordinal, zone)| match zone {
                            ZoneKind::PortZone(port)
                                if state.map[port.port_tile]
                                    .former_owner_nation
                                    .and_then(TileOwnerTag::nation)
                                    == Some(nation.nation()) =>
                            {
                                Some((ordinal, port))
                            }
                            _ => None,
                        })
                        .expect("an Escort mission resolves the nation's first port");
                    let port_zone = OceanZoneId::new(ordinal as u16);
                    assert_eq!(navy.target_zone, Some(port_zone));
                    assert_eq!(navy.resolved_port_zone, Some(port_zone));
                    navy.target_zone
                }
                _ => None,
            };
            if let Some(target) = target {
                expected[usize::from(target.get())] = AiTargetState::MissionQueued;
                queued_navy_target_count += 1;
            }
        }

        let actual = economy
            .ai_zone_targets
            .as_ref()
            .expect("computer majors own AI zone-target state");
        assert_eq!(actual, &expected);
        assert_eq!(
            economy.ai_province_targets.as_ref(),
            Some(&expected_provinces)
        );
        assert_eq!(
            actual
                .iter()
                .filter(|&&target| target == AiTargetState::MissionQueued)
                .count(),
            queued_navy_target_count
        );
        assert!(!actual.contains(&AiTargetState::Candidate));
    }
    for province in (0..ProvinceId::COUNT).map(ProvinceId::new) {
        assert_eq!(state.map.provinces[province].development_stage(), 0);
        assert_eq!(
            state.map.provinces[province].explored_by_majors(),
            &MajorNationTable::default()
        );
    }
}

#[test]
fn creates_a_normal_start_boundary_from_the_retained_preview() {
    let preview = initial_seed_one_preview();
    let state = create_random_game(
        &preview,
        MajorNationId::new(6),
        Difficulty::Normal,
        "Testland",
        true,
        1,
        &crate::test_support::random_game_names(),
    );

    assert_eq!(
        state
            .nations
            .majors
            .iter()
            .map(|nation| nation.common.display_name.as_str())
            .collect::<Vec<_>>(),
        ["N0", "N1", "N2", "N3", "N4", "N5", "Testland"]
    );
    assert_eq!(
        state
            .nations
            .minors
            .iter()
            .flatten()
            .map(|nation| nation.common.display_name.as_str())
            .collect::<Vec<_>>(),
        (7..NationId::COUNT)
            .map(|nation| format!("N{nation}"))
            .collect::<Vec<_>>()
    );

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
            && nation.economy.diplomacy_budget_base == 20_000
            && nation.economy.escalation_counter == 12
    }));
    let initial_ai_expansions =
        ProductionTable::from_array([2, 1, 2, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    for nation in (0..MajorNationId::COUNT - 1).map(MajorNationId::new) {
        assert_eq!(
            state.nations.majors[nation]
                .economy
                .interior_civilian
                .city_order_demand
                .expansions,
            initial_ai_expansions
        );
    }
    assert_eq!(
        state.nations.majors[MajorNationId::new(6)]
            .economy
            .interior_civilian
            .city_order_demand,
        AiCityOrderDemand::default()
    );
    assert!(
        state
            .nations
            .majors
            .iter()
            .all(|nation| nation.towns[0].created_turn == 0)
    );
    assert_eq!(
        state
            .nations
            .majors
            .iter()
            .map(|nation| nation.city.production_accum[CityFacilitySlot::RegionalPopulation])
            .collect::<Vec<_>>(),
        [2; 7]
    );

    let expected_adjacency = build_province_adjacency(&state.map);
    for (index, generated) in preview.map.provinces().iter().enumerate() {
        let province = ProvinceId::new(index as u16);
        let owner = generated.owner.nation().unwrap();
        assert_eq!(state.map.provinces[province].owner(), Some(owner));
        assert_eq!(state.map.provinces[province].former_owner(), Some(owner));
        assert_eq!(
            state.map.provinces[province].adjacency(),
            expected_adjacency[index]
        );
        assert_eq!(
            state.map.provinces[province].region_class,
            Some(generated.region_class)
        );
    }
    for index in preview.map.provinces().len()..crate::PROVINCE_COUNT {
        assert_eq!(
            state.map.provinces[ProvinceId::new(index as u16)],
            ProvinceState::default()
        );
    }
    let province_zero = &state.map.provinces[ProvinceId::new(0)];
    assert_eq!(province_zero.primary_neighbor_tile, Some(TileId::new(507)));
    assert_eq!(
        province_zero.secondary_neighbor_tile,
        Some(TileId::new(614))
    );
    assert_eq!(province_zero.resource_presence_mask, 88);
    // Retail snapshots this before fallback-capital normalization changes a Cotton tile to Grain.
    assert_eq!(
        state.map.provinces[ProvinceId::new(25)].resource_presence_mask,
        65
    );
    for nation in NationId::all() {
        let expected = preview
            .map
            .provinces()
            .iter()
            .enumerate()
            .filter_map(|(index, province)| {
                (province.owner.nation() == Some(nation)).then_some(ProvinceId::new(index as u16))
            })
            .collect::<Vec<_>>();
        let common = state.nations.common(nation).unwrap();
        assert_eq!(common.status(), CountryStatus::Independent);
        assert_eq!(common.owned_regions(), expected);
    }

    assert_eq!(state.turn.phase, crate::PhaseCode::CAPITAL_SELECTION);
    assert_eq!(state.turn.difficulty, Difficulty::Normal);
    assert_eq!(state.turn.selected_nation, NationId::new(6));
    assert!(state.map.map_data_ready);
    assert!(state.map.recruit_search_active);
    assert_eq!(state.map.scenario_tag, "Woopnist");
    assert_eq!(state.map.pending_river_mouth_tile, Some(TileId::new(0)));
    let city_site_candidates = state
        .map
        .tiles
        .iter()
        .enumerate()
        .filter_map(|(index, tile)| {
            (tile.recruit_search_visited == 0).then_some(TileId::new(index as u16))
        })
        .collect::<Vec<_>>();
    assert_eq!(
        city_site_candidates,
        [
            2541, 2543, 2546, 2646, 2648, 2649, 2650, 2653, 2654, 2754, 2755, 2759, 2760, 2862,
            2970, 2971, 2972, 3076, 3077, 3081, 3184, 3400, 3401, 3402, 3508, 3511, 3513, 3514,
            3622, 3731, 3734, 3735, 3839, 3840, 3843, 3844, 3845,
        ]
        .map(TileId::new)
    );
    assert!(
        state
            .map
            .tiles
            .iter()
            .all(|tile| tile.recruit_search_visited <= 1)
    );
    assert_ne!(
        state.rng.map_generation,
        RetailLcg::from_state(preview.final_map_lcg)
    );
    assert_eq!(
        state.map[TileId::new(0)].terrain,
        preview.map.tile(TileId::new(0)).terrain
    );
    assert_eq!(
        state.map[TileId::new(0)].former_owner_nation,
        state.map[TileId::new(0)].owner_nation
    );
    assert_eq!(state.map[TileId::new(0)].recruit_search_visited, 1);
    assert_eq!(state.map[TileId::new(0)].per_tile_visited, 0);
    assert_eq!(state.map[TileId::new(0)].marker_slot_index, -1);
    assert_eq!(state.map[TileId::new(0)].tile_action_ordinal, -1);
    assert_eq!(
        state.map[TileId::new(844)].action.map(TileAction::retail),
        Some(-14),
    );
    assert_eq!(
        (
            state.map[TileId::new(0)].owner_border_mask,
            state.map[TileId::new(0)].city_border_mask,
            state.map[TileId::new(0)].water_adjacency_mask,
        ),
        (39, 0, 0),
    );
    assert_eq!(
        (
            state.map[TileId::new(399)].owner_border_mask,
            state.map[TileId::new(399)].city_border_mask,
            state.map[TileId::new(399)].water_adjacency_mask,
        ),
        (0, 0, 51),
    );
    assert_eq!(
        (
            state.map[TileId::new(831)].owner_border_mask,
            state.map[TileId::new(831)].city_border_mask,
            state.map[TileId::new(831)].water_adjacency_mask,
        ),
        (0, 143, 0),
    );
    assert!(
        state
            .map
            .tiles
            .iter()
            .any(|tile| tile.edge_resources[0].is_some()),
        "post-passes must stamp some edge resources"
    );
    assert!(
        state.map.tiles.iter().any(|tile| tile.flags.is_city()),
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
            .towns
            .first()
            .map(|town| town.tile),
        ai.common.home_tile
    );
    let ai_home = ai.common.home_tile.unwrap();
    assert!(
        state.map[ai_home].flags.is_city(),
        "AI PlaceCity marks the selected capital as a city"
    );
    assert!(
        state.map[ai_home].region.is_some(),
        "retail region markers start at 1"
    );
    assert_eq!(state.rng.zone_status, RetailLcg::from_state(1));

    assert_eq!(state.nations.minor_count(), crate::MINOR_NATION_COUNT);
    let human = &state.nations.majors[MajorNationId::new(6)];
    assert_eq!(
        human.towns.first().map(|town| town.tile),
        Some(TileId::new(0))
    );
    assert_eq!(human.city.stockpile[ResourceKind::Food], 20);

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
            let flags = state.map[home].flags;
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
        state.map.tiles.iter().any(|tile| {
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
