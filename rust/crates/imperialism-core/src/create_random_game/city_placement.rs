use super::*;

/// `g_abResourceTypeUsesHighNibbleFlag` — nonzero means extractive nibble / tech override.
pub(super) const RESOURCE_USES_HIGH_NIBBLE: [u8; 24] = [
    0, 0, 0, 1, 1, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0,
];
/// `g_abGateFlagQualifies` — farmland auto-development gate check in `PlaceCity`.
pub(super) const GATE_FLAG_QUALIFIES: [u8; 24] = [
    0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];
/// Accept-time `CreateFrogCityAtHomeRegionAndAttach` placement.
#[allow(clippy::too_many_arguments)]
pub(super) fn place_initial_frog_cities(
    world: &mut MapMgr,
    province_capitals: &mut [Option<TileId>],
    nations: &mut Nations,
    human_nation: MajorNationId,
    technology: &TechnologyState,
    port_zones: &mut PortZoneTable,
    ocean_zones: &[ZoneKind],
    mission_queues: &mut MajorNationTable<Vec<MissionState>>,
    difficulty: Difficulty,
) {
    let province_adjacency = build_province_adjacency(world);
    for nation in MajorNationId::all().rev() {
        if nation == human_nation && requires_capital_site_selection(difficulty) {
            continue;
        }
        let Some(home) = select_best_secondary_home_tile(
            world,
            nation,
            &technology.city_capabilities_by_nation[nation].university,
        ) else {
            continue;
        };
        place_ai_capital(world, province_capitals, home, nation);
        ensure_port_zone_for_tile(world, port_zones, home);
        let major = nations.major_mut(nation);
        major.common.home_tile = Some(home);
        let home_town = major
            .towns
            .first_mut()
            .expect("random great power has its initial FrogCity marker");
        home_town.name = "FrogCity".to_owned();
        home_town.tile = home;
        home_town.owner_nation = nation.nation();
        // `QueueMapActionMissionsForPortZoneCandidates` runs only for setup-mode-2 AI.
        if nation != human_nation {
            mission_queues[nation] = queue_map_action_missions_for_port_zone_candidates(
                world,
                province_capitals,
                &province_adjacency,
                port_zones,
                ocean_zones,
                nation,
            );
        }
    }
}
pub(super) const LAND_UNIT_TYPE_NAMES: [&str; 8] = [
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
pub(super) fn bootstrap_minors(
    world: &mut MapMgr,
    province_capitals: &mut [Option<TileId>],
    nations: &mut Nations,
    crt: &mut RetailCrtRng,
    military_units: &mut Vec<MilitaryUnitState>,
    unit_ids: &mut UnitIdAllocator,
    difficulty: Difficulty,
    port_zones: &mut PortZoneTable,
) {
    for minor_id in MinorNationId::all() {
        let owner = TileOwnerTag::from_nation(minor_id.nation());
        let Some(home) = select_minor_home_tile(world, owner, crt) else {
            continue;
        };
        reset_tile_to_base_transport_flag(world, province_capitals, home);
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
pub(super) fn select_minor_home_tile(
    world: &MapMgr,
    owner: TileOwnerTag,
    crt: &mut RetailCrtRng,
) -> Option<TileId> {
    let mut selected = None;
    let mut candidates = Vec::new();
    for (index, tile) in world.tiles.iter().enumerate() {
        if tile.owner_nation != Some(owner) {
            continue;
        }
        if tile.flags.has_base_transport() {
            selected = Some(TileId::new(index as usize));
        }
        let tile_id = TileId::new(index as usize);
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
pub(super) fn reset_tile_to_base_transport_flag(
    world: &mut MapMgr,
    province_capitals: &mut [Option<TileId>],
    tile: TileId,
) {
    set_region_tile_subtype_and_refresh_neighbor_flags(world, province_capitals, tile);
    world[tile].flags = TileFlags::MINOR_HOME_STATE;
    initialize_world_tile_neighbor_connection_mask_if_needed(world, tile);
}
pub(super) fn owned_province_ids(
    world: &MapMgr,
    province_capitals: &[Option<TileId>],
    owner: TileOwnerTag,
) -> Vec<ProvinceId> {
    let mut owned = Vec::new();
    for (province_index, capital) in province_capitals.iter().enumerate() {
        let Some(capital) = *capital else {
            continue;
        };
        if world[capital].owner_nation == Some(owner) {
            owned.push(ProvinceId::new(province_index as usize));
        }
    }
    owned
}
/// `TCountry::InitialMilitia` for random-map minors at the pre-capital boundary.
#[allow(clippy::too_many_arguments)]
pub(super) fn spawn_initial_militia_for_minor(
    world: &mut MapMgr,
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
        let capital = province_capitals[province.index()];
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
pub(super) fn push_military_unit(
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
pub(crate) fn name_units_for_nation(
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
pub(super) fn english_ordinal(value: i16) -> String {
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
pub(super) fn select_best_secondary_home_tile(
    world: &MapMgr,
    nation: MajorNationId,
    university: &UniversityTechnologyState,
) -> Option<TileId> {
    let owner = TileOwnerTag::from_nation(nation.nation());
    let mut best_score: i32 = -1;
    let mut best_tile: Option<TileId> = None;
    for index in 0..STRATEGIC_TILE_COUNT {
        let tile = TileId::new(index as usize);
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
        let yields = calculate_city_resources(world, tile, nation, university);
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
pub(super) fn frog_city_score(yields: &ResourceTable<i16>) -> i32 {
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
pub(super) fn calculate_city_resources(
    world: &MapMgr,
    home: TileId,
    nation: MajorNationId,
    university: &UniversityTechnologyState,
) -> ResourceTable<i16> {
    let geometry = world.geometry();
    let owner = TileOwnerTag::from_nation(nation.nation());
    let mut yields = ResourceTable::default();
    // Directions 0..5 are hex neighbors; 6 is the home tile itself (`TownNeighborTile`).
    for tile in geometry
        .neighbors(home)
        .into_iter()
        .filter_map(|(_, tile)| tile)
        .chain(std::iter::once(home))
    {
        let state = &world[tile];
        if state.owner_nation != Some(owner) && state.terrain != TerrainKind::Water {
            continue;
        }
        for resource in crate::all_resources() {
            let mut amount = resource_capability_level(state, resource);
            if amount != 0 {
                let gate = state.gate;
                if (0..24).contains(&gate) && RESOURCE_USES_HIGH_NIBBLE[gate as usize] != 0 {
                    let capability = university.requirement_levels[resource];
                    amount = resource_development_yield(resource, capability);
                }
            }
            yields[resource] += amount;
        }
        if state.river().is_some() {
            yields[ResourceKind::Fish] += 1;
        }
    }
    yields
}
pub(crate) fn resource_capability_level(tile: &TileState, resource: ResourceKind) -> i16 {
    if !tile.edge_resources.contains(&Some(resource)) {
        return 0;
    }
    let resource_index = resource as usize;
    let packed = (tile.development.extractive.get() << 4) | tile.development.surface.get();
    let index = if RESOURCE_USES_HIGH_NIBBLE[resource_index] != 0 {
        packed >> 4
    } else {
        packed & 0x0f
    };
    resource_development_yield(resource, index.min(3))
}

/// `TMapMgr::FindResourceCapabilityRequirementLevel` for one terrain-record edge.
///
/// Unlike [`resource_capability_level`], this does not mask the low nibble when the
/// resource uses the packed development byte as a whole.
pub(crate) fn resource_capability_requirement_level(tile: &TileState, edge: usize) -> i32 {
    let Some(resource) = tile.edge_resources[edge] else {
        return 0;
    };
    let packed = (tile.development.extractive.get() << 4) | tile.development.surface.get();
    let index = if RESOURCE_USES_HIGH_NIBBLE[resource as usize] != 0 {
        packed >> 4
    } else {
        packed
    };
    i32::from(resource_development_yield(resource, index.min(3)))
}
/// Accept-time AI `PlaceCity`: province capital rewrite, flags, flood-fill, farmland nibble.
pub(super) fn place_ai_capital(
    world: &mut MapMgr,
    province_capitals: &mut [Option<TileId>],
    tile: TileId,
    nation: MajorNationId,
) {
    let index = tile.index();
    set_region_tile_subtype_and_refresh_neighbor_flags(world, province_capitals, tile);
    let owner = TileOwnerTag::from_nation(nation.nation());
    place_city(world, tile, owner);

    let origin_marker = world[tile].region;
    for neighbor in place_city_harvest_tiles(index).into_iter().flatten() {
        let neighbor = TileId::new(neighbor as usize);
        if world[neighbor].region != origin_marker {
            continue;
        }
        let gate = world[neighbor].gate;
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
    world[tile].gate = resolve_region_tile_subtype_code(&world[tile], index);
}
/// `TMapMgr::SetRegionTileSubtypeAndRefreshNeighborFlags` (0x00515f80) tile mutations.
pub(super) fn set_region_tile_subtype_and_refresh_neighbor_flags(
    world: &mut MapMgr,
    province_capitals: &mut [Option<TileId>],
    new_tile: TileId,
) {
    let Some(province) = world[new_tile].province else {
        return;
    };
    let province_index = province.index();
    if let Some(old_tile) = province_capitals[province_index] {
        let old_index = old_tile.index();
        world[old_tile].flags = TileFlags::empty();
        world[old_tile].edge_resources[0] = Some(ResourceKind::Grain);
        world[old_tile].gate = resolve_region_tile_subtype_code(&world[old_tile], old_index);
    }
    let new_index = new_tile.index();
    world[new_tile].flags = TileFlags::PROVINCE_ANCHOR_STATE;
    province_capitals[province_index] = Some(new_tile);
    world[new_tile].gate = resolve_region_tile_subtype_code(&world[new_tile], new_index);

    for index in 0..STRATEGIC_TILE_COUNT {
        let tile_id = TileId::new(index as usize);
        if tile_id != new_tile && world[tile_id].province == Some(province) {
            world[tile_id].flags.clear_city_marker();
        }
    }
}
pub(super) fn initialize_world_tile_neighbor_connection_mask_if_needed(
    world: &mut MapMgr,
    tile: TileId,
) {
    let index = tile.index();
    if world[tile].gate == 1 {
        return;
    }
    world[tile].terrain = TerrainKind::Plains;
    world[tile].edge_resources = [Some(ResourceKind::Grain), None];
    world[tile].gate = resolve_region_tile_subtype_code(&world[tile], index);

    let geometry = world.geometry();
    for (direction, neighbor) in geometry.neighbors(tile) {
        let Some(neighbor) = neighbor else {
            continue;
        };
        world[neighbor].rendering.transition_mask &= !(1_u8 << direction.opposite() as u8);
    }
}
/// Harvest ring from `TMapMgr::PlaceCity` (directions 0..5 via hex-area deltas, 6 = self).
pub(super) fn place_city_harvest_tiles(tile_index: usize) -> [Option<usize>; 7] {
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
