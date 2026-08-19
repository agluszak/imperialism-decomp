use super::*;

/// Temporary Accept-time port allocation state before the entries join [`Ocean::zones`].
///
/// Sea-zone ordinals are `water_owner - 0x17`. Port zones allocate the next ordinals in
/// creation order. `ports` is newest-first so `FindFirstPortZone*` walks match retail's
/// `g_pMapActionContextListHead`/`prev18` chain.
pub(super) struct PortZoneTable {
    pub(super) next_ordinal: usize,
    pub(super) ports: Vec<PendingPortZone>,
}
#[derive(Clone, Copy, Debug)]
pub(super) struct PendingPortZone {
    pub(super) ordinal: OceanZoneId,
    pub(super) port_tile: TileId,
    pub(super) sea_tile: TileId,
    pub(super) active_tile: Option<TileId>,
    pub(super) seed_owner: TileContext,
    /// `primaryNeighbors[0]` ordinal (sea zone or another port).
    pub(super) primary_neighbor: Option<OceanZoneId>,
}
impl PortZoneTable {
    pub(super) fn new(sea_zone_count: usize) -> Self {
        Self {
            next_ordinal: sea_zone_count,
            ports: Vec::new(),
        }
    }

    pub(super) fn find_port_by_tile(&self, tile: TileId) -> Option<&PendingPortZone> {
        self.ports.iter().find(|port| {
            port.port_tile == tile || port.sea_tile == tile || port.active_tile == Some(tile)
        })
    }

    pub(super) fn find_first_port_for_nation(
        &self,
        world: &MapMgr,
        nation: NationId,
    ) -> Option<&PendingPortZone> {
        self.ports.iter().find(|port| {
            world[port.port_tile]
                .former_owner_nation
                .and_then(TileContext::nation)
                == Some(nation)
        })
    }
}
pub(super) fn sea_zone_count(world: &MapMgr) -> usize {
    world
        .tiles
        .iter()
        .filter(|tile| tile.terrain == TerrainKind::Water)
        .filter_map(|tile| tile.owner_nation.and_then(TileContext::ocean))
        .map(|zone| zone.get() + 1)
        .max()
        .unwrap_or(0)
}
/// Fresh-map `TOcean::InitializeMapActionContextsForNationCountUsingCostField`.
///
/// Map construction consumes the current CRT stream to break equal-score sea-zone seed ties,
/// stamps three negative overlay frames per zone, then reseeds CRT before setup continues.
pub(super) fn initialize_sea_zone_map_markers(
    world: &mut MapMgr,
    mut map_build_crt: RetailCrtRng,
) -> Vec<ZoneKind> {
    let geometry = world.geometry();
    let costs = build_sea_zone_cost_field(world, geometry);
    let mut zones = Vec::with_capacity(sea_zone_count(world));

    for zone in 0..sea_zone_count(world) {
        let owner = TileContext::Ocean(OceanZoneId::new(zone));
        let center = select_sea_zone_seed_tile(world, geometry, &costs, owner, &mut map_build_crt);
        world[center].action = TileAction::try_from_retail(ACTION_STATE_ZONE_CENTER);

        let north_west = geometry
            .neighbor(center, HexDirection::NorthWest)
            .expect("fresh-map sea-zone seed is below the north map edge");
        world[north_west].action = TileAction::try_from_retail(ACTION_STATE_ZONE_NORTH_WEST);

        let north_east = geometry
            .neighbor(north_west, HexDirection::NorthEast)
            .expect("fresh-map sea-zone marker is below the north map edge");
        world[north_east].action = TileAction::try_from_retail(ACTION_STATE_ZONE_NORTH_EAST);
        zones.push(ZoneKind::Zone(Zone {
            display_name: String::new(),
            status_code: None,
            target_tile: Some(center),
            seed_owner: Some(owner),
            active_tile: Some(north_east),
            primary_neighbors: Vec::new(),
            secondary_neighbors: Vec::new(),
        }));
    }
    zones
}

pub(super) fn initialize_sea_zone_neighbors(
    zones: &mut [ZoneKind],
    world: &MapMgr,
    links: &[[OceanZoneId; 2]],
) {
    for &[left, right] in links {
        for (source, neighbor) in [(left, right), (right, left)] {
            let ZoneKind::Zone(zone) = &mut zones[source.get()] else {
                unreachable!("water-region links only name base zones")
            };
            if !zone.primary_neighbors.contains(&neighbor) {
                zone.primary_neighbors.push(neighbor);
            }
        }
    }

    let geometry = world.geometry();
    for tile in TileId::all() {
        let Some(zone) = world[tile].owner_nation.and_then(TileContext::ocean) else {
            continue;
        };
        let ordinal = zone.get();
        let ZoneKind::Zone(zone) = &mut zones[ordinal] else {
            unreachable!("water owner tags name base zones")
        };
        for neighbor in geometry.neighbors(tile).into_iter().flatten() {
            if let Some(province) = world[neighbor].province
                && !zone.secondary_neighbors.contains(&province)
            {
                zone.secondary_neighbors.push(province);
            }
        }
    }
}

/// Fresh-map `RegenerateAllMapActionContextStatusCodes` status and RNG work.
///
/// Contexts are walked newest-first. This first map-construction pass consumes the shared-LCG
/// name draws too because they determine every following zone's status code; a later final pass
/// rebuilds display names after province names exist.
pub(super) fn generate_base_zone_status_codes(
    zones: &mut [ZoneKind],
    scenario_tag: &[u8],
    runtime_seed: u32,
) {
    let tag_seed = hash_retail_scenario_tag(scenario_tag);
    let mut rng = RetailLcg::from_state(if tag_seed == 0 {
        runtime_seed
    } else {
        tag_seed as u32
    });
    let mut used_cities = [false; PROVINCE_COUNT];
    let mut localized_name_cursor_initialized = false;

    for ordinal in (0..zones.len()).rev() {
        let category = base_zone_status_category(zones, ordinal);
        let status_code = i32::try_from((rng.next_sample_15() & 3) + category * 4)
            .expect("zone status code fits in a short");

        let ZoneKind::Zone(zone) = &zones[ordinal] else {
            unreachable!("base-zone status generation runs before ports exist")
        };
        let selected_city = if zone.secondary_neighbors.is_empty() {
            None
        } else {
            let index =
                usize::try_from(rng.next_sample_15() % zone.secondary_neighbors.len() as u32)
                    .expect("zone secondary-neighbor index fits usize");
            Some(zone.secondary_neighbors[index])
        };
        let needs_fallback_name = match selected_city {
            Some(city) if !used_cities[city.get()] => {
                used_cities[city.get()] = true;
                false
            }
            _ => true,
        };

        if needs_fallback_name && !localized_name_cursor_initialized {
            rng.advance();
            rng.advance();
            localized_name_cursor_initialized = true;
        }

        let ZoneKind::Zone(zone) = &mut zones[ordinal] else {
            unreachable!("base-zone status generation runs before ports exist")
        };
        zone.status_code = Some(status_code);
    }
}

/// Localized `TMapMgr::GenerateProvinceNames` assignment in fixed province-table order.
pub(super) fn generate_province_names(
    provinces: &mut ProvinceTable<ProvinceState>,
    names: &RandomGameNames,
) {
    let mut next_ordinal = NationTable::<usize>::default();
    for province_id in ProvinceId::all() {
        let province = &mut provinces[province_id];
        if province.linked_tiles.is_empty() {
            continue;
        }
        let owner = province
            .owner()
            .expect("a populated fresh-map province has an owner");
        let ordinal = &mut next_ordinal[owner];
        province.name = names.province_names_by_nation[owner]
            .get(*ordinal)
            .expect("retail province-name table covers every generated province")
            .clone();
        *ordinal += 1;
    }
}

/// Final `RegenerateAllMapActionContextStatusCodes` display-name pass.
///
/// Every status is already set at this point: base-zone statuses were created with the map,
/// while port statuses were created with their port. Retail nevertheless reseeds from the
/// scenario tag, resets the used-city and fallback-name cursors, and rebuilds every headline.
pub(super) fn generate_zone_display_names(
    zones: &mut [ZoneKind],
    world: &MapMgr,
    scenario_tag: &[u8],
    runtime_seed: u32,
    names: &RandomGameNames,
) {
    let tag_seed = hash_retail_scenario_tag(scenario_tag);
    let mut rng = RetailLcg::from_state(if tag_seed == 0 {
        runtime_seed
    } else {
        tag_seed as u32
    });
    let mut used_cities = [false; PROVINCE_COUNT];
    let mut fallback_cursor = None;
    let mut fallback_step = 0;

    for ordinal in (0..zones.len()).rev() {
        let raw_name = match &zones[ordinal] {
            ZoneKind::PortZone(port) => {
                let province = world[port.port_tile]
                    .province
                    .expect("a fresh port zone belongs to one province");
                world.provinces[province].name.clone()
            }
            ZoneKind::Zone(zone) => {
                let selected_city = if zone.secondary_neighbors.is_empty() {
                    None
                } else {
                    let index = usize::try_from(
                        rng.next_sample_15() % zone.secondary_neighbors.len() as u32,
                    )
                    .expect("zone secondary-neighbor index fits usize");
                    Some(zone.secondary_neighbors[index])
                };
                match selected_city {
                    Some(province) if !used_cities[province.get()] => {
                        used_cities[province.get()] = true;
                        world.provinces[province].name.clone()
                    }
                    _ => {
                        let cursor = *fallback_cursor.get_or_insert_with(|| {
                            let cursor = usize::try_from(rng.next_sample_15() % 0x25)
                                .expect("fallback ocean-name cursor fits usize");
                            const STEPS: [usize; 4] = [1, 7, 0xb, 0x17];
                            fallback_step = STEPS[usize::try_from(rng.next_sample_15() % 4)
                                .expect("fallback ocean-name step index fits usize")];
                            cursor
                        });
                        let name = names
                            .fallback_ocean_names
                            .get(cursor)
                            .expect("retail fallback ocean-name table has 37 entries")
                            .clone();
                        fallback_cursor = Some((cursor + fallback_step) % 0x25);
                        name
                    }
                }
            }
        };

        let zone = match &mut zones[ordinal] {
            ZoneKind::Zone(zone) => zone,
            ZoneKind::PortZone(port) => &mut port.zone,
        };
        let status = usize::try_from(
            zone.status_code
                .expect("fresh map-action context has a status code"),
        )
        .expect("fresh map-action context status is nonnegative");
        let template = names
            .zone_headline_templates
            .get(status)
            .expect("retail zone-headline table covers every status code");
        zone.display_name = template.replace("[1]", &raw_name);
    }
}

fn base_zone_status_category(zones: &[ZoneKind], ordinal: usize) -> u32 {
    let ZoneKind::Zone(zone) = &zones[ordinal] else {
        unreachable!("base-zone status generation runs before ports exist")
    };
    let mut category = zone.primary_neighbors.len() as u32;
    if category == 2 {
        let first = zone.primary_neighbors[0].get();
        let second = zone.primary_neighbors[1];
        let ZoneKind::Zone(first) = &zones[first] else {
            unreachable!("base-zone links name base zones before ports exist")
        };
        if first.primary_neighbors.contains(&second) {
            category = 1;
        }
    }
    if category > 5 {
        category = 4;
    } else if category > 3 {
        category = 3;
    }
    if zone.secondary_neighbors.is_empty() {
        4
    } else if category == 4 {
        3
    } else {
        category
    }
}

/// `RelaxMapTileCostFieldByNeighborTerrain` to its fixed point.
pub(super) fn build_sea_zone_cost_field(world: &MapMgr, geometry: MapGeometry) -> Vec<i32> {
    let mut costs = vec![0; STRATEGIC_TILE_COUNT];
    loop {
        let mut changed = 0;
        for index in 0..STRATEGIC_TILE_COUNT {
            if costs[index] != 0 {
                continue;
            }
            let tile = TileId::new(index);
            for neighbor in geometry.neighbors(tile) {
                let current = costs[index];
                let Some(neighbor) = neighbor else {
                    if current == 0 {
                        costs[index] = -1;
                        changed += 1;
                    }
                    continue;
                };
                let neighbor_index = neighbor.get();
                if current == 0 && world[neighbor].owner_nation != world[tile].owner_nation {
                    costs[index] = -1;
                    changed += 1;
                    continue;
                }
                let neighbor_cost = costs[neighbor_index];
                if neighbor_cost > 0 && (current == 0 || neighbor_cost < -current) {
                    costs[index] = -1 - neighbor_cost;
                    changed += 1;
                }
            }
        }
        for cost in &mut costs {
            if *cost < 0 {
                *cost = -*cost;
            }
        }
        if changed == 0 {
            return costs;
        }
    }
}
/// `SelectBestSeedTileForNationFromCostField`.
pub(super) fn select_sea_zone_seed_tile(
    world: &MapMgr,
    geometry: MapGeometry,
    costs: &[i32],
    owner: TileContext,
    crt: &mut RetailCrtRng,
) -> TileId {
    let mut best_tile = -1_i32;
    let mut best_score = -1_i32;
    let mut equal_best_count = 0;

    // Retail deliberately excludes the final two map rows from seed selection.
    for index in 0..0x1878_usize {
        let tile = TileId::new(index);
        if world[tile].owner_nation != Some(owner) {
            continue;
        }

        let mut score = costs[index] * 12;
        for (direction, neighbor) in HexDirection::ALL.into_iter().zip(geometry.neighbors(tile)) {
            let Some(neighbor) = neighbor else {
                continue;
            };
            if world[neighbor].owner_nation != Some(owner) {
                continue;
            }
            let neighbor_cost = costs[neighbor.get()];
            score += neighbor_cost * 2;
            if matches!(direction, HexDirection::East | HexDirection::West) {
                score += neighbor_cost;
            }
        }

        if best_tile == -1 || best_score < score {
            best_tile = index as i32;
            best_score = score;
            equal_best_count = 1;
        } else if best_score == score {
            equal_best_count += 1;
            if crt.next_rand() % equal_best_count == 0 || best_tile < 0xd8 {
                best_tile = index as i32;
                best_score = score;
            }
        } else if best_tile < 0xd8 {
            best_tile = index as i32;
            best_score = score;
        }
    }

    TileId::new(best_tile as usize)
}
/// `TOcean::EnsurePortZoneForTile` side effects needed for Accept missions / tile action state.
pub(super) fn ensure_port_zone_for_tile(
    world: &mut MapMgr,
    ports: &mut PortZoneTable,
    tile: TileId,
) {
    if !world[tile].flags.has_base_transport() {
        return;
    }
    if ports.find_port_by_tile(tile).is_some() {
        return;
    }
    let Some(seed_owner) = world[tile].owner_nation else {
        return;
    };
    let Some(owner) = seed_owner.nation() else {
        return;
    };

    // TPortZone first resolves its inherited TZone target from the owning
    // nation's home-region class and leaves this overlay marker in place even
    // after EnsurePortZoneForTile replaces the zone's target with a sea tile.
    let representative = world
        .representative_tile_index_for_nation(owner, Some(tile), false)
        .expect("port owner has representative home-region territory");
    world[representative].action = TileAction::try_from_retail(ACTION_STATE_PORT_ZONE_MARKER);

    let geometry = world.geometry();
    let best_sea = select_port_sea_tile(world, geometry, tile, owner)
        .expect("port zone requires a reachable sea tile");

    let primary_neighbor = if world[best_sea]
        .action
        .is_some_and(|action| matches!(action.retail(), ACTION_STATE_ANCHOR | 14))
    {
        ports.find_port_by_tile(best_sea).map(|port| port.ordinal)
    } else {
        world[best_sea].owner_nation.and_then(TileContext::ocean)
    };

    let ordinal = OceanZoneId::new(ports.next_ordinal);
    ports.next_ordinal += 1;
    world[best_sea].action = TileAction::try_from_retail(ACTION_STATE_ANCHOR);
    let active_tile = find_nearest_active_port_zone_tile(world, ports, best_sea, primary_neighbor);
    ports.ports.insert(
        0,
        PendingPortZone {
            ordinal,
            port_tile: tile,
            sea_tile: best_sea,
            active_tile,
            seed_owner,
            primary_neighbor,
        },
    );
}

fn find_nearest_active_port_zone_tile(
    world: &MapMgr,
    ports: &PortZoneTable,
    origin: TileId,
    primary_neighbor: Option<OceanZoneId>,
) -> Option<TileId> {
    let geometry = world.geometry();
    let MapPosition {
        mut row,
        mut column,
    } = geometry.position(origin);
    let mut ring = 0_i32;
    let mut direction = HexDirection::NorthWest;
    let mut step_in_ring = 1_i32;

    advance_spiral(
        &mut row,
        &mut column,
        &mut ring,
        &mut direction,
        &mut step_in_ring,
        world.topology,
    );
    while ring < 10 {
        if (0..STRATEGIC_MAP_HEIGHT).contains(&row) && (0..STRATEGIC_MAP_WIDTH).contains(&column) {
            let candidate = geometry
                .tile(MapPosition::new(row, column))
                .expect("checked spiral coordinates are on the strategic map");
            let candidate_context = if world[candidate]
                .action
                .is_some_and(|action| matches!(action.retail(), ACTION_STATE_ANCHOR | 14))
            {
                ports.find_port_by_tile(candidate).map(|port| port.ordinal)
            } else {
                world[candidate].owner_nation.and_then(TileContext::ocean)
            };
            if candidate_context == primary_neighbor && world[candidate].action.is_none() {
                return Some(candidate);
            }
        }
        advance_spiral(
            &mut row,
            &mut column,
            &mut ring,
            &mut direction,
            &mut step_in_ring,
            world.topology,
        );
    }
    None
}

fn advance_spiral(
    row: &mut i32,
    column: &mut i32,
    ring: &mut i32,
    direction: &mut HexDirection,
    step_in_ring: &mut i32,
    topology: MapTopology,
) {
    *step_in_ring += 1;
    if *ring <= *step_in_ring {
        *direction = direction.next_clockwise();
        *step_in_ring = 0;
        if *direction == HexDirection::NorthEast {
            *ring += 1;
            step_row_column(row, column, HexDirection::West, topology);
        }
    }
    step_row_column(row, column, *direction, topology);
}

fn step_row_column(
    row: &mut i32,
    column: &mut i32,
    direction: HexDirection,
    topology: MapTopology,
) {
    let odd_row = *row & 1 != 0;
    if direction == HexDirection::West
        || (matches!(direction, HexDirection::SouthWest | HexDirection::NorthWest) && !odd_row)
    {
        *column -= 1;
    } else if direction == HexDirection::East
        || (matches!(direction, HexDirection::NorthEast | HexDirection::SouthEast) && odd_row)
    {
        *column += 1;
    }
    if topology == MapTopology::Wrapping {
        *column = column.rem_euclid(STRATEGIC_MAP_WIDTH);
    }
    if matches!(direction, HexDirection::NorthWest | HexDirection::NorthEast) {
        *row -= 1;
    } else if matches!(direction, HexDirection::SouthWest | HexDirection::SouthEast) {
        *row += 1;
    }
}
pub(super) fn select_port_sea_tile(
    world: &MapMgr,
    geometry: MapGeometry,
    tile: TileId,
    seed_nation: NationId,
) -> Option<TileId> {
    let tile_index = tile.get();
    for direction in HexDirection::ALL
        .into_iter()
        .cycle()
        .skip(tile_index % HexDirection::ALL.len())
        .take(HexDirection::ALL.len())
    {
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
                    !matches!(
                        world[neighbor].owner_nation,
                        Some(TileContext::Nation(nation)) if nation != seed_nation
                    )
                });
        if all_neighbors_qualify {
            return Some(candidate);
        }
    }
    crate::city_site::trace_terrain_flow_to_nearest_sea_tile(world, tile)
}
