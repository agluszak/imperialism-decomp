use super::*;

/// Special-purpose Accept-time port-zone table (no full `TZone` graph).
///
/// Sea-zone ordinals are `water_owner - 0x17`. Port zones allocate the next ordinals in
/// creation order. `ports` is newest-first so `FindFirstPortZone*` walks match retail's
/// `g_pMapActionContextListHead`/`prev18` chain.
pub(super) struct PortZoneTable {
    pub(super) next_ordinal: u16,
    pub(super) ports: Vec<PortZone>,
}
#[derive(Clone, Copy, Debug)]
pub(super) struct PortZone {
    pub(super) ordinal: OceanZoneId,
    pub(super) port_tile: TileId,
    pub(super) sea_tile: TileId,
    /// `primaryNeighbors[0]` ordinal (sea zone or another port).
    pub(super) primary_neighbor: Option<OceanZoneId>,
    pub(super) former_owner: NationId,
}
impl PortZoneTable {
    pub(super) fn new(sea_zone_count: u16) -> Self {
        Self {
            next_ordinal: sea_zone_count,
            ports: Vec::new(),
        }
    }

    pub(super) fn find_port_by_tile(&self, tile: TileId) -> Option<&PortZone> {
        self.ports
            .iter()
            .find(|port| port.port_tile == tile || port.sea_tile == tile)
    }

    pub(super) fn find_first_port_for_nation(&self, nation: NationId) -> Option<&PortZone> {
        self.ports.iter().find(|port| port.former_owner == nation)
    }
}
pub(super) fn sea_zone_count(world: &StrategicMap) -> u16 {
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
/// Fresh-map `TOcean::InitializeMapActionContextsForNationCountUsingCostField`.
///
/// Map construction consumes the current CRT stream to break equal-score sea-zone seed ties,
/// stamps three negative overlay frames per zone, then reseeds CRT before setup continues.
pub(super) fn initialize_sea_zone_map_markers(
    world: &mut StrategicMap,
    mut map_build_crt: RetailCrtRng,
) {
    let geometry = world.geometry();
    let costs = build_sea_zone_cost_field(world, geometry);

    for zone in 0..sea_zone_count(world) {
        let owner = TileOwnerTag::new(
            SEA_OWNER_BIAS + u8::try_from(zone).expect("fresh-map sea-zone tag fits in one byte"),
        );
        let center = select_sea_zone_seed_tile(world, geometry, &costs, owner, &mut map_build_crt);
        world.tile_mut(center).action = TileAction::try_from_retail(ACTION_STATE_ZONE_CENTER);

        let north_west = geometry
            .neighbor(center, HexDirection::NorthWest)
            .expect("fresh-map sea-zone seed is below the north map edge");
        world.tile_mut(north_west).action =
            TileAction::try_from_retail(ACTION_STATE_ZONE_NORTH_WEST);

        let north_east = geometry
            .neighbor(north_west, HexDirection::NorthEast)
            .expect("fresh-map sea-zone marker is below the north map edge");
        world.tile_mut(north_east).action =
            TileAction::try_from_retail(ACTION_STATE_ZONE_NORTH_EAST);
    }
}
/// `RelaxMapTileCostFieldByNeighborTerrain` to its fixed point.
pub(super) fn build_sea_zone_cost_field(world: &StrategicMap, geometry: MapGeometry) -> Vec<i16> {
    let mut costs = vec![0_i16; STRATEGIC_TILE_COUNT];
    loop {
        let mut changed = 0;
        for index in 0..STRATEGIC_TILE_COUNT {
            if costs[index] != 0 {
                continue;
            }
            let tile = TileId::new(index as u16);
            for neighbor in geometry.neighbors(tile) {
                let current = costs[index];
                let Some(neighbor) = neighbor else {
                    if current == 0 {
                        costs[index] = -1;
                        changed += 1;
                    }
                    continue;
                };
                let neighbor_index = usize::from(neighbor.get());
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
    world: &StrategicMap,
    geometry: MapGeometry,
    costs: &[i16],
    owner: TileOwnerTag,
    crt: &mut RetailCrtRng,
) -> TileId {
    let mut best_tile = -1_i32;
    let mut best_score = -1_i32;
    let mut equal_best_count = 0_i16;

    // Retail deliberately excludes the final two map rows from seed selection.
    for index in 0..0x1878_usize {
        let tile = TileId::new(index as u16);
        if world[tile].owner_nation != Some(owner) {
            continue;
        }

        let mut score = i32::from(costs[index]) * 12;
        for (direction, neighbor) in HexDirection::ALL.into_iter().zip(geometry.neighbors(tile)) {
            let Some(neighbor) = neighbor else {
                continue;
            };
            if world[neighbor].owner_nation != Some(owner) {
                continue;
            }
            let neighbor_cost = i32::from(costs[usize::from(neighbor.get())]);
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
            if crt.next_rand() % i32::from(equal_best_count) == 0 || best_tile < 0xd8 {
                best_tile = index as i32;
                best_score = score;
            }
        } else if best_tile < 0xd8 {
            best_tile = index as i32;
            best_score = score;
        }
    }

    TileId::new(u16::try_from(best_tile).expect("fresh-map sea zone has one seed tile"))
}
/// `TOcean::EnsurePortZoneForTile` side effects needed for Accept missions / tile action state.
pub(super) fn ensure_port_zone_for_tile(
    world: &mut StrategicMap,
    ports: &mut PortZoneTable,
    tile: TileId,
) {
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
    world.tile_mut(best_sea).action = TileAction::try_from_retail(ACTION_STATE_ANCHOR);
}
pub(super) fn select_port_sea_tile(
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
    crate::city_site::trace_terrain_flow_to_nearest_sea_tile(world, tile)
}
