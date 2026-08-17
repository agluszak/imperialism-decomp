use crate::civilian_phase::civilian_sea_scan_neighbor;
use crate::*;
use serde::{Deserialize, Serialize};

/// Retail's authoritative `TOcean` state.
///
/// The position of each entry in `zones` is its `TZone::contextOrdinal14`.
/// Routes retain their serialized order because it is also their drawing order.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Ocean {
    pub zones: Vec<ZoneKind>,
    pub routes: Vec<OceanRoute>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ZoneKind {
    Zone(Zone),
    PortZone(PortZone),
}

impl ZoneKind {
    pub fn zone(&self) -> &Zone {
        match self {
            Self::Zone(zone) => zone,
            Self::PortZone(port) => &port.zone,
        }
    }
}

impl Ocean {
    /// Retail `TOcean::FindMapActionContextContainingNodeByIndex`.
    pub fn context_containing_province(&self, province: ProvinceId) -> Option<OceanZoneId> {
        self.zones.iter().enumerate().find_map(|(ordinal, zone)| {
            zone.zone()
                .secondary_neighbors
                .contains(&province)
                .then_some(OceanZoneId::new(
                    u16::try_from(ordinal).expect("ocean zone ordinal fits a zone id"),
                ))
        })
    }
}

/// The saved semantic state shared by `TZone` and `TPortZone`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Zone {
    pub display_name: String,
    pub status_code: Option<i16>,
    pub target_tile: Option<TileId>,
    pub seed_owner: Option<TileOwnerTag>,
    pub active_tile: Option<TileId>,
    pub primary_neighbors: Vec<OceanZoneId>,
    pub secondary_neighbors: Vec<ProvinceId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PortZone {
    pub zone: Zone,
    pub port_tile: TileId,
}

/// One route-line record in doubled-column strategic-map coordinates.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OceanRoute {
    pub start_column: i32,
    pub start_row: i32,
    pub end_column: i32,
    pub end_row: i32,
}

impl GameState {
    /// Newest-first `TOcean::FindFirstPortZoneContextByNation`.
    pub(crate) fn first_port_zone_for_nation(&self, nation: NationId) -> Option<OceanZoneId> {
        self.ocean
            .zones
            .iter()
            .enumerate()
            .rev()
            .find_map(|(index, kind)| {
                let ZoneKind::PortZone(port) = kind else {
                    return None;
                };
                (self.map[port.port_tile]
                    .former_owner_nation
                    .and_then(TileOwnerTag::nation)
                    == Some(nation))
                .then(|| OceanZoneId::new(index as u16))
            })
    }

    /// `TOcean::FindPortZoneBySelectedTile` using the city's home town tile.
    pub(crate) fn port_zone_for_city_tile(&self, home: TileId) -> Option<OceanZoneId> {
        self.ocean
            .zones
            .iter()
            .enumerate()
            .rev()
            .find_map(|(index, kind)| {
                let ZoneKind::PortZone(port) = kind else {
                    return None;
                };
                (port.zone.target_tile == Some(home)
                    || port.zone.active_tile == Some(home)
                    || port.port_tile == home)
                    .then(|| OceanZoneId::new(index as u16))
            })
    }

    /// `TOcean::EnsurePortZoneForTile` (0x005635e0).
    pub(crate) fn ensure_port_zone_for_tile(&mut self, tile: TileId) {
        const ACTION_STATE_ANCHOR: i16 = 3;
        const ACTION_STATE_DOCKED_FLEET: i16 = 14;
        const ACTION_STATE_PORT_ZONE_MARKER: i16 = -14;
        const SEA_OWNER_BIAS: u8 = 0x17;
        const PORT_ZONE_STATUS_CATEGORY: i16 = 5;
        const PORT_ZONE_HEADLINES: [&str; 4] = ["[1] Bay", "[1] Gulf", "Bay of [1]", "Gulf of [1]"];

        if !self.map[tile].flags.has_base_transport() {
            return;
        }
        if self.port_zone_index_for_tile(tile).is_some() {
            return;
        }
        let Some(seed_owner) = self.map[tile].owner_nation else {
            return;
        };
        let nation_seed = seed_owner.get();
        if let Some(nation) = seed_owner.nation() {
            let home = self.nations.home_tile(nation);
            if let Some(representative) = self
                .map
                .representative_tile_index_for_nation(nation, home, false)
            {
                self.map[representative].action =
                    TileAction::try_from_retail(ACTION_STATE_PORT_ZONE_MARKER);
            }
        }

        let geometry = self.map.geometry();
        let Some(best_sea) = select_live_port_sea_tile(&self.map, geometry, tile, nation_seed)
        else {
            return;
        };

        let linked = if self.map[best_sea].action.is_some_and(|action| {
            matches!(
                action.retail(),
                ACTION_STATE_ANCHOR | ACTION_STATE_DOCKED_FLEET
            )
        }) {
            self.port_zone_index_for_tile(best_sea)
                .map(|index| OceanZoneId::new(index as u16))
        } else {
            self.map[best_sea]
                .owner_nation
                .map(TileOwnerTag::get)
                .filter(|&tag| tag >= SEA_OWNER_BIAS)
                .map(|tag| OceanZoneId::new(u16::from(tag - SEA_OWNER_BIAS)))
        };

        let ordinal = OceanZoneId::new(self.ocean.zones.len() as u16);
        if let Some(linked) = linked {
            let linked_index = usize::from(linked.get());
            if linked_index < self.ocean.zones.len() {
                let neighbor = match &mut self.ocean.zones[linked_index] {
                    ZoneKind::Zone(zone) => &mut zone.primary_neighbors,
                    ZoneKind::PortZone(port) => &mut port.zone.primary_neighbors,
                };
                if !neighbor.contains(&ordinal) {
                    neighbor.push(ordinal);
                }
            }
        }

        self.map[best_sea].action = TileAction::try_from_retail(ACTION_STATE_ANCHOR);
        let primary_neighbors: Vec<OceanZoneId> = linked.into_iter().collect();
        let active_tile = find_nearest_active_sea_context_tile(
            &self.map,
            &self.ocean,
            best_sea,
            primary_neighbors.first().copied(),
        );
        let status_code =
            PORT_ZONE_STATUS_CATEGORY * 4 + (self.rng.next_zone_status_sample_15() & 3) as i16;
        let province_name = self.map[tile]
            .province
            .map(|province| self.map.provinces[province].name.clone())
            .unwrap_or_default();
        let template = PORT_ZONE_HEADLINES
            .get(usize::try_from(status_code - PORT_ZONE_STATUS_CATEGORY * 4).unwrap_or(0))
            .copied()
            .unwrap_or("[1] Bay");
        let display_name = template.replace("[1]", &province_name);

        self.ocean.zones.push(ZoneKind::PortZone(PortZone {
            zone: Zone {
                display_name,
                status_code: Some(status_code),
                target_tile: Some(best_sea),
                seed_owner: Some(seed_owner),
                active_tile,
                primary_neighbors,
                secondary_neighbors: Vec::new(),
            },
            port_tile: tile,
        }));

        for nation in MajorNationId::all() {
            if let Some(auto) = self.nations.major_mut(nation).auto.as_mut()
                && auto.zone_targets.len() == usize::from(ordinal.get())
            {
                auto.zone_targets.push(AiTargetState::Unmarked);
            }
        }
    }

    fn port_zone_index_for_tile(&self, tile: TileId) -> Option<usize> {
        self.ocean
            .zones
            .iter()
            .enumerate()
            .rev()
            .find_map(|(index, kind)| {
                let ZoneKind::PortZone(port) = kind else {
                    return None;
                };
                (port.port_tile == tile
                    || port.zone.target_tile == Some(tile)
                    || port.zone.active_tile == Some(tile))
                .then_some(index)
            })
    }
}

fn select_live_port_sea_tile(
    world: &MapMgr,
    geometry: MapGeometry,
    tile: TileId,
    nation_seed: u8,
) -> Option<TileId> {
    const SEA_OWNER_BIAS: u8 = 0x17;

    let tile_index = usize::from(tile.get());
    for offset in 0..6 {
        let direction = HexDirection::ALL[(tile_index + offset) % 6];
        let Some(candidate) = geometry.neighbor(tile, direction) else {
            continue;
        };
        if world[candidate].terrain != TerrainKind::Water {
            continue;
        }
        let all_neighbors_qualify = HexDirection::ALL.iter().all(|&neighbor_dir| {
            let neighbor = civilian_sea_scan_neighbor(candidate, neighbor_dir);
            !matches!(
                world[neighbor].owner_nation,
                Some(owner) if owner.get() < SEA_OWNER_BIAS && owner.get() != nation_seed
            )
        });
        if all_neighbors_qualify {
            return Some(candidate);
        }
    }
    crate::city_site::trace_terrain_flow_to_nearest_sea_tile(world, tile)
}

fn find_nearest_active_sea_context_tile(
    world: &MapMgr,
    ocean: &Ocean,
    origin: TileId,
    expected: Option<OceanZoneId>,
) -> Option<TileId> {
    const ACTION_STATE_ANCHOR: i16 = 3;
    const ACTION_STATE_DOCKED_FLEET: i16 = 14;
    const SEA_OWNER_BIAS: u8 = 0x17;

    let geometry = world.geometry();
    let (row, column) = geometry.row_column(origin);
    let mut row = i32::from(row);
    let mut column = i32::from(column);
    let mut ring = 0_i32;
    let mut direction = HexDirection::NorthWest;
    let mut step_in_ring = 1_i32;

    advance_port_zone_spiral(
        &mut row,
        &mut column,
        &mut ring,
        &mut direction,
        &mut step_in_ring,
        world.topology,
    );
    while ring < 10 {
        if (0..i32::from(STRATEGIC_MAP_HEIGHT)).contains(&row)
            && (0..i32::from(STRATEGIC_MAP_WIDTH)).contains(&column)
        {
            let candidate = geometry
                .tile(row as u16, column as u16)
                .expect("checked spiral coordinates are on the strategic map");
            let candidate_context = if world[candidate].action.is_some_and(|action| {
                matches!(
                    action.retail(),
                    ACTION_STATE_ANCHOR | ACTION_STATE_DOCKED_FLEET
                )
            }) {
                ocean
                    .zones
                    .iter()
                    .enumerate()
                    .rev()
                    .find_map(|(index, kind)| {
                        let ZoneKind::PortZone(port) = kind else {
                            return None;
                        };
                        (port.port_tile == candidate
                            || port.zone.target_tile == Some(candidate)
                            || port.zone.active_tile == Some(candidate))
                        .then(|| OceanZoneId::new(index as u16))
                    })
            } else {
                world[candidate]
                    .owner_nation
                    .map(TileOwnerTag::get)
                    .filter(|&tag| tag >= SEA_OWNER_BIAS)
                    .map(|tag| OceanZoneId::new(u16::from(tag - SEA_OWNER_BIAS)))
            };
            if candidate_context == expected && world[candidate].action.is_none() {
                return Some(candidate);
            }
        }
        advance_port_zone_spiral(
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

fn advance_port_zone_spiral(
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
            step_port_zone_row_column(row, column, HexDirection::West, topology);
        }
    }
    step_port_zone_row_column(row, column, *direction, topology);
}

fn step_port_zone_row_column(
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
        *column = column.rem_euclid(i32::from(STRATEGIC_MAP_WIDTH));
    }
    if matches!(direction, HexDirection::NorthWest | HexDirection::NorthEast) {
        *row -= 1;
    } else if matches!(direction, HexDirection::SouthWest | HexDirection::SouthEast) {
        *row += 1;
    }
}
