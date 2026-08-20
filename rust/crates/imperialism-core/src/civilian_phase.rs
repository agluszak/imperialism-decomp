//! Resource-yield reconstruction from currently linked city territory.

use crate::*;

impl GameState {
    /// Rebuilds one major nation's transportable resource supply from its
    /// currently linked city territory.
    ///
    /// Retail invokes this immediately before opening the Transport screen and
    /// again from city/transport turn resolution. Targets that no longer fit
    /// the rebuilt supply are reduced through the same reserved-capacity seam
    /// used by player allocation.
    pub fn rebuild_nation_resource_yields(&mut self, nation: MajorNationId) {
        let (_transport_influence, town_transport_linked) = self
            .transport_influence(nation)
            .expect("resource-yield rebuild requires the nation's home town marker");

        let mut influence = vec![0_u8; STRATEGIC_TILE_COUNT];
        let major = &self.nations.majors[&nation];
        for ((&town_tile, town), &linked) in major.towns.iter().zip(&town_transport_linked) {
            if !linked {
                continue;
            }
            let level = u8::from(town.enabled != 0) + 1;
            influence[usize::from(town_tile.get())] = level;
            let owner = Some(TileOwnerTag::from_nation(nation.nation()));
            for neighbor in self
                .map
                .geometry()
                .neighbors(town_tile)
                .into_iter()
                .flatten()
            {
                let tile = &self.map[neighbor];
                let entry = &mut influence[usize::from(neighbor.get())];
                if (tile.owner_nation == owner || tile.gate == 0) && *entry < level {
                    *entry = level;
                }
            }
        }

        let mut current = ResourceTable::<i16>::default();
        for (index, &level) in influence.iter().enumerate() {
            if level == 0 {
                continue;
            }
            let tile_id = TileId::new(index as u16);
            let tile = &self.map[tile_id];
            if tile.gate == 0 {
                if level == 2 {
                    current[ResourceKind::Fish] = current[ResourceKind::Fish].wrapping_add(1);
                }
                continue;
            }

            for resource in tile.edge_resources.into_iter().flatten() {
                let development = if matches!(
                    resource,
                    ResourceKind::Coal
                        | ResourceKind::Iron
                        | ResourceKind::Oil
                        | ResourceKind::Gems
                        | ResourceKind::Gold
                ) {
                    tile.development.extractive.get()
                } else {
                    tile.development.surface.get()
                };
                let contribution = resource_development_yield(resource, development);
                current[resource] = current[resource].wrapping_add(contribution);
            }

            if tile.river().is_some() && level == 2 {
                current[ResourceKind::Fish] = current[ResourceKind::Fish].wrapping_add(1);
            }
            if let Some(province) = tile.province
                && self.map.provinces[province].city_tile() == Some(tile_id)
            {
                for resource in ResourceKind::CITY_PRODUCTION {
                    current[resource] = current[resource].wrapping_add(
                        self.map.provinces[province].resource_development_by_type()[resource],
                    );
                }
            }
        }

        let major = &mut self.nations.majors[&nation];
        for ((_, town), linked) in major.towns.iter_mut().zip(town_transport_linked) {
            town.transport_linked = linked;
        }
        major.economy.need_current_by_type = current;
        for resource in all_resources() {
            if major.economy.need_current_by_type[resource]
                < major.economy.need_target_by_type[resource]
            {
                major
                    .economy
                    .update_need_target(resource, major.economy.need_current_by_type[resource]);
            }
        }
        if major.is_auto() {
            let fish = major.economy.need_current_by_type[ResourceKind::Fish];
            major.economy.need_current_by_type[ResourceKind::Fish] = 0;
            major.economy.need_current_by_type[ResourceKind::Livestock] =
                major.economy.need_current_by_type[ResourceKind::Livestock].wrapping_add(fish);
        }
    }

    pub(crate) fn apply_town_transport_links(&mut self, nation: MajorNationId) -> Option<Vec<u8>> {
        let (influence, town_transport_linked) = self.transport_influence(nation)?;
        for ((_, town), linked) in self.nations.majors[&nation]
            .towns
            .iter_mut()
            .zip(town_transport_linked)
        {
            town.transport_linked = linked;
        }
        Some(influence)
    }

    pub fn can_build_port_at_tile(&self, tile: TileId) -> bool {
        let mut can_build = false;
        if !matches!(
            self.map[tile].terrain,
            TerrainKind::Mountain | TerrainKind::Hills
        ) {
            for direction in HexDirection::ALL {
                if self.map[civilian_sea_scan_neighbor(tile, direction)].terrain
                    == TerrainKind::Water
                {
                    can_build = true;
                    break;
                }
            }
        }
        if !can_build
            && self.map[tile].river().is_some()
            && river_reaches_sea_without_crossing_nation(&self.map, tile)
        {
            can_build = true;
        }
        can_build
    }

    /// Retail `TGreatPower::BuildTransportLinkedInfluenceMap` over the complete
    /// ordered `townMarkerList`.
    pub(crate) fn transport_influence(
        &self,
        nation: MajorNationId,
    ) -> Option<(Vec<u8>, Vec<bool>)> {
        let major = self.nations.major(nation);
        let home_tile = major.common.home_tile?;
        let home_town = major.towns.get(&home_tile)?;
        let unblocked_ports = major
            .towns
            .iter()
            .map(|(&tile, town)| {
                town.enabled != 0 && self.has_reachable_sea_outside_beginning_turn_mask(tile)
            })
            .collect::<Vec<_>>();
        let mut influence = vec![0_u8; STRATEGIC_TILE_COUNT];

        let mut home_linked =
            home_town.enabled != 0 && self.has_reachable_sea_outside_beginning_turn_mask(home_tile);
        if !home_linked {
            self.mark_transport_component(nation, home_tile, &mut influence);
            for ((&tile, _), &unblocked_port) in major.towns.iter().zip(&unblocked_ports) {
                if influence[usize::from(tile.get())] != 0 && unblocked_port {
                    home_linked = true;
                    break;
                }
            }
        }

        for ((&tile, town), &unblocked_port) in major.towns.iter().zip(&unblocked_ports) {
            if unblocked_port
                && home_linked
                && town.active
                && influence[usize::from(tile.get())] == 0
            {
                self.mark_transport_component(nation, tile, &mut influence);
            }
        }

        let linked = major
            .towns
            .iter()
            .zip(&unblocked_ports)
            .map(|((&tile, town), &unblocked_port)| {
                !((influence[usize::from(tile.get())] == 0 || !town.active)
                    && (!unblocked_port || !home_linked))
            })
            .collect::<Vec<_>>();

        if home_linked {
            for ((&tile, _), &unblocked_port) in major.towns.iter().zip(&unblocked_ports) {
                if unblocked_port {
                    influence[usize::from(tile.get())] = 1;
                }
            }
        }
        Some((influence, linked))
    }

    fn mark_transport_component(&self, nation: MajorNationId, start: TileId, influence: &mut [u8]) {
        let owner = Some(TileOwnerTag::from_nation(nation.nation()));
        let geometry = self.map.geometry();
        let mut pending = vec![start];
        while let Some(tile) = pending.pop() {
            let index = usize::from(tile.get());
            if influence[index] != 0 {
                continue;
            }
            influence[index] = 1;
            for direction in HexDirection::ALL.into_iter().rev() {
                if !self.map[tile]
                    .transport_links
                    .contains(TileTransportLinks::for_direction(direction))
                {
                    continue;
                }
                if let Some(neighbor) = geometry.neighbor(tile, direction)
                    && influence[usize::from(neighbor.get())] == 0
                    && self.map[neighbor].owner_nation == owner
                {
                    pending.push(neighbor);
                }
            }
        }
    }

    pub(crate) fn has_reachable_sea_outside_beginning_turn_mask(&self, tile: TileId) -> bool {
        let origin_nation = self.map[tile]
            .owner_nation
            .and_then(TileOwnerTag::nation)
            .expect("a town marker must remain on nation-owned territory");
        for direction in HexDirection::ALL {
            let neighbor = civilian_sea_scan_neighbor(tile, direction);
            if self.map[neighbor].terrain == TerrainKind::Water {
                return self.sea_zone_allows_port_access(neighbor, origin_nation);
            }
        }
        if self.map[tile].river().is_none()
            || !river_reaches_sea_without_crossing_nation(&self.map, tile)
        {
            return false;
        }
        let sea_tile = trace_terrain_flow_to_nearest_sea_tile(&self.map, tile)
            .expect("a boundary-safe retail terrain flow must terminate at sea");
        self.sea_zone_allows_port_access(sea_tile, origin_nation)
    }

    /// `TZone::HasDiplomaticallyRelatedNationInActiveType3Or4OrderMask`.
    fn sea_zone_allows_port_access(&self, sea_tile: TileId, origin_nation: NationId) -> bool {
        const SEA_OWNER_BIAS: u8 = 0x17;

        let owner = self.map[sea_tile]
            .owner_nation
            .expect("reachable sea tile must name its ocean context")
            .get();
        let zone = OceanZoneId::new(u16::from(
            owner
                .checked_sub(SEA_OWNER_BIAS)
                .expect("sea owner tag must name a base ocean zone"),
        ));
        let mut active_nations = 0_u32;
        for (&ship_id, ship) in &self.ships {
            if ship.location != zone {
                continue;
            }
            let Some(task_force) = self.task_force_of_ship(ship_id) else {
                continue;
            };
            let Some(task_force) = self.task_force(task_force) else {
                continue;
            };
            if !task_force.defeated
                && matches!(
                    task_force.order,
                    TaskForceOrder::Patrol | TaskForceOrder::Transit
                )
            {
                active_nations |= 1_u32 << ship.nation.get();
            }
        }

        let origin_bit = 1_u32 << origin_nation.get();
        if active_nations & origin_bit != 0 {
            return true;
        }
        for candidate in MajorNationId::all().map(MajorNationId::nation) {
            if active_nations & (1_u32 << candidate.get()) == 0 {
                continue;
            }
            if self.diplomacy.relationships[candidate][origin_nation] == DiplomaticRelationship::War
                && self.diplomacy.relationship_turns[candidate][origin_nation]
                    .is_none_or(|turn| i32::from(turn) != self.turn.economic_turn)
            {
                return false;
            }
        }
        true
    }
}

/// `TMapMgr::GetNeighborTileID` and the inlined port/sea predicates: doubled-column
/// wrap and vertical clamp, ignoring session topology.
pub(crate) fn civilian_sea_scan_neighbor(tile: TileId, direction: HexDirection) -> TileId {
    const COLUMN_X2_DELTAS: HexDirectionTable<i32> =
        HexDirectionTable::from_array([1, 2, 1, -1, -2, -1]);
    const ROW_DELTAS: HexDirectionTable<i32> = HexDirectionTable::from_array([-1, 0, 1, 1, 0, -1]);
    const RASTER_WIDTH: i32 = STRATEGIC_MAP_WIDTH as i32 * 2;

    let row = i32::from(tile.get() / STRATEGIC_MAP_WIDTH);
    let column = i32::from(tile.get() % STRATEGIC_MAP_WIDTH);
    let mut column_x2 = row % 2 + column * 2 + COLUMN_X2_DELTAS[direction];
    let row = (row + ROW_DELTAS[direction]).clamp(0, i32::from(STRATEGIC_MAP_HEIGHT) - 1);
    if column_x2 >= RASTER_WIDTH {
        column_x2 -= RASTER_WIDTH + 1;
    } else if column_x2 < 0 {
        column_x2 += RASTER_WIDTH;
    }
    let index = column_x2 / 2 + row * i32::from(STRATEGIC_MAP_WIDTH);
    TileId::new(u16::try_from(index).expect("retail sea scan produced a valid tile"))
}

fn river_reaches_sea_without_crossing_nation(world: &MapMgr, start: TileId) -> bool {
    const FLOW_DIRECTIONS: [[HexDirection; 2]; 9] = [
        [HexDirection::NorthEast, HexDirection::SouthEast],
        [HexDirection::NorthEast, HexDirection::SouthWest],
        [HexDirection::NorthEast, HexDirection::West],
        [HexDirection::East, HexDirection::SouthWest],
        [HexDirection::East, HexDirection::West],
        [HexDirection::East, HexDirection::NorthWest],
        [HexDirection::SouthEast, HexDirection::West],
        [HexDirection::SouthEast, HexDirection::NorthWest],
        [HexDirection::SouthWest, HexDirection::NorthWest],
    ];

    let geometry = world.geometry();
    let start_owner = world[start].owner_nation;
    let flow_type = match world[start].river().and_then(|river| river.flow_type()) {
        Some(flow_type) => flow_type,
        None => return false,
    };
    for (attempt, mut direction) in FLOW_DIRECTIONS[flow_type].into_iter().enumerate() {
        let mut crossed_boundary = false;
        let mut current = start;
        for _ in 0..100 {
            let Some(next) = geometry.neighbor(current, direction) else {
                return !crossed_boundary;
            };
            current = next;
            let tile = &world[current];
            if tile.terrain == TerrainKind::Water {
                return !crossed_boundary;
            }
            let Some(next_flow_type) = tile.river().and_then(|river| river.flow_type()) else {
                break;
            };
            if tile.owner_nation != start_owner {
                if attempt != 0 {
                    return false;
                }
                crossed_boundary = true;
            }
            let incoming = direction.opposite();
            let pair = FLOW_DIRECTIONS[next_flow_type];
            direction = if pair[0] == incoming {
                pair[1]
            } else if pair[1] == incoming {
                pair[0]
            } else {
                break;
            };
        }
    }
    false
}

/// Retail `TraceTerrainFlowToNearestSeaTile`; unlike the boundary check above,
/// this walk ignores ownership and returns the sea context selected by flow variant order.
fn trace_terrain_flow_to_nearest_sea_tile(world: &MapMgr, start: TileId) -> Option<TileId> {
    const FLOW_DIRECTIONS: [[HexDirection; 2]; 9] = [
        [HexDirection::NorthEast, HexDirection::SouthEast],
        [HexDirection::NorthEast, HexDirection::SouthWest],
        [HexDirection::NorthEast, HexDirection::West],
        [HexDirection::East, HexDirection::SouthWest],
        [HexDirection::East, HexDirection::West],
        [HexDirection::East, HexDirection::NorthWest],
        [HexDirection::SouthEast, HexDirection::West],
        [HexDirection::SouthEast, HexDirection::NorthWest],
        [HexDirection::SouthWest, HexDirection::NorthWest],
    ];

    let geometry = world.geometry();
    let flow_type = world[start].river().and_then(RiverSegment::flow_type)?;
    for mut direction in FLOW_DIRECTIONS[flow_type] {
        let mut current = start;
        for _ in 0..100 {
            let Some(next) = geometry.neighbor(current, direction) else {
                break;
            };
            current = next;
            if world[current].terrain == TerrainKind::Water {
                return Some(current);
            }
            let Some(next_flow_type) = world[current].river().and_then(RiverSegment::flow_type)
            else {
                break;
            };
            let incoming = direction.opposite();
            let pair = FLOW_DIRECTIONS[next_flow_type];
            direction = if pair[0] == incoming {
                pair[1]
            } else if pair[1] == incoming {
                pair[0]
            } else {
                break;
            };
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_rebuild_updates_every_town_in_retail_list_order() {
        let mut state = crate::test_support::game_state();
        let nation = MajorNationId::new(0);
        let home = TileId::new(100);
        let second = state
            .map
            .geometry()
            .neighbor(home, HexDirection::East)
            .unwrap();
        let owner = Some(TileOwnerTag::from_nation(nation.nation()));
        state.map[home].owner_nation = owner;
        state.map[second].owner_nation = owner;
        state.map[home]
            .transport_links
            .insert(TileTransportLinks::for_direction(HexDirection::East));
        state.map[second]
            .transport_links
            .insert(TileTransportLinks::for_direction(HexDirection::West));

        let major = &mut state.nations.majors[&nation];
        major.common.home_tile = Some(home);
        major.towns = [
            (home, TownState::for_frog_city(home, nation.nation())),
            (
                second,
                TownState {
                    name: "Altown".to_owned(),
                    needs_naming: false,
                    created_turn: 2,
                    owner_nation: nation.nation(),
                    resource_yield_by_type: ResourceTable::default(),
                    transport_linked: false,
                    enabled: 1,
                    has_adjacent_city: 0,
                    active: true,
                },
            ),
        ]
        .into_iter()
        .collect();

        state.rebuild_nation_resource_yields(nation);

        assert_eq!(
            state.nations.majors[&nation]
                .towns
                .iter()
                .map(|(_, town)| town.transport_linked)
                .collect::<Vec<_>>(),
            [true, true]
        );
    }

    #[test]
    fn port_access_obeys_active_type_three_and_four_war_orders() {
        let mut state = crate::test_support::game_state();
        let home = TileId::new(2_210);
        let origin = NationId::new(6);
        state.map[home].owner_nation = Some(TileOwnerTag::from_nation(origin));
        for direction in HexDirection::ALL {
            let neighbor = civilian_sea_scan_neighbor(home, direction);
            state.map[neighbor].terrain = TerrainKind::Plains;
        }
        let sea = civilian_sea_scan_neighbor(home, HexDirection::NorthEast);
        state.map[sea].terrain = TerrainKind::Water;
        state.map[sea].owner_nation = Some(TileOwnerTag::new(0x17));

        state.turn.economic_turn = 10;
        let hostile = NationId::new(0);
        state.diplomacy.relationships[hostile][origin] = DiplomaticRelationship::War;
        state.diplomacy.relationship_turns[hostile][origin] = Some(9);
        state.task_forces.insert(
            TaskForceId::new(0),
            TaskForceState {
                aggression: NavalAggression::Balanced,
                order: TaskForceOrder::Patrol,
                target: TaskForceTarget::None,
                location: OceanZoneId::new(0),
                nation: hostile,
                defeated: false,
                ingot_tile: -1,
                flagship: None,
                ships: [(ShipId::new(0), true)].into_iter().collect(),
            },
        );
        state.ships.insert(
            ShipId::new(0),
            ShipState {
                ship_type: ShipType::Frigate,
                location: OceanZoneId::new(0),
                aggression: NavalAggression::Balanced,
                nation: hostile,
                name: String::new(),
                strength: 1,
                experience: 0,
                selection: ShipSelection::Available,
            },
        );

        assert!(!state.has_reachable_sea_outside_beginning_turn_mask(home));

        state.diplomacy.relationship_turns[hostile][origin] = Some(10);
        assert!(state.has_reachable_sea_outside_beginning_turn_mask(home));

        state.diplomacy.relationship_turns[hostile][origin] = Some(9);
        state.task_forces[&TaskForceId::new(0)].defeated = true;
        assert!(state.has_reachable_sea_outside_beginning_turn_mask(home));
    }
}
