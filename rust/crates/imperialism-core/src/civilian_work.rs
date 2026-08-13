use crate::*;

/// A recovered civilian work-order kind.
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CivilianWorkOrder {
    Idle,
    Redeploy {
        destination: TileId,
        turns: TurnsRemaining,
    },
    Sleep,
    LayRail {
        segment: RailSegment,
        turns: TurnsRemaining,
    },
    BuildDepot {
        turns: TurnsRemaining,
    },
    BuildPort {
        turns: TurnsRemaining,
    },
    Prospect {
        turns: TurnsRemaining,
    },
    DevelopResource {
        turns: TurnsRemaining,
    },
    BuildFort {
        turns: TurnsRemaining,
    },
    PurchaseLand {
        turns: TurnsRemaining,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(transparent)]
pub struct TurnsRemaining(i16);

impl<'de> serde::Deserialize<'de> for TurnsRemaining {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = <i16 as serde::Deserialize>::deserialize(deserializer)?;
        Self::try_new(value).ok_or_else(|| {
            serde::de::Error::custom("civilian work orders require a positive turn count")
        })
    }
}
impl TurnsRemaining {
    pub const fn try_new(value: i16) -> Option<Self> {
        if value > 0 { Some(Self(value)) } else { None }
    }

    pub const fn get(self) -> i16 {
        self.0
    }
    fn advance(&mut self) -> bool {
        self.0 -= 1;
        self.0 == 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct RailSegment {
    origin: TileId,
    destination: TileId,
    direction: HexDirection,
}

impl<'de> serde::Deserialize<'de> for RailSegment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct SerializedRailSegment {
            origin: TileId,
            destination: TileId,
            direction: HexDirection,
        }

        let segment = SerializedRailSegment::deserialize(deserializer)?;
        let valid = Self::between(
            crate::MapTopology::Wrapping,
            segment.origin,
            segment.destination,
        )
        .is_some_and(|valid| valid.direction == segment.direction);
        valid
            .then_some(Self {
                origin: segment.origin,
                destination: segment.destination,
                direction: segment.direction,
            })
            .ok_or_else(|| serde::de::Error::custom("rail segment is not an adjacent direction"))
    }
}
impl RailSegment {
    pub fn between(
        topology: crate::MapTopology,
        origin: TileId,
        destination: TileId,
    ) -> Option<Self> {
        let direction = crate::MapGeometry::new(topology).direction_to(origin, destination)?;
        Some(Self {
            origin,
            destination,
            direction,
        })
    }
    pub const fn origin(self) -> TileId {
        self.origin
    }
    pub const fn destination(self) -> TileId {
        self.destination
    }
    pub const fn direction(self) -> HexDirection {
        self.direction
    }
}

/// Why a player rail-construction order was not issued.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RailOrderRejection {
    /// The unit is missing, not an engineer, off-map, or already working.
    IneligibleUnit,
    /// The destination fails adjacency, ownership, terrain, existing-rail, or
    /// bounded wrap-edge checks recovered from `DimByEngineering` / tile dispatch.
    InvalidTarget,
    /// The owner cannot cover the destination terrain's rail cost.
    InsufficientFunds,
}

const RAIL_TURNS: i16 = 1;

const fn rail_cost(terrain: TerrainKind) -> i32 {
    match terrain {
        TerrainKind::Plains => 100,
        TerrainKind::Forest => 150,
        TerrainKind::Hills => 200,
        TerrainKind::Mountain => 400,
        TerrainKind::Swamp => 300,
        TerrainKind::Water => 0,
        TerrainKind::Desert => 150,
        TerrainKind::Farmland => 100,
    }
}

impl GameState {
    /// Issues one player rail-construction order.
    ///
    /// Retail `HandleEngineerConstructionAction` for an adjacent click: charge
    /// the destination terrain cost, write both pending-rail endpoints, queue
    /// `LayRail` for one turn, and move the engineer onto the destination.
    pub fn order_rail_construction(
        &mut self,
        unit: CivilianUnitId,
        destination: TileId,
    ) -> Result<(), RailOrderRejection> {
        let index = self.civilian_index(unit);
        let (segment, nation) = self.rail_construction_target(index, destination)?;
        let cost = rail_cost(self.map[segment.destination()].terrain);
        let major = self.nations.major(nation);
        if major
            .economy
            .available_diplomacy_budget(major.common.treasury)
            < cost
        {
            return Err(RailOrderRejection::InsufficientFunds);
        }
        self.nations.major_mut(nation).common.treasury -= cost;
        self.map[segment.origin()]
            .pending_rail_links
            .insert_direction(segment.direction());
        self.map[segment.destination()]
            .pending_rail_links
            .insert_direction(segment.direction().opposite());
        let unit = &mut self.civilian_units[index];
        unit.location = CivilianLocation::OnMap(segment.destination());
        unit.order = CivilianWorkOrder::LayRail {
            segment,
            turns: TurnsRemaining::try_new(RAIL_TURNS).expect("rail construction lasts one turn"),
        };
        Ok(())
    }

    /// Neighbor tiles `DimByEngineering` would leave undimmed for a rail click.
    pub fn rail_construction_destinations(&self, unit: CivilianUnitId) -> [Option<TileId>; 6] {
        let index = self.civilian_index(unit);
        let Some(origin) = self.civilian_units[index].location.tile() else {
            return [None; 6];
        };
        MapGeometry::new(MapTopology::Bounded)
            .neighbors(origin)
            .map(|destination| {
                destination.filter(|&destination| {
                    self.rail_construction_target(index, destination).is_ok()
                })
            })
    }

    /// The idle-selectable engineer of `nation` standing on `tile`, if any.
    pub fn selectable_engineer_on_tile(
        &self,
        tile: TileId,
        nation: NationId,
    ) -> Option<CivilianUnitId> {
        self.civilian_units.iter().find_map(|unit| {
            (unit.owner_nation() == nation
                && unit.unit_type() == CivilianUnitKind::Engineer
                && unit.location().tile() == Some(tile)
                && idle_selectable(unit.order()))
            .then_some(unit.id())
        })
    }

    fn civilian_index(&self, unit: CivilianUnitId) -> usize {
        self.civilian_units
            .iter()
            .position(|candidate| candidate.id == unit)
            .expect("rail order references a present unit")
    }

    fn rail_construction_target(
        &self,
        index: usize,
        destination: TileId,
    ) -> Result<(RailSegment, MajorNationId), RailOrderRejection> {
        let unit = &self.civilian_units[index];
        if unit.unit_type != CivilianUnitKind::Engineer || !idle_selectable(&unit.order) {
            return Err(RailOrderRejection::IneligibleUnit);
        }
        let origin = unit
            .location
            .tile()
            .ok_or(RailOrderRejection::IneligibleUnit)?;
        let nation = MajorNationId::from_nation(unit.owner_nation)
            .expect("engineers belong to a major nation");
        // DimByEngineering walks BuildHexAreaTileIndexList, which does not wrap.
        let segment = RailSegment::between(MapTopology::Bounded, origin, destination)
            .ok_or(RailOrderRejection::InvalidTarget)?;
        if bounded_seam_tile(&self.map, destination) {
            return Err(RailOrderRejection::InvalidTarget);
        }
        let access =
            self.technology.city_capabilities_by_nation[nation].primary_civilian_distance_terrain;
        if !rail_terrain_allowed(self.map[origin].terrain, access)
            || !rail_terrain_allowed(self.map[destination].terrain, access)
        {
            return Err(RailOrderRejection::InvalidTarget);
        }
        if self.map[destination].owner_nation != Some(TileOwnerTag::from_nation(unit.owner_nation))
        {
            return Err(RailOrderRejection::InvalidTarget);
        }
        if self.map[origin]
            .transport_links
            .contains(TileTransportLinks::for_direction(segment.direction()))
        {
            return Err(RailOrderRejection::InvalidTarget);
        }
        Ok((segment, nation))
    }

    /// Retail `TSimMgr::DoCivilians`.
    pub fn do_civilians(&mut self) {
        self.resolve_civilian_disputes();
        for index in 0..MajorNationId::COUNT {
            let nation = MajorNationId::new(index);
            if !self.nation_eligible_for_optional_phase(nation) {
                continue;
            }
            self.move_civilians(nation);
        }
    }

    fn move_civilians(&mut self, nation: MajorNationId) {
        self.continue_civilian_orders(nation);
        self.sort_tracked_civilian_orders(nation);
    }

    fn continue_civilian_orders(&mut self, nation: MajorNationId) {
        let nation = nation.nation();
        let ids: Vec<_> = self
            .civilian_units
            .iter()
            .filter(|unit| unit.nation == nation)
            .map(|unit| unit.id)
            .collect();
        for id in ids {
            self.advance_civilian_work(id);
        }
    }

    /// `TGreatPower::SortTrackedOrdersByTypePriority` over one nation's civilians.
    fn sort_tracked_civilian_orders(&mut self, nation: MajorNationId) {
        let nation = nation.nation();
        let indices: Vec<usize> = self
            .civilian_units
            .iter()
            .enumerate()
            .filter(|(_, unit)| unit.nation == nation)
            .map(|(index, _)| index)
            .collect();
        for outer in 0..indices.len() {
            for inner in outer + 1..indices.len() {
                if civilian_kind_sort_priority(self.civilian_units[indices[inner]].unit_type)
                    < civilian_kind_sort_priority(self.civilian_units[indices[outer]].unit_type)
                {
                    let left = indices[outer];
                    let right = indices[inner];
                    self.civilian_units.swap(left, right);
                }
            }
        }
    }

    fn resolve_civilian_disputes(&mut self) {
        for index in 0..STRATEGIC_TILE_COUNT {
            let tile = TileId::new(index as u16);
            let competing: Vec<usize> = self
                .civilian_units
                .iter()
                .enumerate()
                .filter(|(_, unit)| {
                    unit.unit_type == CivilianUnitKind::Developer
                        && matches!(unit.order, CivilianWorkOrder::PurchaseLand { .. })
                        && unit.location.tile() == Some(tile)
                })
                .map(|(index, _)| index)
                .collect();
            if competing.len() <= 1 {
                continue;
            }

            let Some(tile_owner) = self.map[tile].owner_nation.and_then(TileOwnerTag::nation)
            else {
                continue;
            };
            let mut winner = competing[0];
            let mut winning_standing =
                self.diplomacy.standings[self.civilian_units[winner].owner_nation][tile_owner];
            for &candidate in &competing[1..] {
                let standing = self.diplomacy.standings
                    [self.civilian_units[candidate].owner_nation][tile_owner];
                if standing > winning_standing
                    || (standing == winning_standing && self.rng.next_crt_rand() & 1 != 0)
                {
                    winner = candidate;
                    winning_standing = standing;
                }
            }

            let refund = self.developer_tile_purchase_cost(tile);
            let winner_owner = self.civilian_units[winner].owner_nation;
            for &loser in &competing {
                if loser == winner {
                    continue;
                }
                let losing_nation = self.civilian_units[loser].owner_nation;
                self.civilian_units[loser].order = CivilianWorkOrder::Idle;
                if let Some(owner) = MajorNationId::from_nation(losing_nation) {
                    self.nations.majors[owner].common.treasury += refund;
                    if self.nations.majors[owner].economy.diplomacy_eligible {
                        self.pending.nations[owner].turn_start_events.push(
                            TurnStartEvent::LandSale {
                                tag: LAND_SALE_TAG,
                                sale: LandSale {
                                    tile,
                                    nation: winner_owner,
                                },
                            },
                        );
                    }
                }
            }
        }
    }

    pub fn advance_civilian_work(&mut self, civilian: CivilianUnitId) {
        let index = self
            .civilian_units
            .iter()
            .position(|unit| unit.id == civilian)
            .expect("scheduled civilian work references a present unit");
        match &mut self.civilian_units[index].order {
            CivilianWorkOrder::Sleep => {}
            CivilianWorkOrder::Idle | CivilianWorkOrder::Redeploy { .. } => {
                self.civilian_units[index].order = CivilianWorkOrder::Idle;
            }
            CivilianWorkOrder::LayRail { segment, turns } => {
                let segment = *segment;
                if turns.advance() {
                    self.complete_rail_construction(index, segment);
                }
            }
            CivilianWorkOrder::DevelopResource { turns } => {
                if turns.advance() {
                    self.complete_resource_development(index);
                }
            }
            CivilianWorkOrder::BuildDepot { turns } => {
                if turns.advance() {
                    self.complete_depot_construction(index);
                }
            }
            CivilianWorkOrder::BuildPort { turns } => {
                if turns.advance() {
                    self.complete_port_construction(index);
                }
            }
            CivilianWorkOrder::Prospect { turns } => {
                if turns.advance() {
                    self.complete_prospecting(index);
                }
            }
            CivilianWorkOrder::BuildFort { turns } => {
                if turns.advance() {
                    self.complete_fort_construction(index);
                }
            }
            CivilianWorkOrder::PurchaseLand { turns } => {
                if turns.advance() {
                    self.complete_land_purchase(index);
                }
            }
        }
    }

    fn complete_depot_construction(&mut self, index: usize) {
        let tile = self.civilian_units[index]
            .location
            .tile()
            .expect("depot orders are on-map");
        let owner = self.civilian_units[index].owner_nation;
        self.queue_depot_construction(tile, owner);
        if let Some(nation) = MajorNationId::from_nation(owner) {
            self.rebuild_nation_resource_yields(nation);
        }
        self.civilian_units[index].order = CivilianWorkOrder::Idle;
    }

    fn complete_port_construction(&mut self, index: usize) {
        let tile = self.civilian_units[index]
            .location
            .tile()
            .expect("port orders are on-map");
        let owner = self.civilian_units[index].owner_nation;
        self.queue_port_construction(tile, owner);
        if let Some(nation) = MajorNationId::from_nation(owner) {
            self.rebuild_nation_resource_yields(nation);
        }
        self.civilian_units[index].order = CivilianWorkOrder::Idle;
    }

    fn complete_prospecting(&mut self, index: usize) {
        let tile = self.civilian_units[index]
            .location
            .tile()
            .expect("prospecting orders are on-map");
        let owner = self.civilian_units[index].owner_nation;
        if let Some(nation) = MajorNationId::from_nation(owner) {
            self.map[tile].development.resource_visible_to_majors[nation] = true;
        }
        self.civilian_units[index].order = CivilianWorkOrder::Idle;
    }

    fn complete_fort_construction(&mut self, index: usize) {
        let tile = self.civilian_units[index]
            .location
            .tile()
            .expect("fort orders are on-map");
        if let Some(province) = self.map[tile].province {
            self.set_province_capital_fort_flag(province);
        }
        self.civilian_units[index].order = CivilianWorkOrder::Idle;
    }

    fn complete_land_purchase(&mut self, index: usize) {
        let tile = self.civilian_units[index]
            .location
            .tile()
            .expect("land-purchase orders are on-map");
        let owner = self.civilian_units[index].owner_nation;
        self.map[tile].secondary_owner_nation = MajorNationId::from_nation(owner);
        self.civilian_units[index].order = CivilianWorkOrder::Idle;
    }

    fn queue_depot_construction(&mut self, tile: TileId, owner: NationId) {
        let Some(nation) = MajorNationId::from_nation(owner) else {
            return;
        };
        if self.map[tile].flags.contains(TileFlags::PORT) {
            if let Some(town) = self.nations.majors[nation]
                .towns
                .iter_mut()
                .find(|town| town.tile == tile)
            {
                town.active = true;
            }
        } else {
            let created_turn = i16::try_from(self.turn.economic_turn).unwrap_or(i16::MAX);
            self.nations.majors[nation]
                .towns
                .push(TownState::constructed(tile, owner, 0, created_turn));
            self.flood_fill_tile_region_marker(tile, TileOwnerTag::from_nation(owner));
        }
        if !self.nations.majors[nation].economy.diplomacy_eligible {
            self.nations.majors[nation].common.treasury -= 2000;
        }
        self.map[tile].flags.insert(TileFlags::DEPOT);
    }

    fn queue_port_construction(&mut self, tile: TileId, owner: NationId) {
        let Some(nation) = MajorNationId::from_nation(owner) else {
            return;
        };
        if self.map[tile].flags.contains(TileFlags::DEPOT) {
            if let Some(town) = self.nations.majors[nation]
                .towns
                .iter_mut()
                .find(|town| town.tile == tile)
            {
                town.enabled = 1;
            }
        } else {
            let created_turn = i16::try_from(self.turn.economic_turn).unwrap_or(i16::MAX);
            self.nations.majors[nation]
                .towns
                .push(TownState::constructed(tile, owner, 1, created_turn));
            self.flood_fill_tile_region_marker(tile, TileOwnerTag::from_nation(owner));
        }
        if !self.nations.majors[nation].economy.diplomacy_eligible {
            self.nations.majors[nation].common.treasury -= 3000;
        }
        self.map[tile].flags.insert(TileFlags::PORT);
        self.ensure_port_zone_for_completed_port(tile);
    }

    fn set_province_capital_fort_flag(&mut self, province: ProvinceId) {
        if let Some(capital) = self.map.provinces[province].city_tile() {
            self.map[capital]
                .flags
                .insert(TileFlags::PROVINCE_CAPITAL_FORTIFICATION);
        }
        self.map.provinces[province].add_fort_level();
    }

    fn flood_fill_tile_region_marker(&mut self, tile: TileId, owner: TileOwnerTag) {
        let marker = crate::city_site::next_region_marker(&self.map);
        self.map[tile].region = Some(marker);
        self.stamp_province_last_turn_tick_if_reserved(tile);
        let neighbors: Vec<_> = self
            .map
            .geometry()
            .neighbors(tile)
            .into_iter()
            .flatten()
            .collect();
        for neighbor in neighbors {
            if self.map[neighbor].owner_nation != Some(owner) {
                continue;
            }
            if self.map[neighbor].region.is_some() {
                continue;
            }
            self.map[neighbor].region = Some(marker);
            self.stamp_province_last_turn_tick_if_reserved(neighbor);
        }
    }

    fn stamp_province_last_turn_tick_if_reserved(&mut self, tile: TileId) {
        if !self.map[tile]
            .flags
            .contains(TileFlags::RECRUITMENT_RESERVED)
        {
            return;
        }
        let Some(province) = self.map[tile].province else {
            return;
        };
        if self.map.provinces[province].last_turn_tick == 999 {
            self.map.provinces[province].last_turn_tick =
                i16::try_from(self.turn.economic_turn).unwrap_or(i16::MAX);
        }
    }

    fn ensure_port_zone_for_completed_port(&mut self, tile: TileId) {
        if !self.map[tile].flags.has_base_transport() {
            return;
        }
        if self.ocean.zones.iter().any(|zone| match zone {
            ZoneKind::PortZone(port) => {
                port.port_tile == tile
                    || port.zone.active_tile == Some(tile)
                    || port.zone.target_tile == Some(tile)
            }
            ZoneKind::Zone(_) => false,
        }) {
            return;
        }
        let geometry = self.map.geometry();
        let Some(sea) = HexDirection::ALL.into_iter().find_map(|direction| {
            geometry
                .neighbor(tile, direction)
                .filter(|&neighbor| self.map[neighbor].terrain == TerrainKind::Water)
        }) else {
            return;
        };
        self.ocean.zones.push(ZoneKind::PortZone(PortZone {
            zone: Zone {
                display_name: String::new(),
                status_code: Some(20),
                target_tile: Some(sea),
                seed_owner: self.map[tile].owner_nation,
                active_tile: None,
                primary_neighbors: Vec::new(),
                secondary_neighbors: Vec::new(),
            },
            port_tile: tile,
        }));
    }

    fn developer_tile_purchase_cost(&self, tile: TileId) -> i32 {
        let mut total = 0;
        for resource in self.map[tile].edge_resources.into_iter().flatten() {
            if let Some(commodity) = TradeCommodity::from_retail(resource as i16) {
                total += self.market.rows[commodity].price * 0x14;
            } else if resource == ResourceKind::Gems {
                total += 10_000;
            } else if resource == ResourceKind::Gold {
                total += 4_000;
            }
        }
        total
    }

    fn complete_resource_development(&mut self, index: usize) {
        let unit = &self.civilian_units[index];
        let tile = unit
            .location
            .tile()
            .expect("development orders are normalized with an on-map location");
        let uses_extractive_development = matches!(
            unit.unit_type,
            CivilianUnitKind::Miner | CivilianUnitKind::Driller
        );

        let tile_state = &mut self.map[tile];
        if uses_extractive_development {
            tile_state.development.extractive.advance();
            tile_state.development.resource_visible_to_majors = MajorNationTable::from_fn(|_| true);
        } else {
            tile_state.development.surface.advance();
        }
        self.civilian_units[index].order = CivilianWorkOrder::Idle;
    }

    /// Completes one retail `LayRail` order.
    ///
    /// A completed rail section becomes a pair of permanent directional
    /// transport links. The pending rail links are placed when the order is
    /// issued and therefore remain unchanged here.
    fn complete_rail_construction(&mut self, index: usize, segment: RailSegment) {
        let source = segment.origin();
        let destination = segment.destination();
        let direction = segment.direction();
        self.map[source].transport_links.insert_direction(direction);
        self.map[destination]
            .transport_links
            .insert_direction(direction.opposite());
        self.civilian_units[index].order = CivilianWorkOrder::Idle;
    }
}

fn idle_selectable(order: &CivilianWorkOrder) -> bool {
    matches!(order, CivilianWorkOrder::Idle | CivilianWorkOrder::Sleep)
}

const LAND_SALE_TAG: i32 = 0x6C61_6E64;

/// `g_DAT_006966d0` priorities indexed by civilian `orderType`.
const fn civilian_kind_sort_priority(kind: CivilianUnitKind) -> i16 {
    [2, 0, 4, 3, 1, 5, 0, 0, 0][kind as usize]
}

fn bounded_seam_tile(map: &MapMgr, tile: TileId) -> bool {
    if map.topology != MapTopology::Bounded {
        return false;
    }
    let (_, column) = map.geometry().row_column(tile);
    column == 0 || column + 1 == STRATEGIC_MAP_WIDTH
}

fn rail_terrain_allowed(terrain: TerrainKind, access: CivilianTerrainAccess) -> bool {
    match terrain {
        TerrainKind::Plains | TerrainKind::Forest | TerrainKind::Desert | TerrainKind::Farmland => {
            true
        }
        TerrainKind::Hills => access.hills,
        TerrainKind::Mountain => access.mountain,
        TerrainKind::Swamp => access.swamp,
        TerrainKind::Water => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn interior() -> (TileId, TileId) {
        let geometry = MapGeometry::new(MapTopology::Bounded);
        let origin = geometry.tile(2, 10).unwrap();
        let destination = geometry.neighbor(origin, HexDirection::East).unwrap();
        (origin, destination)
    }

    fn engineer_on(state: &mut GameState, origin: TileId, destination: TileId) -> CivilianUnitId {
        let nation = NationId::new(0);
        let owner = Some(TileOwnerTag::from_nation(nation));
        state.map[origin].owner_nation = owner;
        state.map[origin].terrain = TerrainKind::Plains;
        state.map[destination].owner_nation = owner;
        state.map[destination].terrain = TerrainKind::Plains;
        let id = CivilianUnitId::new(1);
        state.civilian_units.push(
            CivilianUnitState::new(
                id,
                nation,
                CivilianUnitKind::Engineer,
                CivilianLocation::OnMap(origin),
                CivilianWorkOrder::Idle,
                nation,
                0,
                false,
            )
            .unwrap(),
        );
        id
    }

    #[test]
    fn issuing_rail_writes_both_pending_ends_moves_the_unit_and_completes() {
        let mut state = crate::test_support::game_state();
        let (origin, destination) = interior();
        let unit = engineer_on(&mut state, origin, destination);
        state
            .nations
            .major_mut(MajorNationId::new(0))
            .common
            .treasury = 1_000;
        state.map[origin]
            .pending_rail_links
            .insert_direction(HexDirection::NorthEast);

        state.order_rail_construction(unit, destination).unwrap();

        let east = TileTransportLinks::for_direction(HexDirection::East);
        let west = TileTransportLinks::for_direction(HexDirection::West);
        assert_eq!(
            state.civilian_units[0].location(),
            CivilianLocation::OnMap(destination)
        );
        assert_eq!(
            state.civilian_units[0].order(),
            &CivilianWorkOrder::LayRail {
                segment: RailSegment::between(state.map.topology, origin, destination).unwrap(),
                turns: TurnsRemaining::try_new(1).unwrap(),
            }
        );
        assert!(state.map[origin].pending_rail_links.contains(east));
        assert!(
            state.map[origin]
                .pending_rail_links
                .contains(TileTransportLinks::for_direction(HexDirection::NorthEast))
        );
        assert!(state.map[destination].pending_rail_links.contains(west));
        assert!(!state.map[origin].transport_links.contains(east));
        assert_eq!(
            state.nations.major(MajorNationId::new(0)).common.treasury,
            900
        );

        state.advance_civilian_work(unit);
        assert!(state.map[origin].transport_links.contains(east));
        assert!(state.map[destination].transport_links.contains(west));
        assert_eq!(state.civilian_units[0].order(), &CivilianWorkOrder::Idle);
    }

    #[test]
    fn rejects_unaffordable_and_illegal_rail_targets_without_mutation() {
        let mut state = crate::test_support::game_state();
        let (origin, destination) = interior();
        let unit = engineer_on(&mut state, origin, destination);
        state
            .nations
            .major_mut(MajorNationId::new(0))
            .common
            .treasury = 0;
        assert_eq!(
            state.order_rail_construction(unit, destination),
            Err(RailOrderRejection::InsufficientFunds)
        );

        state
            .nations
            .major_mut(MajorNationId::new(0))
            .common
            .treasury = 1_000;
        state.map[destination].terrain = TerrainKind::Water;
        assert_eq!(
            state.order_rail_construction(unit, destination),
            Err(RailOrderRejection::InvalidTarget)
        );
        state.map[destination].terrain = TerrainKind::Hills;
        assert_eq!(
            state.order_rail_construction(unit, destination),
            Err(RailOrderRejection::InvalidTarget)
        );
        state.map[destination].terrain = TerrainKind::Plains;
        state.map[destination].owner_nation = Some(TileOwnerTag::from_nation(NationId::new(1)));
        assert_eq!(
            state.order_rail_construction(unit, destination),
            Err(RailOrderRejection::InvalidTarget)
        );
        state.map[destination].owner_nation = Some(TileOwnerTag::from_nation(NationId::new(0)));
        state.map[origin]
            .transport_links
            .insert_direction(HexDirection::East);
        assert_eq!(
            state.order_rail_construction(unit, destination),
            Err(RailOrderRejection::InvalidTarget)
        );
        assert!(state.map[origin].pending_rail_links.is_empty());
        assert_eq!(
            state.civilian_units[0].location(),
            CivilianLocation::OnMap(origin)
        );
    }

    #[test]
    fn bounded_seam_and_busy_engineer_are_rejected() {
        let mut state = crate::test_support::game_state();
        let geometry = state.map.geometry();
        let origin = geometry.tile(2, 1).unwrap();
        let seam = geometry.tile(2, 0).unwrap();
        let unit = engineer_on(&mut state, origin, seam);
        assert_eq!(
            state.order_rail_construction(unit, seam),
            Err(RailOrderRejection::InvalidTarget)
        );

        state.civilian_units[0].unit_type = CivilianUnitKind::Miner;
        let (_, destination) = interior();
        state.civilian_units[0].location = CivilianLocation::OnMap(origin);
        state.map[destination].owner_nation = Some(TileOwnerTag::from_nation(NationId::new(0)));
        assert_eq!(
            state.order_rail_construction(unit, destination),
            Err(RailOrderRejection::IneligibleUnit)
        );
    }

    #[test]
    fn wrapping_edge_neighbors_are_not_rail_targets() {
        let mut state = crate::test_support::game_state();
        state.map.topology = MapTopology::Wrapping;
        let geometry = MapGeometry::new(MapTopology::Wrapping);
        let origin = geometry.tile(2, 0).unwrap();
        let wrapped = geometry.neighbor(origin, HexDirection::West).unwrap();
        let unit = engineer_on(&mut state, origin, wrapped);
        assert_eq!(
            state.order_rail_construction(unit, wrapped),
            Err(RailOrderRejection::InvalidTarget)
        );
    }

    #[test]
    fn hills_become_legal_after_the_recovered_technology_unlock() {
        let mut state = crate::test_support::game_state();
        let (origin, destination) = interior();
        let unit = engineer_on(&mut state, origin, destination);
        state.map[destination].terrain = TerrainKind::Hills;
        assert_eq!(
            state.order_rail_construction(unit, destination),
            Err(RailOrderRejection::InvalidTarget)
        );
        state.technology.city_capabilities_by_nation[MajorNationId::new(0)]
            .primary_civilian_distance_terrain
            .hills = true;
        state.order_rail_construction(unit, destination).unwrap();
        assert_eq!(
            state.nations.major(MajorNationId::new(0)).common.treasury,
            800
        );
    }

    fn push_civilian(
        state: &mut GameState,
        id: i32,
        kind: CivilianUnitKind,
        tile: TileId,
        order: CivilianWorkOrder,
    ) {
        state.civilian_units.push(
            CivilianUnitState::new(
                CivilianUnitId::new(id),
                NationId::new(0),
                kind,
                CivilianLocation::OnMap(tile),
                order,
                NationId::new(0),
                0,
                false,
            )
            .unwrap(),
        );
    }

    #[test]
    fn do_civilians_completes_saved_order_kinds_and_idles_redeploy() {
        let mut state = crate::test_support::game_state();
        let tile = TileId::new(50);
        state.map[tile].owner_nation = Some(TileOwnerTag::from_nation(NationId::new(0)));
        state.map[tile].terrain = TerrainKind::Plains;
        state.map[TileId::new(1)].owner_nation = Some(TileOwnerTag::from_nation(NationId::new(0)));
        push_civilian(
            &mut state,
            1,
            CivilianUnitKind::Engineer,
            tile,
            CivilianWorkOrder::BuildDepot {
                turns: TurnsRemaining::try_new(1).unwrap(),
            },
        );
        push_civilian(
            &mut state,
            2,
            CivilianUnitKind::Engineer,
            tile,
            CivilianWorkOrder::Sleep,
        );
        push_civilian(
            &mut state,
            3,
            CivilianUnitKind::Developer,
            tile,
            CivilianWorkOrder::Redeploy {
                destination: tile,
                turns: TurnsRemaining::try_new(2).unwrap(),
            },
        );
        push_civilian(
            &mut state,
            4,
            CivilianUnitKind::Prospector,
            tile,
            CivilianWorkOrder::Prospect {
                turns: TurnsRemaining::try_new(1).unwrap(),
            },
        );

        state.do_civilians();

        assert!(state.map[tile].flags.contains(TileFlags::DEPOT));
        assert!(
            state.nations.majors[MajorNationId::new(0)]
                .towns
                .iter()
                .any(|town| town.tile == tile && town.enabled == 0 && town.active)
        );
        assert_eq!(state.civilian_units[0].order(), &CivilianWorkOrder::Idle);
        assert_eq!(state.civilian_units[1].order(), &CivilianWorkOrder::Idle);
        assert_eq!(state.civilian_units[2].order(), &CivilianWorkOrder::Idle);
        assert_eq!(state.civilian_units[3].order(), &CivilianWorkOrder::Sleep);
        assert!(state.map[tile].development.resource_visible_to_majors[MajorNationId::new(0)]);
        assert_eq!(
            state.civilian_units[0].unit_type(),
            CivilianUnitKind::Developer
        );
        assert_eq!(
            state.civilian_units[1].unit_type(),
            CivilianUnitKind::Prospector
        );
        assert_eq!(
            state.civilian_units[2].unit_type(),
            CivilianUnitKind::Engineer
        );
        assert_eq!(
            state.civilian_units[3].unit_type(),
            CivilianUnitKind::Engineer
        );
    }
}
