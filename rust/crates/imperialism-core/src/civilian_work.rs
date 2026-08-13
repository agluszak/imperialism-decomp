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

    pub fn advance_civilian_work(&mut self, civilian: CivilianUnitId) {
        let index = self
            .civilian_units
            .iter()
            .position(|unit| unit.id == civilian)
            .expect("scheduled civilian work references a present unit");
        #[allow(clippy::collapsible_match)] // match-guard form cannot mutably borrow `turns`
        match &mut self.civilian_units[index].order {
            #[allow(clippy::collapsible_match)]
            CivilianWorkOrder::DevelopResource { turns } => {
                if turns.advance() {
                    self.complete_resource_development(index);
                }
            }
            CivilianWorkOrder::LayRail { segment, turns } => {
                let segment = *segment;
                if turns.advance() {
                    self.complete_rail_construction(index, segment);
                }
            }
            _ => {}
        }
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
}
