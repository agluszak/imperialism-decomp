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
        let (segment, nation) = self.rail_construction_target(unit, destination)?;
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
        self.civilian_units
            .get_mut(&unit)
            .expect("rail construction unit remains present")
            .order = CivilianWorkOrder::LayRail {
            segment,
            turns: TurnsRemaining::try_new(RAIL_TURNS).expect("rail construction lasts one turn"),
        };
        self.move_civilian_to(unit, segment.destination());
        Ok(())
    }

    /// Neighbor tiles `DimByEngineering` would leave undimmed for a rail click.
    pub fn rail_construction_destinations(&self, unit: CivilianUnitId) -> [Option<TileId>; 6] {
        let Some(civilian) = self.civilian_units.get(&unit) else {
            return [None; 6];
        };
        let Some(origin) = civilian.location.tile() else {
            return [None; 6];
        };
        MapGeometry::new(MapTopology::Bounded)
            .neighbors(origin)
            .map(|destination| {
                destination
                    .filter(|&destination| self.rail_construction_target(unit, destination).is_ok())
            })
    }

    /// The idle-selectable civilian of `nation` standing on `tile`, if any.
    pub fn selectable_civilian_on_tile(
        &self,
        tile: TileId,
        nation: NationId,
    ) -> Option<CivilianUnitId> {
        self.civilian_units.iter().find_map(|(&id, unit)| {
            (unit.owner_nation() == nation
                && unit.location().tile() == Some(tile)
                && idle_selectable(unit.order()))
            .then_some(id)
        })
    }

    /// Owner-matched civilian standing on `tile`, idle or not.
    pub fn civilian_on_tile_for_nation(
        &self,
        tile: TileId,
        nation: NationId,
    ) -> Option<&CivilianUnitState> {
        self.civilian_units
            .values()
            .find(|unit| unit.owner_nation() == nation && unit.location().tile() == Some(tile))
    }

    /// `TCivMgr::ClearNationCivilianActionModesAndCycleSelection` unit walk (cycle is app-side).
    pub fn clear_nation_civilian_action_modes(&mut self, nation: NationId) {
        for unit in self.civilian_units.values_mut() {
            if unit.nation() != nation {
                continue;
            }
            // Retail resets unitOrder 2/3/4. Sleep is the recovered idle-mode 2.
            if matches!(unit.order, CivilianWorkOrder::Sleep) {
                unit.order = CivilianWorkOrder::Idle;
            }
        }
    }

    fn rail_construction_target(
        &self,
        id: CivilianUnitId,
        destination: TileId,
    ) -> Result<(RailSegment, MajorNationId), RailOrderRejection> {
        let unit = self
            .civilian_units
            .get(&id)
            .ok_or(RailOrderRejection::IneligibleUnit)?;
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
        self.rebuild_civilian_tile_chains();
        self.resolve_civilian_disputes();
        for nation in MajorNationId::all() {
            if !self.civilian_nation_is_eligible(nation) {
                continue;
            }
            if self.nations.major(nation).auto.is_none() {
                self.continue_civilian_orders(nation);
                self.sort_tracked_orders_by_type_priority(nation);
            } else {
                self.process_ai_civilian_orders(nation);
            }
        }
    }

    pub fn advance_civilian_work(&mut self, civilian: CivilianUnitId) {
        assert!(
            self.civilian_units.contains_key(&civilian),
            "work advances a present unit"
        );
        self.continue_civilian_order(civilian);
    }

    fn civilian_nation_is_eligible(&self, nation: MajorNationId) -> bool {
        !matches!(
            self.nations.major(nation).common.status(),
            CountryStatus::ProtectorateOf(_)
        )
    }

    pub(crate) fn continue_civilian_orders(&mut self, nation: MajorNationId) {
        let ids: Vec<CivilianUnitId> = self
            .civilian_units
            .iter()
            .filter(|(_, unit)| unit.nation == nation.nation())
            .map(|(&id, _)| id)
            .collect();
        for id in ids {
            self.continue_civilian_order(id);
        }
    }

    fn continue_civilian_order(&mut self, id: CivilianUnitId) {
        enum Completion {
            None,
            Idle,
            Rail(RailSegment),
            Depot,
            Port,
            Prospect,
            Develop,
            Fort,
            Purchase,
        }
        let completion = match &mut self
            .civilian_units
            .get_mut(&id)
            .expect("civilian remains present")
            .order
        {
            CivilianWorkOrder::Sleep => Completion::None,
            CivilianWorkOrder::Idle | CivilianWorkOrder::Redeploy { .. } => Completion::Idle,
            CivilianWorkOrder::LayRail { segment, turns } => {
                let segment = *segment;
                if turns.advance() {
                    Completion::Rail(segment)
                } else {
                    Completion::None
                }
            }
            CivilianWorkOrder::BuildDepot { turns } => {
                if turns.advance() {
                    Completion::Depot
                } else {
                    Completion::None
                }
            }
            CivilianWorkOrder::BuildPort { turns } => {
                if turns.advance() {
                    Completion::Port
                } else {
                    Completion::None
                }
            }
            CivilianWorkOrder::Prospect { turns } => {
                if turns.advance() {
                    Completion::Prospect
                } else {
                    Completion::None
                }
            }
            CivilianWorkOrder::DevelopResource { turns } => {
                if turns.advance() {
                    Completion::Develop
                } else {
                    Completion::None
                }
            }
            CivilianWorkOrder::BuildFort { turns } => {
                if turns.advance() {
                    Completion::Fort
                } else {
                    Completion::None
                }
            }
            CivilianWorkOrder::PurchaseLand { turns } => {
                if turns.advance() {
                    Completion::Purchase
                } else {
                    Completion::None
                }
            }
        };
        match completion {
            Completion::None => {}
            Completion::Idle => {
                self.civilian_units
                    .get_mut(&id)
                    .expect("civilian remains present")
                    .order = CivilianWorkOrder::Idle
            }
            Completion::Rail(segment) => self.complete_rail_construction(id, segment),
            Completion::Depot => self.complete_depot_construction(id),
            Completion::Port => self.complete_port_construction(id),
            Completion::Prospect => self.complete_prospecting(id),
            Completion::Develop => self.complete_resource_development(id),
            Completion::Fort => self.complete_fort_construction(id),
            Completion::Purchase => self.complete_land_purchase(id),
        }
    }

    fn sort_tracked_orders_by_type_priority(&mut self, nation: MajorNationId) {
        let (start, end) = self.nation_civilian_range(nation);
        for outer in start..end.saturating_sub(1) {
            for inner in outer + 1..end {
                let outer_priority = civilian_sort_priority(
                    self.civilian_units
                        .get_index(outer)
                        .expect("civilian sort position exists")
                        .1
                        .unit_type,
                );
                let inner_priority = civilian_sort_priority(
                    self.civilian_units
                        .get_index(inner)
                        .expect("civilian sort position exists")
                        .1
                        .unit_type,
                );
                if inner_priority < outer_priority {
                    self.civilian_units.swap_indices(outer, inner);
                }
            }
        }
    }

    fn nation_civilian_range(&self, nation: MajorNationId) -> (usize, usize) {
        let nation = nation.nation();
        let start = self
            .civilian_units
            .iter()
            .position(|(_, unit)| unit.nation == nation)
            .unwrap_or(self.civilian_units.len());
        let end = start
            + self
                .civilian_units
                .iter()
                .skip(start)
                .take_while(|(_, unit)| unit.nation == nation)
                .count();
        (start, end)
    }

    fn resolve_civilian_disputes(&mut self) {
        for tile_index in 0..STRATEGIC_TILE_COUNT {
            let tile = TileId::new(tile_index as u16);
            let on_tile = self.civilians_on_tile_chain(tile);
            if on_tile.len() < 2 {
                continue;
            }
            let competing: Vec<CivilianUnitId> = on_tile
                .into_iter()
                .filter(|&id| {
                    self.civilian_units[&id].unit_type == CivilianUnitKind::Developer
                        && matches!(
                            self.civilian_units[&id].order,
                            CivilianWorkOrder::PurchaseLand { .. }
                        )
                })
                .collect();
            if competing.len() <= 1 {
                continue;
            }

            let tile_owner = self.map[tile]
                .owner_nation
                .and_then(TileOwnerTag::nation)
                .unwrap_or_else(|| NationId::new(0));
            let mut winner = competing[0];
            let mut winning_standing =
                self.diplomacy.standings[self.civilian_units[&winner].owner_nation][tile_owner];
            for &candidate in &competing[1..] {
                let candidate_standing = self.diplomacy.standings
                    [self.civilian_units[&candidate].owner_nation][tile_owner];
                if candidate_standing > winning_standing
                    || (candidate_standing == winning_standing && self.rng.next_crt_rand() & 1 != 0)
                {
                    winner = candidate;
                    winning_standing = candidate_standing;
                }
            }

            let refund = self.developer_tile_purchase_cost(tile);
            let winner_nation = self.civilian_units[&winner].owner_nation;
            let losers: Vec<CivilianUnitId> =
                competing.into_iter().filter(|&id| id != winner).collect();
            for loser in losers {
                let loser_nation = self.civilian_units[&loser].owner_nation;
                self.civilian_units
                    .get_mut(&loser)
                    .expect("civilian remains present")
                    .order = CivilianWorkOrder::Idle;
                if let Some(major) = MajorNationId::from_nation(loser_nation) {
                    self.nations.major_mut(major).common.treasury += refund;
                    if self.nations.major(major).economy.diplomacy_eligible {
                        self.pending.nations[major].turn_start_events.push(
                            TurnStartEvent::LandSale {
                                tag: LAND_SALE_TAG,
                                sale: LandSale {
                                    tile,
                                    nation: winner_nation,
                                },
                            },
                        );
                    }
                }
            }
        }
    }

    pub(crate) fn developer_tile_purchase_cost(&self, tile: TileId) -> i32 {
        self.map[tile]
            .edge_resources
            .into_iter()
            .flatten()
            .map(|resource| {
                if (resource as u8) < ResourceKind::Grain as u8 {
                    let commodity = TradeCommodity::from_retail(i16::from(resource as u8))
                        .expect("manufactured-range resources have market rows");
                    self.market.rows[commodity].price * 20
                } else if resource == ResourceKind::Gems {
                    10_000
                } else if resource == ResourceKind::Gold {
                    4_000
                } else {
                    0
                }
            })
            .sum()
    }

    fn complete_resource_development(&mut self, id: CivilianUnitId) {
        let unit = &self.civilian_units[&id];
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
        self.civilian_units
            .get_mut(&id)
            .expect("civilian remains present")
            .order = CivilianWorkOrder::Idle;
    }

    /// Completes one retail `LayRail` order.
    ///
    /// A completed rail section becomes a pair of permanent directional
    /// transport links. The pending rail links are placed when the order is
    /// issued and therefore remain unchanged here.
    fn complete_rail_construction(&mut self, id: CivilianUnitId, segment: RailSegment) {
        let source = segment.origin();
        let destination = segment.destination();
        let direction = segment.direction();
        self.map[source].transport_links.insert_direction(direction);
        self.map[destination]
            .transport_links
            .insert_direction(direction.opposite());
        self.civilian_units
            .get_mut(&id)
            .expect("civilian remains present")
            .order = CivilianWorkOrder::Idle;
    }

    fn complete_prospecting(&mut self, id: CivilianUnitId) {
        let unit = &self.civilian_units[&id];
        let tile = unit
            .location
            .tile()
            .expect("prospecting orders are normalized with an on-map location");
        let owner = MajorNationId::from_nation(unit.owner_nation)
            .expect("prospectors belong to a major nation");
        self.map[tile].development.resource_visible_to_majors[owner] = true;
        self.civilian_units
            .get_mut(&id)
            .expect("civilian remains present")
            .order = CivilianWorkOrder::Idle;
    }

    fn complete_land_purchase(&mut self, id: CivilianUnitId) {
        let unit = &self.civilian_units[&id];
        let tile = unit
            .location
            .tile()
            .expect("land-purchase orders are normalized with an on-map location");
        let owner = MajorNationId::from_nation(unit.owner_nation)
            .expect("developers belong to a major nation");
        self.map[tile].secondary_owner_nation = Some(owner);
        self.civilian_units
            .get_mut(&id)
            .expect("civilian remains present")
            .order = CivilianWorkOrder::Idle;
    }

    fn complete_fort_construction(&mut self, id: CivilianUnitId) {
        let tile = self.civilian_units[&id]
            .location
            .tile()
            .expect("fort orders are normalized with an on-map location");
        if let Some(province) = self.map[tile].province
            && let Some(capital) = self.map.provinces[province].city_tile()
        {
            self.map[capital]
                .flags
                .insert(TileFlags::PROVINCE_CAPITAL_FORTIFICATION);
            self.map.provinces[province].increment_fort_level();
        }
        self.civilian_units
            .get_mut(&id)
            .expect("civilian remains present")
            .order = CivilianWorkOrder::Idle;
    }

    fn complete_depot_construction(&mut self, id: CivilianUnitId) {
        let unit = &self.civilian_units[&id];
        let tile = unit
            .location
            .tile()
            .expect("depot orders are normalized with an on-map location");
        let nation = MajorNationId::from_nation(unit.owner_nation)
            .expect("engineers belong to a major nation");
        self.queue_depot_construction(tile, nation);
        let _ = self.apply_town_transport_links(nation);
        self.civilian_units
            .get_mut(&id)
            .expect("civilian remains present")
            .order = CivilianWorkOrder::Idle;
    }

    fn complete_port_construction(&mut self, id: CivilianUnitId) {
        let unit = &self.civilian_units[&id];
        let tile = unit
            .location
            .tile()
            .expect("port orders are normalized with an on-map location");
        let nation = MajorNationId::from_nation(unit.owner_nation)
            .expect("engineers belong to a major nation");
        self.queue_port_construction(tile, nation);
        let _ = self.apply_town_transport_links(nation);
        self.civilian_units
            .get_mut(&id)
            .expect("civilian remains present")
            .order = CivilianWorkOrder::Idle;
    }

    fn queue_depot_construction(&mut self, tile: TileId, nation: MajorNationId) {
        if self.map[tile].flags.contains(TileFlags::PORT) {
            if let Some(town) = self.find_town_at_mut(nation, tile) {
                town.active = true;
            }
        } else {
            self.push_new_town(tile, nation, 0);
            self.flood_fill_region_marker(tile, nation);
        }
        if !self.nations.major(nation).economy.diplomacy_eligible {
            self.nations.major_mut(nation).common.treasury -= 2_000;
        }
        self.map[tile].flags.insert(TileFlags::DEPOT);
    }

    fn queue_port_construction(&mut self, tile: TileId, nation: MajorNationId) {
        if self.map[tile].flags.contains(TileFlags::DEPOT) {
            if let Some(town) = self.find_town_at_mut(nation, tile) {
                town.enabled = 1;
            }
        } else {
            self.push_new_town(tile, nation, 1);
            self.flood_fill_region_marker(tile, nation);
        }
        if !self.nations.major(nation).economy.diplomacy_eligible {
            self.nations.major_mut(nation).common.treasury -= 3_000;
        }
        self.map[tile].flags.insert(TileFlags::PORT);
        self.ensure_port_zone_for_tile(tile);
    }

    fn push_new_town(&mut self, tile: TileId, nation: MajorNationId, enabled: u8) {
        self.nations
            .major_mut(nation)
            .towns
            .push(TownState::constructed(
                tile,
                nation.nation(),
                enabled,
                self.turn.economic_turn as i16,
            ));
    }

    fn find_town_at_mut(&mut self, nation: MajorNationId, tile: TileId) -> Option<&mut TownState> {
        self.nations
            .major_mut(nation)
            .towns
            .iter_mut()
            .find(|town| town.tile == tile)
    }

    fn flood_fill_region_marker(&mut self, tile: TileId, nation: MajorNationId) {
        let marker = self.map.allocate_region_marker();
        let owner = Some(TileOwnerTag::from_nation(nation.nation()));
        self.map[tile].region = Some(marker);
        self.stamp_region_last_turn_tick(tile);
        let neighbors: Vec<TileId> = self
            .map
            .geometry()
            .neighbors(tile)
            .into_iter()
            .flatten()
            .collect();
        for neighbor in neighbors {
            if self.map[neighbor].owner_nation != owner || self.map[neighbor].region.is_some() {
                continue;
            }
            self.map[neighbor].region = Some(marker);
            self.stamp_region_last_turn_tick(neighbor);
        }
    }

    fn stamp_region_last_turn_tick(&mut self, tile: TileId) {
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
            self.map.provinces[province].last_turn_tick = self.turn.economic_turn as i16;
        }
    }

    pub(crate) fn move_civilian_to(&mut self, id: CivilianUnitId, tile: TileId) {
        if let Some(old) = self.civilian_units[&id].location.tile() {
            self.unlink_civilian_from_tile_chain(id, old);
        }
        self.civilian_units
            .get_mut(&id)
            .expect("civilian remains present")
            .location = CivilianLocation::OnMap(tile);
        self.prepend_civilian_to_tile_chain(id, tile);
    }

    fn rebuild_civilian_tile_chains(&mut self) {
        for unit in self.civilian_units.values_mut() {
            unit.next_on_tile = None;
        }
        let mut heads = vec![None; STRATEGIC_TILE_COUNT];
        let locations: Vec<_> = self
            .civilian_units
            .iter()
            .filter_map(|(&id, unit)| unit.location.tile().map(|tile| (id, tile)))
            .collect();
        for (id, tile) in locations {
            let Some(unit) = self.civilian_units.get_mut(&id) else {
                continue;
            };
            unit.next_on_tile = heads[usize::from(tile.get())];
            heads[usize::from(tile.get())] = Some(id);
        }
    }

    fn unlink_civilian_from_tile_chain(&mut self, id: CivilianUnitId, tile: TileId) {
        let next = self
            .civilian_units
            .get(&id)
            .and_then(|unit| unit.next_on_tile);
        let previous = self.civilian_units.iter().find_map(|(&candidate, unit)| {
            (candidate != id && unit.location.tile() == Some(tile) && unit.next_on_tile == Some(id))
                .then_some(candidate)
        });
        if let Some(previous) = previous {
            self.civilian_units
                .get_mut(&previous)
                .expect("chain predecessor remains present")
                .next_on_tile = next;
        }
        if let Some(unit) = self.civilian_units.get_mut(&id) {
            unit.next_on_tile = None;
        }
    }

    fn prepend_civilian_to_tile_chain(&mut self, id: CivilianUnitId, tile: TileId) {
        let head = self.chain_head_on_tile(tile).filter(|&head| head != id);
        self.civilian_units
            .get_mut(&id)
            .expect("civilian remains present")
            .next_on_tile = head;
    }

    pub(crate) fn chain_head_on_tile(&self, tile: TileId) -> Option<CivilianUnitId> {
        let on_tile: Vec<CivilianUnitId> = self
            .civilian_units
            .iter()
            .filter(|(_, unit)| unit.location.tile() == Some(tile))
            .map(|(&id, _)| id)
            .collect();
        let pointed: Vec<CivilianUnitId> = on_tile
            .iter()
            .filter_map(|id| {
                self.civilian_units
                    .get(id)
                    .and_then(|unit| unit.next_on_tile)
            })
            .collect();
        on_tile.into_iter().find(|id| !pointed.contains(id))
    }

    pub(crate) fn civilians_on_tile_chain(&self, tile: TileId) -> Vec<CivilianUnitId> {
        let mut chain = Vec::new();
        let mut current = self.chain_head_on_tile(tile);
        while let Some(id) = current {
            if chain.contains(&id) {
                break;
            }
            chain.push(id);
            current = self
                .civilian_units
                .get(&id)
                .and_then(|unit| unit.next_on_tile);
        }
        chain
    }

    pub(crate) fn set_civilian_work_order(&mut self, id: CivilianUnitId, order: CivilianWorkOrder) {
        self.civilian_units
            .get_mut(&id)
            .expect("civilian order requires a present unit")
            .order = order;
    }
}

const LAND_SALE_TAG: i32 = 0x6c61_6e64;

const CIVILIAN_SORT_PRIORITY: CivilianUnitTable<i16> =
    CivilianUnitTable::from_array([2, 0, 4, 3, 1, 5, 0, 0, 0]);

fn civilian_sort_priority(kind: CivilianUnitKind) -> i16 {
    CIVILIAN_SORT_PRIORITY[kind]
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
        state.civilian_units.insert(
            id,
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
    fn missing_civilian_is_an_ineligible_rail_unit() {
        let mut state = crate::test_support::game_state();
        let missing = CivilianUnitId::from_serialized(99);
        assert_eq!(
            state.order_rail_construction(missing, TileId::new(0)),
            Err(RailOrderRejection::IneligibleUnit)
        );
        assert_eq!(state.rail_construction_destinations(missing), [None; 6]);
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

    fn civilian_on(
        state: &mut GameState,
        id: i32,
        kind: CivilianUnitKind,
        tile: TileId,
        order: CivilianWorkOrder,
        nation: NationId,
    ) -> CivilianUnitId {
        state.map[tile].owner_nation = Some(TileOwnerTag::from_nation(nation));
        let id = CivilianUnitId::new(id);
        state.civilian_units.insert(
            id,
            CivilianUnitState::new(
                id,
                nation,
                kind,
                CivilianLocation::OnMap(tile),
                order,
                nation,
                0,
                false,
            )
            .unwrap(),
        );
        id
    }

    fn one_turn() -> TurnsRemaining {
        TurnsRemaining::try_new(1).unwrap()
    }

    #[test]
    fn do_civilians_completes_remaining_work_orders_and_idles_redeploy() {
        let mut state = crate::test_support::game_state();
        let geometry = MapGeometry::new(MapTopology::Bounded);
        let prospect_tile = geometry.tile(3, 10).unwrap();
        let purchase_tile = geometry.tile(3, 12).unwrap();
        let fort_tile = geometry.tile(4, 10).unwrap();
        let capital = geometry.tile(4, 12).unwrap();
        let depot_tile = geometry.tile(5, 10).unwrap();
        let port_tile = geometry.tile(5, 12).unwrap();
        let sleep_tile = geometry.tile(6, 10).unwrap();
        let redeploy_tile = geometry.tile(6, 12).unwrap();
        let develop_tile = geometry.tile(7, 10).unwrap();
        let nation = NationId::new(0);
        state.map[TileId::new(1)].owner_nation = Some(TileOwnerTag::from_nation(nation));

        state.map.provinces[ProvinceId::new(0)] = ProvinceState::new(
            Some(nation),
            Some(nation),
            0,
            Vec::new(),
            Vec::new(),
            Some(0),
            0,
            Some(capital),
            0,
            None,
            None,
            Vec::new(),
            ResourceTable::default(),
            MajorNationTable::default(),
            0,
            false,
            0,
            String::new(),
        );
        state.map[fort_tile].province = Some(ProvinceId::new(0));

        civilian_on(
            &mut state,
            2,
            CivilianUnitKind::Prospector,
            prospect_tile,
            CivilianWorkOrder::Prospect { turns: one_turn() },
            nation,
        );
        civilian_on(
            &mut state,
            3,
            CivilianUnitKind::Developer,
            purchase_tile,
            CivilianWorkOrder::PurchaseLand { turns: one_turn() },
            nation,
        );
        civilian_on(
            &mut state,
            4,
            CivilianUnitKind::Engineer,
            fort_tile,
            CivilianWorkOrder::BuildFort { turns: one_turn() },
            nation,
        );
        civilian_on(
            &mut state,
            5,
            CivilianUnitKind::Engineer,
            depot_tile,
            CivilianWorkOrder::BuildDepot { turns: one_turn() },
            nation,
        );
        civilian_on(
            &mut state,
            6,
            CivilianUnitKind::Engineer,
            port_tile,
            CivilianWorkOrder::BuildPort { turns: one_turn() },
            nation,
        );
        state.map[port_tile].flags.insert(TileFlags::BASE_TRANSPORT);
        let sea_tile = geometry
            .neighbor(
                port_tile,
                HexDirection::ALL[usize::from(port_tile.get()) % 6],
            )
            .expect("port tile has a bounded neighbor");
        state.map[sea_tile].terrain = TerrainKind::Water;
        state.map[sea_tile].owner_nation = Some(TileOwnerTag::new(0x17));
        civilian_on(
            &mut state,
            7,
            CivilianUnitKind::Farmer,
            sleep_tile,
            CivilianWorkOrder::Sleep,
            nation,
        );
        civilian_on(
            &mut state,
            8,
            CivilianUnitKind::Rancher,
            redeploy_tile,
            CivilianWorkOrder::Redeploy {
                destination: purchase_tile,
                turns: one_turn(),
            },
            nation,
        );
        civilian_on(
            &mut state,
            9,
            CivilianUnitKind::Miner,
            develop_tile,
            CivilianWorkOrder::DevelopResource {
                turns: TurnsRemaining::try_new(3).unwrap(),
            },
            nation,
        );

        let province = Some(ProvinceId::new(0));
        state.map[TileId::new(1)].province = province;
        state.map[capital].province = province;
        for unit in state.civilian_units.values() {
            if let Some(tile) = unit.location.tile() {
                state.map[tile].province = province;
            }
        }

        state.do_civilians();

        assert!(
            state.map[prospect_tile]
                .development
                .resource_visible_to_majors[MajorNationId::new(0)]
        );
        assert_eq!(
            state.map[purchase_tile].secondary_owner_nation,
            Some(MajorNationId::new(0))
        );
        assert!(
            state.map[capital]
                .flags
                .contains(TileFlags::PROVINCE_CAPITAL_FORTIFICATION)
        );
        assert_eq!(state.map.provinces[ProvinceId::new(0)].fort_level(), 1);
        assert!(state.map[depot_tile].flags.contains(TileFlags::DEPOT));
        assert!(
            state
                .nations
                .major(MajorNationId::new(0))
                .towns
                .iter()
                .any(|town| town.tile == depot_tile && town.enabled == 0 && town.active)
        );
        assert!(state.map[port_tile].flags.contains(TileFlags::PORT));
        assert!(
            state
                .nations
                .major(MajorNationId::new(0))
                .towns
                .iter()
                .any(|town| town.tile == port_tile && town.enabled == 1 && !town.active)
        );
        assert!(
            matches!(
                &state.ocean.zones[..],
                [ZoneKind::PortZone(port)] if port.port_tile == port_tile
                    && port.zone.target_tile == Some(sea_tile)
            ),
            "port completion should create a live port zone, got {:?}",
            state.ocean.zones
        );
        assert_eq!(
            state.map[sea_tile].action,
            TileAction::try_from_retail(3),
            "EnsurePortZone stamps Anchor on the chosen sea tile"
        );
        assert!(
            state
                .civilian_units
                .values()
                .any(|unit| unit.unit_type == CivilianUnitKind::Farmer
                    && matches!(unit.order, CivilianWorkOrder::Sleep))
        );
        assert!(
            state
                .civilian_units
                .values()
                .any(|unit| unit.unit_type == CivilianUnitKind::Rancher
                    && matches!(unit.order, CivilianWorkOrder::Idle))
        );
        assert!(state.civilian_units.values().any(|unit| {
            unit.unit_type == CivilianUnitKind::Miner
                && matches!(
                    unit.order,
                    CivilianWorkOrder::DevelopResource { turns } if turns.get() == 2
                )
        }));
    }

    #[test]
    fn protectorates_are_skipped_and_humans_sort_by_unit_kind() {
        let mut state = crate::test_support::game_state();
        let (first, second) = interior();
        let nation = NationId::new(0);
        civilian_on(
            &mut state,
            2,
            CivilianUnitKind::Farmer,
            first,
            CivilianWorkOrder::Idle,
            nation,
        );
        civilian_on(
            &mut state,
            3,
            CivilianUnitKind::Miner,
            second,
            CivilianWorkOrder::DevelopResource { turns: one_turn() },
            nation,
        );

        state.set_country_status(nation, CountryStatus::ProtectorateOf(NationId::new(1)));
        state.do_civilians();
        assert_eq!(state.civilian_units[0].unit_type, CivilianUnitKind::Farmer);
        assert!(matches!(
            state.civilian_units[1].order,
            CivilianWorkOrder::DevelopResource { .. }
        ));

        state.set_country_status(nation, CountryStatus::Independent);
        state.do_civilians();
        assert_eq!(state.civilian_units[0].unit_type, CivilianUnitKind::Miner);
        assert_eq!(state.civilian_units[1].unit_type, CivilianUnitKind::Farmer);
        assert_eq!(state.civilian_units[0].order, CivilianWorkOrder::Idle);
    }
}
