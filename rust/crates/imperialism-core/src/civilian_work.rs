use crate::*;

/// A recovered civilian work-order kind.
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CivilianWorkOrder {
    Idle,
    Redeploy { source: TileId, turns: i16 },
    Sleep,
    Later,
    Done,
    LayRail { segment: RailSegment, turns: i16 },
    BuildDepot { source: TileId, turns: i16 },
    BuildPort { source: TileId, turns: i16 },
    Prospect { source: TileId, turns: i16 },
    DevelopResource { source: TileId, turns: i16 },
    BuildFort { source: TileId, turns: i16 },
    PurchaseLand { source: TileId, turns: i16 },
}

impl CivilianWorkOrder {
    fn advance(&mut self) -> bool {
        let turns = match self {
            Self::LayRail { turns, .. }
            | Self::BuildDepot { turns, .. }
            | Self::BuildPort { turns, .. }
            | Self::Prospect { turns, .. }
            | Self::DevelopResource { turns, .. }
            | Self::BuildFort { turns, .. }
            | Self::PurchaseLand { turns, .. } => turns,
            Self::Idle | Self::Redeploy { .. } | Self::Sleep | Self::Later | Self::Done => {
                unreachable!("only civilian work orders advance")
            }
        };
        *turns -= 1;
        *turns == 0
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

/// Retail `CivilianTileActionCode` (0x004d2960).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CivilianTileAction {
    None,
    Blocked,
    SelectUnit,
    MoveUnit,
    EngineerSameTile,
    EngineerDirection14,
    EngineerDirection03,
    EngineerDirection25,
    Prospect,
    DevelopResource,
    ShowOrderReport,
    PurchaseLand,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CivilianOrderRejection {
    Blocked,
    InsufficientFunds,
    ConstructionRequiresChoice,
    PurchaseLandRequiresConfirmation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EngineerConstructionChoice {
    Fort,
    Rail,
    Port,
}

/// Idle civilian modes assigned by `TCivToolbar::DoEvent`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum CivilianIdleOrderMode {
    Sleep = 2,
    Later = 3,
    Done = 4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EngineerConstructionOption {
    pub choice: EngineerConstructionChoice,
    pub cost: i32,
}

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

const fn fort_cost(level: FortLevel) -> i32 {
    match level {
        FortLevel::None => 5_000,
        FortLevel::One => 7_500,
        FortLevel::Two => 10_000,
        FortLevel::Three => 0,
    }
}

impl GameState {
    /// `TCivMgr::DispatchSelectedUnitToGlobalMapStateHandler`.
    ///
    /// The retail map stores the current selected civilian's eligible targets in
    /// `recruitSearchVisited0e`; both click dispatch and cursor selection consume it.
    pub fn prepare_civilian_order_targets(&mut self, unit: CivilianUnitId) {
        let Some(unit) = self.civilian_units.get(&unit) else {
            return;
        };
        let kind = unit.unit_type;
        let nation = MajorNationId::from_nation(unit.owner_nation)
            .expect("civilian orders belong to major nations");
        let origin = unit.location.tile();
        for index in 0..STRATEGIC_TILE_COUNT {
            let tile = TileId::new(index as u16);
            self.map[tile].recruit_search_visited =
                u8::from(!self.civilian_target_eligible(kind, nation, origin, tile));
        }
    }

    /// `TCivMgr::SetActiveCivilianSelection`: move the selected entry to the
    /// head of its tile chain, then refresh its eligible order targets.
    pub fn activate_civilian_selection(&mut self, unit: CivilianUnitId) {
        let tile = self
            .civilian_units
            .get(&unit)
            .and_then(|unit| unit.location.tile());
        if let Some(tile) = tile {
            self.move_civilian_to(unit, tile);
        }
        self.prepare_civilian_order_targets(unit);
    }

    /// `TCivMgr::ResolveCivilianTileOrderActionCode` for a selected civilian.
    pub fn civilian_tile_action(&self, unit: CivilianUnitId, tile: TileId) -> CivilianTileAction {
        let Some(selected) = self.civilian_units.get(&unit) else {
            return CivilianTileAction::Blocked;
        };
        if bounded_seam_tile(&self.map, tile) {
            return CivilianTileAction::Blocked;
        }
        if let Some((clicked, state)) =
            self.civilian_on_tile_for_nation(tile, selected.owner_nation)
            && clicked != unit
        {
            return if matches!(state.order, CivilianWorkOrder::Idle) {
                CivilianTileAction::SelectUnit
            } else {
                CivilianTileAction::ShowOrderReport
            };
        }
        if self.map[tile].recruit_search_visited != 0 {
            if let Some((_, state)) = self.civilian_on_tile_for_nation(tile, selected.owner_nation)
            {
                return if idle_selectable(&state.order) {
                    CivilianTileAction::SelectUnit
                } else {
                    CivilianTileAction::ShowOrderReport
                };
            }
            return if self.can_assign_civilian_to_tile(unit, tile) {
                CivilianTileAction::MoveUnit
            } else {
                CivilianTileAction::Blocked
            };
        }
        match selected.unit_type {
            CivilianUnitKind::Engineer => match selected.location().tile() {
                Some(origin) if tile == origin => CivilianTileAction::EngineerSameTile,
                Some(origin) => {
                    match MapGeometry::new(MapTopology::Bounded).direction_to(origin, tile) {
                        Some(HexDirection::East | HexDirection::West) => {
                            CivilianTileAction::EngineerDirection14
                        }
                        Some(HexDirection::NorthEast | HexDirection::SouthWest) => {
                            CivilianTileAction::EngineerDirection03
                        }
                        Some(HexDirection::SouthEast | HexDirection::NorthWest) => {
                            CivilianTileAction::EngineerDirection25
                        }
                        None => CivilianTileAction::Blocked,
                    }
                }
                None => CivilianTileAction::Blocked,
            },
            CivilianUnitKind::Prospector => CivilianTileAction::Prospect,
            CivilianUnitKind::Developer => CivilianTileAction::PurchaseLand,
            CivilianUnitKind::Miner
            | CivilianUnitKind::Farmer
            | CivilianUnitKind::Forester
            | CivilianUnitKind::Rancher
            | CivilianUnitKind::Fisherman
            | CivilianUnitKind::Driller => CivilianTileAction::DevelopResource,
        }
    }

    /// Executes the non-modal branches of `TCivMgr::HandleCivilianTileOrderAction`.
    pub fn issue_civilian_tile_order(
        &mut self,
        unit: CivilianUnitId,
        tile: TileId,
    ) -> Result<CivilianTileAction, CivilianOrderRejection> {
        match self.civilian_tile_action(unit, tile) {
            CivilianTileAction::Blocked
            | CivilianTileAction::None
            | CivilianTileAction::SelectUnit
            | CivilianTileAction::ShowOrderReport => Err(CivilianOrderRejection::Blocked),
            CivilianTileAction::MoveUnit => {
                if !self.can_assign_civilian_to_tile(unit, tile) {
                    return Err(CivilianOrderRejection::Blocked);
                }
                let source = self.civilian_units[&unit]
                    .location
                    .tile()
                    .expect("selected civilian is on the strategic map");
                self.set_civilian_work_order(
                    unit,
                    CivilianWorkOrder::Redeploy { source, turns: 0 },
                );
                self.move_civilian_to(unit, tile);
                Ok(CivilianTileAction::MoveUnit)
            }
            CivilianTileAction::EngineerSameTile => {
                Err(CivilianOrderRejection::ConstructionRequiresChoice)
            }
            CivilianTileAction::EngineerDirection14
            | CivilianTileAction::EngineerDirection03
            | CivilianTileAction::EngineerDirection25 => self
                .order_rail_construction(unit, tile)
                .map(|_| self.civilian_tile_action(unit, tile))
                .map_err(|error| match error {
                    RailOrderRejection::InsufficientFunds => {
                        CivilianOrderRejection::InsufficientFunds
                    }
                    RailOrderRejection::IneligibleUnit | RailOrderRejection::InvalidTarget => {
                        CivilianOrderRejection::Blocked
                    }
                }),
            CivilianTileAction::Prospect => {
                let source = self.civilian_units[&unit]
                    .location
                    .tile()
                    .expect("selected civilian is on the strategic map");
                self.move_civilian_to(unit, tile);
                self.set_civilian_work_order(
                    unit,
                    CivilianWorkOrder::Prospect { source, turns: 1 },
                );
                Ok(CivilianTileAction::Prospect)
            }
            CivilianTileAction::DevelopResource => {
                let source = self.civilian_units[&unit]
                    .location
                    .tile()
                    .expect("selected civilian is on the strategic map");
                let nation = MajorNationId::from_nation(self.civilian_units[&unit].owner_nation)
                    .expect("civilian orders belong to major nations");
                let extractive = matches!(
                    self.civilian_units[&unit].unit_type,
                    CivilianUnitKind::Miner | CivilianUnitKind::Driller
                );
                let class = if extractive {
                    self.map[tile].development.extractive.get()
                } else {
                    self.map[tile].development.surface.get()
                };
                let cost = match class {
                    0 => 100,
                    1 => 1_000,
                    _ => 5_000,
                };
                let major = self.nations.major(nation);
                let available =
                    (major.common.treasury + major.economy.diplomacy_budget_base / 10).max(0);
                if available < cost {
                    return Err(CivilianOrderRejection::InsufficientFunds);
                }
                self.nations.major_mut(nation).common.treasury -= cost;
                self.move_civilian_to(unit, tile);
                self.set_civilian_work_order(
                    unit,
                    CivilianWorkOrder::DevelopResource { source, turns: 3 },
                );
                Ok(CivilianTileAction::DevelopResource)
            }
            CivilianTileAction::PurchaseLand => {
                Err(CivilianOrderRejection::PurchaseLandRequiresConfirmation)
            }
        }
    }

    /// Retail `TEngineerDialog::BuildCityViewProductionControls` choices for a
    /// same-tile engineer click.
    pub fn engineer_construction_options(
        &self,
        unit: CivilianUnitId,
    ) -> Vec<EngineerConstructionOption> {
        let Some(engineer) = self.civilian_units.get(&unit) else {
            return Vec::new();
        };
        if engineer.unit_type != CivilianUnitKind::Engineer || !idle_selectable(&engineer.order) {
            return Vec::new();
        }
        let Some(tile) = engineer.location.tile() else {
            return Vec::new();
        };
        let nation = MajorNationId::from_nation(engineer.owner_nation)
            .expect("engineers belong to major nations");
        let mut options = Vec::new();
        if let Some(province) = self.map[tile].province
            && self.map.provinces[province].city_tile() == Some(tile)
            && self.map.provinces[province].fort_level()
                < self.technology.city_capabilities_by_nation[nation]
                    .fort_level_cap
                    .level()
        {
            options.push(EngineerConstructionOption {
                choice: EngineerConstructionChoice::Fort,
                cost: fort_cost(self.map.provinces[province].fort_level()),
            });
        }

        let flags = self.map[tile].flags;
        let depot_allowed = !flags.contains(TileFlags::DEPOT);
        let port_allowed = !flags.contains(TileFlags::PORT);
        let production_allowed = if depot_allowed && port_allowed {
            self.map
                .geometry()
                .neighbors(tile)
                .into_iter()
                .flatten()
                .all(|neighbor| {
                    !self.map[neighbor]
                        .flags
                        .intersects(TileFlags::PORT | TileFlags::DEPOT)
                })
        } else {
            true
        };
        if depot_allowed && production_allowed {
            options.push(EngineerConstructionOption {
                choice: EngineerConstructionChoice::Rail,
                cost: 2_000,
            });
        }
        if port_allowed && production_allowed && self.can_build_port_at_tile(tile) {
            options.push(EngineerConstructionOption {
                choice: EngineerConstructionChoice::Port,
                cost: 3_000,
            });
        }
        options
    }

    /// Executes one choice returned by [`Self::engineer_construction_options`].
    pub fn queue_engineer_construction(
        &mut self,
        unit: CivilianUnitId,
        choice: EngineerConstructionChoice,
    ) -> Result<(), CivilianOrderRejection> {
        let option = self
            .engineer_construction_options(unit)
            .into_iter()
            .find(|option| option.choice == choice)
            .ok_or(CivilianOrderRejection::Blocked)?;
        let engineer = &self.civilian_units[&unit];
        let source = engineer
            .location
            .tile()
            .expect("construction engineer is on the strategic map");
        let nation = MajorNationId::from_nation(engineer.owner_nation)
            .expect("engineers belong to major nations");
        if self.civilian_construction_available_cash(nation) < option.cost {
            return Err(CivilianOrderRejection::InsufficientFunds);
        }
        self.nations.major_mut(nation).common.treasury -= option.cost;
        // HandleEngineerConstructionAction maps these dialog choices to the
        // retail order codes this way, despite their surprising names.
        let order = match choice {
            EngineerConstructionChoice::Fort => CivilianWorkOrder::BuildDepot { source, turns: 3 },
            EngineerConstructionChoice::Rail => CivilianWorkOrder::BuildFort { source, turns: 4 },
            EngineerConstructionChoice::Port => CivilianWorkOrder::BuildPort { source, turns: 3 },
        };
        self.set_civilian_work_order(unit, order);
        Ok(())
    }

    pub fn developer_tile_purchase_cost(&self, tile: TileId) -> i32 {
        self.map[tile]
            .edge_resources
            .into_iter()
            .flatten()
            .map(|resource| {
                if let Some(commodity) = TradeCommodity::from_resource(resource) {
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

    pub fn can_afford_developer_tile_purchase(&self, unit: CivilianUnitId, tile: TileId) -> bool {
        let Some(developer) = self.civilian_units.get(&unit) else {
            return false;
        };
        let Some(nation) = MajorNationId::from_nation(developer.owner_nation) else {
            return false;
        };
        self.civilian_construction_available_cash(nation) >= self.developer_tile_purchase_cost(tile)
    }

    pub fn confirm_developer_tile_purchase(
        &mut self,
        unit: CivilianUnitId,
        tile: TileId,
    ) -> Result<(), CivilianOrderRejection> {
        if self.civilian_tile_action(unit, tile) != CivilianTileAction::PurchaseLand {
            return Err(CivilianOrderRejection::Blocked);
        }
        let source = self.civilian_units[&unit]
            .location
            .tile()
            .expect("selected developer is on the strategic map");
        let nation = MajorNationId::from_nation(self.civilian_units[&unit].owner_nation)
            .expect("developers belong to major nations");
        let cost = self.developer_tile_purchase_cost(tile);
        if self.civilian_construction_available_cash(nation) < cost {
            return Err(CivilianOrderRejection::InsufficientFunds);
        }
        self.nations.major_mut(nation).common.treasury -= cost;
        self.move_civilian_to(unit, tile);
        self.set_civilian_work_order(unit, CivilianWorkOrder::PurchaseLand { source, turns: 1 });
        Ok(())
    }

    /// Retail `TCivMgr::HandleCivilianReportDecision` cancel branch.
    pub fn cancel_civilian_work_order(
        &mut self,
        unit: CivilianUnitId,
    ) -> Result<(), CivilianOrderRejection> {
        let Some(civilian) = self.civilian_units.get(&unit) else {
            return Err(CivilianOrderRejection::Blocked);
        };
        let nation = MajorNationId::from_nation(civilian.owner_nation)
            .expect("civilian work orders belong to major nations");
        let tile = civilian
            .location
            .tile()
            .ok_or(CivilianOrderRejection::Blocked)?;
        let order = civilian.order.clone();
        let (source, refund) = match order {
            CivilianWorkOrder::Idle
            | CivilianWorkOrder::Sleep
            | CivilianWorkOrder::Later
            | CivilianWorkOrder::Done => {
                return Err(CivilianOrderRejection::Blocked);
            }
            CivilianWorkOrder::Redeploy { source, .. } => (source, 0),
            CivilianWorkOrder::LayRail { segment, .. } => {
                self.map[segment.origin()]
                    .pending_rail_links
                    .remove(TileTransportLinks::for_direction(segment.direction()));
                self.map[segment.destination()].pending_rail_links.remove(
                    TileTransportLinks::for_direction(segment.direction().opposite()),
                );
                (segment.origin(), rail_cost(self.map[tile].terrain))
            }
            CivilianWorkOrder::BuildDepot { source, .. } => (source, 2_000),
            CivilianWorkOrder::BuildPort { source, .. } => (source, 3_000),
            CivilianWorkOrder::Prospect { source, .. } => (source, 0),
            CivilianWorkOrder::DevelopResource { source, .. } => {
                let extractive = matches!(
                    civilian.unit_type,
                    CivilianUnitKind::Miner | CivilianUnitKind::Driller
                );
                let class = if extractive {
                    self.map[tile].development.extractive.get()
                } else {
                    self.map[tile].development.surface.get()
                };
                let refund = match class {
                    0 => 100,
                    1 => 1_000,
                    _ => 5_000,
                };
                (source, refund)
            }
            CivilianWorkOrder::BuildFort { source, .. } => {
                let refund = self.map[tile]
                    .province
                    .map(|province| fort_cost(self.map.provinces[province].fort_level()))
                    .unwrap_or(0);
                (source, refund)
            }
            CivilianWorkOrder::PurchaseLand { source, .. } => {
                (source, self.developer_tile_purchase_cost(tile))
            }
        };
        self.nations.major_mut(nation).common.treasury += refund;
        self.civilian_units
            .get_mut(&unit)
            .expect("civilian remains present")
            .order = CivilianWorkOrder::Idle;
        self.move_civilian_to(unit, source);
        self.activate_civilian_selection(unit);
        Ok(())
    }

    fn civilian_construction_available_cash(&self, nation: MajorNationId) -> i32 {
        let major = self.nations.major(nation);
        (major.common.treasury + major.economy.diplomacy_budget_base / 100).max(0)
    }

    fn civilian_target_eligible(
        &self,
        kind: CivilianUnitKind,
        nation: MajorNationId,
        origin: Option<TileId>,
        tile: TileId,
    ) -> bool {
        let state = &self.map[tile];
        match kind {
            CivilianUnitKind::Engineer => origin.is_some_and(|origin| {
                if tile == origin {
                    let access = self.technology.city_capabilities_by_nation[nation]
                        .primary_civilian_distance_terrain;
                    return rail_terrain_allowed(state.terrain, access)
                        && (state.region.is_none()
                            || state.province.is_some_and(|province| {
                                self.map.provinces[province].fort_level() < FortLevel::Three
                            }));
                }
                self.rail_construction_target_from(origin, nation, tile)
                    .is_ok()
            }),
            CivilianUnitKind::Prospector => {
                state.terrain != TerrainKind::Water
                    && self.civilian_order_compatible(nation, tile)
                    && (matches!(state.gate, 8 | 9)
                        || (self.technology.city_capabilities_by_nation[nation].oil_drilling
                            && matches!(state.gate, 10..=12)))
                    && !state.development.resource_visible_to_majors[nation]
            }
            CivilianUnitKind::Developer => {
                state.terrain != TerrainKind::Water
                    && state
                        .owner_nation
                        .is_some_and(|owner| owner.get() >= MajorNationId::COUNT)
                    && self.civilian_order_compatible(nation, tile)
                    && state.secondary_owner_nation.is_none()
                    && civilian_gate_qualifies(state.gate)
                    && state.edge_resources.into_iter().flatten().any(|resource| {
                        matches!(
                            resource,
                            ResourceKind::Cotton | ResourceKind::Wool | ResourceKind::Timber
                        ) || (state.development.resource_visible_to_majors[nation]
                            && matches!(
                                resource,
                                ResourceKind::Coal
                                    | ResourceKind::Iron
                                    | ResourceKind::Gems
                                    | ResourceKind::Gold
                            ))
                            || (resource == ResourceKind::Oil
                                && self.technology.city_capabilities_by_nation[nation].oil_drilling
                                && state.development.resource_visible_to_majors[nation])
                    })
            }
            CivilianUnitKind::Miner | CivilianUnitKind::Driller => {
                self.civilian_owned_by(nation, tile)
                    && state
                        .development
                        .resource_visible_to_majors
                        .iter()
                        .any(|&visible| visible)
                    && self.max_resource_capability_for_order(tile, kind, nation)
                        > i16::from(state.development.extractive.get())
            }
            CivilianUnitKind::Fisherman => self.fishing_target_eligible(nation, tile),
            CivilianUnitKind::Farmer | CivilianUnitKind::Forester | CivilianUnitKind::Rancher => {
                self.civilian_owned_by(nation, tile)
                    && civilian_gate_qualifies(state.gate)
                    && state.edge_resources.into_iter().flatten().any(|resource| {
                        civilian_required_kind(resource) == Some(kind)
                            && (civilian_resource_always_qualifies(resource)
                                || self.map[tile].owner_nation
                                    == Some(TileOwnerTag::from_nation(nation.nation())))
                    })
                    && self.max_resource_capability_for_order(tile, kind, nation)
                        > i16::from(state.development.surface.get())
            }
        }
    }
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
            .order = CivilianWorkOrder::LayRail { segment, turns: 1 };
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

    fn rail_construction_target_from(
        &self,
        origin: TileId,
        nation: MajorNationId,
        destination: TileId,
    ) -> Result<RailSegment, RailOrderRejection> {
        let segment = RailSegment::between(MapTopology::Bounded, origin, destination)
            .ok_or(RailOrderRejection::InvalidTarget)?;
        if bounded_seam_tile(&self.map, destination) {
            return Err(RailOrderRejection::InvalidTarget);
        }
        let access =
            self.technology.city_capabilities_by_nation[nation].primary_civilian_distance_terrain;
        if !rail_terrain_allowed(self.map[origin].terrain, access)
            || !rail_terrain_allowed(self.map[destination].terrain, access)
            || self.map[destination].owner_nation
                != Some(TileOwnerTag::from_nation(nation.nation()))
            || self.map[origin]
                .transport_links
                .contains(TileTransportLinks::for_direction(segment.direction()))
        {
            return Err(RailOrderRejection::InvalidTarget);
        }
        Ok(segment)
    }

    fn civilian_owned_by(&self, nation: MajorNationId, tile: TileId) -> bool {
        let state = &self.map[tile];
        state.owner_nation == Some(TileOwnerTag::from_nation(nation.nation()))
            || state.secondary_owner_nation == Some(nation)
    }

    fn can_assign_civilian_to_tile(&self, unit: CivilianUnitId, tile: TileId) -> bool {
        let Some(unit) = self.civilian_units.get(&unit) else {
            return false;
        };
        if unit.location.tile() == Some(tile)
            || self.map[tile].gate == 0
            || (self.map[tile].flags.contains(TileFlags::BASE_TRANSPORT)
                && unit.unit_type != CivilianUnitKind::Engineer)
        {
            return false;
        }
        let Some(owner) = self.map[tile].owner_nation.and_then(TileOwnerTag::nation) else {
            return false;
        };
        if MajorNationId::from_nation(owner).is_some() {
            return owner == unit.owner_nation;
        }
        unit.unit_type != CivilianUnitKind::Engineer
            && (self.diplomacy.mission_levels[unit.owner_nation][owner]
                == DiplomaticMissionLevel::Embassy
                || self.nations.country_status(owner)
                    == Some(CountryStatus::ColonyOf(unit.owner_nation)))
    }

    fn civilian_order_compatible(&self, nation: MajorNationId, tile: TileId) -> bool {
        let Some(owner) = self.map[tile].owner_nation.and_then(TileOwnerTag::nation) else {
            return false;
        };
        owner == nation.nation()
            || (MajorNationId::from_nation(owner).is_none()
                && self.diplomacy.mission_levels[nation.nation()][owner]
                    == DiplomaticMissionLevel::Embassy)
    }

    fn max_resource_capability_for_order(
        &self,
        tile: TileId,
        kind: CivilianUnitKind,
        nation: MajorNationId,
    ) -> i16 {
        self.map[tile]
            .edge_resources
            .into_iter()
            .flatten()
            .filter(|&resource| civilian_required_kind(resource) == Some(kind))
            .map(|resource| {
                i16::from(
                    self.technology.city_capabilities_by_nation[nation]
                        .university
                        .requirement_levels[resource]
                        .retail(),
                )
            })
            .max()
            .unwrap_or(0)
    }

    fn fishing_target_eligible(&self, nation: MajorNationId, tile: TileId) -> bool {
        self.map[tile].terrain == TerrainKind::Water
            && self
                .nations
                .major(nation)
                .towns
                .iter()
                .any(|(&town, state)| {
                    state.enabled != 0
                        && self
                            .map
                            .geometry()
                            .neighbors(town)
                            .into_iter()
                            .flatten()
                            .any(|neighbor| {
                                neighbor == tile
                                    && self.map[neighbor].region == self.map[town].region
                            })
                })
            && i16::from(
                self.technology.city_capabilities_by_nation[nation]
                    .university
                    .requirement_levels[ResourceKind::Fish]
                    .retail(),
            ) > i16::from(self.map[tile].development.extractive.get()) * 16
                + i16::from(self.map[tile].development.surface.get())
    }

    /// The idle-selectable civilian of `nation` standing on `tile`, if any.
    pub fn selectable_civilian_on_tile(
        &self,
        tile: TileId,
        nation: NationId,
    ) -> Option<CivilianUnitId> {
        self.civilians_on_tile_chain(tile).into_iter().find(|id| {
            let unit = &self.civilian_units[id];
            unit.owner_nation() == nation && idle_selectable(unit.order())
        })
    }

    /// Owner-matched civilian standing on `tile`, idle or not.
    pub fn civilian_on_tile_for_nation(
        &self,
        tile: TileId,
        nation: NationId,
    ) -> Option<(CivilianUnitId, &CivilianUnitState)> {
        self.civilians_on_tile_chain(tile)
            .into_iter()
            .find_map(|id| {
                let unit = &self.civilian_units[&id];
                (unit.owner_nation() == nation).then_some((id, unit))
            })
    }

    /// `TCivMgr::ClearNationCivilianActionModesAndCycleSelection` unit walk (cycle is app-side).
    pub fn clear_nation_civilian_action_modes(&mut self, nation: NationId) {
        for unit in self.civilian_units.values_mut() {
            if unit.nation() != nation {
                continue;
            }
            if matches!(
                unit.order,
                CivilianWorkOrder::Sleep | CivilianWorkOrder::Later | CivilianWorkOrder::Done
            ) {
                unit.order = CivilianWorkOrder::Idle;
            }
        }
    }

    /// `TCivMgr::OrderAndCycle` world-state mutation; selection cycling is app-side.
    pub fn set_civilian_idle_order(
        &mut self,
        id: CivilianUnitId,
        mode: CivilianIdleOrderMode,
    ) -> bool {
        let Some(unit) = self.civilian_units.get_mut(&id) else {
            return false;
        };
        if !idle_selectable(&unit.order) {
            return false;
        }
        unit.order = match mode {
            CivilianIdleOrderMode::Sleep => CivilianWorkOrder::Sleep,
            CivilianIdleOrderMode::Later => CivilianWorkOrder::Later,
            CivilianIdleOrderMode::Done => CivilianWorkOrder::Done,
        };
        true
    }

    /// `TCivUnit::ResetCivWorkOrderAndRefreshCounters` used by confirmed disband.
    pub fn disband_civilian(&mut self, id: CivilianUnitId) -> bool {
        let Some(unit) = self.civilian_units.get(&id) else {
            return false;
        };
        let tile = unit.location.tile();
        let kind = unit.unit_type;
        let nation = unit.owner_nation;
        if let Some(tile) = tile {
            self.unlink_civilian_from_tile_chain(id, tile);
        }
        self.civilian_units.shift_remove(&id);
        if kind == CivilianUnitKind::Developer {
            let audience = MajorNationId::from_nation(self.turn.active_nation);
            self.pending
                .queue_newspaper_event(PendingNewspaperEvent::Miscellaneous {
                    audience,
                    story_code: 0,
                });
        } else {
            let nation = MajorNationId::from_nation(nation)
                .expect("civilian specialists belong to a major nation");
            self.nations.city_mut(nation).population.add_expert(1);
        }
        true
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
        let order = &mut self
            .civilian_units
            .get_mut(&id)
            .expect("civilian remains present")
            .order;
        let completion = match order {
            CivilianWorkOrder::Sleep => Completion::None,
            CivilianWorkOrder::Idle
            | CivilianWorkOrder::Later
            | CivilianWorkOrder::Done
            | CivilianWorkOrder::Redeploy { .. } => Completion::Idle,
            CivilianWorkOrder::LayRail { segment, .. } => {
                let segment = *segment;
                if order.advance() {
                    Completion::Rail(segment)
                } else {
                    Completion::None
                }
            }
            CivilianWorkOrder::BuildDepot { .. } => {
                if order.advance() {
                    Completion::Depot
                } else {
                    Completion::None
                }
            }
            CivilianWorkOrder::BuildPort { .. } => {
                if order.advance() {
                    Completion::Port
                } else {
                    Completion::None
                }
            }
            CivilianWorkOrder::Prospect { .. } => {
                if order.advance() {
                    Completion::Prospect
                } else {
                    Completion::None
                }
            }
            CivilianWorkOrder::DevelopResource { .. } => {
                if order.advance() {
                    Completion::Develop
                } else {
                    Completion::None
                }
            }
            CivilianWorkOrder::BuildFort { .. } => {
                if order.advance() {
                    Completion::Fort
                } else {
                    Completion::None
                }
            }
            CivilianWorkOrder::PurchaseLand { .. } => {
                if order.advance() {
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
        let nation = nation.nation();
        let mut entries: Vec<_> = std::mem::take(&mut self.civilian_units)
            .into_iter()
            .collect();
        entries.sort_by_key(|(_, unit)| {
            (
                unit.nation,
                (unit.nation == nation).then(|| civilian_sort_priority(unit.unit_type)),
            )
        });
        self.civilian_units = entries.into_iter().collect();
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

    pub(crate) fn queue_depot_construction(&mut self, tile: TileId, nation: MajorNationId) {
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

    pub(crate) fn queue_port_construction(&mut self, tile: TileId, nation: MajorNationId) {
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
        let needs_naming = self.nations.major(nation).auto.is_none();
        let mut town = TownState::constructed(
            tile,
            nation.nation(),
            enabled,
            self.turn.economic_turn as i16,
        );
        town.needs_naming = needs_naming;
        self.nations.major_mut(nation).towns.insert(tile, town);
    }

    fn finish_new_town(&mut self, tile: TileId, nation: MajorNationId) {
        let yields = self.new_town_raw_resources(tile, nation);
        self.nations.majors[&nation].towns[&tile].resource_yield_by_type = yields;
    }

    /// Retail `TNewTownView::StuffValues` calls `TTown::CalculateRawResources`
    /// before presenting the variable list of resource bars.
    fn new_town_raw_resources(
        &self,
        town_tile: TileId,
        nation: MajorNationId,
    ) -> ResourceTable<i16> {
        let town = &self.nations.majors[&nation].towns[&town_tile];
        let town_region = self.map[town_tile].region;
        let owner = Some(TileOwnerTag::from_nation(nation.nation()));
        let mut yields = ResourceTable::default();
        let mut tiles = self
            .map
            .geometry()
            .neighbors(town_tile)
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        tiles.push(town_tile);
        for tile_id in tiles {
            let tile = &self.map[tile_id];
            if !((tile.owner_nation == owner && tile.region == town_region)
                || tile.terrain == TerrainKind::Water)
            {
                continue;
            }
            for resource in tile.edge_resources.into_iter().flatten() {
                if resource == ResourceKind::Fish && town.enabled == 0 {
                    continue;
                }
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
                yields[resource] += resource_development_yield(resource, development);
            }
            if tile.terrain == TerrainKind::Water && town.enabled != 0 {
                yields[ResourceKind::Fish] += 1;
            }
            if tile.river().is_some() && town.enabled != 0 {
                yields[ResourceKind::Fish] += 1;
            }
            if let Some(province) = tile.province
                && self.map.provinces[province].city_tile() == Some(tile_id)
            {
                for resource in ResourceKind::CITY_PRODUCTION {
                    yields[resource] +=
                        self.map.provinces[province].resource_development_by_type()[resource];
                }
            }
        }
        yields
    }

    pub fn pending_town_naming(&self) -> Option<(MajorNationId, TileId)> {
        MajorNationId::all().find_map(|nation| {
            self.nations
                .major(nation)
                .towns
                .iter()
                .find_map(|(&tile, town)| town.needs_naming.then_some((nation, tile)))
        })
    }

    /// Retail `TNewTownView::StuffValues` computes raw resources when the naming
    /// view is actually presented, not when `TTown` is constructed.
    pub fn prepare_pending_town_naming(&mut self) -> Option<(MajorNationId, TileId)> {
        let (nation, tile) = self.pending_town_naming()?;
        self.finish_new_town(tile, nation);
        Some((nation, tile))
    }

    /// Retail `TTownNameDialog::DoPostCreate` selects one of eight STR# 7250 entries.
    pub fn roll_pending_town_name_suggestion(&mut self) -> u8 {
        assert!(self.pending_town_naming().is_some(), "a town needs naming");
        (self.rng.next_crt_rand() % 8 + 1) as u8
    }

    pub fn name_pending_town(&mut self, name: String) -> bool {
        let Some((nation, tile)) = self.pending_town_naming() else {
            return false;
        };
        let town = self
            .nations
            .major_mut(nation)
            .towns
            .get_mut(&tile)
            .expect("pending town remains present");
        town.name = name;
        town.needs_naming = false;
        true
    }

    fn find_town_at_mut(&mut self, nation: MajorNationId, tile: TileId) -> Option<&mut TownState> {
        self.nations.major_mut(nation).towns.get_mut(&tile)
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

    pub(crate) fn rebuild_civilian_tile_chains(&mut self) {
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

    pub fn civilian_chain_head_on_tile(&self, tile: TileId) -> Option<CivilianUnitId> {
        self.chain_head_on_tile(tile)
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
    matches!(
        order,
        CivilianWorkOrder::Idle | CivilianWorkOrder::Sleep | CivilianWorkOrder::Later
    )
}

fn civilian_gate_qualifies(gate: i8) -> bool {
    matches!(gate, 2 | 3 | 5..=13 | 16..=23)
}

fn civilian_required_kind(resource: ResourceKind) -> Option<CivilianUnitKind> {
    match resource {
        ResourceKind::Cotton | ResourceKind::Grain | ResourceKind::Fruit => {
            Some(CivilianUnitKind::Farmer)
        }
        ResourceKind::Wool | ResourceKind::Livestock => Some(CivilianUnitKind::Rancher),
        ResourceKind::Timber => Some(CivilianUnitKind::Forester),
        ResourceKind::Coal | ResourceKind::Iron | ResourceKind::Gems | ResourceKind::Gold => {
            Some(CivilianUnitKind::Miner)
        }
        ResourceKind::Oil => Some(CivilianUnitKind::Driller),
        ResourceKind::Fish => Some(CivilianUnitKind::Fisherman),
        _ => None,
    }
}

fn civilian_resource_always_qualifies(resource: ResourceKind) -> bool {
    matches!(
        resource,
        ResourceKind::Cotton
            | ResourceKind::Wool
            | ResourceKind::Timber
            | ResourceKind::Coal
            | ResourceKind::Iron
            | ResourceKind::Oil
            | ResourceKind::Gems
            | ResourceKind::Gold
    )
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
            state.civilian_units[&unit].location(),
            CivilianLocation::OnMap(destination)
        );
        assert_eq!(
            state.civilian_units[&unit].order(),
            &CivilianWorkOrder::LayRail {
                segment: RailSegment::between(state.map.topology, origin, destination).unwrap(),
                turns: 1,
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
        assert_eq!(
            state.civilian_units[&unit].order(),
            &CivilianWorkOrder::Idle
        );
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
            state.civilian_units[&unit].location(),
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

        state.civilian_units[&unit].unit_type = CivilianUnitKind::Miner;
        let (_, destination) = interior();
        state.civilian_units[&unit].location = CivilianLocation::OnMap(origin);
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

    #[test]
    fn civilian_target_dispatch_keeps_retail_kind_specific_branches() {
        let mut state = crate::test_support::game_state();
        let (origin, destination) = interior();
        let engineer = engineer_on(&mut state, origin, destination);
        state.map[origin].region = None;
        state.map[origin].province = None;

        state.activate_civilian_selection(engineer);
        assert_eq!(
            state.civilian_tile_action(engineer, origin),
            CivilianTileAction::EngineerSameTile
        );
        assert_eq!(
            state.issue_civilian_tile_order(engineer, origin),
            Err(CivilianOrderRejection::ConstructionRequiresChoice)
        );
        assert_eq!(
            state.civilian_tile_action(engineer, destination),
            CivilianTileAction::EngineerDirection14
        );

        let miner_tile = state.map.geometry().tile(3, 10).unwrap();
        let worker_origin = state.map.geometry().tile(3, 9).unwrap();
        let miner = civilian_on(
            &mut state,
            2,
            CivilianUnitKind::Miner,
            worker_origin,
            CivilianWorkOrder::Idle,
            NationId::new(0),
        );
        state.map[miner_tile].owner_nation = Some(TileOwnerTag::from_nation(NationId::new(0)));
        state.map[miner_tile].edge_resources = [Some(ResourceKind::Oil), None];
        state.map[miner_tile].development.resource_visible_to_majors[MajorNationId::new(0)] = true;
        state.activate_civilian_selection(miner);
        assert_eq!(
            state.civilian_tile_action(miner, miner_tile),
            CivilianTileAction::Blocked
        );
        state.civilian_units[&miner].unit_type = CivilianUnitKind::Driller;
        state.technology.city_capabilities_by_nation[MajorNationId::new(0)]
            .university
            .requirement_levels[ResourceKind::Oil] = UniversityRequirementLevel::One;
        state.activate_civilian_selection(miner);
        assert_eq!(
            state.civilian_tile_action(miner, miner_tile),
            CivilianTileAction::DevelopResource
        );

        let move_tile = state.map.geometry().tile(3, 12).unwrap();
        state.map[move_tile].owner_nation = Some(TileOwnerTag::from_nation(NationId::new(0)));
        state.map[move_tile].gate = 1;
        assert_eq!(
            state.civilian_tile_action(miner, move_tile),
            CivilianTileAction::MoveUnit
        );
        assert_eq!(
            state.issue_civilian_tile_order(miner, move_tile),
            Ok(CivilianTileAction::MoveUnit)
        );
        assert_eq!(
            state.civilian_units[&miner].order,
            CivilianWorkOrder::Redeploy {
                source: worker_origin,
                turns: 0,
            }
        );
    }

    #[test]
    fn mining_targets_use_the_retail_nonzero_discovery_bitfield_gate() {
        let mut state = crate::test_support::game_state();
        let origin = state.map.geometry().tile(3, 9).unwrap();
        let target = state.map.geometry().tile(3, 10).unwrap();
        let nation = NationId::new(0);
        let major = MajorNationId::new(0);
        let miner = civilian_on(
            &mut state,
            2,
            CivilianUnitKind::Miner,
            origin,
            CivilianWorkOrder::Idle,
            nation,
        );
        state.map[target].owner_nation = Some(TileOwnerTag::from_nation(nation));
        state.map[target].edge_resources = [Some(ResourceKind::Coal), None];
        state.technology.city_capabilities_by_nation[major]
            .university
            .requirement_levels[ResourceKind::Coal] = UniversityRequirementLevel::One;
        state.map[target].development.resource_visible_to_majors[MajorNationId::new(1)] = true;

        state.activate_civilian_selection(miner);
        assert_eq!(
            state.civilian_tile_action(miner, target),
            CivilianTileAction::DevelopResource
        );

        state.map[target].development.resource_visible_to_majors[MajorNationId::new(1)] = false;
        state.activate_civilian_selection(miner);
        assert_eq!(
            state.civilian_tile_action(miner, target),
            CivilianTileAction::Blocked
        );
    }

    #[test]
    fn civilian_modal_orders_queue_and_rescind_with_retail_payloads_and_refunds() {
        let mut state = crate::test_support::game_state();
        let geometry = MapGeometry::new(MapTopology::Bounded);
        let origin = geometry.tile(4, 10).unwrap();
        let rail_target = geometry
            .neighbor(origin, HexDirection::East)
            .expect("interior tile has an eastern neighbor");
        let nation = NationId::new(0);
        let major = MajorNationId::new(0);
        state.map[origin].owner_nation = Some(TileOwnerTag::from_nation(nation));
        state.map[origin].terrain = TerrainKind::Plains;
        state.map[origin].gate = 1;
        state.map[rail_target].owner_nation = Some(TileOwnerTag::from_nation(nation));
        state.map[rail_target].terrain = TerrainKind::Plains;
        state.map[rail_target].gate = 1;
        state.map.provinces[ProvinceId::new(0)] = ProvinceState::new(
            Some(nation),
            Some(nation),
            ProvinceDevelopmentStage::None,
            Vec::new(),
            Vec::new(),
            Some(0),
            FortLevel::None,
            Some(origin),
            0,
            None,
            None,
            Vec::new(),
            ResourceTable::default(),
            MajorNationTable::default(),
            0,
            false,
            0,
            "Capital".to_owned(),
        );
        state.map[origin].province = Some(ProvinceId::new(0));
        state.nations.major_mut(major).common.treasury = 10_000;
        let engineer = civilian_on(
            &mut state,
            20,
            CivilianUnitKind::Engineer,
            origin,
            CivilianWorkOrder::Idle,
            nation,
        );

        assert!(
            state
                .engineer_construction_options(engineer)
                .iter()
                .any(|option| option.choice == EngineerConstructionChoice::Fort
                    && option.cost == 5_000)
        );
        state
            .queue_engineer_construction(engineer, EngineerConstructionChoice::Fort)
            .unwrap();
        assert_eq!(state.nations.major(major).common.treasury, 5_000);
        assert_eq!(
            state.civilian_units[&engineer].order,
            CivilianWorkOrder::BuildDepot {
                source: origin,
                turns: 3,
            }
        );
        state.cancel_civilian_work_order(engineer).unwrap();
        assert_eq!(state.nations.major(major).common.treasury, 7_000);
        assert_eq!(
            state.civilian_units[&engineer].order,
            CivilianWorkOrder::Idle
        );

        state
            .order_rail_construction(engineer, rail_target)
            .unwrap();
        assert!(!state.map[origin].pending_rail_links.is_empty());
        state.cancel_civilian_work_order(engineer).unwrap();
        assert_eq!(
            state.civilian_units[&engineer].location.tile(),
            Some(origin)
        );
        assert!(state.map[origin].pending_rail_links.is_empty());
        assert!(state.map[rail_target].pending_rail_links.is_empty());
        assert_eq!(state.nations.major(major).common.treasury, 7_000);
    }

    #[test]
    fn confirmed_land_purchase_uses_retail_cost_and_rescinds_to_the_source_tile() {
        let mut state = crate::test_support::game_state();
        let geometry = MapGeometry::new(MapTopology::Bounded);
        let source = geometry.tile(5, 10).unwrap();
        let target = geometry.tile(5, 12).unwrap();
        let nation = NationId::new(0);
        let major = MajorNationId::new(0);
        let minor = NationId::new(7);
        state.map[source].owner_nation = Some(TileOwnerTag::from_nation(nation));
        state.map[target].owner_nation = Some(TileOwnerTag::from_nation(minor));
        state.map[target].terrain = TerrainKind::Plains;
        state.map[target].gate = 8;
        state.map[target].edge_resources[0] = Some(ResourceKind::Gems);
        state.map[target].development.resource_visible_to_majors[major] = true;
        state.diplomacy.mission_levels[nation][minor] = DiplomaticMissionLevel::Embassy;
        state.nations.major_mut(major).common.treasury = 10_000;
        let developer = civilian_on(
            &mut state,
            21,
            CivilianUnitKind::Developer,
            source,
            CivilianWorkOrder::Idle,
            nation,
        );
        state.activate_civilian_selection(developer);

        assert_eq!(state.developer_tile_purchase_cost(target), 10_000);
        assert!(state.can_afford_developer_tile_purchase(developer, target));
        state
            .confirm_developer_tile_purchase(developer, target)
            .unwrap();
        assert_eq!(state.nations.major(major).common.treasury, 0);
        assert_eq!(
            state.civilian_units[&developer].location.tile(),
            Some(target)
        );
        assert_eq!(
            state.civilian_units[&developer].order,
            CivilianWorkOrder::PurchaseLand { source, turns: 1 }
        );
        state.cancel_civilian_work_order(developer).unwrap();
        assert_eq!(state.nations.major(major).common.treasury, 10_000);
        assert_eq!(
            state.civilian_units[&developer].location.tile(),
            Some(source)
        );
        assert_eq!(
            state.civilian_units[&developer].order,
            CivilianWorkOrder::Idle
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
            ProvinceDevelopmentStage::None,
            Vec::new(),
            Vec::new(),
            Some(0),
            FortLevel::None,
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
            CivilianWorkOrder::Prospect {
                source: prospect_tile,
                turns: 1,
            },
            nation,
        );
        civilian_on(
            &mut state,
            3,
            CivilianUnitKind::Developer,
            purchase_tile,
            CivilianWorkOrder::PurchaseLand {
                source: purchase_tile,
                turns: 1,
            },
            nation,
        );
        civilian_on(
            &mut state,
            4,
            CivilianUnitKind::Engineer,
            fort_tile,
            CivilianWorkOrder::BuildFort {
                source: fort_tile,
                turns: 1,
            },
            nation,
        );
        civilian_on(
            &mut state,
            5,
            CivilianUnitKind::Engineer,
            depot_tile,
            CivilianWorkOrder::BuildDepot {
                source: depot_tile,
                turns: 1,
            },
            nation,
        );
        civilian_on(
            &mut state,
            6,
            CivilianUnitKind::Engineer,
            port_tile,
            CivilianWorkOrder::BuildPort {
                source: port_tile,
                turns: 1,
            },
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
                source: redeploy_tile,
                turns: 1,
            },
            nation,
        );
        civilian_on(
            &mut state,
            9,
            CivilianUnitKind::Miner,
            develop_tile,
            CivilianWorkOrder::DevelopResource {
                source: develop_tile,
                turns: 3,
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
        assert_eq!(
            state.map.provinces[ProvinceId::new(0)].fort_level(),
            FortLevel::One
        );
        assert!(state.map[depot_tile].flags.contains(TileFlags::DEPOT));
        assert!(
            state
                .nations
                .major(MajorNationId::new(0))
                .towns
                .get(&depot_tile)
                .is_some_and(|town| town.enabled == 0 && town.active)
        );
        assert!(state.map[port_tile].flags.contains(TileFlags::PORT));
        assert!(
            state
                .nations
                .major(MajorNationId::new(0))
                .towns
                .get(&port_tile)
                .is_some_and(|town| town.enabled == 1 && !town.active)
        );
        assert_eq!(
            state.pending_town_naming(),
            Some((MajorNationId::new(0), depot_tile))
        );
        assert!(state.name_pending_town("Depot Name".to_owned()));
        assert_eq!(
            state.nations.major(MajorNationId::new(0)).towns[&depot_tile].name,
            "Depot Name"
        );
        assert_eq!(
            state.pending_town_naming(),
            Some((MajorNationId::new(0), port_tile))
        );
        assert_eq!(state.advance_turn(&[]), TurnStop::TownNaming);
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
                    CivilianWorkOrder::DevelopResource { turns, .. } if turns == 2
                )
        }));
    }

    #[test]
    fn protectorates_are_skipped_and_humans_sort_by_unit_kind() {
        let mut state = crate::test_support::game_state();
        let (first, second) = interior();
        let nation = NationId::new(0);
        let farmer = civilian_on(
            &mut state,
            2,
            CivilianUnitKind::Farmer,
            first,
            CivilianWorkOrder::Idle,
            nation,
        );
        let miner = civilian_on(
            &mut state,
            3,
            CivilianUnitKind::Miner,
            second,
            CivilianWorkOrder::DevelopResource {
                source: second,
                turns: 1,
            },
            nation,
        );

        state.set_country_status(nation, CountryStatus::ProtectorateOf(NationId::new(1)));
        state.do_civilians();
        assert_eq!(
            state.civilian_units[&farmer].unit_type,
            CivilianUnitKind::Farmer
        );
        assert!(matches!(
            state.civilian_units[&miner].order,
            CivilianWorkOrder::DevelopResource { .. }
        ));

        state.set_country_status(nation, CountryStatus::Independent);
        state.do_civilians();
        assert_eq!(
            state.civilian_units[&miner].unit_type,
            CivilianUnitKind::Miner
        );
        assert_eq!(
            state.civilian_units[&farmer].unit_type,
            CivilianUnitKind::Farmer
        );
        assert_eq!(state.civilian_units[&miner].order, CivilianWorkOrder::Idle);
    }

    #[test]
    fn civilian_toolbar_orders_preserve_retail_idle_modes() {
        let mut state = crate::test_support::game_state();
        let tile = interior().0;
        let nation = NationId::new(0);
        let unit = civilian_on(
            &mut state,
            2,
            CivilianUnitKind::Engineer,
            tile,
            CivilianWorkOrder::Idle,
            nation,
        );

        assert!(state.set_civilian_idle_order(unit, CivilianIdleOrderMode::Later));
        assert_eq!(state.civilian_units[&unit].order, CivilianWorkOrder::Later);
        assert!(state.set_civilian_idle_order(unit, CivilianIdleOrderMode::Done));
        assert_eq!(state.civilian_units[&unit].order, CivilianWorkOrder::Done);
        assert!(!state.set_civilian_idle_order(unit, CivilianIdleOrderMode::Sleep));
    }

    #[test]
    fn disbanding_specialist_returns_expert_and_unlinks_unit() {
        let mut state = crate::test_support::game_state();
        let tile = interior().0;
        let nation = NationId::new(0);
        let major = MajorNationId::new(0);
        let before = state.nations.city(major).population.clone();
        let unit = civilian_on(
            &mut state,
            2,
            CivilianUnitKind::Engineer,
            tile,
            CivilianWorkOrder::Idle,
            nation,
        );

        assert!(state.disband_civilian(unit));
        assert!(state.civilian_unit(unit).is_none());
        assert!(!state.civilians_on_tile_chain(tile).contains(&unit));
        let after = &state.nations.city(major).population;
        assert_eq!(after.count(), before.count() + 1);
        assert_eq!(after.strength(), before.strength() + 4);
        assert_eq!(
            after.baseline_labor().high,
            before.baseline_labor().high + 1
        );
        assert_eq!(
            after.production_labor().high,
            before.production_labor().high + 1
        );
    }
}
