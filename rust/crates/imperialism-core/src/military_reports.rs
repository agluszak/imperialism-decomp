//! Strategic army/navy report and roster projections (`TArmyInfoView`, `TGarrisonView`,
//! `TSuperArmyRoster`, `InspectTaskForceDialog` / `NavalIntelligenceDialog`,
//! `TNavyRoster` / `TSuperNavyRoster`).

use crate::combat_moves::stationed_chain_ids;
use crate::military_phase::tactical_category;
use crate::*;
use enum_map::Enum;

/// `TArmyInfoView::StuffValues` for a province's stationed units.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArmyReportModel {
    pub province: ProvinceId,
    pub city_name: String,
    pub owned_by_viewer: bool,
    pub composition: Vec<(ArmyUnitCategory, i32)>,
}

/// One `TArmyUnitLine` in `TGarrisonView`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GarrisonRow {
    pub unit: MilitaryUnitId,
    pub name: String,
    pub kind: MilitaryUnitKind,
    pub order: MilitaryOrderCode,
    pub idle: bool,
    pub militia: bool,
    pub can_upgrade: bool,
}

/// `TGarrisonView::StuffValues`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GarrisonModel {
    pub province: ProvinceId,
    pub city_name: String,
    pub units: Vec<GarrisonRow>,
}

/// One `TMiniArmyLine` in `TSuperArmyRoster`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArmyRosterRow {
    pub unit: MilitaryUnitId,
    pub name: String,
    pub province: ProvinceId,
    pub city_name: String,
    pub can_upgrade: bool,
}

/// `TSuperArmyRoster::PopulateArmyOrderPageEntries`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArmyRosterModel {
    pub units: Vec<ArmyRosterRow>,
}

/// Friendly inspect vs foreign intelligence (`InspectTaskForceDialog` / `NavalIntelligenceDialog`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FleetReportKind {
    Friendly(TaskForceId),
    Intelligence { zone: OceanZoneId, nation: NationId },
}

/// Admiral/ship attribution used by fleet reports and intelligence source lines.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FleetAuthority {
    pub admiral: Option<String>,
    pub ship: Option<String>,
}

/// `TMapUberPicture::InspectTaskForceDialog`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FriendlyFleetReport {
    pub force: TaskForceId,
    pub zone: OceanZoneId,
    pub zone_name: String,
    pub authority: FleetAuthority,
    pub composition: Vec<(ShipType, i32)>,
    pub order: TaskForceOrder,
    pub target_name: Option<String>,
    pub aggression: NavalAggression,
}

/// `TMapUberPicture::NavalIntelligenceDialog`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnemyFleetReport {
    pub nation: NationId,
    pub nation_name: String,
    pub zone: OceanZoneId,
    pub zone_name: String,
    pub authority: FleetAuthority,
    pub composition: Vec<(ShipType, i32)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FleetReportModel {
    Friendly(FriendlyFleetReport),
    Intelligence(EnemyFleetReport),
}

/// Nation-wide `TSuperNavyRoster` vs a single `TNavyRoster` task-force page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NavyRosterKind {
    Nation,
    TaskForce(TaskForceId),
}

/// One `TMiniShipLine` / `TShipLine`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NavyRosterRow {
    pub ship: ShipId,
    pub name: String,
    pub ship_type: ShipType,
    pub location: OceanZoneId,
    pub zone_name: String,
    pub force: Option<TaskForceId>,
    pub selected: bool,
    pub has_admiral: bool,
}

/// `TSuperNavyRoster` / `TNavyRoster::StuffValues`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NavyRosterModel {
    pub kind: NavyRosterKind,
    pub ships: Vec<NavyRosterRow>,
}

impl GameState {
    /// Stationed-unit category counts for MapView 3100.
    pub fn army_report_model(&self, province: ProvinceId) -> ArmyReportModel {
        let mut counts = ArmyCategoryTable::<i32>::default();
        for id in stationed_chain_ids(&self.military_units, province) {
            let unit = &self.military_units[&id];
            counts[tactical_category(unit.unit_type())] += 1;
        }
        let composition = ArmyUnitCategory::all()
            .filter_map(|category| {
                let count = counts[category];
                (count != 0).then_some((category, count))
            })
            .collect();
        ArmyReportModel {
            province,
            city_name: self.province_display_name(province),
            owned_by_viewer: self.normalized_province_owner(province)
                == Some(self.turn.active_nation),
            composition,
        }
    }

    /// Stationed units excluding those already on a redeploy order.
    pub fn garrison_model(&self, province: ProvinceId) -> GarrisonModel {
        let units = stationed_chain_ids(&self.military_units, province)
            .into_iter()
            .filter_map(|id| {
                let unit = self.military_units.get(&id)?;
                if unit.order.code() == MilitaryOrderCode::Redeploy {
                    return None;
                }
                let order = unit.order.code();
                Some(GarrisonRow {
                    unit: id,
                    name: unit.name().to_owned(),
                    kind: unit.unit_type(),
                    order,
                    idle: order == MilitaryOrderCode::Idle,
                    militia: tactical_category(unit.unit_type()) == ArmyUnitCategory::Garrison,
                    can_upgrade: self.unit_can_upgrade(unit),
                })
            })
            .collect();
        GarrisonModel {
            province,
            city_name: self.province_display_name(province),
            units,
        }
    }

    /// Every unit stationed in a province owned by the active nation.
    pub fn army_roster_model(&self) -> ArmyRosterModel {
        let nation = self.turn.active_nation;
        let mut units = Vec::new();
        for province in ProvinceId::all() {
            if self.normalized_province_owner(province) != Some(nation) {
                continue;
            }
            let city_name = self.province_display_name(province);
            for id in stationed_chain_ids(&self.military_units, province) {
                let unit = &self.military_units[&id];
                units.push(ArmyRosterRow {
                    unit: id,
                    name: unit.name().to_owned(),
                    province,
                    city_name: city_name.clone(),
                    can_upgrade: self.unit_can_upgrade(unit),
                });
            }
        }
        ArmyRosterModel { units }
    }

    /// Friendly task-force inspect or foreign-zone intelligence.
    pub fn fleet_report_model(&self, kind: FleetReportKind) -> Option<FleetReportModel> {
        match kind {
            FleetReportKind::Friendly(force) => self
                .friendly_fleet_report(force)
                .map(FleetReportModel::Friendly),
            FleetReportKind::Intelligence { zone, nation } => Some(FleetReportModel::Intelligence(
                self.enemy_fleet_report(zone, nation),
            )),
        }
    }

    /// Nation-wide navy book or the selected task force's ship list.
    pub fn navy_roster_model(&self, kind: NavyRosterKind) -> NavyRosterModel {
        let ships = match kind {
            NavyRosterKind::Nation => self.nation_navy_roster_rows(),
            NavyRosterKind::TaskForce(force) => self.task_force_navy_roster_rows(force),
        };
        NavyRosterModel { kind, ships }
    }

    /// `TArmyUnitView` checkbox: idle ↔ later (`UNIT_ORDER_LATR`). Militia is ignored.
    pub fn toggle_garrison_unit_ready(&mut self, unit: MilitaryUnitId) {
        let Some(state) = self.military_units.get(&unit) else {
            return;
        };
        if tactical_category(state.unit_type()) == ArmyUnitCategory::Garrison {
            return;
        }
        let next = if state.order.code() == MilitaryOrderCode::Idle {
            MilitaryOrderCode::Latr
        } else {
            MilitaryOrderCode::Idle
        };
        crate::combat_moves::set_unit_order(
            self.military_units
                .get_mut(&unit)
                .expect("garrison unit remains live"),
            next,
            None,
        );
    }

    fn friendly_fleet_report(&self, force: TaskForceId) -> Option<FriendlyFleetReport> {
        let entry = self.task_force(force)?;
        let zone = entry.location;
        let order = entry.order;
        let aggression = entry.aggression;
        let target_name = match (order, entry.target) {
            (TaskForceOrder::Sail | TaskForceOrder::Blockade, TaskForceTarget::Zone(target)) => {
                Some(self.zone_display_name(target))
            }
            (TaskForceOrder::Patrol, _) => Some(self.zone_display_name(zone)),
            (TaskForceOrder::Marines, TaskForceTarget::Province(province)) => {
                Some(self.province_display_name(province))
            }
            _ => None,
        };
        let composition = self.ship_composition(entry.ships().map(|(id, _)| id));
        Some(FriendlyFleetReport {
            force,
            zone,
            zone_name: self.zone_display_name(zone),
            authority: self.flagship_authority(entry.flagship()),
            composition,
            order,
            target_name,
            aggression,
        })
    }

    fn enemy_fleet_report(&self, zone: OceanZoneId, nation: NationId) -> EnemyFleetReport {
        let ships = self.ships_in_zone_for_nation(zone, nation);
        EnemyFleetReport {
            nation,
            nation_name: self.nations.display_name(nation).unwrap_or("").to_owned(),
            zone,
            zone_name: self.zone_display_name(zone),
            authority: self.observing_authority(zone),
            composition: self.ship_composition(ships),
        }
    }

    fn nation_navy_roster_rows(&self) -> Vec<NavyRosterRow> {
        let nation = self.turn.active_nation;
        let mut rows = Vec::new();
        for zone in (0..self.ocean.zones.len())
            .rev()
            .map(|index| OceanZoneId::new(index as u16))
        {
            for (id, ship) in self.ships_in_retail_order() {
                if ship.location != zone || ship.nation != nation {
                    continue;
                }
                rows.push(self.navy_roster_row(id, ship));
            }
        }
        rows
    }

    fn task_force_navy_roster_rows(&self, force: TaskForceId) -> Vec<NavyRosterRow> {
        let Some(entry) = self.task_force(force) else {
            return Vec::new();
        };
        entry
            .ships()
            .filter_map(|(id, selected)| {
                let ship = self.ship(id)?;
                let mut row = self.navy_roster_row(id, ship);
                row.force = Some(force);
                row.selected = selected;
                Some(row)
            })
            .collect()
    }

    fn navy_roster_row(&self, id: ShipId, ship: &ShipState) -> NavyRosterRow {
        NavyRosterRow {
            ship: id,
            name: ship.name.clone(),
            ship_type: ship.ship_type,
            location: ship.location,
            zone_name: self.zone_display_name(ship.location),
            force: self.task_force_of_ship(id),
            selected: false,
            has_admiral: self.admiral_assigned_to(id).is_some(),
        }
    }

    fn flagship_authority(&self, flagship: Option<ShipId>) -> FleetAuthority {
        let Some(ship) = flagship.and_then(|id| self.ship(id)) else {
            return FleetAuthority {
                admiral: None,
                ship: None,
            };
        };
        FleetAuthority {
            admiral: flagship.and_then(|id| {
                self.admiral_assigned_to(id)
                    .map(|admiral| admiral.name.clone())
            }),
            ship: Some(ship.name.clone()),
        }
    }

    fn observing_authority(&self, zone: OceanZoneId) -> FleetAuthority {
        let observer = self.turn.active_nation;
        let Some(ship) = self.finest_ship_in_zone(zone, observer) else {
            return FleetAuthority {
                admiral: None,
                ship: None,
            };
        };
        self.flagship_authority(Some(ship))
    }

    fn finest_ship_in_zone(&self, zone: OceanZoneId, nation: NationId) -> Option<ShipId> {
        self.ships_in_zone_for_nation(zone, nation)
            .reduce(|best, candidate| {
                if self.ship_outranks(candidate, best) {
                    candidate
                } else {
                    best
                }
            })
    }

    fn ship_outranks(&self, ship: ShipId, candidate: ShipId) -> bool {
        match (
            self.admiral_assigned_to(ship)
                .map(|admiral| admiral.experience),
            self.admiral_assigned_to(candidate)
                .map(|admiral| admiral.experience),
        ) {
            (Some(left), Some(right)) if left != right => left > right,
            (Some(_), None) => true,
            (None, Some(_)) => false,
            _ => {
                let left = self.ship(ship).expect("finest candidate exists");
                let right = self.ship(candidate).expect("finest candidate exists");
                left.ship_type.into_usize() > right.ship_type.into_usize()
            }
        }
    }

    fn ships_in_zone_for_nation(
        &self,
        zone: OceanZoneId,
        nation: NationId,
    ) -> impl Iterator<Item = ShipId> + '_ {
        self.ships_in_retail_order().filter_map(move |(id, ship)| {
            (ship.location == zone && ship.nation == nation).then_some(id)
        })
    }

    fn ship_composition(&self, ships: impl Iterator<Item = ShipId>) -> Vec<(ShipType, i32)> {
        let mut counts = ShipTypeTable::<i32>::default();
        for id in ships {
            if let Some(ship) = self.ship(id) {
                counts[ship.ship_type] += 1;
            }
        }
        (0..ShipType::LENGTH)
            .filter_map(|index| {
                let kind = ShipType::from_index(index as u8)?;
                let count = counts[kind];
                (count != 0).then_some((kind, count))
            })
            .collect()
    }

    fn admiral_assigned_to(&self, ship: ShipId) -> Option<&AdmiralState> {
        self.admirals
            .values()
            .find(|admiral| admiral.ship == Some(ship))
    }

    fn province_display_name(&self, province: ProvinceId) -> String {
        self.map.provinces[province].name.clone()
    }

    fn zone_display_name(&self, zone: OceanZoneId) -> String {
        self.ocean
            .zones
            .get(usize::from(zone.get()))
            .map(|zone| zone.zone().display_name.clone())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::game_state;
    use indexmap::IndexMap;

    fn place_unit(
        state: &mut GameState,
        kind: MilitaryUnitKind,
        province: ProvinceId,
        order: MilitaryOrderCode,
        name: &str,
    ) -> MilitaryUnitId {
        let id = MilitaryUnitId::new(state.military_units.len() as i32 + 1);
        let nation = state.turn.active_nation;
        state.military_units.insert(
            id,
            MilitaryUnitState::new(
                nation,
                kind,
                Some(province),
                if order == MilitaryOrderCode::Idle {
                    MilitaryOrder::idle([None; 3], [None; 3])
                } else {
                    MilitaryOrder::retail(order, None, [None; 3], [None; 3])
                },
                nation,
                0,
                true,
                name.to_owned(),
                0x1f4,
                MilitaryEra::First,
                0,
                0,
            ),
        );
        id
    }

    fn own(state: &mut GameState, province: ProvinceId) {
        let nation = state.turn.active_nation;
        state.map.provinces[province].set_owner(Some(nation));
        state.map.provinces[province].name = format!("City{}", province.get());
    }

    fn add_zone(state: &mut GameState, name: &str) -> OceanZoneId {
        let id = OceanZoneId::new(state.ocean.zones.len() as u16);
        state.ocean.zones.push(ZoneKind::Zone(Zone {
            display_name: name.to_owned(),
            status_code: None,
            target_tile: None,
            seed_owner: None,
            active_tile: None,
            primary_neighbors: Vec::new(),
            secondary_neighbors: Vec::new(),
        }));
        id
    }

    fn add_ship(
        state: &mut GameState,
        ship_type: ShipType,
        location: OceanZoneId,
        nation: NationId,
        name: &str,
    ) -> ShipId {
        state.insert_ship(ShipState {
            ship_type,
            location,
            aggression: NavalAggression::Cautious,
            nation,
            name: name.to_owned(),
            strength: 900,
            experience: 0,
            selection: ShipSelection::Available,
        })
    }

    #[test]
    fn army_report_lists_nonzero_categories_in_toolbar_order() {
        let mut state = game_state();
        let province = ProvinceId::new(3);
        own(&mut state, province);
        place_unit(
            &mut state,
            MilitaryUnitKind::Hussars,
            province,
            MilitaryOrderCode::Idle,
            "Hussars",
        );
        place_unit(
            &mut state,
            MilitaryUnitKind::Regulars,
            province,
            MilitaryOrderCode::Idle,
            "1st",
        );
        place_unit(
            &mut state,
            MilitaryUnitKind::Regulars,
            province,
            MilitaryOrderCode::Sleep,
            "2nd",
        );
        let report = state.army_report_model(province);
        assert_eq!(report.city_name, "City3");
        assert!(report.owned_by_viewer);
        assert_eq!(
            report.composition,
            [
                (ArmyUnitCategory::LineInfantry, 2),
                (ArmyUnitCategory::LightCavalry, 1)
            ]
        );
    }

    #[test]
    fn garrison_skips_redeploying_units_and_marks_militia() {
        let mut state = game_state();
        let province = ProvinceId::new(4);
        own(&mut state, province);
        let idle = place_unit(
            &mut state,
            MilitaryUnitKind::Regulars,
            province,
            MilitaryOrderCode::Idle,
            "Ready",
        );
        place_unit(
            &mut state,
            MilitaryUnitKind::Regulars,
            province,
            MilitaryOrderCode::Redeploy,
            "Gone",
        );
        let militia = place_unit(
            &mut state,
            MilitaryUnitKind::Minutemen,
            province,
            MilitaryOrderCode::Idle,
            "Watch",
        );
        let model = state.garrison_model(province);
        assert_eq!(
            model
                .units
                .iter()
                .map(|row| (row.unit, row.militia, row.idle))
                .collect::<Vec<_>>(),
            [(militia, true, true), (idle, false, true)]
        );
        state.toggle_garrison_unit_ready(idle);
        assert_eq!(
            state.military_unit(idle).map(|unit| unit.order.code()),
            Some(MilitaryOrderCode::Latr)
        );
        state.toggle_garrison_unit_ready(militia);
        assert_eq!(
            state.military_unit(militia).map(|unit| unit.order.code()),
            Some(MilitaryOrderCode::Idle)
        );
    }

    #[test]
    fn army_roster_walks_owned_provinces_in_id_order() {
        let mut state = game_state();
        let first = ProvinceId::new(1);
        let second = ProvinceId::new(5);
        own(&mut state, second);
        own(&mut state, first);
        state.map.provinces[ProvinceId::new(2)].set_owner(Some(NationId::new(1)));
        place_unit(
            &mut state,
            MilitaryUnitKind::Regulars,
            second,
            MilitaryOrderCode::Idle,
            "Later",
        );
        place_unit(
            &mut state,
            MilitaryUnitKind::Regulars,
            first,
            MilitaryOrderCode::Idle,
            "First",
        );
        place_unit(
            &mut state,
            MilitaryUnitKind::Regulars,
            ProvinceId::new(2),
            MilitaryOrderCode::Idle,
            "Foreign",
        );
        let roster = state.army_roster_model();
        assert_eq!(
            roster
                .units
                .iter()
                .map(|row| (row.name.as_str(), row.province, row.city_name.as_str()))
                .collect::<Vec<_>>(),
            [("First", first, "City1"), ("Later", second, "City5")]
        );
    }

    #[test]
    fn friendly_fleet_report_names_flagship_and_counts_types() {
        let mut state = game_state();
        let zone = add_zone(&mut state, "Home Sea");
        let target = add_zone(&mut state, "Far Sea");
        let nation = state.turn.active_nation;
        let frigate = add_ship(&mut state, ShipType::Frigate, zone, nation, "Valiant");
        let extra = add_ship(&mut state, ShipType::Frigate, zone, nation, "Second");
        add_ship(&mut state, ShipType::Raider, zone, nation, "Raider");
        state.admirals.insert(
            state.object_ids.admiral(),
            AdmiralState {
                nation,
                name: "Nelson".into(),
                experience: 150,
                ship: Some(frigate),
            },
        );
        let force = state.object_ids.task_force();
        state.task_forces.insert(
            force,
            TaskForceState {
                aggression: NavalAggression::Aggressive,
                order: TaskForceOrder::Sail,
                target: TaskForceTarget::Zone(target),
                location: zone,
                nation,
                defeated: false,
                ingot_tile: -1,
                flagship: Some(frigate),
                ships: [(frigate, true), (extra, false)].into_iter().collect(),
            },
        );
        let FleetReportModel::Friendly(report) = state
            .fleet_report_model(FleetReportKind::Friendly(force))
            .expect("friendly force")
        else {
            panic!("expected friendly report");
        };
        assert_eq!(report.zone_name, "Home Sea");
        assert_eq!(report.authority.admiral.as_deref(), Some("Nelson"));
        assert_eq!(report.authority.ship.as_deref(), Some("Valiant"));
        assert_eq!(report.composition, [(ShipType::Frigate, 2)]);
        assert_eq!(report.order, TaskForceOrder::Sail);
        assert_eq!(report.target_name.as_deref(), Some("Far Sea"));
        assert_eq!(report.aggression, NavalAggression::Aggressive);
    }

    #[test]
    fn navy_roster_nation_lists_owned_ships_newest_zone_first() {
        let mut state = game_state();
        let near = add_zone(&mut state, "Near");
        let far = add_zone(&mut state, "Far");
        let nation = state.turn.active_nation;
        add_ship(&mut state, ShipType::Frigate, near, nation, "Old");
        add_ship(&mut state, ShipType::Raider, far, nation, "New");
        add_ship(
            &mut state,
            ShipType::Frigate,
            near,
            NationId::new(1),
            "Foreign",
        );
        let roster = state.navy_roster_model(NavyRosterKind::Nation);
        assert_eq!(
            roster
                .ships
                .iter()
                .map(|row| row.name.as_str())
                .collect::<Vec<_>>(),
            ["New", "Old"]
        );
    }

    #[test]
    fn navy_roster_task_force_keeps_selection_flags() {
        let mut state = game_state();
        let zone = add_zone(&mut state, "Home");
        let nation = state.turn.active_nation;
        let first = add_ship(&mut state, ShipType::Frigate, zone, nation, "A");
        let second = add_ship(&mut state, ShipType::Raider, zone, nation, "B");
        let force = state.object_ids.task_force();
        let mut ships = IndexMap::new();
        ships.insert(first, true);
        ships.insert(second, false);
        state.task_forces.insert(
            force,
            TaskForceState {
                aggression: NavalAggression::Balanced,
                order: TaskForceOrder::Patrol,
                target: TaskForceTarget::None,
                location: zone,
                nation,
                defeated: false,
                ingot_tile: -1,
                flagship: Some(first),
                ships,
            },
        );
        let roster = state.navy_roster_model(NavyRosterKind::TaskForce(force));
        assert_eq!(
            roster
                .ships
                .iter()
                .map(|row| (row.name.as_str(), row.selected))
                .collect::<Vec<_>>(),
            [("A", true), ("B", false)]
        );
    }
}
