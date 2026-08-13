use crate::*;
use serde::{Deserialize, Serialize};

const MILITARY_MAINTENANCE_MULTIPLIER: i32 = 25;

const NAVY_ARMS_BY_SHIP_TYPE: ShipTypeTable<i32> =
    ShipTypeTable::from_array([0, 0, 0, 2, 5, 0, 0, 3, 6, 15, 0, 8, 24, 18]);

impl GameState {
    pub(crate) fn military_power_score(&self, nation: MajorNationId) -> i32 {
        let nation_id = nation.nation();
        self.military_units
            .iter()
            .filter(|unit| unit.nation == nation_id)
            .map(|unit| unit.unit_type.arms_required())
            .sum::<i32>()
            + self
                .ships
                .iter()
                .filter(|ship| ship.nation == nation_id)
                .map(|ship| NAVY_ARMS_BY_SHIP_TYPE[ship.ship_type])
                .sum::<i32>()
            + 4
    }

    /// Charges one major nation for its current army and navy.
    pub fn pay_for_military(&mut self, nation: MajorNationId) {
        let arms = self.military_power_score(nation) - 4;
        let charge = arms * MILITARY_MAINTENANCE_MULTIPLIER;

        let MajorNation {
            common,
            economy: major,
            ..
        } = &mut self.nations.majors[nation];
        major.military_expenses = charge;
        common.treasury -= charge;
    }

    /// Prepends a ship the way `TShip::TShip` prepends `g_pNavyPrimaryOrderListHead`.
    pub(crate) fn insert_ship_at_head(&mut self, ship: ShipState) {
        self.bump_ship_ids();
        self.ships.insert(0, ship);
    }

    fn bump_ship_ids(&mut self) {
        for admiral in &mut self.admirals {
            if let Some(ship) = &mut admiral.ship {
                *ship = ShipId::new(ship.get() + 1);
            }
        }
        for force in &mut self.task_forces {
            if let Some(flagship) = &mut force.flagship {
                *flagship = ShipId::new(flagship.get() + 1);
            }
            for selected in &mut force.ships {
                selected.ship = ShipId::new(selected.ship.get() + 1);
            }
        }
        for mission in &mut self.missions {
            bump_mission_ship_ids(&mut mission.data);
        }
    }

    /// Retail `TOcean::FindFirstPortZoneContextByNation`: newest port whose
    /// port tile's former owner is `nation`.
    pub(crate) fn first_port_zone_for_nation(&self, nation: NationId) -> Option<OceanZoneId> {
        self.ocean
            .zones
            .iter()
            .enumerate()
            .rev()
            .find_map(|(ordinal, kind)| {
                let ZoneKind::PortZone(port) = kind else {
                    return None;
                };
                (self.map[port.port_tile].former_owner_nation
                    == Some(TileOwnerTag::from_nation(nation)))
                .then(|| OceanZoneId::new(ordinal as u16))
            })
    }
}

fn bump_mission_ship_ids(data: &mut MissionData) {
    match data {
        MissionData::ControlSeaZone(navy)
        | MissionData::Escort(navy)
        | MissionData::ScatteredShips(navy)
        | MissionData::Beachhead(navy) => bump_navy_mission_ship_ids(navy),
        MissionData::BlockadePort { navy, .. } => bump_navy_mission_ship_ids(navy),
        MissionData::Invade { beachhead, .. } => {
            if let Some(navy) = beachhead {
                bump_navy_mission_ship_ids(navy);
            }
        }
        MissionData::AttackProvince(_) | MissionData::DefendProvince { .. } => {}
    }
}

fn bump_navy_mission_ship_ids(navy: &mut NavyMissionState) {
    if let Some(ship) = &mut navy.selected_ship {
        *ship = ShipId::new(ship.get() + 1);
    }
    for selected in &mut navy.ships {
        selected.ship = ShipId::new(selected.ship.get() + 1);
    }
}

/// A ship in primary-list order. Ship and task-force references are snapshot-local
/// ordinals because retail does not persist a stable identity for either collection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShipState {
    pub ship_type: ShipType,
    pub location: OceanZoneId,
    pub task_force: Option<TaskForceId>,
    pub aggression: i32,
    pub nation: NationId,
    pub name: String,
    pub strength: i16,
    pub experience: i16,
    pub selection: i32,
}

/// A navy secondary-order node (`TAdmiral`) in head-first list order.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AdmiralState {
    pub nation: NationId,
    pub name: String,
    pub experience: i16,
    pub ship: Option<ShipId>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "target", rename_all = "snake_case")]
pub enum TaskForceTarget {
    None,
    Zone(OceanZoneId),
    Province(ProvinceId),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TaskForceState {
    pub aggression: i32,
    pub order: i32,
    pub target: TaskForceTarget,
    pub location: OceanZoneId,
    pub nation: NationId,
    pub ship_counts: [i16; 4],
    pub defeated: bool,
    pub ingot_tile: i16,
    pub flagship: Option<ShipId>,
    pub ships: Vec<SelectedShip>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SelectedShip {
    pub ship: ShipId,
    pub selected: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ArmyMissionState {
    /// Exact IEEE-754 bits retained for deterministic mission scoring.
    pub required_equipage_bits: [u32; 5],
    pub units: Vec<MilitaryUnitId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NavyMissionState {
    pub target_zone: Option<OceanZoneId>,
    pub resolved_port_zone: Option<OceanZoneId>,
    pub selected_ship: Option<ShipId>,
    pub task_force: Option<TaskForceId>,
    /// Retail target-selection state. Values 0, 1, and 2 select between the
    /// resolved port and target zone; the save field remains open until more
    /// lifecycle behavior is implemented.
    pub state: i32,
    /// Exact IEEE-754 bits retained for deterministic mission scoring.
    pub required_equipage_bits: [u32; 4],
    pub ships: Vec<SelectedShip>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttackMissionState {
    pub army: ArmyMissionState,
    pub present_province: Option<ProvinceId>,
    pub target_province: ProvinceId,
    pub amassing_province: Option<ProvinceId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MissionData {
    AttackProvince(AttackMissionState),
    Invade {
        attack: AttackMissionState,
        beachhead: Option<NavyMissionState>,
    },
    DefendProvince {
        province: ProvinceId,
        army: ArmyMissionState,
    },
    ControlSeaZone(NavyMissionState),
    Escort(NavyMissionState),
    ScatteredShips(NavyMissionState),
    BlockadePort {
        navy: NavyMissionState,
        port_zone: OceanZoneId,
    },
    Beachhead(NavyMissionState),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MissionState {
    pub nation: NationId,
    pub data: MissionData,
    pub path_nation: Option<NationId>,
    /// Open retail lifecycle code; currently produced as 2 and preserved from saves.
    pub state: u8,
    /// Exact IEEE-754 importance-score bits.
    pub importance_bits: u32,
    /// Whether retail's AI assignment pass is currently holding this mission.
    pub held: bool,
    /// Open retail mission-status byte; bit zero is consumed by current retail AI logic.
    pub marker: u8,
}
