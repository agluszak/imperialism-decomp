//! Observable semantic projection used by native differential tests.
//!
//! This is not a second game model. [`GameState`] remains authoritative; a
//! [`ComparisonSnapshot`] drops process-local allocator identities and
//! uninitialized retail bytes so C++ capture and Rust state can be compared
//! with `assert_eq!`.

use crate::*;
use indexmap::IndexMap;
use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;

/// Zero-based ordinal in the retail newest-first ship list.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ShipOrdinal(pub u32);

impl ShipOrdinal {
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Zero-based ordinal in the retail newest-first task-force queue.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct TaskForceOrdinal(pub u32);

impl TaskForceOrdinal {
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// One ship membership flag as captured from a retail linked list.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SelectedShip {
    pub ship: ShipOrdinal,
    pub selected: bool,
}

/// One `TTown` marker in its owning nation's list order.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TownSnapshot {
    pub name: String,
    pub tile: TileId,
    pub created_turn: i16,
    pub owner_nation: NationId,
    pub resource_yield_by_type: ResourceTable<i16>,
    pub transport_linked: bool,
    pub enabled: u8,
    /// Absent when `TTown::ITown` has not yet written a semantic value.
    #[serde(default)]
    pub has_adjacent_city: Option<u8>,
    pub active: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ShipSnapshot {
    pub ship_type: ShipType,
    pub location: OceanZoneId,
    pub aggression: NavalAggression,
    pub nation: NationId,
    pub name: String,
    pub strength: i16,
    pub experience: i16,
    pub selection: ShipSelection,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AdmiralSnapshot {
    pub nation: NationId,
    pub name: String,
    pub experience: i16,
    pub ship: Option<ShipOrdinal>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TaskForceSnapshot {
    pub aggression: NavalAggression,
    pub order: TaskForceOrder,
    pub target: TaskForceTarget,
    pub location: OceanZoneId,
    pub nation: NationId,
    pub defeated: bool,
    pub ingot_tile: i16,
    pub flagship: Option<ShipOrdinal>,
    pub ships: Vec<SelectedShip>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NavyMissionSnapshot {
    pub target_zone: Option<OceanZoneId>,
    pub resolved_port_zone: Option<OceanZoneId>,
    pub selected_ship: Option<ShipOrdinal>,
    pub task_force: Option<TaskForceOrdinal>,
    pub state: NavyMissionSelection,
    pub required_equipage_bits: [u32; 4],
    pub ships: Vec<SelectedShip>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MissionDataSnapshot {
    AttackProvince(AttackMissionState),
    Invade {
        attack: AttackMissionState,
        beachhead: Option<NavyMissionSnapshot>,
    },
    DefendProvince {
        province: ProvinceId,
        army: ArmyMissionState,
    },
    ControlSeaZone(NavyMissionSnapshot),
    Escort(NavyMissionSnapshot),
    ScatteredShips(NavyMissionSnapshot),
    BlockadePort {
        navy: NavyMissionSnapshot,
        port_zone: OceanZoneId,
    },
    Beachhead(NavyMissionSnapshot),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MissionSnapshot {
    pub nation: NationId,
    pub data: MissionDataSnapshot,
    pub path_nation: Option<NationId>,
    pub state: u8,
    pub importance_bits: u32,
    pub held: bool,
    pub marker: u8,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MilitaryUnitSnapshot {
    pub id: MilitaryUnitId,
    #[serde(flatten)]
    pub unit: MilitaryUnitState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CivilianUnitSnapshot {
    pub id: CivilianUnitId,
    #[serde(flatten)]
    pub unit: CivilianUnitState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MajorNationSnapshot {
    pub auto: Option<AutoGreatPowerState>,
    pub common: NationCommonState,
    pub economy: GreatPowerState,
    pub city: CityState,
    pub towns: Vec<TownSnapshot>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NationsSnapshot {
    pub majors: Vec<MajorNationSnapshot>,
    pub minors: Vec<Option<MinorNation>>,
}

/// Observable semantic state for native `before`/`after` comparison.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ComparisonSnapshot {
    pub turn: TurnState,
    pub unit_ids: UnitIdAllocator,
    pub map: MapMgr,
    pub ocean: Ocean,
    pub rng: RngState,
    pub market: TradeMarketState,
    pub technology: TechnologyState,
    pub diplomacy: DiplomacyState,
    pub nations: NationsSnapshot,
    pub military_units: Vec<MilitaryUnitSnapshot>,
    pub civilian_units: Vec<CivilianUnitSnapshot>,
    pub ships: Vec<ShipSnapshot>,
    pub admirals: Vec<AdmiralSnapshot>,
    pub task_forces: Vec<TaskForceSnapshot>,
    pub missions: Vec<MissionSnapshot>,
    pub news: NewsState,
    pub pending: PendingWorkState,
    pub battle_reports: Vec<BattleReport>,
    pub continuation: TurnContinuation,
}

impl GameState {
    /// Projects authoritative state into the comparison snapshot.
    pub fn comparison_snapshot(&self) -> ComparisonSnapshot {
        ComparisonSnapshot::from_game_state(self)
    }
}

impl ComparisonSnapshot {
    pub fn from_game_state(game: &GameState) -> Self {
        let ship_ordinals = ordinals(game.ships_in_retail_order().map(|(id, _)| id), ShipOrdinal);
        let task_force_ordinals = ordinals(
            game.task_forces_in_retail_order().map(|(id, _)| id),
            TaskForceOrdinal,
        );
        Self {
            turn: game.turn,
            unit_ids: game.unit_ids,
            map: game.map.clone(),
            ocean: game.ocean.clone(),
            rng: game.rng,
            market: game.market.clone(),
            technology: game.technology.clone(),
            diplomacy: game.diplomacy.clone(),
            nations: NationsSnapshot {
                majors: game
                    .nations
                    .majors
                    .values()
                    .map(|major| MajorNationSnapshot {
                        auto: major.auto.clone(),
                        common: major.common.clone(),
                        economy: major.economy.clone(),
                        city: major.city.clone(),
                        towns: major
                            .towns
                            .iter()
                            .map(|(&tile, town)| TownSnapshot {
                                name: town.name.clone(),
                                tile,
                                created_turn: town.created_turn,
                                owner_nation: town.owner_nation,
                                resource_yield_by_type: town.resource_yield_by_type,
                                transport_linked: town.transport_linked,
                                enabled: town.enabled,
                                has_adjacent_city: adjacent_city_if_initialized(town),
                                active: town.active,
                            })
                            .collect(),
                    })
                    .collect(),
                minors: {
                    let mut minors = vec![None; MINOR_NATION_COUNT];
                    for (&id, minor) in &game.nations.minors {
                        minors[id.table_index()] = Some(minor.clone());
                    }
                    minors
                },
            },
            military_units: game
                .military_units
                .iter()
                .map(|(&id, unit)| MilitaryUnitSnapshot {
                    id,
                    unit: unit.clone(),
                })
                .collect(),
            civilian_units: game
                .civilian_units
                .iter()
                .map(|(&id, unit)| CivilianUnitSnapshot {
                    id,
                    unit: unit.clone(),
                })
                .collect(),
            ships: game
                .ships_in_retail_order()
                .map(|(_, ship)| ShipSnapshot {
                    ship_type: ship.ship_type,
                    location: ship.location,
                    aggression: ship.aggression,
                    nation: ship.nation,
                    name: ship.name.clone(),
                    strength: ship.strength,
                    experience: ship.experience,
                    selection: ship.selection,
                })
                .collect(),
            admirals: game
                .admirals_in_retail_order()
                .map(|(_, admiral)| AdmiralSnapshot {
                    nation: admiral.nation,
                    name: admiral.name.clone(),
                    experience: admiral.experience,
                    ship: admiral.ship.map(|id| ship_ordinals[&id]),
                })
                .collect(),
            task_forces: game
                .task_forces_in_retail_order()
                .map(|(_, force)| TaskForceSnapshot {
                    aggression: force.aggression,
                    order: force.order,
                    target: force.target,
                    location: force.location,
                    nation: force.nation,
                    defeated: force.defeated,
                    ingot_tile: force.ingot_tile,
                    flagship: force.flagship.map(|id| ship_ordinals[&id]),
                    ships: selected_ships(&force.ships, &ship_ordinals),
                })
                .collect(),
            missions: game
                .missions
                .values()
                .map(|mission| MissionSnapshot {
                    nation: mission.nation,
                    data: mission_data_snapshot(
                        &mission.data,
                        &ship_ordinals,
                        &task_force_ordinals,
                    ),
                    path_nation: mission.path_nation,
                    state: mission.state,
                    importance_bits: mission.importance_bits,
                    held: mission.held,
                    marker: mission.marker,
                })
                .collect(),
            news: game.news.clone(),
            pending: game.pending.clone(),
            battle_reports: game.battle_reports.clone(),
            continuation: game.continuation.clone(),
        }
    }

    /// Rebuilds a [`GameState`] so a Rust operation can run on a native `before` snapshot.
    ///
    /// Allocator IDs are assigned sequentially and are not part of the comparison.
    pub fn into_game_state(self) -> GameState {
        let mut object_ids = ObjectIdAllocator::default();
        let ship_ids = allocate_retail_ids(self.ships.len(), || object_ids.ship());
        let admiral_ids = allocate_retail_ids(self.admirals.len(), || object_ids.admiral());
        let task_force_ids =
            allocate_retail_ids(self.task_forces.len(), || object_ids.task_force());

        let ships = insert_retail_order(
            &ship_ids,
            self.ships.into_iter().map(|ship| ShipState {
                ship_type: ship.ship_type,
                location: ship.location,
                aggression: ship.aggression,
                nation: ship.nation,
                name: ship.name,
                strength: ship.strength,
                experience: ship.experience,
                selection: ship.selection,
            }),
        );
        let admirals = insert_retail_order(
            &admiral_ids,
            self.admirals.into_iter().map(|admiral| AdmiralState {
                nation: admiral.nation,
                name: admiral.name,
                experience: admiral.experience,
                ship: admiral.ship.map(|ordinal| ship_id(&ship_ids, ordinal)),
            }),
        );
        let task_forces = insert_retail_order(
            &task_force_ids,
            self.task_forces.into_iter().map(|force| {
                let mut state = TaskForceState::from_parts(
                    force.aggression,
                    force.order,
                    force.target,
                    force.location,
                    force.nation,
                    force.defeated,
                    force.ingot_tile,
                    membership(&force.ships, &ship_ids),
                );
                state.flagship = force.flagship.map(|ordinal| ship_id(&ship_ids, ordinal));
                state
            }),
        );
        let missions = self
            .missions
            .into_iter()
            .map(|mission| {
                (
                    object_ids.mission(),
                    MissionState {
                        nation: mission.nation,
                        data: mission_data_state(mission.data, &ship_ids, &task_force_ids),
                        path_nation: mission.path_nation,
                        state: mission.state,
                        importance_bits: mission.importance_bits,
                        held: mission.held,
                        marker: mission.marker,
                    },
                )
            })
            .collect();

        let majors = self
            .nations
            .majors
            .into_iter()
            .enumerate()
            .map(|(slot, major)| {
                (
                    MajorNationId::new(slot as u8),
                    MajorNation {
                        auto: major.auto,
                        common: major.common,
                        economy: major.economy,
                        city: major.city,
                        towns: major
                            .towns
                            .into_iter()
                            .map(|town| {
                                (
                                    town.tile,
                                    TownState {
                                        name: town.name,
                                        needs_naming: false,
                                        created_turn: town.created_turn,
                                        owner_nation: town.owner_nation,
                                        resource_yield_by_type: town.resource_yield_by_type,
                                        transport_linked: town.transport_linked,
                                        enabled: town.enabled,
                                        has_adjacent_city: town.has_adjacent_city.unwrap_or(0),
                                        active: town.active,
                                    },
                                )
                            })
                            .collect(),
                    },
                )
            })
            .collect::<IndexMap<_, _>>();
        let minors: IndexMap<_, _> = MinorNationId::all()
            .zip(self.nations.minors)
            .filter_map(|(id, minor)| minor.map(|minor| (id, minor)))
            .collect();

        GameState::from_parts(GameStateParts {
            turn: self.turn,
            unit_ids: self.unit_ids,
            map: self.map,
            ocean: self.ocean,
            rng: self.rng,
            market: self.market,
            technology: self.technology,
            diplomacy: self.diplomacy,
            nations: Nations::new(majors, minors),
            military_units: self
                .military_units
                .into_iter()
                .map(|unit| (unit.id, unit.unit))
                .collect(),
            civilian_units: self
                .civilian_units
                .into_iter()
                .map(|unit| (unit.id, unit.unit))
                .collect(),
            object_ids,
            ships,
            admirals,
            task_forces,
            missions,
            news: self.news,
            pending: self.pending,
            battle_reports: self.battle_reports,
            continuation: self.continuation,
        })
    }
}

impl<'de> Deserialize<'de> for ComparisonSnapshot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        NativeCapture::deserialize(deserializer)?
            .try_into()
            .map_err(DeError::custom)
    }
}

fn adjacent_city_if_initialized(town: &TownState) -> Option<u8> {
    let uncalculated =
        town.created_turn > 0 && town.resource_yield_by_type.values().all(|&v| v == 0);
    (!uncalculated).then_some(town.has_adjacent_city)
}

fn ordinals<Id: Copy + Eq + std::hash::Hash, Ordinal>(
    ids: impl IntoIterator<Item = Id>,
    wrap: impl Fn(u32) -> Ordinal,
) -> HashMap<Id, Ordinal> {
    ids.into_iter()
        .enumerate()
        .map(|(ordinal, id)| (id, wrap(ordinal as u32)))
        .collect()
}

fn selected_ships(
    ships: &IndexMap<ShipId, bool>,
    ordinals: &HashMap<ShipId, ShipOrdinal>,
) -> Vec<SelectedShip> {
    ships
        .iter()
        .map(|(&id, &selected)| SelectedShip {
            ship: ordinals[&id],
            selected,
        })
        .collect()
}

fn allocate_retail_ids<Id: Copy>(count: usize, mut next: impl FnMut() -> Id) -> Vec<Id> {
    let oldest_first: Vec<Id> = (0..count).map(|_| next()).collect();
    oldest_first.into_iter().rev().collect()
}

fn insert_retail_order<Id: Copy + Eq + std::hash::Hash, T>(
    ids: &[Id],
    values: impl DoubleEndedIterator<Item = T>,
) -> IndexMap<Id, T> {
    ids.iter().rev().copied().zip(values.rev()).collect()
}

fn ship_id(ids: &[ShipId], ordinal: ShipOrdinal) -> ShipId {
    ids.get(ordinal.0 as usize)
        .copied()
        .expect("ship ordinal is in the snapshot ship list")
}

fn task_force_id(ids: &[TaskForceId], ordinal: TaskForceOrdinal) -> TaskForceId {
    ids.get(ordinal.0 as usize)
        .copied()
        .expect("task-force ordinal is in the snapshot force list")
}

fn membership(ships: &[SelectedShip], ids: &[ShipId]) -> IndexMap<ShipId, bool> {
    ships
        .iter()
        .map(|ship| (ship_id(ids, ship.ship), ship.selected))
        .collect()
}

fn navy_mission_snapshot(
    mission: &NavyMissionState,
    ships: &HashMap<ShipId, ShipOrdinal>,
    forces: &HashMap<TaskForceId, TaskForceOrdinal>,
) -> NavyMissionSnapshot {
    NavyMissionSnapshot {
        target_zone: mission.target_zone,
        resolved_port_zone: mission.resolved_port_zone,
        selected_ship: mission.selected_ship.map(|id| ships[&id]),
        task_force: mission.task_force.map(|id| forces[&id]),
        state: mission.state,
        required_equipage_bits: mission.required_equipage_bits,
        ships: selected_ships(&mission.ships, ships),
    }
}

fn navy_mission_state(
    mission: NavyMissionSnapshot,
    ships: &[ShipId],
    forces: &[TaskForceId],
) -> NavyMissionState {
    NavyMissionState {
        target_zone: mission.target_zone,
        resolved_port_zone: mission.resolved_port_zone,
        selected_ship: mission.selected_ship.map(|ordinal| ship_id(ships, ordinal)),
        task_force: mission
            .task_force
            .map(|ordinal| task_force_id(forces, ordinal)),
        state: mission.state,
        required_equipage_bits: mission.required_equipage_bits,
        ships: membership(&mission.ships, ships),
    }
}

fn mission_data_snapshot(
    data: &MissionData,
    ships: &HashMap<ShipId, ShipOrdinal>,
    forces: &HashMap<TaskForceId, TaskForceOrdinal>,
) -> MissionDataSnapshot {
    match data {
        MissionData::AttackProvince(attack) => MissionDataSnapshot::AttackProvince(attack.clone()),
        MissionData::Invade { attack, beachhead } => MissionDataSnapshot::Invade {
            attack: attack.clone(),
            beachhead: beachhead
                .as_ref()
                .map(|mission| navy_mission_snapshot(mission, ships, forces)),
        },
        MissionData::DefendProvince { province, army } => MissionDataSnapshot::DefendProvince {
            province: *province,
            army: army.clone(),
        },
        MissionData::ControlSeaZone(mission) => {
            MissionDataSnapshot::ControlSeaZone(navy_mission_snapshot(mission, ships, forces))
        }
        MissionData::Escort(mission) => {
            MissionDataSnapshot::Escort(navy_mission_snapshot(mission, ships, forces))
        }
        MissionData::ScatteredShips(mission) => {
            MissionDataSnapshot::ScatteredShips(navy_mission_snapshot(mission, ships, forces))
        }
        MissionData::BlockadePort { navy, port_zone } => MissionDataSnapshot::BlockadePort {
            navy: navy_mission_snapshot(navy, ships, forces),
            port_zone: *port_zone,
        },
        MissionData::Beachhead(mission) => {
            MissionDataSnapshot::Beachhead(navy_mission_snapshot(mission, ships, forces))
        }
    }
}

fn mission_data_state(
    data: MissionDataSnapshot,
    ships: &[ShipId],
    forces: &[TaskForceId],
) -> MissionData {
    match data {
        MissionDataSnapshot::AttackProvince(attack) => MissionData::AttackProvince(attack),
        MissionDataSnapshot::Invade { attack, beachhead } => MissionData::Invade {
            attack,
            beachhead: beachhead.map(|mission| navy_mission_state(mission, ships, forces)),
        },
        MissionDataSnapshot::DefendProvince { province, army } => {
            MissionData::DefendProvince { province, army }
        }
        MissionDataSnapshot::ControlSeaZone(mission) => {
            MissionData::ControlSeaZone(navy_mission_state(mission, ships, forces))
        }
        MissionDataSnapshot::Escort(mission) => {
            MissionData::Escort(navy_mission_state(mission, ships, forces))
        }
        MissionDataSnapshot::ScatteredShips(mission) => {
            MissionData::ScatteredShips(navy_mission_state(mission, ships, forces))
        }
        MissionDataSnapshot::BlockadePort { navy, port_zone } => MissionData::BlockadePort {
            navy: navy_mission_state(navy, ships, forces),
            port_zone,
        },
        MissionDataSnapshot::Beachhead(mission) => {
            MissionData::Beachhead(navy_mission_state(mission, ships, forces))
        }
    }
}

#[derive(Deserialize)]
struct NativeCapture {
    turn: NativeTurn,
    unit_ids: UnitIdAllocator,
    map: MapMgr,
    ocean: Ocean,
    rng: RngState,
    market: TradeMarketState,
    technology: TechnologyState,
    diplomacy: DiplomacyState,
    nations: NativeNations,
    military_units: Vec<NativeMilitaryUnit>,
    civilian_units: Vec<CivilianUnitSnapshot>,
    ships: Vec<NativeShip>,
    admirals: Vec<AdmiralSnapshot>,
    task_forces: Vec<NativeTaskForce>,
    missions: Vec<NativeMission>,
    news: NewsState,
    pending: PendingWorkState,
    #[serde(default)]
    battle_reports: Vec<BattleReport>,
    #[serde(default, deserialize_with = "deserialize_native_continuation")]
    continuation: TurnContinuation,
}

#[allow(clippy::large_enum_variant)]
#[derive(Deserialize)]
#[serde(untagged)]
enum NativeContinuation {
    IndexedTechnology {
        #[serde(rename = "TechnologyReport")]
        technology: u8,
    },
    Core(TurnContinuation),
}

#[derive(Deserialize)]
struct NativeTurn {
    scenario_map: Option<ScenarioMapId>,
    economic_turn: i32,
    diplomacy_year_term_raw: i16,
    #[serde(default)]
    selected_asset_set: i16,
    phase: PhaseCode,
    turn_flow_status_flags: u32,
    quarter_gate_by_decade: [u8; 10],
    difficulty: Difficulty,
    active_nation: NationId,
    #[serde(default)]
    last_turn_alert_tick: i32,
    #[serde(default)]
    turn_cooldown_defer_counter: i16,
}

#[derive(Deserialize)]
struct NativeNations {
    majors: Vec<NativeMajorNation>,
    minors: Vec<Option<MinorNation>>,
}

#[derive(Deserialize)]
struct NativeMajorNation {
    kind: NativeMajorKind,
    common: NationCommonState,
    economy: NativeEconomy,
    city: CityState,
    towns: Vec<TownSnapshot>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum NativeMajorKind {
    GreatPower,
    AutoGreatPower,
}

#[derive(Deserialize)]
struct NativeEconomy {
    #[serde(flatten)]
    great_power: GreatPowerState,
    #[serde(default)]
    ai_zone_targets: Option<Vec<AiTargetState>>,
    #[serde(default)]
    ai_province_targets: Option<ProvinceTable<AiTargetState>>,
    #[serde(default)]
    ai_trade: Option<AiTradeState>,
}

#[derive(Deserialize)]
struct NativeShip {
    ship_type: ShipType,
    location: OceanZoneId,
    aggression: i32,
    nation: NationId,
    name: String,
    strength: i16,
    experience: i16,
    selection: i32,
}

#[derive(Deserialize)]
struct NativeTaskForce {
    aggression: i32,
    order: TaskForceOrder,
    target: TaskForceTarget,
    location: OceanZoneId,
    nation: NationId,
    defeated: bool,
    ingot_tile: i16,
    flagship: Option<ShipOrdinal>,
    ships: Vec<SelectedShip>,
}

#[derive(Deserialize)]
struct NativeMilitaryUnit {
    id: MilitaryUnitId,
    nation: NationId,
    unit_type: MilitaryUnitKind,
    stationed_province: Option<ProvinceId>,
    order: MilitaryOrder,
    owner_nation: NationId,
    roster_id: i16,
    registered: bool,
    name: String,
    strength: i16,
    era: i32,
    experience: i16,
    battle_flags: i16,
}

#[derive(Deserialize)]
struct NativeMission {
    nation: NationId,
    data: NativeMissionData,
    path_nation: Option<NationId>,
    state: u8,
    importance_bits: u32,
    held: bool,
    marker: u8,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum NativeMissionData {
    AttackProvince(AttackMissionState),
    Invade {
        attack: AttackMissionState,
        beachhead: Option<NativeNavyMission>,
    },
    DefendProvince {
        province: ProvinceId,
        army: ArmyMissionState,
    },
    ControlSeaZone(NativeNavyMission),
    Escort(NativeNavyMission),
    ScatteredShips(NativeNavyMission),
    BlockadePort {
        navy: NativeNavyMission,
        port_zone: OceanZoneId,
    },
    Beachhead(NativeNavyMission),
}

#[derive(Deserialize)]
struct NativeNavyMission {
    target_zone: Option<OceanZoneId>,
    resolved_port_zone: Option<OceanZoneId>,
    selected_ship: Option<ShipOrdinal>,
    task_force: Option<TaskForceOrdinal>,
    state: i32,
    required_equipage_bits: [u32; 4],
    ships: Vec<SelectedShip>,
}

impl TryFrom<NativeCapture> for ComparisonSnapshot {
    type Error = String;

    fn try_from(capture: NativeCapture) -> Result<Self, Self::Error> {
        Ok(Self {
            turn: capture.turn.into_turn(),
            unit_ids: capture.unit_ids,
            map: capture.map,
            ocean: capture.ocean,
            rng: capture.rng,
            market: capture.market,
            technology: capture.technology,
            diplomacy: capture.diplomacy,
            nations: NationsSnapshot {
                majors: capture
                    .nations
                    .majors
                    .into_iter()
                    .map(NativeMajorNation::into_snapshot)
                    .collect(),
                minors: capture.nations.minors,
            },
            military_units: capture
                .military_units
                .into_iter()
                .map(NativeMilitaryUnit::try_into_snapshot)
                .collect::<Result<_, _>>()?,
            civilian_units: capture.civilian_units,
            ships: capture
                .ships
                .into_iter()
                .map(NativeShip::try_into_snapshot)
                .collect::<Result<_, _>>()?,
            admirals: capture.admirals,
            task_forces: capture
                .task_forces
                .into_iter()
                .map(NativeTaskForce::try_into_snapshot)
                .collect::<Result<_, _>>()?,
            missions: capture
                .missions
                .into_iter()
                .map(NativeMission::try_into_snapshot)
                .collect::<Result<_, _>>()?,
            news: capture.news,
            pending: capture.pending,
            battle_reports: capture.battle_reports,
            continuation: capture.continuation,
        })
    }
}

impl NativeTurn {
    fn into_turn(self) -> TurnState {
        let mut phase_state_by_decade = [0; 12];
        phase_state_by_decade[..10].copy_from_slice(&self.quarter_gate_by_decade);
        let mut turn = TurnState::new(
            self.scenario_map,
            self.economic_turn,
            self.diplomacy_year_term_raw,
            self.selected_asset_set,
            self.phase,
            self.turn_flow_status_flags,
            phase_state_by_decade,
            self.difficulty,
            self.active_nation,
        );
        turn.last_turn_alert_tick = self.last_turn_alert_tick;
        turn.turn_cooldown_defer_counter = self.turn_cooldown_defer_counter;
        turn
    }
}

impl NativeMajorNation {
    fn into_snapshot(self) -> MajorNationSnapshot {
        let auto = match self.kind {
            NativeMajorKind::GreatPower => None,
            NativeMajorKind::AutoGreatPower => Some(AutoGreatPowerState {
                province_targets: self.economy.ai_province_targets.unwrap_or_default(),
                zone_targets: self.economy.ai_zone_targets.unwrap_or_default(),
                trade: self.economy.ai_trade.unwrap_or_default(),
            }),
        };
        MajorNationSnapshot {
            auto,
            common: self.common,
            economy: self.economy.great_power,
            city: self.city,
            towns: self.towns,
        }
    }
}

impl NativeShip {
    fn try_into_snapshot(self) -> Result<ShipSnapshot, String> {
        Ok(ShipSnapshot {
            ship_type: self.ship_type,
            location: self.location,
            aggression: NavalAggression::from_retail(self.aggression).ok_or_else(|| {
                format!(
                    "ship aggression {} is outside the retail range",
                    self.aggression
                )
            })?,
            nation: self.nation,
            name: self.name,
            strength: self.strength,
            experience: self.experience,
            selection: ShipSelection::from_retail(self.selection).ok_or_else(|| {
                format!(
                    "ship selection {} is outside the retail range",
                    self.selection
                )
            })?,
        })
    }
}

impl NativeTaskForce {
    fn try_into_snapshot(self) -> Result<TaskForceSnapshot, String> {
        Ok(TaskForceSnapshot {
            aggression: NavalAggression::from_retail(self.aggression).ok_or_else(|| {
                format!(
                    "task-force aggression {} is outside the retail range",
                    self.aggression
                )
            })?,
            order: self.order,
            target: self.target,
            location: self.location,
            nation: self.nation,
            defeated: self.defeated,
            ingot_tile: self.ingot_tile,
            flagship: self.flagship,
            ships: self.ships,
        })
    }
}

impl NativeMilitaryUnit {
    fn try_into_snapshot(self) -> Result<MilitaryUnitSnapshot, String> {
        let era = i16::try_from(self.era)
            .ok()
            .and_then(MilitaryEra::from_retail)
            .ok_or_else(|| format!("military era {} is outside the retail range", self.era))?;
        Ok(MilitaryUnitSnapshot {
            id: self.id,
            unit: MilitaryUnitState::new(
                self.nation,
                self.unit_type,
                self.stationed_province,
                self.order,
                self.owner_nation,
                self.roster_id,
                self.registered,
                self.name,
                self.strength,
                era,
                self.experience,
                self.battle_flags,
            ),
        })
    }
}

impl NativeMission {
    fn try_into_snapshot(self) -> Result<MissionSnapshot, String> {
        Ok(MissionSnapshot {
            nation: self.nation,
            data: self.data.try_into_snapshot()?,
            path_nation: self.path_nation,
            state: self.state,
            importance_bits: self.importance_bits,
            held: self.held,
            marker: self.marker,
        })
    }
}

impl NativeMissionData {
    fn try_into_snapshot(self) -> Result<MissionDataSnapshot, String> {
        Ok(match self {
            Self::AttackProvince(attack) => MissionDataSnapshot::AttackProvince(attack),
            Self::Invade { attack, beachhead } => MissionDataSnapshot::Invade {
                attack,
                beachhead: beachhead
                    .map(NativeNavyMission::try_into_snapshot)
                    .transpose()?,
            },
            Self::DefendProvince { province, army } => {
                MissionDataSnapshot::DefendProvince { province, army }
            }
            Self::ControlSeaZone(mission) => {
                MissionDataSnapshot::ControlSeaZone(mission.try_into_snapshot()?)
            }
            Self::Escort(mission) => MissionDataSnapshot::Escort(mission.try_into_snapshot()?),
            Self::ScatteredShips(mission) => {
                MissionDataSnapshot::ScatteredShips(mission.try_into_snapshot()?)
            }
            Self::BlockadePort { navy, port_zone } => MissionDataSnapshot::BlockadePort {
                navy: navy.try_into_snapshot()?,
                port_zone,
            },
            Self::Beachhead(mission) => {
                MissionDataSnapshot::Beachhead(mission.try_into_snapshot()?)
            }
        })
    }
}

impl NativeNavyMission {
    fn try_into_snapshot(self) -> Result<NavyMissionSnapshot, String> {
        Ok(NavyMissionSnapshot {
            target_zone: self.target_zone,
            resolved_port_zone: self.resolved_port_zone,
            selected_ship: self.selected_ship,
            task_force: self.task_force,
            state: NavyMissionSelection::from_retail(self.state).ok_or_else(|| {
                format!(
                    "navy mission state {} is outside the retail range",
                    self.state
                )
            })?,
            required_equipage_bits: self.required_equipage_bits,
            ships: self.ships,
        })
    }
}

fn deserialize_native_continuation<'de, D>(deserializer: D) -> Result<TurnContinuation, D::Error>
where
    D: Deserializer<'de>,
{
    match NativeContinuation::deserialize(deserializer)? {
        NativeContinuation::IndexedTechnology { technology } => {
            let technology = Technology::from_index(technology).ok_or_else(|| {
                DeError::custom(format!("invalid C++ technology report id {technology}"))
            })?;
            Ok(TurnContinuation::TechnologyReport(technology))
        }
        NativeContinuation::Core(continuation) => Ok(continuation),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::game_state;

    fn sample_ship(name: &str, location: u16) -> ShipState {
        ShipState {
            ship_type: ShipType::Trader,
            location: OceanZoneId::new(location),
            aggression: NavalAggression::Balanced,
            nation: NationId::new(0),
            name: name.to_owned(),
            strength: 8,
            experience: 0,
            selection: ShipSelection::Available,
        }
    }

    #[test]
    fn snapshot_uses_retail_ship_ordinals() {
        let mut game = game_state();
        let older = game.object_ids.ship();
        let newer = game.object_ids.ship();
        game.ships.insert(older, sample_ship("older", 1));
        game.ships.insert(newer, sample_ship("newer", 2));
        let admiral = game.object_ids.admiral();
        game.admirals.insert(
            admiral,
            AdmiralState {
                nation: NationId::new(0),
                name: "Nelson".to_owned(),
                experience: 3,
                ship: Some(newer),
            },
        );
        let force = game.object_ids.task_force();
        let mut ships = IndexMap::new();
        ships.insert(newer, true);
        ships.insert(older, false);
        game.task_forces.insert(
            force,
            TaskForceState::from_parts(
                NavalAggression::Aggressive,
                TaskForceOrder::Sail,
                TaskForceTarget::None,
                OceanZoneId::new(2),
                NationId::new(0),
                false,
                -1,
                ships,
            ),
        );
        let mission = game.object_ids.mission();
        game.missions.insert(
            mission,
            MissionState {
                nation: NationId::new(1),
                data: MissionData::ControlSeaZone(NavyMissionState {
                    target_zone: Some(OceanZoneId::new(2)),
                    resolved_port_zone: None,
                    selected_ship: Some(newer),
                    task_force: Some(force),
                    state: NavyMissionSelection::ExecuteAtTarget,
                    required_equipage_bits: [0; 4],
                    ships: [(newer, true)].into_iter().collect(),
                }),
                path_nation: None,
                state: 2,
                importance_bits: 0,
                held: false,
                marker: 0,
            },
        );

        let snapshot = game.comparison_snapshot();
        assert_eq!(
            snapshot
                .ships
                .iter()
                .map(|ship| ship.name.as_str())
                .collect::<Vec<_>>(),
            ["newer", "older"]
        );
        assert_eq!(snapshot.admirals[0].ship, Some(ShipOrdinal(0)));
        assert_eq!(snapshot.task_forces[0].ships[0].ship, ShipOrdinal(0));
        assert_eq!(snapshot.task_forces[0].ships[1].ship, ShipOrdinal(1));
        match &snapshot.missions[0].data {
            MissionDataSnapshot::ControlSeaZone(navy) => {
                assert_eq!(navy.selected_ship, Some(ShipOrdinal(0)));
                assert_eq!(navy.task_force, Some(TaskForceOrdinal(0)));
            }
            other => panic!("expected a navy mission, got {other:?}"),
        }
    }

    #[test]
    fn omits_uninitialized_new_town_adjacent_city() {
        let mut game = game_state();
        let nation = game.nations.major_mut(MajorNationId::new(0));
        nation.towns.insert(
            TileId::new(2),
            TownState {
                name: "Depot".to_owned(),
                needs_naming: false,
                created_turn: 4,
                owner_nation: NationId::new(0),
                resource_yield_by_type: ResourceTable::default(),
                transport_linked: false,
                enabled: 0,
                has_adjacent_city: 0xcd,
                active: false,
            },
        );

        let snapshot = game.comparison_snapshot();
        let towns = &snapshot.nations.majors[0].towns;
        assert_eq!(towns[0].created_turn, 0);
        assert_eq!(towns[0].has_adjacent_city, Some(0));
        assert_eq!(towns[1].created_turn, 4);
        assert_eq!(towns[1].has_adjacent_city, None);
    }

    #[test]
    fn snapshot_round_trips_through_game_state() {
        let mut game = game_state();
        let ship = game.object_ids.ship();
        game.ships.insert(ship, sample_ship("flag", 3));
        let expected = game.comparison_snapshot();
        let actual = expected.clone().into_game_state().comparison_snapshot();
        assert_eq!(actual, expected);
    }

    #[test]
    fn native_json_omits_uninitialized_town_bytes() {
        let json = serde_json::json!({
            "name": "Depot",
            "tile": 2,
            "created_turn": 4,
            "owner_nation": 0,
            "resource_yield_by_type": {
                "cotton": 0, "wool": 0, "timber": 0, "coal": 0, "iron": 0, "horses": 0,
                "oil": 0, "food": 0, "fabric": 0, "lumber": 0, "paper": 0, "steel": 0,
                "fuel": 0, "clothing": 0, "furniture": 0, "hardware": 0, "arms": 0,
                "grain": 0, "fruit": 0, "fish": 0, "livestock": 0, "gems": 0, "gold": 0
            },
            "transport_linked": false,
            "enabled": 0,
            "active": false
        });
        let town: TownSnapshot = serde_json::from_value(json).unwrap();
        assert_eq!(town.has_adjacent_city, None);
    }
}
