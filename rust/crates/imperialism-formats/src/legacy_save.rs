use crate::legacy_stream::{LegacyStream, StreamError};
use imperialism_core::*;

const SAVE_MAGIC: [u8; 4] = *b"IBMA";
const CURRENT_RETAIL_VERSION: u32 = 0x3e;
const SAVE_LABEL_LENGTH: usize = 0x20;
const ACTIVE_NATION_NAME_LENGTH: usize = 0x20;
const RESOURCE_KIND_COUNT: usize = 23;
const CITY_PRODUCTION_SLOT_COUNT: usize = 16;
const TRADE_CATEGORY_COUNT: usize = 17;
const DIPLOMACY_SERIALIZED_SIZE_V62: usize = 5_460;
const TECH_SERIALIZED_SIZE_V62: usize = 1_914;
const TECH_GLOBAL_UNLOCK_FLAGS_OFFSET_V62: usize = 0x180;
const TECH_ADVANCED_IRON_WORKING_OFFSET_V62: usize = 0x1a5;
const TECH_MARINE_ENGINEERING_OFFSET_V62: usize = 0x1a8;
const TECH_ORDER_CAP_ROWS_OFFSET_V62: usize = 0x262;
const TECH_ORDER_CAP_ROW_SIZE: usize = 0x1d;
const TECH_ADVANCED_IRON_WORKING_ID: usize = 0x0f;
const TECH_OIL_DRILLING_ID: usize = 0x13;
const TECH_UNIVERSITY_AVAILABILITY_OFFSET_V62: usize = 0x461;
const TECH_UNIVERSITY_AVAILABILITY_ROW_SIZE: usize = 9;
const TECH_FINAL_REQUIREMENT_LEVELS_OFFSET_V62: usize = 0x636;
const TECH_REQUIREMENT_LEVELS_ROW_SIZE: usize = RESOURCE_KIND_COUNT * std::mem::size_of::<i16>();
const TERRAIN_TILE_SERIALIZED_SIZE: usize = 0x24;
const PROVINCE_COUNT: usize = 0x180;
const PROVINCE_FIXED_SERIALIZED_SIZE: usize = 0xa4;
/// Format-specific ceilings for externally supplied collection lengths.
const MAX_MISSIONS: usize = 1_024;
const MAX_OCEAN_ZONES: usize = 4_096;
const MAX_OCEAN_ROUTES: usize = 4_096;
const AI_ZONE_TARGET_CAPACITY: usize = 0x70;
const MAX_SHIPS: usize = 1_024;
const MAX_ADMIRALS: usize = 1_024;
const MAX_TASK_FORCES: usize = 1_024;
const MAX_TASK_FORCE_CHILDREN: usize = 256;
const MAX_MILITARY_UNITS: usize = 4_096;
const MAX_OWNED_REGIONS: usize = PROVINCE_COUNT;
const MAX_CITY_TASKS: usize = 1_024;
const MAX_ARMY_REPORTS: usize = 1_024;
const MAX_TRADE_HISTORY_RECORDS: usize = 65_536;
const MAX_LONGINT_LIST: usize = 65_536;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LegacySaveHeader {
    pub format_version: u32,
    pub saved_session_slot: i32,
    pub save_label: String,
    /// Save-browser preview data. The live loader deliberately discards these tags.
    pub preview_owner_nation_by_tile: Vec<i8>,
    pub preview_economic_year_offset: i16,
    pub preview_difficulty: u8,
    pub preview_active_nation: u8,
    pub preview_active_nation_name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LegacyGameSetup {
    pub multiplayer_game_active: u8,
    pub nation_control_modes: [i16; 7],
    pub city_minister_policy_ids: [i16; 7],
    pub foreign_minister_policy_ids: [i16; 7],
    pub defense_minister_policy_ids: [i16; 7],
    pub reload_political_map_state: u8,
    pub scenario_map: Option<ScenarioMapId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LegacySimulationPrefix {
    pub language_code: u32,
    pub economic_turn: i16,
    pub active_nation: i16,
    pub turn_state_code: i16,
    pub mode: i16,
    pub previous_turn_state_code: i16,
    pub previous_mode: i16,
    pub nation_count: i32,
    pub minor_nation_count: i32,
    pub difficulty: u8,
    pub game_setup: LegacyGameSetup,
    pub persistent_unit_id_counter: i32,
    pub nation_availability: [u8; NATION_COUNT],
    pub saved_multiplayer_role: i32,
    pub preference_slot_10: i16,
    pub selected_asset_set: i16,
    pub diplomacy_year_term_raw: i16,
    pub phase_state_by_decade: [u8; 12],
    pub nation_names: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct LegacySaveV62 {
    header: LegacySaveHeader,
    simulation: LegacySimulationPrefix,
    animator_idle_frequency: i32,
    market: TradeMarketState,
    diplomacy: DiplomacyState,
    technology: TechnologyState,
    map: LegacyMapState,
    ocean: LegacyOceanState,
    navy: LegacyNavyState,
    army_report_count: u16,
    /// Byte position immediately after `TArmyMgr`; nation records start here.
    remaining_manager_chain_offset: usize,
    major_nations: Vec<LegacyMajorNationState>,
    minor_nations: Vec<LegacyMinorState>,
    help: LegacyHelpState,
    /// Must equal the input length for a complete, non-trailing v62 save.
    end_offset: usize,
}

/// Runtime-only state that the retail save format does not persist.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LegacyGameStateContext {
    pub crt_rand_state: u32,
    pub map_generation_lcg: u32,
    pub zone_status_lcg: u32,
    pub selected_nation: NationId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LegacyZone {
    pub display_name: String,
    pub status_code: i16,
    pub tile_or_terrain_id: i32,
    pub seed_nation_id: i16,
    pub active_tile_index: i16,
    pub context_ordinal: i16,
    pub port_tile_index: Option<i16>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LegacyOceanState {
    pub zones: Vec<LegacyZone>,
    pub port_zones: Vec<LegacyZone>,
    pub route_segments: Vec<[i32; 4]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LegacyShip {
    pub ship_type: i16,
    pub aggression: i32,
    pub nation: i16,
    pub name: String,
    pub strength: i16,
    pub selection: i32,
    pub experience: i16,
    pub zone_ordinal: i16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LegacyAdmiral {
    pub nation: i16,
    pub name: String,
    pub experience: i16,
    pub ship_index: i16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LegacyTaskForce {
    pub aggression: i32,
    pub order: i32,
    pub target_ordinal: i16,
    pub location_ordinal: i16,
    pub nation: i16,
    pub ingot_tile: i16,
    pub ships: Vec<[i16; 2]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LegacyNavyState {
    /// Head-first runtime order, matching canonical snapshot IDs.
    pub ships: Vec<LegacyShip>,
    pub admirals: Vec<LegacyAdmiral>,
    pub task_forces: Vec<LegacyTaskForce>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LegacyMilitaryUnit {
    pub unit_type: i16,
    pub stationed_province: i16,
    pub order_target: i16,
    pub owner_nation: i16,
    pub roster_id: i16,
    pub registered: u8,
    pub order: i32,
    pub persistent_id: i32,
    pub name: String,
    pub order_target_tiles: [i16; 3],
    pub order_target_mirrors: [i16; 3],
    pub strength: i16,
    pub era: i16,
    pub experience: i16,
    pub battle_flags: i16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LegacyCountryBase {
    pub identity: String,
    pub alternate_identity: String,
    pub nation_slot: i16,
    pub encoded_nation_slot: i16,
    pub unit_name_ordinal_by_type: [i16; 30],
    pub unit_name_counter: i16,
    pub treasury: i32,
    pub home_tile: i32,
    pub overlay_anchor_tile: i32,
    pub need_level_by_nation: [i16; NATION_COUNT],
    pub military_units: Vec<LegacyMilitaryUnit>,
    pub owned_regions: Vec<i32>,
}

impl LegacyCountryBase {
    fn military_unit_states(
        &self,
        nation: NationId,
    ) -> Result<Vec<MilitaryUnitState>, LegacySaveError> {
        self.military_units
            .iter()
            .map(|unit| {
                let unit_type = u8::try_from(unit.unit_type)
                    .ok()
                    .and_then(MilitaryUnitKind::from_index)
                    .ok_or_else(|| {
                        LegacySaveError::StateProjection(format!(
                            "invalid military unit type {}",
                            unit.unit_type
                        ))
                    })?;
                let targets = optional_province_array(unit.order_target_tiles)?;
                let target_mirrors = optional_province_array(unit.order_target_mirrors)?;
                let target = optional_province_id(unit.order_target)?;
                let order = if unit.order == 0 && target.is_none() {
                    MilitaryOrder::idle(targets, target_mirrors)
                } else {
                    MilitaryOrder::retail(
                        MilitaryOrderCode::from_retail(unit.order),
                        target,
                        targets,
                        target_mirrors,
                    )
                };
                Ok(MilitaryUnitState::new(
                    MilitaryUnitId::from_serialized(unit.persistent_id),
                    nation,
                    unit_type,
                    optional_province_id(unit.stationed_province)?,
                    order,
                    nation_id_from_retail_i16(unit.owner_nation)?,
                    unit.roster_id,
                    unit.registered != 0,
                    unit.name.clone(),
                    unit.strength,
                    unit.era,
                    unit.experience,
                    unit.battle_flags,
                ))
            })
            .collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LegacyGreatPowerPrefix {
    pub diplomacy_eligible: u8,
    pub capacities: [i16; 4],
    pub grant_total_cost: i32,
    pub unfilled_trade_offer_count: i16,
    pub diplomacy_policy_by_nation: [i16; NATION_COUNT],
    pub diplomacy_grant_by_nation: [i16; NATION_COUNT],
    pub need_current_by_type: [i16; RESOURCE_KIND_COUNT],
    pub need_target_by_type: [i16; RESOURCE_KIND_COUNT],
    pub relation_delta_current: [i16; RESOURCE_KIND_COUNT],
    pub purchased_items_by_resource: [i16; RESOURCE_KIND_COUNT],
    pub item_potentials: [i16; RESOURCE_KIND_COUNT],
    pub unfilled_trade_turns_by_resource: [i16; RESOURCE_KIND_COUNT],
    pub transported_items_by_resource: [i16; RESOURCE_KIND_COUNT],
    pub remembered_trade_offers_by_resource: [i16; RESOURCE_KIND_COUNT],
    pub budget_pool_base: i32,
    pub budget_pool_delta: i32,
    pub aid_allocation_by_minor_nation: [[i32; RESOURCE_KIND_COUNT]; MINOR_NATION_COUNT],
    pub pending_action_status: [i8; PENDING_ACTION_COUNT],
    pub pending_action_payload_by_action: [i16; PENDING_ACTION_COUNT],
    pub relationship_lists: Vec<LegacyFixedRecordList>,
    pub minister_presence_mask: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LegacyFixedRecordList {
    pub record_size: u16,
    pub records: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LegacyPopulationState {
    pub count: i16,
    pub strength: i16,
    pub extra: i16,
    pub phase_value: i16,
    pub predicted_need_by_resource: [i16; RESOURCE_KIND_COUNT],
    pub count_float_bits: u32,
    pub baseline_labor: [i16; 3],
    pub production_labor: [i16; 3],
    pub pending_labor_delta: [i16; 3],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LegacyCityTask {
    pub kind: u8,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LegacyCityState {
    pub power_plant_upgrade_queued: u8,
    pub low_production: u8,
    pub low_stock: u8,
    pub production_flags: [u8; CITY_PRODUCTION_SLOT_COUNT],
    pub food_substitution_count: i16,
    pub starvation_population_loss: i16,
    pub serialized_state: i16,
    pub phase_counter: i16,
    pub power_available: i16,
    pub military_recruit_count_by_kind: [i16; 30],
    pub civilian_recruit_count_by_kind: [i16; 9],
    pub order_count_by_type: [i16; 14],
    pub stockpile: [i16; RESOURCE_KIND_COUNT],
    pub production_orders: [i16; CITY_PRODUCTION_SLOT_COUNT],
    pub production_accum: [i16; CITY_PRODUCTION_SLOT_COUNT],
    pub unmet_resource_retries: [i16; RESOURCE_KIND_COUNT],
    pub reserved_by_type: [i16; RESOURCE_KIND_COUNT],
    pub production_current: [i16; CITY_PRODUCTION_SLOT_COUNT],
    pub production_progress: [i16; CITY_PRODUCTION_SLOT_COUNT],
    pub consumed_production_input_by_type: [i16; RESOURCE_KIND_COUNT],
    pub rolling_item_production_score: i32,
    pub population: LegacyPopulationState,
    pub orders: CityOrders,
    pub tasks: Vec<LegacyCityTask>,
    pub transport_requests: LegacyFixedRecordList,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LegacyForeignMinisterState {
    pub skill_index: i16,
    pub scalar_fields: [i16; 7],
    pub purchase_priority_by_resource: [i16; 17],
    pub preferred_resource_slots: [i16; 4],
    pub status_flag: u8,
    pub trade_partner_enabled: [u8; 7],
    pub development_grant_by_nation: [i16; NATION_COUNT],
    pub bill_order_flag: Option<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LegacyInteriorMinisterState {
    pub skill_index: i16,
    pub scalar_prefix: [i16; 4],
    pub trailing_table: [i16; 7],
    pub order_scalars: [i16; 8],
    pub order_metrics: [i16; 61],
    pub deferred_labor_shortfall: i16,
    pub order_short_table: [i16; 16],
    pub order_type_tables: [[i16; RESOURCE_KIND_COUNT]; 3],
    pub temporarily_reserved_ship_arms: i16,
    pub integer_lists: [Vec<i32>; 3],
    pub civilian_order_demand_by_resource: [i16; RESOURCE_KIND_COUNT],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LegacyDefenseMinisterState {
    pub skill_index: i16,
    pub scalar_fields: [i16; 2],
    pub recruit_order_count_by_type: [i16; 30],
    pub order_weight_by_type: [i16; 30],
    pub thresholds: [i16; 4],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LegacyGreatPowerMinisters {
    pub foreign: Option<LegacyForeignMinisterState>,
    pub interior: Option<LegacyInteriorMinisterState>,
    pub defense: Option<LegacyDefenseMinisterState>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LegacyTown {
    pub name: String,
    pub tile_index: i16,
    pub opaque_fields: [i16; 2],
    pub created_turn: i16,
    pub owner_nation: i16,
    pub resource_yield_by_type: [i16; RESOURCE_KIND_COUNT],
    pub transport_linked: u8,
    pub enabled: u8,
    pub has_adjacent_city: u8,
    pub active: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LegacyCivilianUnit {
    pub unit_type: i16,
    pub tile_index: i16,
    pub order_target: i16,
    pub owner_nation: i16,
    pub roster_id: i16,
    pub registered: u8,
    pub order: i32,
    pub persistent_id: i32,
    pub remaining_turns: i16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LegacyGreatPowerPostCity {
    pub towns: Vec<LegacyTown>,
    pub civilian_units: Vec<LegacyCivilianUnit>,
    pub candidate_nation_flags: [u8; NATION_COUNT],
    pub diplomacy_budget_base: i32,
    pub escalation_counter: i8,
    pub pending_commitment_cost: i32,
    pub pressure_counter: i8,
    pub opaque_counter: i32,
    pub turn_finished_flag: u8,
    pub special_resource_trade_balance: i32,
    pub aid_allocation_total: i32,
    pub colony_boycott_flags: [u8; NATION_COUNT],
    pub military_expenses: i32,
}

impl LegacyGreatPowerPostCity {
    fn civilian_unit_states(
        &self,
        nation: NationId,
        topology: MapTopology,
    ) -> Result<Vec<CivilianUnitState>, LegacySaveError> {
        self.civilian_units
            .iter()
            .map(|unit| {
                let unit_type = u8::try_from(unit.unit_type)
                    .ok()
                    .and_then(CivilianUnitKind::from_index)
                    .ok_or_else(|| {
                        LegacySaveError::StateProjection(format!(
                            "invalid civilian unit type {}",
                            unit.unit_type
                        ))
                    })?;
                let tile = optional_tile_id(i32::from(unit.tile_index))?;
                let target = optional_tile_id(i32::from(unit.order_target))?;
                CivilianUnitState::new(
                    CivilianUnitId::from_serialized(unit.persistent_id),
                    nation,
                    unit_type,
                    tile.map_or(CivilianLocation::OffMap, CivilianLocation::OnMap),
                    civilian_work_order(unit.order, tile, target, unit.remaining_turns, topology)?,
                    nation_id_from_retail_i16(unit.owner_nation)?,
                    unit.roster_id,
                    unit.registered != 0,
                )
                .ok_or_else(|| {
                    LegacySaveError::StateProjection(format!(
                        "civilian unit {} has an order inconsistent with its location",
                        unit.persistent_id
                    ))
                })
            })
            .collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LegacyAutoGreatPowerPrefix {
    pub action_metric_by_quarter: [i16; 6],
    pub map_node_state_flags: [u8; 0x180],
    pub port_zone_state_flags: [u8; 0x70],
    pub mission_count: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LegacyGreatPowerState {
    pub country: LegacyCountryBase,
    pub prefix: LegacyGreatPowerPrefix,
    pub ministers: LegacyGreatPowerMinisters,
    pub city: Option<LegacyCityState>,
    pub post_city: LegacyGreatPowerPostCity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LegacyAutoGreatPowerState {
    pub great_power: LegacyGreatPowerState,
    pub auto_prefix: LegacyAutoGreatPowerPrefix,
    pub missions: Vec<LegacyMission>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LegacyMinorState {
    pub country: LegacyCountryBase,
    pub need_current_by_type: [i16; RESOURCE_KIND_COUNT],
    pub trade_offers_by_resource: [i16; RESOURCE_KIND_COUNT],
    pub grant_amounts_by_resource: [i16; RESOURCE_KIND_COUNT],
    pub diplomacy_thresholds: [i16; 7],
    pub diplomacy_policy_fields: [i16; 4],
    pub diplomacy_save_fields: [i16; 4],
    pub diplomacy_save_extension: [i16; RESOURCE_KIND_COUNT],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum LegacyMajorNationState {
    Auto(Box<LegacyAutoGreatPowerState>),
    Other(Box<LegacyGreatPowerState>),
}

impl LegacyMajorNationState {
    const fn great_power(&self) -> &LegacyGreatPowerState {
        match self {
            Self::Auto(nation) => &nation.great_power,
            Self::Other(nation) => nation,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LegacyHelpState {
    pub index_records: LegacyFixedRecordList,
    pub civilian_completion_counters: [i16; 5],
    pub help_index_ready: i16,
}

/// Persistent pointer/class map owned by the surrounding MFC `CArchive`.
///
/// MFC allocates entries from one shared index space: null occupies index zero,
/// and every newly encountered runtime class and object consumes the next index.
/// The state must therefore survive across all nation mission queues in one save.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LegacyMfcArchiveState {
    entries: Vec<Option<String>>,
}

impl Default for LegacyMfcArchiveState {
    fn default() -> Self {
        Self {
            entries: vec![None],
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LegacyArmyMission {
    pub present_location: i16,
    pub required_equipage_bits: [u32; 5],
    /// One-based ordinals in the owning nation's military-unit list.
    pub unit_ordinals: Vec<i16>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LegacyNavyMission {
    pub target_zone: i16,
    pub resolved_port_zone: i16,
    pub required_equipage_bits: [u32; 4],
    /// Zero-based ordinals in the global ship list.
    pub ship_ordinals: Vec<i16>,
    pub state: i32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LegacyMission {
    pub class: String,
    pub source_nation: i16,
    pub state: u8,
    pub importance_bits: u32,
    pub flag: u8,
    pub path_marker: i16,
    pub marker: u8,
    pub army: Option<LegacyArmyMission>,
    pub navy: Option<LegacyNavyMission>,
    pub target_province: Option<i16>,
    pub amassing_province: Option<i16>,
    pub beachhead: Option<LegacyNavyMission>,
    pub blockade_port_zone: Option<i16>,
}

impl LegacyMission {
    fn mission_state(
        &self,
        nation: NationId,
        queue_index: usize,
        military_units: &[LegacyMilitaryUnit],
    ) -> Result<MissionState, LegacySaveError> {
        let army = if let Some(army) = &self.army {
            let mut units = Vec::with_capacity(army.unit_ordinals.len());
            for ordinal in &army.unit_ordinals {
                let unit = usize::try_from(*ordinal - 1)
                    .ok()
                    .and_then(|unit_index| military_units.get(unit_index))
                    .ok_or_else(|| {
                        LegacySaveError::StateProjection(format!(
                            "mission queue {queue_index} references absent unit ordinal {ordinal} for nation {}",
                            nation.get()
                        ))
                    })?;
                units.push(MilitaryUnitId::from_serialized(unit.persistent_id));
            }
            Some((
                optional_province_id(army.present_location)?,
                ArmyMissionState {
                    required_equipage_bits: army.required_equipage_bits,
                    units,
                },
            ))
        } else {
            None
        };
        let navy = self.navy.as_ref().map(navy_mission_state).transpose()?;
        let beachhead = self
            .beachhead
            .as_ref()
            .map(navy_mission_state)
            .transpose()?;
        let attack = match (self.target_province, self.amassing_province, army.clone()) {
            (Some(target_province), Some(amassing_province), Some((present_province, army))) => {
                Some(AttackMissionState {
                    army,
                    present_province,
                    target_province: required_state(
                        optional_province_id(target_province)?,
                        "attack target province",
                    )?,
                    amassing_province: optional_province_id(amassing_province)?,
                })
            }
            _ => None,
        };
        let data = match self.class.as_str() {
            "TDefendProvinceMission" => {
                let (province, army) = required_state(army, "defend-province army mission")?;
                MissionData::DefendProvince {
                    province: required_state(province, "defend-province mission province")?,
                    army,
                }
            }
            "TAttackProvinceMission" => MissionData::AttackProvince(required_state(
                attack,
                "attack-province mission payload",
            )?),
            "TInvadeMission" => MissionData::Invade {
                attack: required_state(attack, "invade mission payload")?,
                beachhead,
            },
            "TControlSeaZoneMission" => {
                MissionData::ControlSeaZone(required_state(navy, "control-sea-zone navy mission")?)
            }
            "TEscortMission" => MissionData::Escort(required_state(navy, "escort navy mission")?),
            "TScatteredShipsMission" => {
                MissionData::ScatteredShips(required_state(navy, "scattered-ships navy mission")?)
            }
            "TBlockadePortMission" => {
                let port_zone = required_state(self.blockade_port_zone, "blockade port zone")?;
                MissionData::BlockadePort {
                    navy: required_state(navy, "blockade-port navy mission")?,
                    port_zone: required_state(
                        optional_ocean_zone_id(port_zone)?,
                        "blockade port zone",
                    )?,
                }
            }
            "TBeachheadMission" => {
                MissionData::Beachhead(required_state(navy, "beachhead navy mission")?)
            }
            class => {
                return Err(LegacySaveError::StateProjection(format!(
                    "unsupported mission class {class}"
                )));
            }
        };
        let source_nation = nation_id_from_retail_i16(self.source_nation)?;
        if source_nation != nation {
            return Err(LegacySaveError::StateProjection(format!(
                "mission queue {queue_index} belongs to nation {} but stores source nation {}",
                nation.get(),
                source_nation.get()
            )));
        }
        Ok(MissionState {
            nation,
            data,
            path_nation: optional_nation_id(self.path_marker)?,
            state: self.state,
            importance_bits: self.importance_bits,
            marker: self.marker,
        })
    }
}

fn navy_mission_state(mission: &LegacyNavyMission) -> Result<NavyMissionState, LegacySaveError> {
    if let Some(ordinal) = mission.ship_ordinals.first() {
        return Err(LegacySaveError::StateProjection(format!(
            "semantic projection of navy mission ship ordinal {ordinal} is not implemented"
        )));
    }
    Ok(NavyMissionState {
        target_zone: optional_ocean_zone_id(mission.target_zone)?,
        resolved_port_zone: optional_ocean_zone_id(mission.resolved_port_zone)?,
        // TNavyMission::ReadFrom rebuilds these runtime-only links as null.
        selected_ship: None,
        task_force: None,
        state: mission.state,
        required_equipage_bits: mission.required_equipage_bits,
        ships: Vec::new(),
    })
}

impl LegacyCityState {
    fn city_state(&self, home_town_tile: Option<TileId>) -> Result<CityState, LegacySaveError> {
        if !self.tasks.is_empty() {
            return Err(LegacySaveError::StateProjection(
                "semantic projection of city tasks is not implemented".into(),
            ));
        }
        if !self.transport_requests.records.is_empty() {
            return Err(LegacySaveError::StateProjection(
                "semantic projection of city transport requests is not implemented".into(),
            ));
        }

        let strike_phase =
            StrikePhase::from_retail(self.population.phase_value).ok_or_else(|| {
                LegacySaveError::StateProjection(format!(
                    "invalid population strike phase {}",
                    self.population.phase_value
                ))
            })?;
        let accumulator =
            PopulationAccumulator::new(f32::from_bits(self.population.count_float_bits))
                .ok_or_else(|| {
                    LegacySaveError::StateProjection("population accumulator is not finite".into())
                })?;

        Ok(CityState {
            orders: Box::new(self.orders.clone()),
            power_plant_upgrade_queued: self.power_plant_upgrade_queued != 0,
            food_substitution_count: self.food_substitution_count,
            starvation_population_loss: self.starvation_population_loss,
            serialized_state: self.serialized_state,
            phase_counter: self.phase_counter,
            military_recruit_count_by_kind: MilitaryUnitTable::from_array(
                self.military_recruit_count_by_kind,
            ),
            civilian_recruit_count_by_kind: CivilianUnitTable::from_array(
                self.civilian_recruit_count_by_kind,
            ),
            ship_order_count_by_type: ShipTypeTable::from_array(self.order_count_by_type),
            rolling_item_production_score: self.rolling_item_production_score,
            low_production: self.low_production != 0,
            low_stock: self.low_stock != 0,
            reserved_by_type: ResourceTable::from_array(self.reserved_by_type),
            home_town_tile,
            power_available: self.power_available,
            stockpile: Stockpile::from_table(ResourceTable::from_array(self.stockpile)),
            production_orders: ProductionTable::from_array(self.production_orders),
            production_accum: ProductionTable::from_array(self.production_accum),
            production_flags: ProductionTable::from_array(self.production_flags),
            production_current: ProductionTable::from_array(self.production_current),
            production_progress: ProductionTable::from_array(self.production_progress),
            // This constructed cache is not persisted by TCity::ReadFrom.
            population_growth_penalty_ticks: 0,
            unmet_resource_retries: ResourceTable::from_array(self.unmet_resource_retries),
            consumed_production_input_by_type: ResourceTable::from_array(
                self.consumed_production_input_by_type,
            ),
            population: PopulationState::new(
                self.population.count,
                accumulator,
                self.population.strength,
                self.population.extra,
                strike_phase,
                LaborPool::from(self.population.baseline_labor),
                LaborPool::from(self.population.production_labor),
                LaborPool::from(self.population.pending_labor_delta),
                ResourceTable::from_array(self.population.predicted_need_by_resource),
            ),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LegacyTerrainTile {
    pub terrain_kind: i8,
    pub region_tile_subtype: i8,
    pub river_sprite: u8,
    pub owner_nation: i8,
    pub former_owner_nation: i8,
    pub secondary_owner_nation: i8,
    pub region: i8,
    pub adjacency_bits: u8,
    pub city_or_province_index: i16,
    pub development_classes: i8,
    pub pending_development_visibility: u8,
    pub edge_resources: [i8; 2],
    pub rail_flags: u8,
    pub action_state: i8,
    pub active_flags: u16,
}

impl LegacyTerrainTile {
    fn tile_state(self, tile: usize) -> Result<TileState, LegacySaveError> {
        Ok(TileState {
            terrain: TerrainKind::from_retail(self.terrain_kind).ok_or_else(|| {
                LegacySaveError::StateProjection(format!(
                    "tile {tile} has invalid terrain {}",
                    self.terrain_kind
                ))
            })?,
            region_tile_subtype: RegionTileSubtype::from_retail(self.region_tile_subtype),
            owner_nation: optional_tile_owner_tag(self.owner_nation)?,
            former_owner_nation: optional_tile_owner_tag(self.former_owner_nation)?,
            secondary_owner_nation: optional_major_nation_id(self.secondary_owner_nation, tile)?,
            province: optional_province_id(self.city_or_province_index)?,
            development: TileDevelopment {
                surface: DevelopmentLevel::new((self.development_classes as u8) & 0x0f),
                extractive: DevelopmentLevel::new((self.development_classes as u8) >> 4),
                resource_visible_to_majors: MajorNationTable::from_fn(|nation| {
                    self.pending_development_visibility & (1 << nation.get()) != 0
                }),
            },
            edge_resources: [
                optional_resource_kind(self.edge_resources[0], tile)?,
                optional_resource_kind(self.edge_resources[1], tile)?,
            ],
            transport_links: decode_tile_transport_links(
                tile,
                "transport_links",
                self.adjacency_bits,
            )?,
            pending_rail_links: decode_tile_transport_links(
                tile,
                "pending_rail_links",
                self.rail_flags,
            )?,
            action: TileAction::try_from_retail(i16::from(self.action_state)),
            flags: TileFlags::from_bits_retain(self.active_flags),
            region: optional_region_id(self.region)?,
            river: river_segment_from_retail_sprite(self.river_sprite, tile)?,
        })
    }
}

fn river_segment_from_retail_sprite(
    mut sprite: u8,
    tile: usize,
) -> Result<Option<RiverSegment>, LegacySaveError> {
    const FLOW_CONNECTIONS: [u8; 16] = [1, 2, 3, 3, 4, 4, 5, 5, 5, 5, 6, 6, 7, 7, 8, 9];

    if sprite == 0 {
        return Ok(None);
    }
    if (0x1b..=0x2a).contains(&sprite) {
        sprite -= 0x10;
    }
    let connection_code = if (0x0b..=0x1a).contains(&sprite) {
        FLOW_CONNECTIONS[usize::from(sprite - 0x0b)]
    } else {
        match sprite {
            0x2b => 0x0a,
            0x2c | 0x2d => 0x0b,
            0x2e => 0x0c,
            0x2f => 0x0d,
            0x30 | 0x31 => 0x0e,
            0x32 => 0x0f,
            0x33 => 0x13,
            0x34 | 0x35 => 0x14,
            0x36 => 0x15,
            0x37 => 0x10,
            0x38 | 0x39 => 0x11,
            0x3a => 0x12,
            _ => {
                return Err(LegacySaveError::StateProjection(format!(
                    "tile {tile} has invalid river sprite {sprite:#04x}"
                )));
            }
        }
    };
    Ok(RiverSegment::from_connection_code(connection_code))
}

fn optional_region_id(value: i8) -> Result<Option<RegionId>, LegacySaveError> {
    if value == -1 {
        return Ok(None);
    }
    u8::try_from(value)
        .map(RegionId::new)
        .map(Some)
        .map_err(|_| LegacySaveError::StateProjection(format!("region ID {value} is invalid")))
}

fn optional_resource_kind(value: i8, tile: usize) -> Result<Option<ResourceKind>, LegacySaveError> {
    if value == -1 {
        return Ok(None);
    }
    u8::try_from(value)
        .ok()
        .and_then(ResourceKind::from_index)
        .map(Some)
        .ok_or_else(|| {
            LegacySaveError::StateProjection(format!(
                "tile {tile} has invalid edge resource {value}"
            ))
        })
}

fn decode_tile_transport_links(
    tile: usize,
    field: &'static str,
    bits: u8,
) -> Result<TileTransportLinks, LegacySaveError> {
    TileTransportLinks::from_bits(bits).ok_or(LegacySaveError::UnsupportedTileTransportLinkBits {
        tile,
        field,
        bits: bits & !TileTransportLinks::all().bits(),
    })
}

fn optional_tile_owner_tag(value: i8) -> Result<Option<TileOwnerTag>, LegacySaveError> {
    if value == -1 {
        return Ok(None);
    }
    u8::try_from(value)
        .map(TileOwnerTag::new)
        .map(Some)
        .map_err(|_| LegacySaveError::StateProjection(format!("tile owner tag {value} is invalid")))
}

fn optional_major_nation_id(
    value: i8,
    tile: usize,
) -> Result<Option<MajorNationId>, LegacySaveError> {
    if value == -1 {
        return Ok(None);
    }
    let raw = value;
    u8::try_from(value)
        .ok()
        .filter(|value| *value < MajorNationId::COUNT)
        .map(MajorNationId::new)
        .map(Some)
        .ok_or_else(|| {
            LegacySaveError::StateProjection(format!(
                "tile {tile} has invalid secondary major-nation owner {raw}"
            ))
        })
}

fn optional_province_id(value: i16) -> Result<Option<ProvinceId>, LegacySaveError> {
    if value == -1 {
        return Ok(None);
    }
    u16::try_from(value)
        .ok()
        .and_then(ProvinceId::try_new)
        .map(Some)
        .ok_or_else(|| {
            LegacySaveError::StateProjection(format!("province ID {value} is out of range"))
        })
}

fn optional_province_array(values: [i16; 3]) -> Result<[Option<ProvinceId>; 3], LegacySaveError> {
    Ok([
        optional_province_id(values[0])?,
        optional_province_id(values[1])?,
        optional_province_id(values[2])?,
    ])
}

fn optional_ocean_zone_id(value: i16) -> Result<Option<OceanZoneId>, LegacySaveError> {
    if value == -1 {
        return Ok(None);
    }
    u16::try_from(value)
        .map(OceanZoneId::new)
        .map(Some)
        .map_err(|_| {
            LegacySaveError::StateProjection(format!(
                "ocean-zone ordinal {value} is negative and not the absent sentinel"
            ))
        })
}

fn optional_nation_id(value: i16) -> Result<Option<NationId>, LegacySaveError> {
    if value == -1 {
        return Ok(None);
    }
    nation_id_from_retail_i16(value).map(Some)
}

fn optional_tile_id(value: i32) -> Result<Option<TileId>, LegacySaveError> {
    if value == -1 {
        return Ok(None);
    }
    u16::try_from(value)
        .ok()
        .and_then(TileId::try_new)
        .map(Some)
        .ok_or_else(|| {
            LegacySaveError::StateProjection(format!("strategic tile ID {value} is out of range"))
        })
}

fn civilian_work_order(
    value: i32,
    tile: Option<TileId>,
    target: Option<TileId>,
    remaining: i16,
    topology: MapTopology,
) -> Result<CivilianWorkOrder, LegacySaveError> {
    let turns = || {
        TurnsRemaining::try_new(remaining).ok_or_else(|| {
            LegacySaveError::StateProjection(format!(
                "civilian order {value} has invalid remaining-turn count {remaining}"
            ))
        })
    };
    let required_tile = || {
        tile.ok_or_else(|| {
            LegacySaveError::StateProjection(format!("civilian order {value} has no tile"))
        })
    };
    let order = match value {
        0 => CivilianWorkOrder::Idle,
        1 => CivilianWorkOrder::Redeploy {
            destination: target.ok_or_else(|| {
                LegacySaveError::StateProjection("redeploy order has no destination".into())
            })?,
            turns: turns()?,
        },
        2 => CivilianWorkOrder::Sleep,
        5 => CivilianWorkOrder::LayRail {
            segment: RailSegment::between(
                topology,
                target.ok_or_else(|| {
                    LegacySaveError::StateProjection("rail order has no source".into())
                })?,
                required_tile()?,
            )
            .ok_or_else(|| {
                LegacySaveError::StateProjection("rail order tiles are not adjacent".into())
            })?,
            turns: turns()?,
        },
        6 => {
            required_tile()?;
            CivilianWorkOrder::BuildDepot { turns: turns()? }
        }
        7 => {
            required_tile()?;
            CivilianWorkOrder::BuildPort { turns: turns()? }
        }
        8 => {
            required_tile()?;
            CivilianWorkOrder::Prospect { turns: turns()? }
        }
        10 => {
            required_tile()?;
            CivilianWorkOrder::DevelopResource { turns: turns()? }
        }
        12 => {
            required_tile()?;
            CivilianWorkOrder::BuildFort { turns: turns()? }
        }
        13 => {
            required_tile()?;
            CivilianWorkOrder::PurchaseLand { turns: turns()? }
        }
        _ => {
            return Err(LegacySaveError::StateProjection(format!(
                "unrecovered civilian work order {value}"
            )));
        }
    };
    Ok(order)
}

fn required_state<T>(value: Option<T>, name: &str) -> Result<T, LegacySaveError> {
    value.ok_or_else(|| LegacySaveError::StateProjection(format!("missing {name}")))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LegacyProvince {
    pub owner_nation: i8,
    pub former_owner_nation: i8,
    pub development_stage: i8,
    pub fort_level: i8,
    pub city_tile: i16,
    pub last_turn_tick: i16,
    pub adjacent_region_count: i8,
    pub adjacent_region_ids: [i16; 12],
    pub region_class: i8,
    pub name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LegacyMapState {
    pub initialized_flag: i16,
    pub search_state_active: u8,
    pub secondary_state: u8,
    pub city_score_total: i32,
    pub scenario_tag: String,
    /// The original field is inverted: zero enables horizontal wrapping.
    pub no_horizontal_wrap: u8,
    pub tiles: Vec<LegacyTerrainTile>,
    pub provinces: Vec<LegacyProvince>,
    pub pending_river_mouth_tile: i16,
}

impl LegacyMapState {
    const fn topology(&self) -> MapTopology {
        if self.no_horizontal_wrap == 0 {
            MapTopology::Wrapping
        } else {
            MapTopology::Bounded
        }
    }

    fn world_state(&self) -> Result<StrategicMap, LegacySaveError> {
        StrategicMap::new(
            self.topology(),
            self.tiles
                .iter()
                .copied()
                .enumerate()
                .map(|(tile, terrain)| terrain.tile_state(tile))
                .collect::<Result<Vec<_>, _>>()?,
        )
        .map_err(|error| LegacySaveError::StateProjection(error.to_string()))
    }

    fn province_states(&self) -> Result<ProvinceTable<ProvinceState>, LegacySaveError> {
        if self.provinces.len() != PROVINCE_COUNT {
            return Err(LegacySaveError::StateProjection(format!(
                "province table has {} records; expected {PROVINCE_COUNT}",
                self.provinces.len()
            )));
        }
        let provinces = self
            .provinces
            .iter()
            .enumerate()
            .map(|(index, province)| province_state(index, province))
            .collect::<Result<Vec<_>, _>>()?;
        let provinces: [ProvinceState; PROVINCE_COUNT] = provinces
            .try_into()
            .expect("province table length was checked before projection");
        Ok(ProvinceTable::from_array(provinces))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LegacySaveError {
    #[error(
        "legacy save ended at offset {offset:#x}: requested {requested} bytes, {remaining} remain"
    )]
    Truncated {
        offset: usize,
        requested: usize,
        remaining: usize,
    },
    #[error("invalid Imperialism save magic {0:?}")]
    InvalidMagic([u8; 4]),
    #[error(
        "unsupported Imperialism save version {0:#x}; the current decoder requires {CURRENT_RETAIL_VERSION:#x}"
    )]
    UnsupportedVersion(u32),
    #[error(
        "multiplayer save role {0} requires the game-flow manager DTO before the simulation suffix can be located"
    )]
    UnsupportedMultiplayerRole(i32),
    #[error("{context} contains {count} MFC polymorphic object(s) at {offset:#x}")]
    UnsupportedPolymorphicObjects {
        context: &'static str,
        count: u32,
        offset: usize,
    },
    #[error("invalid MFC object at {offset:#x}: {detail}")]
    InvalidMfcObject { offset: usize, detail: String },
    #[error(
        "nation {nation} has unsupported retail diplomacy-grant flags for target {target}: {entry:#06x}"
    )]
    UnsupportedDiplomacyGrantFlags {
        nation: i16,
        target: usize,
        entry: i16,
    },
    #[error(
        "nation {nation} has unsupported retail diplomacy policy for target {target}: {entry:#06x}"
    )]
    UnsupportedDiplomacyPolicy {
        nation: i16,
        target: usize,
        entry: i16,
    },
    #[error("tile {tile} has unsupported {field} bits {bits:#04x}")]
    UnsupportedTileTransportLinkBits {
        tile: usize,
        field: &'static str,
        bits: u8,
    },
    #[error("{0}")]
    StateProjection(String),
    #[error("city order {order}: {detail}")]
    InvalidCityOrder { order: &'static str, detail: String },
    #[error("{context}: invalid count {value}; maximum is {maximum}")]
    InvalidCount {
        context: &'static str,
        value: i64,
        maximum: usize,
    },
    #[error("{context}: declared count {declared} does not match availability flags ({available})")]
    CountAvailabilityMismatch {
        context: &'static str,
        declared: usize,
        available: usize,
    },
    #[error("{context}: nation slot {slot} is outside the expected range")]
    InvalidNationSlot { context: &'static str, slot: i16 },
    #[error("{context} entry {index} has invalid retail value {value}")]
    InvalidDiplomacyValue {
        context: &'static str,
        index: usize,
        value: i16,
    },
    #[error("{context} has invalid retail boolean value {value}")]
    InvalidBoolean { context: &'static str, value: u8 },
    #[error(
        "trade commodity {commodity} maximum offer for minor nation slot {nation} is negative: {value}"
    )]
    NegativeTradeOfferMaximum {
        commodity: usize,
        nation: usize,
        value: i16,
    },
    #[error(
        "legacy save ends at offset {end_offset:#x} but input length is {length:#x}; trailing bytes are not represented"
    )]
    TrailingData { end_offset: usize, length: usize },
    #[error("MFC Unicode CString marker at offset {offset:#x} is not supported")]
    UnsupportedUnicodeString { offset: usize },
}

impl From<StreamError> for LegacySaveError {
    fn from(error: StreamError) -> Self {
        match error {
            StreamError::Truncated {
                offset,
                requested,
                remaining,
            } => Self::Truncated {
                offset,
                requested,
                remaining,
            },
            StreamError::UnsupportedUnicodeString { offset } => {
                Self::UnsupportedUnicodeString { offset }
            }
            StreamError::InvalidCount {
                context,
                value,
                maximum,
            } => Self::InvalidCount {
                context,
                value,
                maximum,
            },
        }
    }
}

fn bounded_count(
    value: i32,
    maximum: usize,
    context: &'static str,
) -> Result<usize, LegacySaveError> {
    let Ok(count) = usize::try_from(value) else {
        return Err(LegacySaveError::InvalidCount {
            context,
            value: i64::from(value),
            maximum,
        });
    };
    if count > maximum {
        return Err(LegacySaveError::InvalidCount {
            context,
            value: i64::from(value),
            maximum,
        });
    }
    Ok(count)
}

fn bounded_u32(
    value: u32,
    maximum: usize,
    context: &'static str,
) -> Result<usize, LegacySaveError> {
    let count = value as usize;
    if count > maximum {
        return Err(LegacySaveError::InvalidCount {
            context,
            value: i64::from(value),
            maximum,
        });
    }
    Ok(count)
}

fn validate_nation_slot(
    slot: i16,
    expected: std::ops::Range<i16>,
    context: &'static str,
) -> Result<(), LegacySaveError> {
    if !expected.contains(&slot) {
        return Err(LegacySaveError::InvalidNationSlot { context, slot });
    }
    Ok(())
}

impl LegacySaveV62 {
    pub fn parse(bytes: &[u8]) -> Result<Self, LegacySaveError> {
        let mut stream = LegacyStream::new(bytes);
        let magic: [u8; 4] = stream.read_bytes(4)?.try_into().unwrap();
        if magic != SAVE_MAGIC {
            return Err(LegacySaveError::InvalidMagic(magic));
        }
        let format_version = stream.read_le_u32()?;
        if format_version != CURRENT_RETAIL_VERSION {
            return Err(LegacySaveError::UnsupportedVersion(format_version));
        }
        let saved_session_slot = stream.read_le_i32()?;
        let save_label = fixed_text(stream.read_bytes(SAVE_LABEL_LENGTH)?);
        let preview_owner_nation_by_tile = (0..STRATEGIC_TILE_COUNT)
            .map(|_| stream.read_i8())
            .collect::<Result<Vec<_>, _>>()?;
        let preview_economic_year_offset = stream.read_le_i16()?;
        let preview_difficulty = stream.read_u8()?;
        let preview_active_nation = stream.read_u8()?;
        let preview_active_nation_name = fixed_text(stream.read_bytes(ACTIVE_NATION_NAME_LENGTH)?);
        let header = LegacySaveHeader {
            format_version,
            saved_session_slot,
            save_label,
            preview_owner_nation_by_tile,
            preview_economic_year_offset,
            preview_difficulty,
            preview_active_nation,
            preview_active_nation_name,
        };

        let language_code = stream.read_le_u32()?;
        let economic_turn = stream.read_le_i16()?;
        let active_nation = stream.read_le_i16()?;
        let turn_state_code = stream.read_le_i16()?;
        let mode = stream.read_le_i16()?;
        let previous_turn_state_code = stream.read_le_i16()?;
        let previous_mode = stream.read_le_i16()?;
        stream.skip(1)?;
        let nation_count_raw = stream.read_le_i32()?;
        let minor_nation_count_raw = stream.read_le_i32()?;
        let nation_count = bounded_count(
            nation_count_raw,
            MAJOR_NATION_COUNT,
            "simulation major nation_count",
        )?;
        let minor_nation_count = bounded_count(
            minor_nation_count_raw,
            MINOR_NATION_COUNT,
            "simulation minor_nation_count",
        )?;
        stream.read_le_u32()?;
        let difficulty = stream.read_u8()?;
        let game_setup = read_game_setup(&mut stream)?;
        let persistent_unit_id_counter = stream.read_le_i32()?;
        let nation_availability: [u8; NATION_COUNT] =
            stream.read_bytes(NATION_COUNT)?.try_into().unwrap();
        let available_majors = nation_availability[..MAJOR_NATION_COUNT]
            .iter()
            .filter(|&&flag| flag != 0)
            .count();
        let available_minors = nation_availability[MAJOR_NATION_COUNT..]
            .iter()
            .filter(|&&flag| flag != 0)
            .count();
        if nation_count != available_majors {
            return Err(LegacySaveError::CountAvailabilityMismatch {
                context: "simulation major nation_count",
                declared: nation_count,
                available: available_majors,
            });
        }
        if minor_nation_count != available_minors {
            return Err(LegacySaveError::CountAvailabilityMismatch {
                context: "simulation minor_nation_count",
                declared: minor_nation_count,
                available: available_minors,
            });
        }
        let saved_multiplayer_role = stream.read_le_i32()?;
        if saved_multiplayer_role != 0 {
            return Err(LegacySaveError::UnsupportedMultiplayerRole(
                saved_multiplayer_role,
            ));
        }
        let preference_slot_10 = stream.read_le_i16()?;
        let selected_asset_set = stream.read_le_i16()?;
        let diplomacy_year_term_raw = stream.read_le_i16()?;
        let phase_state_by_decade = stream.read_bytes(12)?.try_into().unwrap();
        let nation_names = (0..NATION_COUNT)
            .map(|_| stream.read_mfc_string().map(|bytes| lossy_text(&bytes)))
            .collect::<Result<Vec<_>, _>>()?;
        let simulation = LegacySimulationPrefix {
            language_code,
            economic_turn,
            active_nation,
            turn_state_code,
            mode,
            previous_turn_state_code,
            previous_mode,
            nation_count: nation_count_raw,
            minor_nation_count: minor_nation_count_raw,
            difficulty,
            game_setup,
            persistent_unit_id_counter,
            nation_availability,
            saved_multiplayer_role,
            preference_slot_10,
            selected_asset_set,
            diplomacy_year_term_raw,
            phase_state_by_decade,
            nation_names,
        };
        let animator_idle_frequency = stream.read_le_i32()?;
        let market = read_trade_market(&mut stream)?;
        let diplomacy_start = stream.position();
        let diplomacy = read_diplomacy_state(&mut stream)?;
        debug_assert_eq!(
            stream.position() - diplomacy_start,
            DIPLOMACY_SERIALIZED_SIZE_V62
        );
        let technology = read_technology_state(&mut stream)?;
        let map = read_map(&mut stream)?;
        let ocean = read_ocean(&mut stream)?;
        let navy = read_navy(&mut stream)?;
        let army_report_count = skip_army_reports(&mut stream)?;
        let remaining_manager_chain_offset = stream.position();

        let mut archive = LegacyMfcArchiveState::default();
        let mut nation_offset = remaining_manager_chain_offset;
        let mut major_nations = Vec::with_capacity(nation_count);
        for nation in 0..MAJOR_NATION_COUNT {
            if simulation.nation_availability[nation] == 0 {
                continue;
            }
            let foreign_policy_id = simulation.game_setup.foreign_minister_policy_ids[nation];
            if simulation.game_setup.nation_control_modes[nation] == 2 {
                let (major, next_offset) = parse_auto_great_power_record_at(
                    bytes,
                    nation_offset,
                    foreign_policy_id,
                    &mut archive,
                )?;
                validate_nation_slot(
                    major.great_power.country.nation_slot,
                    0..MAJOR_NATION_COUNT as i16,
                    "major nation record",
                )?;
                if major.great_power.country.nation_slot as usize != nation {
                    return Err(LegacySaveError::InvalidNationSlot {
                        context: "major nation record slot does not match availability walk",
                        slot: major.great_power.country.nation_slot,
                    });
                }
                major_nations.push(LegacyMajorNationState::Auto(Box::new(major)));
                nation_offset = next_offset;
            } else {
                let (major, next_offset) =
                    parse_great_power_record_at(bytes, nation_offset, foreign_policy_id)?;
                validate_nation_slot(
                    major.country.nation_slot,
                    0..MAJOR_NATION_COUNT as i16,
                    "major nation record",
                )?;
                if major.country.nation_slot as usize != nation {
                    return Err(LegacySaveError::InvalidNationSlot {
                        context: "major nation record slot does not match availability walk",
                        slot: major.country.nation_slot,
                    });
                }
                major_nations.push(LegacyMajorNationState::Other(Box::new(major)));
                nation_offset = next_offset;
            }
        }

        let mut minor_nations = Vec::with_capacity(minor_nation_count);
        for nation in MAJOR_NATION_COUNT..NATION_COUNT {
            if simulation.nation_availability[nation] == 0 {
                continue;
            }
            let (minor, next_offset) = parse_minor_record_at(bytes, nation_offset)?;
            validate_nation_slot(
                minor.country.nation_slot,
                MAJOR_NATION_COUNT as i16..NATION_COUNT as i16,
                "minor nation record",
            )?;
            if minor.country.nation_slot as usize != nation {
                return Err(LegacySaveError::InvalidNationSlot {
                    context: "minor nation record slot does not match availability walk",
                    slot: minor.country.nation_slot,
                });
            }
            minor_nations.push(minor);
            nation_offset = next_offset;
        }

        // TViewMgr, TMacViewMgr, and TNewsMgr persist no fields beyond TObject.
        let (help, end_offset) = parse_help_manager_at(bytes, nation_offset)?;
        if end_offset != bytes.len() {
            return Err(LegacySaveError::TrailingData {
                end_offset,
                length: bytes.len(),
            });
        }
        Ok(Self {
            header,
            simulation,
            animator_idle_frequency,
            market,
            diplomacy,
            technology,
            map,
            ocean,
            navy,
            army_report_count,
            remaining_manager_chain_offset,
            major_nations,
            minor_nations,
            help,
            end_offset,
        })
    }

    /// Projects the decoded strategic map into the semantic world state.
    pub fn world_state(&self) -> Result<StrategicMap, LegacySaveError> {
        self.map.world_state()
    }

    /// Projects the fully decoded save directly into live semantic state.
    /// Runtime-only RNG and selection state must be supplied by the process that loaded
    /// the save because the retail stream does not contain them.
    pub fn game_state(
        &self,
        context: LegacyGameStateContext,
    ) -> Result<GameState, LegacySaveError> {
        if !self.navy.ships.is_empty()
            || !self.navy.admirals.is_empty()
            || !self.navy.task_forces.is_empty()
        {
            return Err(LegacySaveError::StateProjection(
                "semantic projection of non-empty retail navy relationships is not implemented"
                    .to_owned(),
            ));
        }

        let mut minors = MinorNationTable::default();
        let mut military_units = Vec::new();
        let mut civilian_units = Vec::new();
        let mut missions = Vec::new();
        let mut pending = PendingWorkState::default();
        let live_ocean_context_count = validate_ocean_contexts(&self.ocean)?;
        let port_zone_owners = port_zone_owners(&self.ocean, &self.map)?;
        let mut majors = Vec::with_capacity(MAJOR_NATION_COUNT);
        for slot in 0..MAJOR_NATION_COUNT {
            let major_id = MajorNationId::new(slot as u8);
            let nation_id = major_id.nation();
            let nation = self
                .major_nations
                .iter()
                .find(|nation| nation.great_power().country.nation_slot == slot as i16)
                .ok_or_else(|| {
                    LegacySaveError::StateProjection(format!("major nation slot {slot} is absent"))
                })?;
            let great_power = nation.great_power();
            let city = great_power.city.as_ref().ok_or_else(|| {
                LegacySaveError::StateProjection(format!("major nation slot {slot} has no city"))
            })?;
            if great_power.post_city.towns.len() > 1 {
                return Err(LegacySaveError::StateProjection(format!(
                    "major nation slot {slot} has {} towns; semantic projection supports one city",
                    great_power.post_city.towns.len()
                )));
            }
            let city = {
                let home_town = great_power
                    .post_city
                    .towns
                    .first()
                    .map_or(great_power.country.home_tile, |town| {
                        i32::from(town.tile_index)
                    });
                city.city_state(optional_tile_id(home_town)?)?
            };
            let foreign_minister_personality = foreign_minister_personality(
                nation,
                self.simulation.game_setup.foreign_minister_policy_ids[slot],
            )?;
            let (ai_zone_targets, ai_trade) = match nation {
                LegacyMajorNationState::Auto(auto) => (
                    Some(ai_zone_targets(
                        &auto.auto_prefix.port_zone_state_flags,
                        live_ocean_context_count,
                        slot,
                    )?),
                    Some(AiTradeState {
                        temporary_processed_stock: ProcessedTradeCommodityTable::from_array(
                            auto.auto_prefix.action_metric_by_quarter,
                        ),
                    }),
                ),
                LegacyMajorNationState::Other(_) => (None, None),
            };
            majors.push(MajorNation::from_parts(
                country_common(&great_power.country)?,
                great_power_state(
                    great_power,
                    foreign_minister_personality,
                    ai_zone_targets,
                    ai_trade,
                )?,
                city,
            ));
            military_units.extend(great_power.country.military_unit_states(nation_id)?);
            civilian_units.extend(
                great_power
                    .post_city
                    .civilian_unit_states(nation_id, self.map.topology())?,
            );
            if let LegacyMajorNationState::Auto(auto) = nation {
                for (queue_index, mission) in auto.missions.iter().enumerate() {
                    missions.push(mission.mission_state(
                        nation_id,
                        queue_index,
                        &great_power.country.military_units,
                    )?);
                }
            }
            let lists = &great_power.prefix.relationship_lists;
            pending.nations[major_id].turn_events =
                diplomacy_notices(&lists[0], great_power.country.nation_slot)?;
            pending.nations[major_id].proposals =
                diplomacy_proposals(&lists[1], great_power.country.nation_slot)?;
        }
        let majors = MajorNationTable::from_array(majors.try_into().map_err(
            |majors: Vec<MajorNation>| {
                LegacySaveError::StateProjection(format!(
                    "expected {MAJOR_NATION_COUNT} major nations, found {}",
                    majors.len()
                ))
            },
        )?);
        for slot in MAJOR_NATION_COUNT..NATION_COUNT {
            let minor_id = MinorNationId::new(slot as u8);
            if let Some(nation) = self
                .minor_nations
                .iter()
                .find(|nation| nation.country.nation_slot == slot as i16)
            {
                minors[minor_id] = Some(MinorNation {
                    common: country_common(&nation.country)?,
                    consortium_members: nation
                        .diplomacy_save_fields
                        .map(minor_nation_id_from_retail_i16)
                        .into_iter()
                        .collect::<Result<Vec<_>, _>>()?
                        .try_into()
                        .expect("four persisted consortium members"),
                    trade: minor_trade_state(nation)?,
                });
                military_units.extend(
                    nation
                        .country
                        .military_unit_states(NationId::new(slot as u8))?,
                );
            }
        }

        // The retail load path restores this counter before deserializing units.
        // Every TUnit constructor increments it once, even though ReadFrom then
        // replaces the unit's generated ID with the persisted ID.
        let loaded_unit_count = military_units.len() + civilian_units.len();
        let loaded_unit_count = i32::try_from(loaded_unit_count).map_err(|_| {
            LegacySaveError::StateProjection("loaded unit count does not fit an i32".into())
        })?;
        let persistent_unit_id_counter = self
            .simulation
            .persistent_unit_id_counter
            .checked_add(loaded_unit_count)
            .ok_or_else(|| {
                LegacySaveError::StateProjection(
                    "persistent unit ID counter overflows while loading units".into(),
                )
            })?;

        Ok(GameState {
            turn: TurnState {
                scenario_map: self.simulation.game_setup.scenario_map,
                economic_turn: i32::from(self.simulation.economic_turn),
                diplomacy_year_term_raw: self.simulation.diplomacy_year_term_raw,
                phase: PhaseCode::from_retail(i32::from(self.simulation.turn_state_code)),
                difficulty: Difficulty::try_from(self.simulation.difficulty).map_err(|_| {
                    LegacySaveError::StateProjection(format!(
                        "invalid difficulty {}",
                        self.simulation.difficulty
                    ))
                })?,
                active_nation: nation_id_from_retail_i16(self.simulation.active_nation)?,
                selected_nation: context.selected_nation,
            },
            unit_ids: UnitIdAllocator::from_retail(persistent_unit_id_counter),
            world: self.map.world_state()?,
            provinces: self.map.province_states()?,
            port_zone_owners,
            rng: RngState {
                crt_rand: RetailCrtRng::from_state(context.crt_rand_state),
                map_generation: RetailLcg::from_state(context.map_generation_lcg),
                zone_status: RetailLcg::from_state(context.zone_status_lcg),
            },
            market: self.market.clone(),
            technology: self.technology,
            diplomacy: self.diplomacy.clone(),
            nations: Nations::new(majors, minors),
            military_units,
            civilian_units,
            ships: Vec::new(),
            task_forces: Vec::new(),
            missions,
            pending,
        })
    }
}

fn diplomacy_notices(
    list: &LegacyFixedRecordList,
    owner: i16,
) -> Result<Vec<DiplomacyNotice>, LegacySaveError> {
    let records = relationship_records(list, owner, "turn-event queue")?;
    Ok(records
        .into_iter()
        .map(|(code, source)| DiplomacyNotice { source, code })
        .collect())
}

fn diplomacy_proposals(
    list: &LegacyFixedRecordList,
    owner: i16,
) -> Result<Vec<DiplomacyProposal>, LegacySaveError> {
    let records = relationship_records(list, owner, "proposal queue")?;
    records
        .into_iter()
        .map(|(entry, source)| {
            Ok(DiplomacyProposal {
                source,
                policy: diplomacy_policy_from_retail(entry, owner, usize::from(source.get()))?,
            })
        })
        .collect()
}

fn relationship_records(
    list: &LegacyFixedRecordList,
    owner: i16,
    queue: &'static str,
) -> Result<Vec<(i16, NationId)>, LegacySaveError> {
    if list.record_size != 4 {
        return Err(LegacySaveError::StateProjection(format!(
            "nation {owner} {queue} has record size {}; expected 4",
            list.record_size
        )));
    }
    let mut records = list
        .records
        .iter()
        .map(|record| {
            let value = i16::from_le_bytes(record[0..2].try_into().unwrap());
            let source =
                nation_id_from_retail_i16(i16::from_le_bytes(record[2..4].try_into().unwrap()))?;
            Ok((value, source))
        })
        .collect::<Result<Vec<_>, LegacySaveError>>()?;
    records.sort_by_key(|(_, source)| *source);
    if let Some((_, source)) = records
        .windows(2)
        .find(|pair| pair[0].1 == pair[1].1 && pair[0].0 != pair[1].0)
        .map(|pair| pair[0])
    {
        return Err(LegacySaveError::StateProjection(format!(
            "nation {owner} {queue} contains distinguishable records from source {}; retail load order depends on unavailable pre-load CRT state",
            source.get()
        )));
    }
    Ok(records)
}

fn deal_book_state(
    lists: &[LegacyFixedRecordList],
    owner: i16,
) -> Result<TradeCommodityTable<Vec<TradeDealBookEntry>>, LegacySaveError> {
    let deal_lists = lists.get(2..).ok_or_else(|| {
        LegacySaveError::StateProjection(format!(
            "nation {owner} has {} relationship lists; expected 19",
            lists.len()
        ))
    })?;
    if deal_lists.len() != TRADE_CATEGORY_COUNT {
        return Err(LegacySaveError::StateProjection(format!(
            "nation {owner} has {} deal-book lists; expected {TRADE_CATEGORY_COUNT}",
            deal_lists.len()
        )));
    }

    let mut deal_book = TradeCommodityTable::default();
    for (commodity_index, list) in deal_lists.iter().enumerate() {
        let commodity = TradeCommodity::from_retail(commodity_index as i16)
            .expect("the deal-book list count equals the trade-commodity count");
        deal_book[commodity] = deal_book_entries(list, owner, commodity)?;
    }
    Ok(deal_book)
}

fn deal_book_entries(
    list: &LegacyFixedRecordList,
    owner: i16,
    commodity: TradeCommodity,
) -> Result<Vec<TradeDealBookEntry>, LegacySaveError> {
    if list.record_size != 12 {
        return Err(LegacySaveError::StateProjection(format!(
            "nation {owner} {commodity:?} deal book has record size {}; expected 12",
            list.record_size
        )));
    }
    let mut entries = list
        .records
        .iter()
        .map(|record| {
            let kind = match i16::from_le_bytes(record[0..2].try_into().unwrap()) {
                0 => DealBookEntryKind::Accept,
                1 => DealBookEntryKind::Offer,
                value => {
                    return Err(LegacySaveError::StateProjection(format!(
                        "nation {owner} {commodity:?} deal-book entry kind {value} is invalid"
                    )));
                }
            };
            let nation_raw = i16::from_le_bytes(record[2..4].try_into().unwrap());
            let nation = nation_id_from_retail_i16(nation_raw)?;
            let amount = i16::from_le_bytes(record[4..6].try_into().unwrap());
            let eligibility = i16::from_le_bytes(record[6..8].try_into().unwrap());
            let expected_eligibility = match kind {
                DealBookEntryKind::Offer => 1,
                DealBookEntryKind::Accept
                    if nation.get() >= MajorNationId::COUNT =>
                {
                    1
                }
                DealBookEntryKind::Accept => 0,
            };
            if eligibility != expected_eligibility {
                return Err(LegacySaveError::StateProjection(format!(
                    "nation {owner} {commodity:?} deal-book entry for nation {nation_raw} has eligibility {eligibility}; expected {expected_eligibility}"
                )));
            }
            Ok(TradeDealBookEntry {
                kind,
                nation,
                amount,
                unit_price: i32::from_le_bytes(record[8..12].try_into().unwrap()),
            })
        })
        .collect::<Result<Vec<_>, LegacySaveError>>()?;
    entries.sort_by_key(|entry| entry.nation);
    if let Some(entry) = entries.windows(2).find_map(|pair| {
        (pair[0].nation == pair[1].nation && pair[0] != pair[1]).then_some(pair[0])
    }) {
        return Err(LegacySaveError::StateProjection(format!(
            "nation {owner} {commodity:?} deal book contains distinguishable records for nation {}; retail load order depends on unavailable pre-load CRT state",
            entry.nation.get()
        )));
    }
    Ok(entries)
}

fn validate_ocean_contexts(ocean: &LegacyOceanState) -> Result<usize, LegacySaveError> {
    let live_count = ocean.zones.len() + ocean.port_zones.len();
    if live_count > AI_ZONE_TARGET_CAPACITY {
        return Err(LegacySaveError::StateProjection(format!(
            "ocean has {live_count} live contexts; AI state supports at most {AI_ZONE_TARGET_CAPACITY}"
        )));
    }
    let mut seen = vec![false; live_count];
    for context in ocean.zones.iter().chain(&ocean.port_zones) {
        let ordinal = usize::try_from(context.context_ordinal).map_err(|_| {
            LegacySaveError::StateProjection(format!(
                "ocean context ordinal {} is negative",
                context.context_ordinal
            ))
        })?;
        if ordinal >= live_count {
            return Err(LegacySaveError::StateProjection(format!(
                "ocean context ordinal {ordinal} is outside the live range 0..{live_count}"
            )));
        }
        if std::mem::replace(&mut seen[ordinal], true) {
            return Err(LegacySaveError::StateProjection(format!(
                "ocean context ordinal {ordinal} is duplicated"
            )));
        }
    }
    Ok(live_count)
}

fn ai_zone_targets(
    flags: &[u8; AI_ZONE_TARGET_CAPACITY],
    live_count: usize,
    nation: usize,
) -> Result<Vec<AiZoneTargetState>, LegacySaveError> {
    let targets = flags[..live_count]
        .iter()
        .enumerate()
        .map(|(ordinal, value)| match value {
            0 => Ok(AiZoneTargetState::Unmarked),
            1 => Ok(AiZoneTargetState::Candidate),
            2 => Ok(AiZoneTargetState::MissionQueued),
            value => Err(LegacySaveError::StateProjection(format!(
                "AI nation {nation} ocean context {ordinal} has invalid target state {value}"
            ))),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if let Some((offset, value)) = flags[live_count..]
        .iter()
        .copied()
        .enumerate()
        .find(|(_, value)| *value != 0)
    {
        let ordinal = live_count + offset;
        return Err(LegacySaveError::StateProjection(format!(
            "AI nation {nation} unused ocean context {ordinal} has nonzero target state {value}"
        )));
    }
    Ok(targets)
}

fn port_zone_owners(
    ocean: &LegacyOceanState,
    map: &LegacyMapState,
) -> Result<Vec<PortZoneOwner>, LegacySaveError> {
    ocean
        .port_zones
        .iter()
        .rev()
        .map(|context| {
            let port_tile = required_state(
                optional_tile_id(i32::from(required_state(
                    context.port_tile_index,
                    "port-zone tile index",
                )?))?,
                "port-zone tile",
            )?;
            let former_owner = nation_id_from_retail_i16(i16::from(
                map.tiles[usize::from(port_tile.get())].former_owner_nation,
            ))?;
            Ok(PortZoneOwner {
                zone: required_state(
                    optional_ocean_zone_id(context.context_ordinal)?,
                    "port-zone context ordinal",
                )?,
                former_owner,
            })
        })
        .collect()
}

fn foreign_minister_personality(
    nation: &LegacyMajorNationState,
    setup_policy_id: i16,
) -> Result<ForeignMinisterPersonality, LegacySaveError> {
    if !matches!(nation, LegacyMajorNationState::Auto(_)) {
        return Ok(ForeignMinisterPersonality::Base);
    }
    match setup_policy_id {
        0 => Ok(ForeignMinisterPersonality::Arms),
        1 => Ok(ForeignMinisterPersonality::Trader),
        2 => Ok(ForeignMinisterPersonality::Textile),
        3 => Ok(ForeignMinisterPersonality::Diplomat),
        4 => Ok(ForeignMinisterPersonality::Bill),
        5 => Ok(ForeignMinisterPersonality::Ted),
        _ => Err(LegacySaveError::StateProjection(format!(
            "unsupported AI foreign-minister setup policy {setup_policy_id}"
        ))),
    }
}

fn trade_commodity_from_retail(
    value: i16,
    context: impl std::fmt::Display,
) -> Result<TradeCommodity, LegacySaveError> {
    TradeCommodity::from_retail(value).ok_or_else(|| {
        LegacySaveError::StateProjection(format!(
            "{context} trade commodity {value} is out of range"
        ))
    })
}

fn optional_trade_commodity_from_retail(
    value: i16,
    context: impl std::fmt::Display,
) -> Result<Option<TradeCommodity>, LegacySaveError> {
    if value == -10 {
        return Ok(None);
    }
    trade_commodity_from_retail(value, context).map(Some)
}

fn optional_manufactured_trade_commodity_from_retail(
    value: i16,
    context: impl std::fmt::Display,
) -> Result<Option<TradeCommodity>, LegacySaveError> {
    let commodity = optional_trade_commodity_from_retail(value, context)?;
    if matches!(
        commodity,
        None | Some(
            TradeCommodity::Clothing
                | TradeCommodity::Furniture
                | TradeCommodity::Hardware
                | TradeCommodity::Arms
        )
    ) {
        Ok(commodity)
    } else {
        Err(LegacySaveError::StateProjection(format!(
            "manufactured trade request {value} is outside the recovered range"
        )))
    }
}

fn foreign_trade_state(
    minister: &LegacyForeignMinisterState,
    nation: i16,
) -> Result<ForeignTradeState, LegacySaveError> {
    let interior_bid = optional_trade_commodity_from_retail(
        minister.scalar_fields[0],
        format_args!("major nation {nation} interior-bid"),
    )?
    .map(|commodity| ForeignTradeBid {
        commodity,
        amount: minister.scalar_fields[1],
    });
    let requested_ship = match minister.scalar_fields[6] {
        1 => ShipType::Trader,
        2 => ShipType::Indiaman,
        value => {
            return Err(LegacySaveError::StateProjection(format!(
                "major nation {nation} foreign-minister ship order kind {value} is outside the recovered range"
            )));
        }
    };
    let mut preferred_resources = [None; 4];
    for (index, value) in minister.preferred_resource_slots.into_iter().enumerate() {
        preferred_resources[index] = optional_trade_commodity_from_retail(
            value,
            format_args!("major nation {nation} preferred-resource slot {index}"),
        )?;
    }
    Ok(ForeignTradeState {
        interior_bid,
        phase_counter: minister.scalar_fields[4],
        refresh_interval: minister.scalar_fields[5],
        requested_ship,
        purchase_priority: TradeCommodityTable::from_array(minister.purchase_priority_by_resource),
        preferred_resources,
    })
}

fn pending_ship(
    minister: &LegacyInteriorMinisterState,
    nation: i16,
) -> Result<Option<ShipType>, LegacySaveError> {
    match minister.order_scalars[1] {
        0 => Ok(None),
        1 => Ok(Some(ShipType::Trader)),
        2 => Ok(Some(ShipType::Indiaman)),
        value => Err(LegacySaveError::StateProjection(format!(
            "major nation {nation} pending ship type {value} is outside the recovered range"
        ))),
    }
}

fn minor_trade_state(nation: &LegacyMinorState) -> Result<MinorTradeState, LegacySaveError> {
    let slot = nation.country.nation_slot;
    Ok(MinorTradeState {
        current_supply: ResourceTable::from_array(nation.need_current_by_type),
        offers: ResourceTable::from_array(nation.trade_offers_by_resource),
        grant_deltas: ResourceTable::from_array(nation.grant_amounts_by_resource),
        thresholds: MinorTradeThresholds {
            primary_manufactured_price: nation.diplomacy_thresholds[0],
            secondary_manufactured_price: nation.diplomacy_thresholds[1],
            general_offer_price: nation.diplomacy_thresholds[2],
            random_offer_price: nation.diplomacy_thresholds[3],
            coal_offer_price: nation.diplomacy_thresholds[4],
            iron_offer_price: nation.diplomacy_thresholds[5],
            oil_offer_price: nation.diplomacy_thresholds[6],
        },
        primary_manufactured_request: optional_manufactured_trade_commodity_from_retail(
            nation.diplomacy_policy_fields[0],
            format_args!("minor nation {slot} primary request"),
        )?,
        secondary_manufactured_request: optional_manufactured_trade_commodity_from_retail(
            nation.diplomacy_policy_fields[1],
            format_args!("minor nation {slot} secondary request"),
        )?,
        primary_request_fulfilled: nation.diplomacy_policy_fields[2],
        secondary_request_fulfilled: nation.diplomacy_policy_fields[3],
        independent_resource_counts: ResourceTable::from_array(nation.diplomacy_save_extension),
    })
}

fn great_power_state(
    nation: &LegacyGreatPowerState,
    foreign_minister_personality: ForeignMinisterPersonality,
    ai_zone_targets: Option<Vec<AiZoneTargetState>>,
    ai_trade: Option<AiTradeState>,
) -> Result<GreatPowerState, LegacySaveError> {
    let prefix = &nation.prefix;
    let post = &nation.post_city;
    let foreign_minister = nation.ministers.foreign.as_ref().ok_or_else(|| {
        LegacySaveError::StateProjection(format!(
            "major nation slot {} has no foreign minister",
            nation.country.nation_slot
        ))
    })?;
    let defense_minister = nation.ministers.defense.as_ref().ok_or_else(|| {
        LegacySaveError::StateProjection(format!(
            "major nation slot {} has no defense minister",
            nation.country.nation_slot
        ))
    })?;
    let interior_minister = nation.ministers.interior.as_ref().ok_or_else(|| {
        LegacySaveError::StateProjection(format!(
            "major nation slot {} has no interior minister",
            nation.country.nation_slot
        ))
    })?;
    for (&status, &payload) in prefix
        .pending_action_status
        .iter()
        .zip(prefix.pending_action_payload_by_action.iter())
    {
        validate_pending_action(status, payload)?;
    }
    Ok(GreatPowerState {
        controller: if prefix.diplomacy_eligible != 0 {
            MajorNationController::Human
        } else {
            MajorNationController::Computer
        },
        ai_zone_targets,
        foreign_minister_personality,
        foreign_minister_skill_index: foreign_minister.skill_index,
        foreign_trade: foreign_trade_state(foreign_minister, nation.country.nation_slot)?,
        development_grant_by_nation: NationTable::from_array(
            foreign_minister.development_grant_by_nation,
        ),
        defense_minister_skill_index: defense_minister.skill_index,
        capacities: NationCapacities::from_array(prefix.capacities),
        grant_total_cost: prefix.grant_total_cost,
        unfilled_trade_offer_count: prefix.unfilled_trade_offer_count,
        diplomacy_policy_by_nation: diplomacy_policies_from_retail_entries(
            prefix.diplomacy_policy_by_nation,
            nation.country.nation_slot,
        )?,
        diplomacy_grants_by_nation: diplomacy_grants_from_retail_entries(
            prefix.diplomacy_grant_by_nation,
            nation.country.nation_slot,
        )?,
        need_current_by_type: ResourceTable::from_array(prefix.need_current_by_type),
        need_target_by_type: ResourceTable::from_array(prefix.need_target_by_type),
        relation_delta_current: ResourceTable::from_array(prefix.relation_delta_current),
        purchased_items_by_resource: ResourceTable::from_array(prefix.purchased_items_by_resource),
        item_potentials: ResourceTable::from_array(prefix.item_potentials),
        unfilled_trade_turns_by_resource: ResourceTable::from_array(
            prefix.unfilled_trade_turns_by_resource,
        ),
        transported_items_by_resource: ResourceTable::from_array(
            prefix.transported_items_by_resource,
        ),
        remembered_trade_offers_by_resource: ResourceTable::from_array(
            prefix.remembered_trade_offers_by_resource,
        ),
        deal_book: deal_book_state(&prefix.relationship_lists, nation.country.nation_slot)?,
        pending_ship: pending_ship(interior_minister, nation.country.nation_slot)?,
        ai_trade,
        aid_allocation_by_minor_nation: MinorNationTable::from_array(
            prefix
                .aid_allocation_by_minor_nation
                .map(ResourceTable::from_array),
        ),
        budget_pool_base: prefix.budget_pool_base,
        budget_pool_delta: prefix.budget_pool_delta,
        special_resource_trade_balance: post.special_resource_trade_balance,
        candidate_nation_flags: NationTable::from_array(post.candidate_nation_flags),
        // scenarioInitFlag is constructed as zero and is not part of the save stream.
        scenario_initialized: false,
        turn_finished: post.turn_finished_flag != 0,
        pending_actions: PendingActionTable::from_fn(|action| {
            let index = action as usize;
            normalized_pending_action(
                prefix.pending_action_status[index],
                prefix.pending_action_payload_by_action[index],
            )
        }),
        diplomacy_budget_base: post.diplomacy_budget_base,
        escalation_counter: i16::from(post.escalation_counter),
        pending_commitment_cost: post.pending_commitment_cost,
        pressure_counter: i16::from(post.pressure_counter),
        aid_allocation_total: post.aid_allocation_total,
        colony_boycott_flags: NationTable::from_array(post.colony_boycott_flags),
        military_expenses: post.military_expenses,
    })
}

fn validate_pending_action(status: i8, payload: i16) -> Result<(), LegacySaveError> {
    match status {
        0 | 0x32..=0x34 if payload >= -1 => Ok(()),
        0 | 0x32..=0x34 => Err(LegacySaveError::StateProjection(format!(
            "pending-action payload {payload} is below the -1 sentinel"
        ))),
        _ => Err(LegacySaveError::StateProjection(format!(
            "unsupported pending-action status {status}"
        ))),
    }
}

fn normalized_pending_action(status: i8, payload: i16) -> PendingActionState {
    let status = match status {
        0 => PendingActionStatus::None,
        0x32 => PendingActionStatus::Queued,
        0x33 => PendingActionStatus::Level3,
        0x34 => PendingActionStatus::Level4,
        _ => unreachable!("pending action was validated before normalization"),
    };
    PendingActionState::new(status, (payload != -1).then_some(payload))
}

fn diplomacy_grants_from_retail_entries(
    entries: [i16; NATION_COUNT],
    nation: i16,
) -> Result<NationTable<Option<DiplomacyGrant>>, LegacySaveError> {
    let mut grants = NationTable::default();
    for (target, entry) in entries.into_iter().enumerate() {
        grants[NationId::new(target as u8)] = if entry == -1 {
            None
        } else {
            if entry < 0 {
                return Err(LegacySaveError::UnsupportedDiplomacyGrantFlags {
                    nation,
                    target,
                    entry,
                });
            }
            Some(DiplomacyGrant {
                amount: i32::from(entry & 0x3fff),
                recurring: entry & 0x4000 != 0,
            })
        };
    }
    Ok(grants)
}

fn diplomacy_policies_from_retail_entries(
    entries: [i16; NATION_COUNT],
    nation: i16,
) -> Result<NationTable<Option<DiplomacyPolicy>>, LegacySaveError> {
    let mut policies = NationTable::default();
    for (target, entry) in entries.into_iter().enumerate() {
        policies[NationId::new(target as u8)] = match entry {
            -1 => None,
            _ => Some(diplomacy_policy_from_retail(entry, nation, target)?),
        };
    }
    Ok(policies)
}

fn diplomacy_policy_from_retail(
    entry: i16,
    nation: i16,
    target: usize,
) -> Result<DiplomacyPolicy, LegacySaveError> {
    match entry {
        0x12d => Ok(DiplomacyPolicy::JoinEmpire),
        0x12e => Ok(DiplomacyPolicy::Alliance),
        0x12f => Ok(DiplomacyPolicy::NonAggressionPact),
        0x130 => Ok(DiplomacyPolicy::PeaceTreaty),
        0x131 => Ok(DiplomacyPolicy::DeclareWar),
        0x132 => Ok(DiplomacyPolicy::JoinEmpireWithWarEntanglements),
        0x133 => Ok(DiplomacyPolicy::BuildConsulate),
        0x134 => Ok(DiplomacyPolicy::BuildEmbassy),
        _ => Err(LegacySaveError::UnsupportedDiplomacyPolicy {
            nation,
            target,
            entry,
        }),
    }
}

fn country_status_from_retail(value: i16) -> Result<CountryStatus, LegacySaveError> {
    match value {
        -1 => Ok(CountryStatus::Independent),
        100..=122 => Ok(CountryStatus::ProtectorateOf(NationId::new(
            (value - 100) as u8,
        ))),
        200..=222 => Ok(CountryStatus::ColonyOf(NationId::new((value - 200) as u8))),
        _ => Err(LegacySaveError::StateProjection(format!(
            "invalid encoded nation status {value}"
        ))),
    }
}

fn owned_region_id_from_retail(value: i32) -> Result<ProvinceId, LegacySaveError> {
    u16::try_from(value)
        .ok()
        .and_then(ProvinceId::try_new)
        .ok_or_else(|| {
            LegacySaveError::StateProjection(format!(
                "owned-region province ID {value} is out of range"
            ))
        })
}

fn province_state(
    index: usize,
    province: &LegacyProvince,
) -> Result<ProvinceState, LegacySaveError> {
    let count = usize::try_from(province.adjacent_region_count).map_err(|_| {
        LegacySaveError::StateProjection(format!(
            "province {index} has negative adjacency count {}",
            province.adjacent_region_count
        ))
    })?;
    if count > province.adjacent_region_ids.len() {
        return Err(LegacySaveError::StateProjection(format!(
            "province {index} has adjacency count {count}; maximum is {}",
            province.adjacent_region_ids.len()
        )));
    }
    let adjacency = province.adjacent_region_ids[..count]
        .iter()
        .copied()
        .map(|value| {
            u16::try_from(value)
                .ok()
                .and_then(ProvinceId::try_new)
                .ok_or_else(|| {
                    LegacySaveError::StateProjection(format!(
                        "province {index} adjacency ID {value} is out of range"
                    ))
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let optional_owner = |value: i8, field: &str| {
        if value == -1 {
            return Ok(None);
        }
        u8::try_from(value)
            .ok()
            .and_then(NationId::try_new)
            .map(Some)
            .ok_or_else(|| {
                LegacySaveError::StateProjection(format!(
                    "province {index} {field} nation ID {value} is out of range"
                ))
            })
    };
    let region_class = match province.region_class {
        -1 => None,
        0..=23 => Some(province.region_class as u8),
        value => {
            return Err(LegacySaveError::StateProjection(format!(
                "province {index} region class {value} is out of range"
            )));
        }
    };

    ProvinceState::new(
        optional_owner(province.owner_nation, "owner")?,
        optional_owner(province.former_owner_nation, "former-owner")?,
        adjacency,
        region_class,
    )
    .map_err(|error| {
        LegacySaveError::StateProjection(format!("province {index} is invalid: {error}"))
    })
}

fn country_common(country: &LegacyCountryBase) -> Result<NationCommonState, LegacySaveError> {
    Ok(NationCommonState {
        status: country_status_from_retail(country.encoded_nation_slot)?,
        owned_regions: country
            .owned_regions
            .iter()
            .copied()
            .map(owned_region_id_from_retail)
            .collect::<Result<Vec<_>, _>>()?,
        treasury: country.treasury,
        home_tile: optional_tile_id(country.home_tile)?,
        trade_policy_by_nation: NationTable::from_array(
            country
                .need_level_by_nation
                .map(|score| TradePolicyScore::new(i32::from(score))),
        ),
    })
}

/// Decodes the common `TCountry` prefix at an already-located nation record.
///
/// The returned offset is the first byte of the derived `TGreatPower` or `TMinor`
/// suffix. Keeping location separate from decoding lets the manager-chain parser
/// choose the concrete retail nation class without embedding C++ layout in the DTO.
fn parse_country_base_at(
    bytes: &[u8],
    offset: usize,
) -> Result<(LegacyCountryBase, usize), LegacySaveError> {
    let remaining = bytes.get(offset..).ok_or(StreamError::Truncated {
        offset,
        requested: 1,
        remaining: 0,
    })?;
    let mut stream = LegacyStream::new(remaining);
    let country = read_country_base(&mut stream)?;
    Ok((country, offset + stream.position()))
}

/// Decodes the fixed portion of a `TGreatPower` derived record.
///
/// The returned offset points just after the minister-presence byte, at the first
/// optional minister or city payload. It includes the two turn/proposal queues and
/// 17 diplomacy lists serialized as fixed-size `TSortedPtrList` records.
fn parse_great_power_prefix_at(
    bytes: &[u8],
    offset: usize,
) -> Result<(LegacyGreatPowerPrefix, usize), LegacySaveError> {
    let remaining = bytes.get(offset..).ok_or(StreamError::Truncated {
        offset,
        requested: 1,
        remaining: 0,
    })?;
    let mut stream = LegacyStream::new(remaining);
    let prefix = read_great_power_prefix(&mut stream)?;
    Ok((prefix, offset + stream.position()))
}

/// Decodes the complete current-format `TCity` payload at an already-located city.
fn parse_city_at(bytes: &[u8], offset: usize) -> Result<(LegacyCityState, usize), LegacySaveError> {
    let remaining = bytes.get(offset..).ok_or(StreamError::Truncated {
        offset,
        requested: 1,
        remaining: 0,
    })?;
    let mut stream = LegacyStream::new(remaining);
    let city = read_city(&mut stream)?;
    Ok((city, offset + stream.position()))
}

/// Decodes the optional minister payload selected by `TGreatPower`'s presence mask.
/// The foreign policy ID matters only for Bill's one-byte derived suffix.
fn parse_great_power_ministers_at(
    bytes: &[u8],
    offset: usize,
    presence_mask: u8,
    foreign_policy_id: i16,
) -> Result<(LegacyGreatPowerMinisters, usize), LegacySaveError> {
    let remaining = bytes.get(offset..).ok_or(StreamError::Truncated {
        offset,
        requested: 1,
        remaining: 0,
    })?;
    let mut stream = LegacyStream::new(remaining);
    let ministers = read_great_power_ministers(&mut stream, presence_mask, foreign_policy_id)?;
    Ok((ministers, offset + stream.position()))
}

fn parse_great_power_post_city_at(
    bytes: &[u8],
    offset: usize,
) -> Result<(LegacyGreatPowerPostCity, usize), LegacySaveError> {
    let remaining = bytes.get(offset..).ok_or(StreamError::Truncated {
        offset,
        requested: 1,
        remaining: 0,
    })?;
    let mut stream = LegacyStream::new(remaining);
    let post_city = read_great_power_post_city(&mut stream, offset)?;
    Ok((post_city, offset + stream.position()))
}

fn parse_auto_great_power_prefix_at(
    bytes: &[u8],
    offset: usize,
) -> Result<(LegacyAutoGreatPowerPrefix, usize), LegacySaveError> {
    let remaining = bytes.get(offset..).ok_or(StreamError::Truncated {
        offset,
        requested: 1,
        remaining: 0,
    })?;
    let mut stream = LegacyStream::new(remaining);
    let prefix = read_auto_great_power_prefix(&mut stream)?;
    Ok((prefix, offset + stream.position()))
}

/// Decodes a mission queue written through MFC `CArchive::WriteObject`.
///
/// `archive` is intentionally supplied by the caller because its class/object map
/// spans the complete save stream rather than resetting at each nation.
fn parse_missions_at(
    bytes: &[u8],
    offset: usize,
    count: u32,
    archive: &mut LegacyMfcArchiveState,
) -> Result<(Vec<LegacyMission>, usize), LegacySaveError> {
    let remaining = bytes.get(offset..).ok_or(StreamError::Truncated {
        offset,
        requested: 1,
        remaining: 0,
    })?;
    let mut stream = LegacyStream::new(remaining);
    let count = bounded_u32(count, MAX_MISSIONS, "AI mission queue")?;
    let mut missions = Vec::with_capacity(count);
    for _ in 0..count {
        missions.push(read_mfc_mission(&mut stream, offset, archive)?);
    }
    Ok((missions, offset + stream.position()))
}

/// Decodes the complete common `TGreatPower` record, stopping before any
/// controller-specific derived suffix.
fn parse_great_power_record_at(
    bytes: &[u8],
    offset: usize,
    foreign_policy_id: i16,
) -> Result<(LegacyGreatPowerState, usize), LegacySaveError> {
    let (country, prefix_offset) = parse_country_base_at(bytes, offset)?;
    let (prefix, optional_offset) = parse_great_power_prefix_at(bytes, prefix_offset)?;
    let (ministers, city_offset) = parse_great_power_ministers_at(
        bytes,
        optional_offset,
        prefix.minister_presence_mask,
        foreign_policy_id,
    )?;
    let (city, post_city_offset) = if prefix.minister_presence_mask & 8 != 0 {
        let (city, next) = parse_city_at(bytes, city_offset)?;
        (Some(city), next)
    } else {
        (None, city_offset)
    };
    let (post_city, next_offset) = parse_great_power_post_city_at(bytes, post_city_offset)?;
    Ok((
        LegacyGreatPowerState {
            country,
            prefix,
            ministers,
            city,
            post_city,
        },
        next_offset,
    ))
}

/// Decodes one AI-controlled major nation and advances the shared MFC object map.
fn parse_auto_great_power_record_at(
    bytes: &[u8],
    offset: usize,
    foreign_policy_id: i16,
    archive: &mut LegacyMfcArchiveState,
) -> Result<(LegacyAutoGreatPowerState, usize), LegacySaveError> {
    let (great_power, auto_offset) = parse_great_power_record_at(bytes, offset, foreign_policy_id)?;
    let (auto_prefix, mission_offset) = parse_auto_great_power_prefix_at(bytes, auto_offset)?;
    let (missions, next_offset) =
        parse_missions_at(bytes, mission_offset, auto_prefix.mission_count, archive)?;
    Ok((
        LegacyAutoGreatPowerState {
            great_power,
            auto_prefix,
            missions,
        },
        next_offset,
    ))
}

/// Decodes one v62 `TMinor` record including its current-format diplomacy extension.
fn parse_minor_record_at(
    bytes: &[u8],
    offset: usize,
) -> Result<(LegacyMinorState, usize), LegacySaveError> {
    let (country, suffix_offset) = parse_country_base_at(bytes, offset)?;
    let remaining = bytes.get(suffix_offset..).ok_or(StreamError::Truncated {
        offset: suffix_offset,
        requested: 1,
        remaining: 0,
    })?;
    let mut stream = LegacyStream::new(remaining);
    let minor = LegacyMinorState {
        country,
        need_current_by_type: read_be_short_array(&mut stream)?,
        trade_offers_by_resource: read_be_short_array(&mut stream)?,
        grant_amounts_by_resource: read_be_short_array(&mut stream)?,
        diplomacy_thresholds: read_short_array(&mut stream)?,
        diplomacy_policy_fields: read_short_array(&mut stream)?,
        diplomacy_save_fields: read_be_short_array(&mut stream)?,
        diplomacy_save_extension: read_be_short_array(&mut stream)?,
    };
    Ok((minor, suffix_offset + stream.position()))
}

fn parse_help_manager_at(
    bytes: &[u8],
    offset: usize,
) -> Result<(LegacyHelpState, usize), LegacySaveError> {
    let remaining = bytes.get(offset..).ok_or(StreamError::Truncated {
        offset,
        requested: 1,
        remaining: 0,
    })?;
    let mut stream = LegacyStream::new(remaining);
    let help = LegacyHelpState {
        index_records: read_fixed_record_list(&mut stream)?,
        civilian_completion_counters: read_be_short_array(&mut stream)?,
        help_index_ready: stream.read_le_i16()?,
    };
    Ok((help, offset + stream.position()))
}

fn read_diplomacy_state(stream: &mut LegacyStream<'_>) -> Result<DiplomacyState, LegacySaveError> {
    const NATION_PAIR_COUNT: usize = NATION_COUNT * NATION_COUNT;

    let start = stream.position();
    let standings = nation_pair_table(read_be_short_array::<NATION_PAIR_COUNT>(stream)?);
    let relationships = read_be_short_array::<NATION_PAIR_COUNT>(stream)?
        .into_iter()
        .enumerate()
        .map(|(index, value)| {
            DiplomaticRelationship::try_from_retail(value).ok_or(
                LegacySaveError::InvalidDiplomacyValue {
                    context: "diplomacy relationships",
                    index,
                    value,
                },
            )
        })
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .expect("one relationship per nation pair");
    let relationships = nation_pair_table(relationships);
    let relationship_turns = read_be_short_array::<NATION_PAIR_COUNT>(stream)?
        .into_iter()
        .enumerate()
        .map(|(index, value)| match value {
            -1 => Ok(None),
            0..=i16::MAX => Ok(Some(value)),
            _ => Err(LegacySaveError::InvalidDiplomacyValue {
                context: "diplomacy relationship turns",
                index,
                value,
            }),
        })
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .expect("one turn stamp per nation pair");
    let relationship_turns = nation_pair_table(relationship_turns);

    let influence_thresholds =
        ProvinceTable::from_array(read_be_short_array::<PROVINCE_COUNT>(stream)?);
    let influence_sides = (0..PROVINCE_COUNT)
        .map(|index| {
            let value = i16::from(stream.read_i8()?);
            optional_major_nation(value, "diplomacy influence sides", index)
        })
        .collect::<Result<Vec<_>, LegacySaveError>>()?
        .try_into()
        .expect("one influence side per province");
    let influence_sides = ProvinceTable::from_array(influence_sides);
    let last_diplomatic_effort_turn = stream.read_le_i16()?;

    let mission_levels = read_be_short_array::<NATION_PAIR_COUNT>(stream)?
        .into_iter()
        .enumerate()
        .map(|(index, value)| {
            DiplomaticMissionLevel::try_from_retail(value).ok_or(
                LegacySaveError::InvalidDiplomacyValue {
                    context: "diplomacy mission levels",
                    index,
                    value,
                },
            )
        })
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .expect("one mission level per nation pair");
    let mission_levels = nation_pair_table(mission_levels);

    let chairman = optional_major_nation(stream.read_be_i16()?, "diplomatic congress chairman", 0)?;
    let counterpart =
        optional_major_nation(stream.read_be_i16()?, "diplomatic congress counterpart", 0)?;
    let congress = DiplomaticCongressState {
        chairman,
        counterpart,
        chairman_support: stream.read_be_i16()?,
        counterpart_support: stream.read_be_i16()?,
        neutral_support: stream.read_be_i16()?,
    };

    let special_relation_sources =
        read_optional_major_nation_table(stream, "diplomacy special-relation sources")?;
    let special_relation_targets =
        read_optional_major_nation_table(stream, "diplomacy special-relation targets")?;

    assert_eq!(
        stream.position() - start,
        DIPLOMACY_SERIALIZED_SIZE_V62,
        "recovered v62 diplomacy payload layout must remain exact"
    );
    Ok(DiplomacyState {
        standings,
        relationships,
        relationship_turns,
        influence_thresholds,
        influence_sides,
        last_diplomatic_effort_turn,
        mission_levels,
        congress,
        special_relation_sources,
        special_relation_targets,
        // The retail constructor restores both values before ReadFrom consumes the payload.
        last_processed_nation: None,
        proposal_mode_raw: 0,
    })
}

fn nation_pair_table<T: Copy>(
    values: [T; NATION_COUNT * NATION_COUNT],
) -> NationTable<NationTable<T>> {
    NationTable::from_array(std::array::from_fn(|source| {
        NationTable::from_array(std::array::from_fn(|target| {
            values[source * NATION_COUNT + target]
        }))
    }))
}

fn optional_major_nation(
    value: i16,
    context: &'static str,
    index: usize,
) -> Result<Option<MajorNationId>, LegacySaveError> {
    if value == -1 {
        return Ok(None);
    }
    if (0..MAJOR_NATION_COUNT as i16).contains(&value) {
        return Ok(Some(MajorNationId::new(value as u8)));
    }
    Err(LegacySaveError::InvalidDiplomacyValue {
        context,
        index,
        value,
    })
}

fn read_optional_major_nation_table(
    stream: &mut LegacyStream<'_>,
    context: &'static str,
) -> Result<MinorNationTable<Option<MajorNationId>>, LegacySaveError> {
    let values = (0..MINOR_NATION_COUNT)
        .map(|index| optional_major_nation(stream.read_be_i16()?, context, index))
        .collect::<Result<Vec<_>, LegacySaveError>>()?
        .try_into()
        .expect("one special-relation value per minor nation");
    Ok(MinorNationTable::from_array(values))
}

fn read_trade_market(stream: &mut LegacyStream<'_>) -> Result<TradeMarketState, LegacySaveError> {
    let rows = (0..TRADE_CATEGORY_COUNT)
        .map(|commodity| read_trade_market_row(stream, commodity))
        .collect::<Result<Vec<_>, _>>()?;
    let rows: [TradeMarketRow; TRADE_CATEGORY_COUNT] =
        rows.try_into().expect("one market row per trade commodity");
    for _ in 0..TRADE_CATEGORY_COUNT {
        let record_size = usize::from(stream.read_le_u16()?);
        let record_count = bounded_u32(
            stream.read_le_u32()?,
            MAX_TRADE_HISTORY_RECORDS,
            "trade history",
        )?;
        let byte_len = record_size * record_count;
        stream.skip(byte_len)?;
    }
    Ok(TradeMarketState {
        rows: TradeCommodityTable::from_array(rows),
    })
}

fn read_trade_market_row(
    stream: &mut LegacyStream<'_>,
    commodity: usize,
) -> Result<TradeMarketRow, LegacySaveError> {
    let previous_price = i32::from(stream.read_le_i16()?);
    let price = i32::from(stream.read_le_i16()?);
    let request_count = i32::from(stream.read_le_i16()?);
    let offer_count = i32::from(stream.read_le_i16()?);
    let adjusted_offer_count = f64::from_le_bytes(stream.read_bytes(8)?.try_into().unwrap());
    let amount_offered = i32::from(stream.read_le_i16()?);
    let base_price = i32::from(stream.read_le_i16()?);
    // The first two per-nation sub-rows are transient current and accumulated offers.
    stream.skip(2 * NATION_COUNT * std::mem::size_of::<i16>())?;
    let mut maximum_offer_by_nation = [0; NATION_COUNT];
    for (nation, maximum) in maximum_offer_by_nation.iter_mut().enumerate() {
        let value = stream.read_be_i16()?;
        if value < 0 {
            return Err(LegacySaveError::NegativeTradeOfferMaximum {
                commodity,
                nation,
                value,
            });
        }
        *maximum = value;
    }
    Ok(TradeMarketRow {
        previous_price,
        price,
        base_price,
        request_count,
        offer_count,
        amount_offered,
        adjusted_offer_count,
        maximum_offer_by_nation: NationTable::from_array(maximum_offer_by_nation),
    })
}

fn read_technology_state(
    stream: &mut LegacyStream<'_>,
) -> Result<TechnologyState, LegacySaveError> {
    let bytes = stream.read_bytes(TECH_SERIALIZED_SIZE_V62)?;
    let researched = |nation: usize, technology: usize| {
        let offset = TECH_ORDER_CAP_ROWS_OFFSET_V62 + nation * TECH_ORDER_CAP_ROW_SIZE + technology;
        match bytes[offset] {
            0 | 1 => Ok(false),
            2 => Ok(true),
            value => Err(LegacySaveError::StateProjection(format!(
                "major nation {nation} technology {technology} status {value} is invalid"
            ))),
        }
    };
    let mut city_capabilities_by_nation =
        std::array::from_fn(|_| CityTechnologyCapabilities::default());
    for (nation, capabilities) in city_capabilities_by_nation.iter_mut().enumerate() {
        capabilities.advanced_iron_working = researched(nation, TECH_ADVANCED_IRON_WORKING_ID)?;
        capabilities.oil_drilling = researched(nation, TECH_OIL_DRILLING_ID)?;

        let mut available = [false; TECH_UNIVERSITY_AVAILABILITY_ROW_SIZE];
        for (category, value) in available.iter_mut().enumerate() {
            let offset = TECH_UNIVERSITY_AVAILABILITY_OFFSET_V62
                + nation * TECH_UNIVERSITY_AVAILABILITY_ROW_SIZE
                + category;
            *value = retail_boolean(bytes[offset], "university recruitment availability")?;
        }

        let mut requirement_levels = [0; RESOURCE_KIND_COUNT];
        for (resource, value) in requirement_levels.iter_mut().enumerate() {
            let offset = TECH_FINAL_REQUIREMENT_LEVELS_OFFSET_V62
                + nation * TECH_REQUIREMENT_LEVELS_ROW_SIZE
                + resource * std::mem::size_of::<i16>();
            let raw = i16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
            *value = u8::try_from(raw).map_err(|_| {
                LegacySaveError::StateProjection(format!(
                    "major nation {nation} university requirement level {raw} for resource {resource} is invalid"
                ))
            })?;
            if *value > 3 {
                return Err(LegacySaveError::StateProjection(format!(
                    "major nation {nation} university requirement level {raw} for resource {resource} is invalid"
                )));
            }
        }
        capabilities.university = UniversityTechnologyState {
            available: CivilianUnitTable::from_array(available),
            requirement_levels: ResourceTable::from_array(requirement_levels),
        };
    }
    Ok(TechnologyState {
        advanced_iron_working: retail_boolean(
            bytes[TECH_ADVANCED_IRON_WORKING_OFFSET_V62],
            "technology advanced iron working",
        )?,
        marine_engineering: retail_boolean(
            bytes[TECH_MARINE_ENGINEERING_OFFSET_V62],
            "technology marine engineering",
        )?,
        oil_drilling_available: retail_boolean(
            bytes[TECH_GLOBAL_UNLOCK_FLAGS_OFFSET_V62 + TECH_OIL_DRILLING_ID],
            "technology oil drilling availability",
        )?,
        city_capabilities_by_nation: MajorNationTable::from_array(city_capabilities_by_nation),
    })
}

fn retail_boolean(value: u8, context: &'static str) -> Result<bool, LegacySaveError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        value => Err(LegacySaveError::InvalidBoolean { context, value }),
    }
}

fn read_map(stream: &mut LegacyStream<'_>) -> Result<LegacyMapState, StreamError> {
    let initialized_flag = stream.read_le_i16()?;
    let search_state_active = stream.read_u8()?;
    let secondary_state = stream.read_u8()?;
    let city_score_total = stream.read_le_i32()?;
    let scenario_tag = lossy_text(&stream.read_mfc_string()?);
    let no_horizontal_wrap = stream.read_u8()?;
    let tiles = (0..STRATEGIC_TILE_COUNT)
        .map(|_| read_terrain_tile(stream))
        .collect::<Result<Vec<_>, _>>()?;
    let provinces = (0..PROVINCE_COUNT)
        .map(|_| read_province(stream))
        .collect::<Result<Vec<_>, _>>()?;
    let pending_river_mouth_tile = stream.read_le_i16()?;
    Ok(LegacyMapState {
        initialized_flag,
        search_state_active,
        secondary_state,
        city_score_total,
        scenario_tag,
        no_horizontal_wrap,
        tiles,
        provinces,
        pending_river_mouth_tile,
    })
}

fn read_ocean(stream: &mut LegacyStream<'_>) -> Result<LegacyOceanState, LegacySaveError> {
    let zone_count = bounded_u32(
        u32::from(stream.read_le_u16()?),
        MAX_OCEAN_ZONES,
        "ocean zones",
    )?;
    let zones = (0..zone_count)
        .map(|_| read_zone(stream, false))
        .collect::<Result<Vec<_>, _>>()?;
    let port_zone_count = bounded_u32(
        u32::from(stream.read_le_u16()?),
        MAX_OCEAN_ZONES,
        "ocean port zones",
    )?;
    let port_zones = (0..port_zone_count)
        .map(|_| read_zone(stream, true))
        .collect::<Result<Vec<_>, _>>()?;
    let route_count = bounded_u32(
        u32::from(stream.read_le_u16()?),
        MAX_OCEAN_ROUTES,
        "ocean routes",
    )?;
    let route_segments = (0..route_count)
        .map(|_| {
            Ok([
                stream.read_le_i32()?,
                stream.read_le_i32()?,
                stream.read_le_i32()?,
                stream.read_le_i32()?,
            ])
        })
        .collect::<Result<Vec<_>, StreamError>>()?;
    Ok(LegacyOceanState {
        zones,
        port_zones,
        route_segments,
    })
}

fn read_zone(stream: &mut LegacyStream<'_>, port: bool) -> Result<LegacyZone, StreamError> {
    let display_name = lossy_text(&stream.read_mfc_string()?);
    let status_code = stream.read_le_i16()?;
    let tile_or_terrain_id = stream.read_le_i32()?;
    let seed_nation_id = stream.read_le_i16()?;
    let active_tile_index = stream.read_le_i16()?;
    let context_ordinal = stream.read_le_i16()?;
    let port_tile_index = port.then(|| stream.read_le_i16()).transpose()?;
    Ok(LegacyZone {
        display_name,
        status_code,
        tile_or_terrain_id,
        seed_nation_id,
        active_tile_index,
        context_ordinal,
        port_tile_index,
    })
}

fn read_navy(stream: &mut LegacyStream<'_>) -> Result<LegacyNavyState, LegacySaveError> {
    let ship_count = bounded_u32(u32::from(stream.read_le_u16()?), MAX_SHIPS, "navy ships")?;
    let mut ships = (0..ship_count)
        .map(|_| read_ship(stream))
        .collect::<Result<Vec<_>, _>>()?;
    ships.reverse();
    let admiral_count = bounded_u32(
        u32::from(stream.read_le_u16()?),
        MAX_ADMIRALS,
        "navy admirals",
    )?;
    let admirals = (0..admiral_count)
        .map(|_| read_admiral(stream))
        .collect::<Result<Vec<_>, _>>()?;
    let task_force_count = bounded_u32(
        u32::from(stream.read_le_u16()?),
        MAX_TASK_FORCES,
        "navy task forces",
    )?;
    let task_forces = (0..task_force_count)
        .map(|_| read_task_force(stream))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(LegacyNavyState {
        ships,
        admirals,
        task_forces,
    })
}

fn read_ship(stream: &mut LegacyStream<'_>) -> Result<LegacyShip, StreamError> {
    Ok(LegacyShip {
        ship_type: stream.read_le_i16()?,
        aggression: stream.read_le_i32()?,
        nation: stream.read_le_i16()?,
        name: lossy_text(&stream.read_mfc_string()?),
        strength: stream.read_le_i16()?,
        selection: stream.read_le_i32()?,
        experience: stream.read_le_i16()?,
        zone_ordinal: stream.read_le_i16()?,
    })
}

fn read_admiral(stream: &mut LegacyStream<'_>) -> Result<LegacyAdmiral, StreamError> {
    Ok(LegacyAdmiral {
        nation: stream.read_le_i16()?,
        name: lossy_text(&stream.read_mfc_string()?),
        experience: stream.read_le_i16()?,
        ship_index: stream.read_le_i16()?,
    })
}

fn read_task_force(stream: &mut LegacyStream<'_>) -> Result<LegacyTaskForce, LegacySaveError> {
    let aggression = stream.read_le_i32()?;
    let order = stream.read_le_i32()?;
    let target_ordinal = stream.read_le_i16()?;
    let location_ordinal = stream.read_le_i16()?;
    let nation = stream.read_le_i16()?;
    stream.skip(1)?;
    let ingot_tile = stream.read_le_i16()?;
    let child_count = bounded_u32(
        u32::from(stream.read_le_u16()?),
        MAX_TASK_FORCE_CHILDREN,
        "task force ships",
    )?;
    let ships = (0..child_count)
        .map(|_| Ok([stream.read_le_i16()?, stream.read_le_i16()?]))
        .collect::<Result<Vec<_>, StreamError>>()?;
    Ok(LegacyTaskForce {
        aggression,
        order,
        target_ordinal,
        location_ordinal,
        nation,
        ingot_tile,
        ships,
    })
}

fn skip_army_reports(stream: &mut LegacyStream<'_>) -> Result<u16, LegacySaveError> {
    let report_count = stream.read_le_u16()?;
    bounded_u32(u32::from(report_count), MAX_ARMY_REPORTS, "army reports")?;
    for _ in 0..report_count {
        stream.skip(8)?;
        for _ in 0..2 {
            stream.skip(1 + 0x20 + 0xff)?;
            let child_count = bounded_u32(
                u32::from(stream.read_le_u16()?),
                MAX_MILITARY_UNITS,
                "army report children",
            )?;
            let byte_len = child_count * 42;
            stream.skip(byte_len)?;
        }
    }
    Ok(report_count)
}

fn read_country_base(stream: &mut LegacyStream<'_>) -> Result<LegacyCountryBase, LegacySaveError> {
    let identity = lossy_text(&stream.read_mfc_string()?);
    let alternate_identity = lossy_text(&stream.read_mfc_string()?);
    let nation_slot = stream.read_le_i16()?;
    let encoded_nation_slot = stream.read_le_i16()?;
    let unit_name_ordinal_by_type = read_be_short_array(stream)?;
    let unit_name_counter = stream.read_le_i16()?;
    let treasury = stream.read_le_i32()?;
    let home_tile = stream.read_le_i32()?;
    let overlay_anchor_tile = stream.read_le_i32()?;
    let need_level_by_nation = read_be_short_array(stream)?;

    // TSortedList::ReadFrom is a retail no-op; the count follows immediately.
    let military_unit_count = bounded_u32(
        stream.read_le_u32()?,
        MAX_MILITARY_UNITS,
        "country military units",
    )?;
    let military_units = (0..military_unit_count)
        .map(|_| read_military_unit(stream))
        .collect::<Result<Vec<_>, _>>()?;

    // TLongintList::NoOpReadFrom is likewise a no-op.
    let owned_region_count = bounded_u32(
        stream.read_le_u32()?,
        MAX_OWNED_REGIONS,
        "country owned regions",
    )?;
    let owned_regions = (0..owned_region_count)
        .map(|_| stream.read_le_i32())
        .collect::<Result<Vec<_>, _>>()?;

    Ok(LegacyCountryBase {
        identity,
        alternate_identity,
        nation_slot,
        encoded_nation_slot,
        unit_name_ordinal_by_type,
        unit_name_counter,
        treasury,
        home_tile,
        overlay_anchor_tile,
        need_level_by_nation,
        military_units,
        owned_regions,
    })
}

fn read_military_unit(stream: &mut LegacyStream<'_>) -> Result<LegacyMilitaryUnit, StreamError> {
    Ok(LegacyMilitaryUnit {
        unit_type: stream.read_le_i16()?,
        stationed_province: stream.read_le_i16()?,
        order_target: stream.read_le_i16()?,
        owner_nation: stream.read_le_i16()?,
        roster_id: stream.read_le_i16()?,
        registered: stream.read_u8()?,
        order: stream.read_le_i32()?,
        persistent_id: stream.read_le_i32()?,
        name: lossy_text(&stream.read_mfc_string()?),
        order_target_tiles: read_be_short_array(stream)?,
        order_target_mirrors: read_be_short_array(stream)?,
        strength: stream.read_le_i16()?,
        era: stream.read_le_i16()?,
        experience: stream.read_le_i16()?,
        battle_flags: stream.read_le_i16()?,
    })
}

fn read_great_power_prefix(
    stream: &mut LegacyStream<'_>,
) -> Result<LegacyGreatPowerPrefix, StreamError> {
    let diplomacy_eligible = stream.read_u8()?;
    let capacities = read_short_array(stream)?;
    let grant_total_cost = stream.read_le_i32()?;
    let unfilled_trade_offer_count = stream.read_le_i16()?;
    let diplomacy_policy_by_nation = read_be_short_array(stream)?;
    let diplomacy_grant_by_nation = read_be_short_array(stream)?;
    let need_current_by_type = read_be_short_array(stream)?;
    let need_target_by_type = read_be_short_array(stream)?;
    let relation_delta_current = read_be_short_array(stream)?;
    let purchased_items_by_resource = read_be_short_array(stream)?;
    let item_potentials = read_be_short_array(stream)?;
    let unfilled_trade_turns_by_resource = read_be_short_array(stream)?;
    let transported_items_by_resource = read_be_short_array(stream)?;
    let remembered_trade_offers_by_resource = read_be_short_array(stream)?;
    let budget_pool_base = stream.read_le_i32()?;
    let budget_pool_delta = stream.read_le_i32()?;
    let mut aid_allocation_by_minor_nation = [[0; RESOURCE_KIND_COUNT]; MINOR_NATION_COUNT];
    for resource_values in &mut aid_allocation_by_minor_nation {
        for value in resource_values {
            *value = stream.read_be_i32()?;
        }
    }
    let mut pending_action_status = [0; PENDING_ACTION_COUNT];
    for value in &mut pending_action_status {
        *value = stream.read_i8()?;
    }
    let pending_action_payload_by_action = read_be_short_array(stream)?;

    // These are TSortedByRelationshipList/TSortedPtrList instances, unlike the
    // no-op TSortedList hooks used by object-owning lists elsewhere.
    let relationship_lists = (0..19)
        .map(|_| read_fixed_record_list(stream))
        .collect::<Result<Vec<_>, _>>()?;
    let minister_presence_mask = stream.read_u8()?;

    Ok(LegacyGreatPowerPrefix {
        diplomacy_eligible,
        capacities,
        grant_total_cost,
        unfilled_trade_offer_count,
        diplomacy_policy_by_nation,
        diplomacy_grant_by_nation,
        need_current_by_type,
        need_target_by_type,
        relation_delta_current,
        purchased_items_by_resource,
        item_potentials,
        unfilled_trade_turns_by_resource,
        transported_items_by_resource,
        remembered_trade_offers_by_resource,
        budget_pool_base,
        budget_pool_delta,
        aid_allocation_by_minor_nation,
        pending_action_status,
        pending_action_payload_by_action,
        relationship_lists,
        minister_presence_mask,
    })
}

fn read_fixed_record_list(
    stream: &mut LegacyStream<'_>,
) -> Result<LegacyFixedRecordList, StreamError> {
    let record_size = stream.read_le_u16()?;
    let record_count = stream.read_le_u32()? as usize;
    let records = (0..record_count)
        .map(|_| Ok(stream.read_bytes(usize::from(record_size))?.to_vec()))
        .collect::<Result<Vec<_>, StreamError>>()?;
    Ok(LegacyFixedRecordList {
        record_size,
        records,
    })
}

fn read_great_power_ministers(
    stream: &mut LegacyStream<'_>,
    presence_mask: u8,
    foreign_policy_id: i16,
) -> Result<LegacyGreatPowerMinisters, StreamError> {
    let foreign = (presence_mask & 1 != 0)
        .then(|| read_foreign_minister(stream, foreign_policy_id))
        .transpose()?;
    let interior = (presence_mask & 2 != 0)
        .then(|| read_interior_minister(stream))
        .transpose()?;
    let defense = (presence_mask & 4 != 0)
        .then(|| read_defense_minister(stream))
        .transpose()?;
    Ok(LegacyGreatPowerMinisters {
        foreign,
        interior,
        defense,
    })
}

fn read_foreign_minister(
    stream: &mut LegacyStream<'_>,
    foreign_policy_id: i16,
) -> Result<LegacyForeignMinisterState, StreamError> {
    let skill_index = stream.read_le_i16()?;
    let scalar_fields = read_short_array(stream)?;
    let purchase_priority_by_resource = read_be_short_array(stream)?;
    let preferred_resource_slots = read_be_short_array(stream)?;
    let status_flag = stream.read_u8()?;
    let trade_partner_enabled = stream.read_bytes(7)?.try_into().unwrap();
    let development_grant_by_nation = read_be_short_array(stream)?;
    let bill_order_flag = (foreign_policy_id == 4)
        .then(|| stream.read_u8())
        .transpose()?;
    Ok(LegacyForeignMinisterState {
        skill_index,
        scalar_fields,
        purchase_priority_by_resource,
        preferred_resource_slots,
        status_flag,
        trade_partner_enabled,
        development_grant_by_nation,
        bill_order_flag,
    })
}

fn read_interior_minister(
    stream: &mut LegacyStream<'_>,
) -> Result<LegacyInteriorMinisterState, StreamError> {
    let skill_index = stream.read_le_i16()?;
    let scalar_prefix = read_short_array(stream)?;
    let trailing_table = read_be_short_array(stream)?;
    let order_scalars = read_short_array(stream)?;
    let order_metrics = read_be_short_array(stream)?;
    let deferred_labor_shortfall = stream.read_le_i16()?;
    let order_short_table = read_be_short_array(stream)?;
    let order_type_tables = [
        read_be_short_array(stream)?,
        read_be_short_array(stream)?,
        read_be_short_array(stream)?,
    ];
    let temporarily_reserved_ship_arms = stream.read_le_i16()?;
    let integer_lists = [
        read_longint_list(stream)?,
        read_longint_list(stream)?,
        read_longint_list(stream)?,
    ];
    let civilian_order_demand_by_resource = read_be_short_array(stream)?;
    Ok(LegacyInteriorMinisterState {
        skill_index,
        scalar_prefix,
        trailing_table,
        order_scalars,
        order_metrics,
        deferred_labor_shortfall,
        order_short_table,
        order_type_tables,
        temporarily_reserved_ship_arms,
        integer_lists,
        civilian_order_demand_by_resource,
    })
}

fn read_defense_minister(
    stream: &mut LegacyStream<'_>,
) -> Result<LegacyDefenseMinisterState, StreamError> {
    Ok(LegacyDefenseMinisterState {
        skill_index: stream.read_le_i16()?,
        scalar_fields: read_short_array(stream)?,
        recruit_order_count_by_type: read_be_short_array(stream)?,
        order_weight_by_type: read_be_short_array(stream)?,
        thresholds: read_short_array(stream)?,
    })
}

fn read_longint_list(stream: &mut LegacyStream<'_>) -> Result<Vec<i32>, StreamError> {
    let count = stream.read_le_u32()? as usize;
    if count > MAX_LONGINT_LIST {
        return Err(StreamError::InvalidCount {
            context: "longint list",
            value: count as i64,
            maximum: MAX_LONGINT_LIST,
        });
    }
    (0..count)
        .map(|_| stream.read_le_i32())
        .collect::<Result<Vec<_>, _>>()
}

fn read_city(stream: &mut LegacyStream<'_>) -> Result<LegacyCityState, LegacySaveError> {
    let power_plant_upgrade_queued = stream.read_u8()?;
    let low_production = stream.read_u8()?;
    let low_stock = stream.read_u8()?;
    let production_flags = stream
        .read_bytes(CITY_PRODUCTION_SLOT_COUNT)?
        .try_into()
        .unwrap();
    let food_substitution_count = stream.read_le_i16()?;
    let starvation_population_loss = stream.read_le_i16()?;
    let serialized_state = stream.read_le_i16()?;
    let phase_counter = stream.read_le_i16()?;
    let power_available = stream.read_le_i16()?;
    let military_recruit_count_by_kind = read_be_short_array(stream)?;
    let civilian_recruit_count_by_kind = read_be_short_array(stream)?;
    let order_count_by_type = read_be_short_array(stream)?;
    let stockpile = read_be_short_array(stream)?;
    let production_orders = read_be_short_array(stream)?;
    let production_accum = read_be_short_array(stream)?;
    let unmet_resource_retries = read_be_short_array(stream)?;
    let reserved_by_type = read_be_short_array(stream)?;
    let production_current = read_be_short_array(stream)?;
    let production_progress = read_be_short_array(stream)?;
    let consumed_production_input_by_type = read_be_short_array(stream)?;
    let rolling_item_production_score = stream.read_le_i32()?;
    let population = read_population(stream)?;
    let orders = read_city_orders(stream)?;

    // TTaskList's inherited TSortedList stream hook is a no-op.
    let task_count = stream.read_le_u32()? as usize;
    if task_count > MAX_CITY_TASKS {
        return Err(LegacySaveError::InvalidCount {
            context: "city tasks",
            value: task_count as i64,
            maximum: MAX_CITY_TASKS,
        });
    }
    let tasks = (0..task_count)
        .map(|_| {
            let kind = stream.read_u8()?;
            let payload_size = if kind == 1 { 8 } else { 12 };
            Ok(LegacyCityTask {
                kind,
                payload: stream.read_bytes(payload_size)?.to_vec(),
            })
        })
        .collect::<Result<Vec<_>, StreamError>>()?;
    let transport_requests = read_fixed_record_list(stream)?;

    Ok(LegacyCityState {
        power_plant_upgrade_queued,
        low_production,
        low_stock,
        production_flags,
        food_substitution_count,
        starvation_population_loss,
        serialized_state,
        phase_counter,
        power_available,
        military_recruit_count_by_kind,
        civilian_recruit_count_by_kind,
        order_count_by_type,
        stockpile,
        production_orders,
        production_accum,
        unmet_resource_retries,
        reserved_by_type,
        production_current,
        production_progress,
        consumed_production_input_by_type,
        rolling_item_production_score,
        population,
        orders,
        tasks,
        transport_requests,
    })
}

struct LegacyRequestedCityOrder {
    product: i16,
    state: RequestedCityOrderState,
    primary_input: i16,
    secondary_input: i16,
    production_slot: i16,
}

struct LegacyRecruitOrder {
    product: i16,
    progress: ProductionProgress,
    primary_input: i16,
    secondary_input: i16,
    primary_per_unit: i16,
    secondary_per_unit: i16,
    cash_per_unit: i16,
    workforce: i16,
    specialist: u8,
}

fn read_city_orders(stream: &mut LegacyStream<'_>) -> Result<CityOrders, LegacySaveError> {
    // TCity owns a fixed but untagged 61-pointer registry. Only these 47 entries
    // are constructed, so their concrete type is established by ICity's slot map.
    let food_processing = read_plain_city_order(stream, "slot 7 food processing", 7)?;

    let mut items = ResourceTable::default();
    for output in [
        ResourceKind::Fabric,
        ResourceKind::Lumber,
        ResourceKind::Paper,
        ResourceKind::Steel,
        ResourceKind::Fuel,
        ResourceKind::Clothing,
        ResourceKind::Furniture,
        ResourceKind::Hardware,
        ResourceKind::Arms,
    ] {
        items[output] = Some(read_item_order(stream, output)?);
    }

    let training = TrainingOrderTable::from_array([
        read_plain_city_order(stream, "slot 23 medium training", 1)?,
        read_plain_city_order(stream, "slot 24 high training", 2)?,
    ]);

    let military_recruitment = MilitaryRecruitOrderTable::from_array([
        read_military_recruit_order(
            stream,
            "slot 25 light infantry",
            MilitaryRecruitmentCategory::LightInfantry,
        )?,
        read_military_recruit_order(
            stream,
            "slot 26 regular infantry",
            MilitaryRecruitmentCategory::RegularInfantry,
        )?,
        read_military_recruit_order(
            stream,
            "slot 27 heavy infantry",
            MilitaryRecruitmentCategory::HeavyInfantry,
        )?,
        read_military_recruit_order(
            stream,
            "slot 28 light cavalry",
            MilitaryRecruitmentCategory::LightCavalry,
        )?,
        read_military_recruit_order(
            stream,
            "slot 29 heavy cavalry",
            MilitaryRecruitmentCategory::HeavyCavalry,
        )?,
        read_military_recruit_order(
            stream,
            "slot 30 light artillery",
            MilitaryRecruitmentCategory::LightArtillery,
        )?,
        read_military_recruit_order(
            stream,
            "slot 31 heavy artillery",
            MilitaryRecruitmentCategory::HeavyArtillery,
        )?,
        read_military_recruit_order(
            stream,
            "slot 32 combat engineers",
            MilitaryRecruitmentCategory::Demolitionist,
        )?,
    ]);

    let civilian_recruitment = CivilianUnitTable::from_array([
        read_civilian_recruit_order(stream, CivilianUnitKind::Miner)?,
        read_civilian_recruit_order(stream, CivilianUnitKind::Prospector)?,
        read_civilian_recruit_order(stream, CivilianUnitKind::Farmer)?,
        read_civilian_recruit_order(stream, CivilianUnitKind::Forester)?,
        read_civilian_recruit_order(stream, CivilianUnitKind::Engineer)?,
        read_civilian_recruit_order(stream, CivilianUnitKind::Rancher)?,
        read_civilian_recruit_order(stream, CivilianUnitKind::Fisherman)?,
        read_civilian_recruit_order(stream, CivilianUnitKind::Developer)?,
        read_civilian_recruit_order(stream, CivilianUnitKind::Driller)?,
    ]);

    let ships = ShipOrderTable::from_array([
        read_ship_order(
            stream,
            "slot 43 early merchant primary",
            ShipOrderSlot::MerchantEarlyPrimary,
        )?,
        read_ship_order(
            stream,
            "slot 44 early merchant secondary",
            ShipOrderSlot::MerchantEarlySecondary,
        )?,
        read_ship_order(
            stream,
            "slot 45 advanced merchant primary",
            ShipOrderSlot::MerchantAdvancedPrimary,
        )?,
        read_ship_order(
            stream,
            "slot 46 advanced merchant secondary",
            ShipOrderSlot::MerchantAdvancedSecondary,
        )?,
        read_ship_order(
            stream,
            "slot 47 early warship primary",
            ShipOrderSlot::WarshipEarlyPrimary,
        )?,
        read_ship_order(
            stream,
            "slot 48 early warship secondary",
            ShipOrderSlot::WarshipEarlySecondary,
        )?,
        read_ship_order(
            stream,
            "slot 49 advanced warship primary",
            ShipOrderSlot::WarshipAdvancedPrimary,
        )?,
        read_ship_order(
            stream,
            "slot 50 advanced warship secondary",
            ShipOrderSlot::WarshipAdvancedSecondary,
        )?,
    ]);

    let transport_capacity = read_transport_capacity_order(stream)?;
    let power_plant = read_power_plant_order(stream)?;

    let mut expansions = ProductionTable::default();
    for target in [
        ProductionSlot::TextileMill,
        ProductionSlot::ClothingFactory,
        ProductionSlot::SteelMill,
        ProductionSlot::Metalworks,
        ProductionSlot::LumberMill,
        ProductionSlot::FurnitureFactory,
        ProductionSlot::OilRefinery,
    ] {
        expansions[target] = Some(read_expansion_order(stream, target)?);
    }

    let population_growth = read_plain_city_order(stream, "slot 60 population growth", 1)?;

    Ok(CityOrders {
        items,
        civilian_recruitment,
        military_recruitment,
        ships,
        training,
        expansions,
        food_processing,
        power_plant,
        transport_capacity,
        population_growth,
    })
}

fn read_order_progress(
    stream: &mut LegacyStream<'_>,
    order: &'static str,
) -> Result<(i16, ProductionProgress), LegacySaveError> {
    let _constructor_product = stream.read_le_i16()?;
    let quantity = stream.read_le_i16()?;
    let limiting_constraint = match stream.read_le_i16()? {
        0 => ProductionConstraint::Resources,
        1 => ProductionConstraint::Workforce,
        2 => ProductionConstraint::Capacity,
        3 => ProductionConstraint::Treasury,
        value => {
            return Err(invalid_city_order(
                order,
                format!("limiting constraint {value} is outside 0..=3"),
            ));
        }
    };
    // TProductionOrder::ReadFrom overwrites the constructor product with this
    // second serialized word. The first word is not authoritative live state.
    let product = stream.read_le_i16()?;
    let tracking_by_resource = ResourceTable::from_array(read_short_array(stream)?);
    let accumulated_value = stream.read_le_i32()?;
    Ok((
        product,
        ProductionProgress {
            quantity,
            tracking_by_resource,
            // TProductionOrder::ReadFrom does not persist or reconstruct this field.
            reserved_workforce: 0,
            limiting_constraint,
            accumulated_value,
        },
    ))
}

fn read_plain_city_order(
    stream: &mut LegacyStream<'_>,
    order: &'static str,
    expected_product: i16,
) -> Result<ProductionProgress, LegacySaveError> {
    let (product, progress) = read_order_progress(stream, order)?;
    require_city_order_value(order, "product", product, expected_product)?;
    Ok(progress)
}

fn read_requested_city_order(
    stream: &mut LegacyStream<'_>,
    order: &'static str,
) -> Result<LegacyRequestedCityOrder, LegacySaveError> {
    let (product, progress) = read_order_progress(stream, order)?;
    let requested_quantity = stream.read_le_i16()?;
    Ok(LegacyRequestedCityOrder {
        product,
        state: RequestedCityOrderState {
            progress,
            requested_quantity,
        },
        primary_input: stream.read_le_i16()?,
        secondary_input: stream.read_le_i16()?,
        production_slot: stream.read_le_i16()?,
    })
}

fn read_item_order(
    stream: &mut LegacyStream<'_>,
    output: ResourceKind,
) -> Result<RequestedCityOrderState, LegacySaveError> {
    let order = "slots 8..=16 item production";
    let raw = read_requested_city_order(stream, order)?;
    let spec = item_order_spec(output).expect("the fixed item-order list contains only products");
    let (primary_input, secondary_input) = match spec.inputs {
        ItemInputs::Double(primary) => (primary as i16, -1),
        ItemInputs::Both(primary, secondary) | ItemInputs::Either(primary, secondary) => {
            (primary as i16, secondary as i16)
        }
    };
    require_city_order_value(order, "product", raw.product, output as i16)?;
    require_city_order_value(order, "primary input", raw.primary_input, primary_input)?;
    require_city_order_value(
        order,
        "secondary input",
        raw.secondary_input,
        secondary_input,
    )?;
    require_city_order_value(
        order,
        "production slot",
        raw.production_slot,
        spec.production_slot as i16,
    )?;
    Ok(raw.state)
}

fn read_transport_capacity_order(
    stream: &mut LegacyStream<'_>,
) -> Result<RequestedCityOrderState, LegacySaveError> {
    let order = "slot 51 transport capacity";
    let raw = read_requested_city_order(stream, order)?;
    let spec = transport_capacity_order_spec();
    require_city_order_value(
        order,
        "product",
        raw.product,
        ProductionSlot::Transport as i16,
    )?;
    require_city_order_value(
        order,
        "primary input",
        raw.primary_input,
        spec.primary as i16,
    )?;
    require_city_order_value(
        order,
        "secondary input",
        raw.secondary_input,
        spec.secondary as i16,
    )?;
    require_city_order_value(
        order,
        "production slot",
        raw.production_slot,
        spec.production_slot as i16,
    )?;
    Ok(raw.state)
}

fn read_expansion_order(
    stream: &mut LegacyStream<'_>,
    target: ProductionSlot,
) -> Result<RequestedCityOrderState, LegacySaveError> {
    let order = "slots 53..=59 industry expansion";
    let raw = read_requested_city_order(stream, order)?;
    let spec =
        expansion_order_spec(target).expect("the fixed expansion list contains only targets");
    require_city_order_value(order, "product", raw.product, target as i16)?;
    require_city_order_value(
        order,
        "primary input",
        raw.primary_input,
        spec.primary as i16,
    )?;
    require_city_order_value(
        order,
        "secondary input",
        raw.secondary_input,
        spec.secondary as i16,
    )?;
    require_city_order_value(
        order,
        "production slot",
        raw.production_slot,
        spec.production_slot as i16,
    )?;
    Ok(raw.state)
}

fn read_recruit_order(
    stream: &mut LegacyStream<'_>,
    order: &'static str,
) -> Result<LegacyRecruitOrder, LegacySaveError> {
    let (product, progress) = read_order_progress(stream, order)?;
    let raw = LegacyRecruitOrder {
        product,
        progress,
        primary_input: stream.read_le_i16()?,
        secondary_input: stream.read_le_i16()?,
        primary_per_unit: stream.read_le_i16()?,
        secondary_per_unit: stream.read_le_i16()?,
        cash_per_unit: stream.read_le_i16()?,
        workforce: stream.read_le_i16()?,
        specialist: stream.read_u8()?,
    };
    Ok(raw)
}

fn read_military_recruit_order(
    stream: &mut LegacyStream<'_>,
    order: &'static str,
    category: MilitaryRecruitmentCategory,
) -> Result<MilitaryRecruitOrderState, LegacySaveError> {
    let raw = read_recruit_order(stream, order)?;
    require_city_order_value(order, "specialist flag", i16::from(raw.specialist), 1)?;
    let unit_kind = u8::try_from(raw.product)
        .ok()
        .and_then(MilitaryUnitKind::from_index)
        .ok_or_else(|| {
            invalid_city_order(order, format!("invalid military unit type {}", raw.product))
        })?;
    if military_recruitment_category(unit_kind) != Some(category) {
        return Err(invalid_city_order(
            order,
            format!("{unit_kind:?} does not belong to the {category:?} armory category"),
        ));
    }
    let spec = military_recruitment_spec(unit_kind).ok_or_else(|| {
        invalid_city_order(
            order,
            format!("{unit_kind:?} has no retail recruitment recipe"),
        )
    })?;
    validate_recruit_order_spec(order, &raw, spec)?;
    Ok(MilitaryRecruitOrderState {
        unit_kind,
        progress: raw.progress,
    })
}

fn read_civilian_recruit_order(
    stream: &mut LegacyStream<'_>,
    kind: CivilianUnitKind,
) -> Result<ProductionProgress, LegacySaveError> {
    let order = "slots 34..=42 civilian recruitment";
    let raw = read_recruit_order(stream, order)?;
    require_city_order_value(order, "product", raw.product, kind as i16)?;
    require_city_order_value(order, "specialist flag", i16::from(raw.specialist), 0)?;
    let spec = civilian_recruitment_spec(kind);
    validate_recruit_order_spec(order, &raw, spec)?;
    Ok(raw.progress)
}

fn read_ship_order(
    stream: &mut LegacyStream<'_>,
    order: &'static str,
    slot: ShipOrderSlot,
) -> Result<ShipOrderState, LegacySaveError> {
    let (product, progress) = read_order_progress(stream, order)?;
    let ship_type = ship_type_from_retail(order, product)?;
    if !ship_type_is_valid_for_order_slot(slot, ship_type) {
        return Err(invalid_city_order(
            order,
            format!("{ship_type:?} is not valid for {slot:?}"),
        ));
    }
    Ok(ShipOrderState {
        ship_type,
        progress,
    })
}

fn read_power_plant_order(
    stream: &mut LegacyStream<'_>,
) -> Result<PowerPlantOrderState, LegacySaveError> {
    let order = "slot 52 power plant";
    let (product, progress) = read_order_progress(stream, order)?;
    require_city_order_value(order, "product", product, 0)?;
    let desired_quantity = stream.read_le_i16()?;
    Ok(PowerPlantOrderState {
        progress,
        desired_quantity,
    })
}

fn validate_recruit_order_spec(
    order: &'static str,
    raw: &LegacyRecruitOrder,
    spec: RecruitmentOrderSpec,
) -> Result<(), LegacySaveError> {
    let (secondary_input, secondary_per_unit) = match spec.secondary {
        Some(cost) => (cost.resource as i16, cost.per_unit()),
        None => (-1, 0),
    };
    require_city_order_value(
        order,
        "primary input",
        raw.primary_input,
        spec.primary.resource as i16,
    )?;
    require_city_order_value(
        order,
        "primary per-unit cost",
        raw.primary_per_unit,
        spec.primary.per_unit(),
    )?;
    require_city_order_value(
        order,
        "secondary input",
        raw.secondary_input,
        secondary_input,
    )?;
    require_city_order_value(
        order,
        "secondary per-unit cost",
        raw.secondary_per_unit,
        secondary_per_unit,
    )?;
    require_city_order_value(order, "cash cost", raw.cash_per_unit, spec.cash_per_unit)?;
    require_city_order_value(
        order,
        "workforce mode",
        raw.workforce,
        spec.workforce as i16,
    )
}

fn ship_type_from_retail(order: &'static str, value: i16) -> Result<ShipType, LegacySaveError> {
    let ship_type = match value {
        0 => ShipType::NoShip,
        1 => ShipType::Trader,
        2 => ShipType::Indiaman,
        3 => ShipType::Frigate,
        4 => ShipType::ShipOfTheLine,
        5 => ShipType::Paddlewheeler,
        6 => ShipType::Clipper,
        7 => ShipType::Raider,
        8 => ShipType::Ironclad,
        9 => ShipType::AdvancedIronclad,
        10 => ShipType::Freighter,
        11 => ShipType::ArmoredCruiser,
        12 => ShipType::Dreadnought,
        13 => ShipType::Battlecruiser,
        _ => {
            return Err(invalid_city_order(
                order,
                format!("ship type {value} is outside 0..=13"),
            ));
        }
    };
    Ok(ship_type)
}

fn require_city_order_value(
    order: &'static str,
    field: &'static str,
    actual: i16,
    expected: i16,
) -> Result<(), LegacySaveError> {
    if actual != expected {
        return Err(invalid_city_order(
            order,
            format!("{field} is {actual}; expected {expected}"),
        ));
    }
    Ok(())
}

fn invalid_city_order(order: &'static str, detail: String) -> LegacySaveError {
    LegacySaveError::InvalidCityOrder { order, detail }
}

fn read_population(stream: &mut LegacyStream<'_>) -> Result<LegacyPopulationState, StreamError> {
    Ok(LegacyPopulationState {
        count: stream.read_le_i16()?,
        strength: stream.read_le_i16()?,
        extra: stream.read_le_i16()?,
        phase_value: stream.read_le_i16()?,
        // TPopulationMgr persists this block raw, unlike TCity's swapped arrays.
        predicted_need_by_resource: read_short_array(stream)?,
        count_float_bits: stream.read_le_u32()?,
        baseline_labor: read_short_array(stream)?,
        production_labor: read_short_array(stream)?,
        pending_labor_delta: read_short_array(stream)?,
    })
}

fn read_great_power_post_city(
    stream: &mut LegacyStream<'_>,
    absolute_offset: usize,
) -> Result<LegacyGreatPowerPostCity, LegacySaveError> {
    let town_count = stream.read_le_u32()? as usize;
    let towns = (0..town_count)
        .map(|_| read_town(stream))
        .collect::<Result<Vec<_>, _>>()?;
    let civilian_count = stream.read_le_u32()? as usize;
    let civilian_units = (0..civilian_count)
        .map(|_| read_civilian_unit(stream))
        .collect::<Result<Vec<_>, _>>()?;
    let candidate_nation_flags = stream.read_bytes(NATION_COUNT)?.try_into().unwrap();
    let diplomacy_budget_base = stream.read_le_i32()?;
    let escalation_counter = stream.read_i8()?;
    let pending_commitment_cost = stream.read_le_i32()?;
    let pressure_counter = stream.read_i8()?;
    let opaque_counter = stream.read_le_i32()?;
    let turn_finished_flag = stream.read_u8()?;

    let object_count_offset = absolute_offset + stream.position();
    let mission_node_count = stream.read_le_u32()?;
    if mission_node_count != 0 {
        return Err(LegacySaveError::UnsupportedPolymorphicObjects {
            context: "great-power turn-start queue",
            count: mission_node_count,
            offset: object_count_offset,
        });
    }

    let special_resource_trade_balance = stream.read_le_i32()?;
    let aid_allocation_total = stream.read_le_i32()?;
    let colony_boycott_flags = stream.read_bytes(NATION_COUNT)?.try_into().unwrap();
    let military_expenses = stream.read_le_i32()?;
    Ok(LegacyGreatPowerPostCity {
        towns,
        civilian_units,
        candidate_nation_flags,
        diplomacy_budget_base,
        escalation_counter,
        pending_commitment_cost,
        pressure_counter,
        opaque_counter,
        turn_finished_flag,
        special_resource_trade_balance,
        aid_allocation_total,
        colony_boycott_flags,
        military_expenses,
    })
}

fn read_town(stream: &mut LegacyStream<'_>) -> Result<LegacyTown, StreamError> {
    Ok(LegacyTown {
        name: fixed_text(stream.read_bytes(0x10)?),
        tile_index: stream.read_le_i16()?,
        opaque_fields: read_short_array(stream)?,
        created_turn: stream.read_le_i16()?,
        owner_nation: stream.read_le_i16()?,
        resource_yield_by_type: read_be_short_array(stream)?,
        transport_linked: stream.read_u8()?,
        enabled: stream.read_u8()?,
        has_adjacent_city: stream.read_u8()?,
        active: stream.read_u8()?,
    })
}

fn read_civilian_unit(stream: &mut LegacyStream<'_>) -> Result<LegacyCivilianUnit, StreamError> {
    Ok(LegacyCivilianUnit {
        unit_type: stream.read_le_i16()?,
        tile_index: stream.read_le_i16()?,
        order_target: stream.read_le_i16()?,
        owner_nation: stream.read_le_i16()?,
        roster_id: stream.read_le_i16()?,
        registered: stream.read_u8()?,
        order: stream.read_le_i32()?,
        persistent_id: stream.read_le_i32()?,
        remaining_turns: stream.read_le_i16()?,
    })
}

fn read_auto_great_power_prefix(
    stream: &mut LegacyStream<'_>,
) -> Result<LegacyAutoGreatPowerPrefix, StreamError> {
    Ok(LegacyAutoGreatPowerPrefix {
        action_metric_by_quarter: read_be_short_array(stream)?,
        map_node_state_flags: stream.read_bytes(0x180)?.try_into().unwrap(),
        port_zone_state_flags: stream.read_bytes(0x70)?.try_into().unwrap(),
        mission_count: stream.read_le_u32()?,
    })
}

fn read_mfc_mission(
    stream: &mut LegacyStream<'_>,
    base_offset: usize,
    archive: &mut LegacyMfcArchiveState,
) -> Result<LegacyMission, LegacySaveError> {
    const NEW_CLASS_TAG: u16 = 0xffff;
    const CLASS_TAG: u16 = 0x8000;
    const BIG_TAG: u16 = 0x7fff;
    const BIG_CLASS_TAG: u32 = 0x8000_0000;

    let object_offset = base_offset + stream.position();
    let word_tag = stream.read_le_u16()?;
    let object_tag = if word_tag == BIG_TAG {
        stream.read_le_u32()?
    } else {
        (u32::from(word_tag & CLASS_TAG) << 16) | u32::from(word_tag & !CLASS_TAG)
    };
    if object_tag & BIG_CLASS_TAG == 0 {
        return Err(LegacySaveError::InvalidMfcObject {
            offset: object_offset,
            detail: format!("object reference tag {object_tag:#x} is not a new mission"),
        });
    }

    let class = if word_tag == NEW_CLASS_TAG {
        let schema = stream.read_le_u16()?;
        if schema != 1 {
            return Err(LegacySaveError::InvalidMfcObject {
                offset: object_offset,
                detail: format!("mission schema {schema} is not schema 1"),
            });
        }
        let name_length = usize::from(stream.read_le_u16()?);
        let name = lossy_text(stream.read_bytes(name_length)?);
        archive.entries.push(Some(name.clone()));
        name
    } else {
        let class_index = (object_tag & !BIG_CLASS_TAG) as usize;
        archive
            .entries
            .get(class_index)
            .and_then(Clone::clone)
            .ok_or_else(|| LegacySaveError::InvalidMfcObject {
                offset: object_offset,
                detail: format!("class tag references absent map index {class_index}"),
            })?
    };

    // ReadObject reserves the object index before invoking Serialize, allowing cycles.
    archive.entries.push(None);
    read_mission_payload(stream, class, object_offset)
}

fn read_mission_payload(
    stream: &mut LegacyStream<'_>,
    class: String,
    object_offset: usize,
) -> Result<LegacyMission, LegacySaveError> {
    let source_nation = stream.read_le_i16()?;
    let state = stream.read_u8()?;
    let importance_bits = stream.read_le_u32()?;
    let flag = stream.read_u8()?;
    let path_marker = stream.read_le_i16()?;
    let marker = stream.read_u8()?;

    let mut mission = LegacyMission {
        class: class.clone(),
        source_nation,
        state,
        importance_bits,
        flag,
        path_marker,
        marker,
        army: None,
        navy: None,
        target_province: None,
        amassing_province: None,
        beachhead: None,
        blockade_port_zone: None,
    };

    match class.as_str() {
        "TDefendProvinceMission" => mission.army = Some(read_army_mission(stream)?),
        "TAttackProvinceMission" => {
            mission.army = Some(read_army_mission(stream)?);
            read_attack_mission(stream, &mut mission)?;
        }
        "TInvadeMission" => {
            mission.army = Some(read_army_mission(stream)?);
            read_attack_mission(stream, &mut mission)?;
            mission.beachhead = Some(read_navy_mission(stream)?);
        }
        "TControlSeaZoneMission"
        | "TEscortMission"
        | "TScatteredShipsMission"
        | "TBeachheadMission" => mission.navy = Some(read_navy_mission(stream)?),
        "TBlockadePortMission" => {
            mission.navy = Some(read_navy_mission(stream)?);
            mission.blockade_port_zone = Some(stream.read_le_i16()?);
        }
        _ => {
            return Err(LegacySaveError::InvalidMfcObject {
                offset: object_offset,
                detail: format!("unsupported mission runtime class {class}"),
            });
        }
    }

    Ok(mission)
}

fn read_army_mission(stream: &mut LegacyStream<'_>) -> Result<LegacyArmyMission, LegacySaveError> {
    let present_location = stream.read_le_i16()?;
    let required_equipage_bits = read_be_u32_array(stream)?;
    let count = bounded_count(
        i32::from(stream.read_le_i16()?),
        MAX_MILITARY_UNITS,
        "army mission units",
    )?;
    let unit_ordinals = (0..count)
        .map(|_| stream.read_le_i16())
        .collect::<Result<Vec<_>, _>>()?;
    Ok(LegacyArmyMission {
        present_location,
        required_equipage_bits,
        unit_ordinals,
    })
}

fn read_navy_mission(stream: &mut LegacyStream<'_>) -> Result<LegacyNavyMission, StreamError> {
    let target_zone = stream.read_le_i16()?;
    let resolved_port_zone = stream.read_le_i16()?;
    let required_equipage_bits = read_be_u32_array(stream)?;
    let mut ship_ordinals = Vec::new();
    loop {
        let ordinal = stream.read_le_i16()?;
        if ordinal < 0 {
            break;
        }
        ship_ordinals.push(ordinal);
    }
    let state = stream.read_le_i32()?;
    Ok(LegacyNavyMission {
        target_zone,
        resolved_port_zone,
        required_equipage_bits,
        ship_ordinals,
        state,
    })
}

fn read_attack_mission(
    stream: &mut LegacyStream<'_>,
    mission: &mut LegacyMission,
) -> Result<(), StreamError> {
    mission.target_province = Some(stream.read_le_i16()?);
    mission.amassing_province = Some(stream.read_le_i16()?);
    Ok(())
}

fn read_terrain_tile(stream: &mut LegacyStream<'_>) -> Result<LegacyTerrainTile, StreamError> {
    let bytes = stream.read_bytes(TERRAIN_TILE_SERIALIZED_SIZE)?;
    Ok(LegacyTerrainTile {
        terrain_kind: bytes[0] as i8,
        region_tile_subtype: bytes[0x13] as i8,
        river_sprite: bytes[2],
        former_owner_nation: bytes[3] as i8,
        owner_nation: bytes[4] as i8,
        secondary_owner_nation: bytes[0x18] as i8,
        region: bytes[5] as i8,
        adjacency_bits: bytes[6],
        development_classes: bytes[0x0c] as i8,
        pending_development_visibility: bytes[0x0d],
        edge_resources: [bytes[0x11] as i8, bytes[0x12] as i8],
        city_or_province_index: i16::from_le_bytes(bytes[0x14..0x16].try_into().unwrap()),
        action_state: bytes[0x16] as i8,
        rail_flags: bytes[0x17],
        active_flags: u16::from_le_bytes(bytes[0x1c..0x1e].try_into().unwrap()),
    })
}

fn read_province(stream: &mut LegacyStream<'_>) -> Result<LegacyProvince, StreamError> {
    let bytes = stream.read_bytes(PROVINCE_FIXED_SERIALIZED_SIZE)?;
    let name = lossy_text(&stream.read_mfc_string()?);
    Ok(LegacyProvince {
        owner_nation: bytes[0] as i8,
        former_owner_nation: bytes[1] as i8,
        development_stage: bytes[2] as i8,
        fort_level: bytes[3] as i8,
        city_tile: i16::from_le_bytes(bytes[4..6].try_into().unwrap()),
        last_turn_tick: i16::from_le_bytes(bytes[6..8].try_into().unwrap()),
        adjacent_region_count: bytes[8] as i8,
        adjacent_region_ids: std::array::from_fn(|index| {
            let offset = 0x0a + index * 2;
            i16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
        }),
        region_class: bytes[0xa3] as i8,
        name,
    })
}

fn read_game_setup(stream: &mut LegacyStream<'_>) -> Result<LegacyGameSetup, StreamError> {
    let multiplayer_game_active = stream.read_u8()?;
    stream.skip(1)?;
    let nation_control_modes = read_short_array(stream)?;
    let city_minister_policy_ids = read_short_array(stream)?;
    let foreign_minister_policy_ids = read_short_array(stream)?;
    let defense_minister_policy_ids = read_short_array(stream)?;
    let reload_political_map_state = stream.read_u8()?;
    stream.skip(1)?;
    let raw_scenario_map = stream.read_le_i16()?;
    let scenario_map =
        (raw_scenario_map > 0).then(|| ScenarioMapId::new((raw_scenario_map - 1) as u16));
    Ok(LegacyGameSetup {
        multiplayer_game_active,
        nation_control_modes,
        city_minister_policy_ids,
        foreign_minister_policy_ids,
        defense_minister_policy_ids,
        reload_political_map_state,
        scenario_map,
    })
}

fn nation_id_from_retail_i16(value: i16) -> Result<NationId, LegacySaveError> {
    u8::try_from(value)
        .ok()
        .and_then(NationId::try_new)
        .ok_or_else(|| {
            LegacySaveError::StateProjection(format!(
                "nation slot {value} is outside the retail range 0..={}",
                NATION_COUNT - 1
            ))
        })
}

fn minor_nation_id_from_retail_i16(value: i16) -> Result<MinorNationId, LegacySaveError> {
    let nation = nation_id_from_retail_i16(value)?;
    if nation.get() < MAJOR_NATION_COUNT as u8 {
        return Err(LegacySaveError::InvalidNationSlot {
            context: "minor consortium member",
            slot: value,
        });
    }
    Ok(MinorNationId::new(nation.get()))
}

fn read_short_array<const N: usize>(
    stream: &mut LegacyStream<'_>,
) -> Result<[i16; N], StreamError> {
    let mut values = [0; N];
    for value in &mut values {
        *value = stream.read_le_i16()?;
    }
    Ok(values)
}

fn read_be_short_array<const N: usize>(
    stream: &mut LegacyStream<'_>,
) -> Result<[i16; N], StreamError> {
    let mut values = [0; N];
    for value in &mut values {
        *value = stream.read_be_i16()?;
    }
    Ok(values)
}

fn read_be_u32_array<const N: usize>(
    stream: &mut LegacyStream<'_>,
) -> Result<[u32; N], StreamError> {
    let mut values = [0; N];
    for value in &mut values {
        *value = u32::from_be_bytes(stream.read_bytes(4)?.try_into().unwrap());
    }
    Ok(values)
}

fn fixed_text(bytes: &[u8]) -> String {
    let length = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    lossy_text(&bytes[..length])
}

/// Decodes save-string bytes.
///
/// Retail ANSI `CString` payloads use a Windows code page selected by the build's
/// localization; `language_code` is retained on the simulation prefix for that mapping.
/// Until localized retail fixtures establish the per-language code pages, bytes are
/// decoded as UTF-8 with lossy replacement so English fixtures keep loading.
fn lossy_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const RETAIL_FIXTURE: &[u8] =
        include_bytes!("../../../../fixtures/retail/beginning_of_game.imp");
    const DIPLOMACY_YEAR_TERM_ABSOLUTE_OFFSET_V62: usize = 0x1a1f;
    const MARKET_ABSOLUTE_OFFSET_V62: usize = 0x1ac1;
    const MARKET_ROW_SERIALIZED_SIZE_V62: usize = 0x9e;
    const MARKET_MAXIMUM_OFFER_OFFSET_V62: usize = 0x70;
    const TECH_ABSOLUTE_OFFSET_V62: usize = 0x3af9;

    fn game_context() -> LegacyGameStateContext {
        LegacyGameStateContext {
            crt_rand_state: 1,
            map_generation_lcg: 0,
            zone_status_lcg: 3_916_827_792,
            selected_nation: NationId::new(6),
        }
    }

    const NATION_PAIR_BYTES: usize = NATION_COUNT * NATION_COUNT * 2;
    const RELATIONSHIP_OFFSET: usize = NATION_PAIR_BYTES;
    const TURN_STAMP_OFFSET: usize = RELATIONSHIP_OFFSET + NATION_PAIR_BYTES;
    const INFLUENCE_THRESHOLD_OFFSET: usize = TURN_STAMP_OFFSET + NATION_PAIR_BYTES;
    const INFLUENCE_SIDE_OFFSET: usize = INFLUENCE_THRESHOLD_OFFSET + PROVINCE_COUNT * 2;
    const MISSION_LEVEL_OFFSET: usize = INFLUENCE_SIDE_OFFSET + PROVINCE_COUNT + 2;
    const CONGRESS_OFFSET: usize = MISSION_LEVEL_OFFSET + NATION_PAIR_BYTES;

    fn push_be_i16(bytes: &mut Vec<u8>, value: i16) {
        bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn nonzero_steel_order_payload() -> Vec<u8> {
        let mut bytes = Vec::with_capacity(66);
        // Retail overwrites this first constructor product with the second
        // product word, so keep them deliberately different.
        for value in [99_i16, 3, 2, 11] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        for resource in 0..RESOURCE_KIND_COUNT {
            let tracked = if resource == ResourceKind::Coal as usize
                || resource == ResourceKind::Iron as usize
            {
                3_i16
            } else {
                0_i16
            };
            bytes.extend_from_slice(&tracked.to_le_bytes());
        }
        bytes.extend_from_slice(&27_i32.to_le_bytes());
        for value in [5_i16, 4, 3, 2] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn decodes_nonzero_item_order_field_sequence() {
        let bytes = nonzero_steel_order_payload();
        let mut stream = LegacyStream::new(&bytes);

        let state = read_item_order(&mut stream, ResourceKind::Steel).unwrap();

        assert_eq!(stream.position(), 66);
        assert_eq!(state.progress.quantity, 3);
        assert_eq!(
            state.progress.limiting_constraint,
            ProductionConstraint::Capacity
        );
        assert_eq!(state.progress.tracking_by_resource[ResourceKind::Coal], 3);
        assert_eq!(state.progress.tracking_by_resource[ResourceKind::Iron], 3);
        assert_eq!(state.progress.reserved_workforce, 0);
        assert_eq!(state.progress.accumulated_value, 27);
        assert_eq!(state.requested_quantity, 5);
    }

    #[test]
    fn rejects_item_order_with_the_wrong_static_production_slot() {
        let mut bytes = nonzero_steel_order_payload();
        bytes[64..66].copy_from_slice(&3_i16.to_le_bytes());
        let mut stream = LegacyStream::new(&bytes);

        assert!(matches!(
            read_item_order(&mut stream, ResourceKind::Steel),
            Err(LegacySaveError::InvalidCityOrder { .. })
        ));
    }

    fn valid_diplomacy_payload() -> Vec<u8> {
        let mut bytes = Vec::with_capacity(DIPLOMACY_SERIALIZED_SIZE_V62);
        for index in 0..NATION_COUNT * NATION_COUNT {
            push_be_i16(&mut bytes, if index == 0 { 0x1234 } else { 90 });
        }
        for _ in 0..NATION_COUNT * NATION_COUNT {
            push_be_i16(&mut bytes, DiplomaticRelationship::Peace.retail());
        }
        for index in 0..NATION_COUNT * NATION_COUNT {
            push_be_i16(&mut bytes, if index == 0 { 7 } else { -1 });
        }
        for index in 0..PROVINCE_COUNT {
            push_be_i16(&mut bytes, if index == 0 { 0x2345 } else { 0 });
        }
        bytes.extend(std::iter::once(6).chain(std::iter::repeat_n(0xff, PROVINCE_COUNT - 1)));
        bytes.extend_from_slice(&0x3456_i16.to_le_bytes());
        for index in 0..NATION_COUNT * NATION_COUNT {
            push_be_i16(
                &mut bytes,
                if index == 1 {
                    DiplomaticMissionLevel::Embassy.retail()
                } else {
                    DiplomaticMissionLevel::None.retail()
                },
            );
        }
        push_be_i16(&mut bytes, 6);
        push_be_i16(&mut bytes, -1);
        push_be_i16(&mut bytes, 1);
        push_be_i16(&mut bytes, 2);
        push_be_i16(&mut bytes, 3);
        for index in 0..MINOR_NATION_COUNT {
            push_be_i16(&mut bytes, if index == 0 { 5 } else { -1 });
        }
        for _ in 0..MINOR_NATION_COUNT {
            push_be_i16(&mut bytes, -1);
        }
        assert_eq!(bytes.len(), DIPLOMACY_SERIALIZED_SIZE_V62);
        bytes
    }

    #[test]
    fn reads_phase_six_inputs_from_their_exact_v62_offsets() {
        let mut bytes = RETAIL_FIXTURE.to_vec();
        bytes[DIPLOMACY_YEAR_TERM_ABSOLUTE_OFFSET_V62..DIPLOMACY_YEAR_TERM_ABSOLUTE_OFFSET_V62 + 2]
            .copy_from_slice(&(-1234_i16).to_le_bytes());
        let category = 6;
        let nation_slot = 22;
        let maximum_offset = MARKET_ABSOLUTE_OFFSET_V62
            + category * MARKET_ROW_SERIALIZED_SIZE_V62
            + MARKET_MAXIMUM_OFFER_OFFSET_V62
            + nation_slot * std::mem::size_of::<i16>();
        assert_eq!(maximum_offset, 0x1f11);
        bytes[maximum_offset..maximum_offset + 2].copy_from_slice(&321_i16.to_be_bytes());
        bytes[TECH_ABSOLUTE_OFFSET_V62 + TECH_ADVANCED_IRON_WORKING_OFFSET_V62] = 1;
        bytes[TECH_ABSOLUTE_OFFSET_V62 + TECH_MARINE_ENGINEERING_OFFSET_V62] = 1;
        assert_eq!(
            TECH_ABSOLUTE_OFFSET_V62 + TECH_ADVANCED_IRON_WORKING_OFFSET_V62,
            0x3c9e
        );
        assert_eq!(
            TECH_ABSOLUTE_OFFSET_V62 + TECH_MARINE_ENGINEERING_OFFSET_V62,
            0x3ca1
        );

        let save = LegacySaveV62::parse(&bytes).unwrap();
        let state = save.game_state(game_context()).unwrap();
        assert_eq!(state.turn.diplomacy_year_term_raw, -1234);
        assert!(state.technology.advanced_iron_working);
        assert!(state.technology.marine_engineering);
        assert_eq!(
            state.market.rows[TradeCommodity::Oil].maximum_offer_by_nation[NationId::new(22)],
            321
        );
    }

    #[test]
    fn technology_decoder_requires_boolean_resource_type_flags() {
        let mut bytes = [0_u8; TECH_SERIALIZED_SIZE_V62];
        bytes[TECH_ADVANCED_IRON_WORKING_OFFSET_V62] = 1;
        bytes[TECH_MARINE_ENGINEERING_OFFSET_V62] = 1;
        bytes[TECH_GLOBAL_UNLOCK_FLAGS_OFFSET_V62 + TECH_OIL_DRILLING_ID] = 1;
        bytes[TECH_ORDER_CAP_ROWS_OFFSET_V62
            + 2 * TECH_ORDER_CAP_ROW_SIZE
            + TECH_ADVANCED_IRON_WORKING_ID] = 2;
        bytes
            [TECH_ORDER_CAP_ROWS_OFFSET_V62 + 3 * TECH_ORDER_CAP_ROW_SIZE + TECH_OIL_DRILLING_ID] =
            2;
        bytes[TECH_UNIVERSITY_AVAILABILITY_OFFSET_V62
            + TECH_UNIVERSITY_AVAILABILITY_ROW_SIZE
            + CivilianUnitKind::Driller as usize] = 1;
        let requirement_offset = TECH_FINAL_REQUIREMENT_LEVELS_OFFSET_V62
            + TECH_REQUIREMENT_LEVELS_ROW_SIZE
            + ResourceKind::Oil as usize * std::mem::size_of::<i16>();
        bytes[requirement_offset..requirement_offset + 2].copy_from_slice(&3_i16.to_be_bytes());
        let mut stream = LegacyStream::new(&bytes);
        let technology = read_technology_state(&mut stream).unwrap();
        assert!(technology.advanced_iron_working);
        assert!(technology.marine_engineering);
        assert!(technology.oil_drilling_available);
        assert!(
            technology.city_capabilities_by_nation[MajorNationId::new(2)].advanced_iron_working
        );
        assert!(technology.city_capabilities_by_nation[MajorNationId::new(3)].oil_drilling);
        assert!(
            technology.city_capabilities_by_nation[MajorNationId::new(1)]
                .university
                .available[CivilianUnitKind::Driller]
        );
        assert_eq!(
            technology.city_capabilities_by_nation[MajorNationId::new(1)]
                .university
                .requirement_levels[ResourceKind::Oil],
            3
        );
        assert_eq!(stream.position(), TECH_SERIALIZED_SIZE_V62);

        for (offset, value) in [
            (TECH_ADVANCED_IRON_WORKING_OFFSET_V62, 2),
            (TECH_MARINE_ENGINEERING_OFFSET_V62, u8::MAX),
            (
                TECH_GLOBAL_UNLOCK_FLAGS_OFFSET_V62 + TECH_OIL_DRILLING_ID,
                2,
            ),
        ] {
            let mut bytes = [0_u8; TECH_SERIALIZED_SIZE_V62];
            bytes[offset] = value;
            assert!(matches!(
                read_technology_state(&mut LegacyStream::new(&bytes)),
                Err(LegacySaveError::InvalidBoolean {
                    value: invalid,
                    ..
                }) if invalid == value
            ));
        }

        let mut bytes = [0_u8; TECH_SERIALIZED_SIZE_V62];
        bytes[TECH_ORDER_CAP_ROWS_OFFSET_V62 + TECH_OIL_DRILLING_ID] = 3;
        assert!(matches!(
            read_technology_state(&mut LegacyStream::new(&bytes)),
            Err(LegacySaveError::StateProjection(message))
                if message == "major nation 0 technology 19 status 3 is invalid"
        ));

        let mut bytes = [0_u8; TECH_SERIALIZED_SIZE_V62];
        bytes[TECH_UNIVERSITY_AVAILABILITY_OFFSET_V62] = 2;
        assert!(matches!(
            read_technology_state(&mut LegacyStream::new(&bytes)),
            Err(LegacySaveError::InvalidBoolean { value: 2, .. })
        ));

        let mut bytes = [0_u8; TECH_SERIALIZED_SIZE_V62];
        bytes[TECH_FINAL_REQUIREMENT_LEVELS_OFFSET_V62..][..2]
            .copy_from_slice(&4_i16.to_be_bytes());
        assert!(matches!(
            read_technology_state(&mut LegacyStream::new(&bytes)),
            Err(LegacySaveError::StateProjection(message))
                if message.contains("university requirement level 4")
        ));
    }

    #[test]
    fn trade_maximum_decoder_keeps_all_nation_slots_and_rejects_negatives() {
        let mut bytes = [0_u8; MARKET_ROW_SERIALIZED_SIZE_V62];
        let nation_zero_offset = MARKET_MAXIMUM_OFFER_OFFSET_V62;
        let nation_twenty_two_offset = MARKET_MAXIMUM_OFFER_OFFSET_V62 + 22 * 2;
        assert_eq!(nation_zero_offset, 0x70);
        assert_eq!(nation_twenty_two_offset, 0x9c);
        bytes[nation_zero_offset..nation_zero_offset + 2].copy_from_slice(&17_i16.to_be_bytes());
        bytes[nation_twenty_two_offset..nation_twenty_two_offset + 2]
            .copy_from_slice(&222_i16.to_be_bytes());

        let mut stream = LegacyStream::new(&bytes);
        let row = read_trade_market_row(&mut stream, 6).unwrap();
        assert_eq!(stream.position(), MARKET_ROW_SERIALIZED_SIZE_V62);
        assert_eq!(row.maximum_offer_by_nation[NationId::new(0)], 17);
        assert_eq!(row.maximum_offer_by_nation[NationId::new(22)], 222);

        bytes[nation_twenty_two_offset..nation_twenty_two_offset + 2]
            .copy_from_slice(&(-1_i16).to_be_bytes());
        assert!(matches!(
            read_trade_market_row(&mut LegacyStream::new(&bytes), 6),
            Err(LegacySaveError::NegativeTradeOfferMaximum {
                commodity: 6,
                nation: 22,
                value: -1,
            })
        ));
    }

    #[test]
    fn reads_the_exact_v62_diplomacy_payload_and_endianness() {
        let bytes = valid_diplomacy_payload();
        let mut stream = LegacyStream::new(&bytes);
        let diplomacy = read_diplomacy_state(&mut stream).unwrap();

        assert_eq!(stream.position(), DIPLOMACY_SERIALIZED_SIZE_V62);
        assert_eq!(
            diplomacy.standings[NationId::new(0)][NationId::new(0)],
            0x1234
        );
        assert_eq!(
            diplomacy.relationship_turns[NationId::new(0)][NationId::new(0)],
            Some(7)
        );
        assert_eq!(diplomacy.influence_thresholds[ProvinceId::new(0)], 0x2345);
        assert_eq!(
            diplomacy.influence_sides[ProvinceId::new(0)],
            Some(MajorNationId::new(6))
        );
        assert_eq!(diplomacy.last_diplomatic_effort_turn, 0x3456);
        assert_eq!(
            diplomacy.mission_levels[NationId::new(0)][NationId::new(1)],
            DiplomaticMissionLevel::Embassy
        );
        assert_eq!(diplomacy.congress.chairman, Some(MajorNationId::new(6)));
        assert_eq!(diplomacy.congress.counterpart, None);
        assert_eq!(diplomacy.congress.neutral_support, 3);
        assert_eq!(
            diplomacy.special_relation_sources[MinorNationId::new(7)],
            Some(MajorNationId::new(5))
        );
        assert_eq!(diplomacy.last_processed_nation, None);
        assert_eq!(diplomacy.proposal_mode_raw, 0);
    }

    #[test]
    fn rejects_malformed_closed_diplomacy_domains_and_sentinels() {
        for (offset, replacement) in [
            (RELATIONSHIP_OFFSET, 1_i16.to_be_bytes()),
            (TURN_STAMP_OFFSET, (-2_i16).to_be_bytes()),
            (MISSION_LEVEL_OFFSET, 3_i16.to_be_bytes()),
            (CONGRESS_OFFSET, 7_i16.to_be_bytes()),
        ] {
            let mut bytes = valid_diplomacy_payload();
            bytes[offset..offset + 2].copy_from_slice(&replacement);
            assert!(matches!(
                read_diplomacy_state(&mut LegacyStream::new(&bytes)),
                Err(LegacySaveError::InvalidDiplomacyValue { .. })
            ));
        }

        let mut bytes = valid_diplomacy_payload();
        bytes[INFLUENCE_SIDE_OFFSET] = 7;
        assert!(matches!(
            read_diplomacy_state(&mut LegacyStream::new(&bytes)),
            Err(LegacySaveError::InvalidDiplomacyValue { .. })
        ));
    }

    fn first_great_power_mut(save: &mut LegacySaveV62) -> &mut LegacyGreatPowerState {
        match &mut save.major_nations[0] {
            LegacyMajorNationState::Auto(nation) => &mut nation.great_power,
            LegacyMajorNationState::Other(nation) => nation,
        }
    }

    fn relationship_record(value: i16, source: i16) -> Vec<u8> {
        [value.to_le_bytes(), source.to_le_bytes()].concat()
    }

    #[test]
    fn projects_typed_relationship_queues_in_retail_source_order_without_rng_draws() {
        let mut save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
        let lists = &mut first_great_power_mut(&mut save).prefix.relationship_lists;
        lists[0].records = vec![relationship_record(-7, 2), relationship_record(9, 0)];
        lists[1].records = vec![relationship_record(0x134, 5), relationship_record(0x12d, 1)];
        let mut context = game_context();
        context.crt_rand_state = 0x1234_5678;

        let state = save.game_state(context).unwrap();
        let pending = &state.pending.nations[MajorNationId::new(0)];
        assert_eq!(
            pending.turn_events,
            vec![
                DiplomacyNotice {
                    source: NationId::new(0),
                    code: 9,
                },
                DiplomacyNotice {
                    source: NationId::new(2),
                    code: -7,
                },
            ]
        );
        assert_eq!(
            pending.proposals,
            vec![
                DiplomacyProposal {
                    source: NationId::new(1),
                    policy: DiplomacyPolicy::JoinEmpire,
                },
                DiplomacyProposal {
                    source: NationId::new(5),
                    policy: DiplomacyPolicy::BuildEmbassy,
                },
            ]
        );
        assert_eq!(state.rng.crt_rand.state(), 0x1234_5678);
    }

    #[test]
    fn rejects_relationship_queues_that_need_unavailable_load_time_rng() {
        let mut save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
        first_great_power_mut(&mut save).prefix.relationship_lists[0].records =
            vec![relationship_record(1, 2), relationship_record(2, 2)];

        assert!(matches!(
            save.game_state(game_context()),
            Err(LegacySaveError::StateProjection(message))
                if message == "nation 0 turn-event queue contains distinguishable records from source 2; retail load order depends on unavailable pre-load CRT state"
        ));
    }

    #[test]
    fn accepts_identical_equal_source_relationship_records_without_rng_draws() {
        let mut save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
        let lists = &mut first_great_power_mut(&mut save).prefix.relationship_lists;
        lists[0].records = vec![relationship_record(-7, 2), relationship_record(-7, 2)];
        lists[1].records = vec![relationship_record(0x12d, 1), relationship_record(0x12d, 1)];
        let mut context = game_context();
        context.crt_rand_state = 0x1234_5678;

        let state = save.game_state(context).unwrap();
        let pending = &state.pending.nations[MajorNationId::new(0)];
        assert_eq!(
            pending.turn_events,
            vec![
                DiplomacyNotice {
                    source: NationId::new(2),
                    code: -7,
                },
                DiplomacyNotice {
                    source: NationId::new(2),
                    code: -7,
                },
            ]
        );
        assert_eq!(
            pending.proposals,
            vec![
                DiplomacyProposal {
                    source: NationId::new(1),
                    policy: DiplomacyPolicy::JoinEmpire,
                },
                DiplomacyProposal {
                    source: NationId::new(1),
                    policy: DiplomacyPolicy::JoinEmpire,
                },
            ]
        );
        assert_eq!(state.rng.crt_rand.state(), 0x1234_5678);
    }

    #[test]
    fn validates_relationship_record_shape_source_and_policy() {
        let mut save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
        first_great_power_mut(&mut save).prefix.relationship_lists[0].record_size = 2;
        assert!(matches!(
            save.game_state(game_context()),
            Err(LegacySaveError::StateProjection(message))
                if message == "nation 0 turn-event queue has record size 2; expected 4"
        ));

        let mut save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
        first_great_power_mut(&mut save).prefix.relationship_lists[0].records =
            vec![relationship_record(1, 23)];
        assert!(matches!(
            save.game_state(game_context()),
            Err(LegacySaveError::StateProjection(message))
                if message == "nation slot 23 is outside the retail range 0..=22"
        ));

        let mut save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
        first_great_power_mut(&mut save).prefix.relationship_lists[1].records =
            vec![relationship_record(0x12c, 1)];
        assert!(matches!(
            save.game_state(game_context()),
            Err(LegacySaveError::UnsupportedDiplomacyPolicy {
                nation: 0,
                target: 1,
                entry: 0x12c,
            })
        ));
    }

    #[test]
    fn projects_exact_fixture_ai_zone_targets_and_newest_port_owners() {
        let save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
        assert_eq!(save.ocean.zones.len(), 60);
        assert_eq!(save.ocean.port_zones.len(), 23);
        let state = save.game_state(game_context()).unwrap();
        let expected_mission_queued = [[22, 66], [42, 65], [26, 64], [21, 63], [8, 62], [11, 61]];
        for (slot, expected) in expected_mission_queued.into_iter().enumerate() {
            let targets = state
                .nations
                .major(MajorNationId::new(slot as u8))
                .economy()
                .ai_zone_targets
                .as_ref()
                .unwrap();
            assert_eq!(targets.len(), 83);
            let mut expected_targets = vec![AiZoneTargetState::Unmarked; 83];
            for ordinal in expected {
                expected_targets[ordinal] = AiZoneTargetState::MissionQueued;
            }
            assert_eq!(targets, &expected_targets);
        }
        assert!(
            state
                .nations
                .major(MajorNationId::new(6))
                .economy()
                .ai_zone_targets
                .is_none()
        );
        assert_eq!(state.port_zone_owners.len(), 23);
        for (owner, saved) in state
            .port_zone_owners
            .iter()
            .zip(save.ocean.port_zones.iter().rev())
        {
            assert_eq!(owner.zone.get(), saved.context_ordinal as u16);
            let tile = saved.port_tile_index.unwrap() as usize;
            assert_eq!(
                owner.former_owner.get(),
                save.map.tiles[tile].former_owner_nation as u8
            );
        }
    }

    #[test]
    fn validates_ai_zone_domain_status_and_unused_tail() {
        let save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
        assert_eq!(validate_ocean_contexts(&save.ocean).unwrap(), 83);

        let mut ocean = save.ocean.clone();
        ocean.zones[0].context_ordinal = -1;
        assert!(matches!(
            validate_ocean_contexts(&ocean),
            Err(LegacySaveError::StateProjection(message))
                if message == "ocean context ordinal -1 is negative"
        ));

        let mut ocean = save.ocean.clone();
        ocean.zones[1].context_ordinal = ocean.zones[0].context_ordinal;
        assert!(matches!(
            validate_ocean_contexts(&ocean),
            Err(LegacySaveError::StateProjection(message))
                if message == "ocean context ordinal 0 is duplicated"
        ));

        let mut ocean = save.ocean.clone();
        ocean.zones[0].context_ordinal = 83;
        assert!(matches!(
            validate_ocean_contexts(&ocean),
            Err(LegacySaveError::StateProjection(message))
                if message == "ocean context ordinal 83 is outside the live range 0..83"
        ));

        let mut ocean = save.ocean.clone();
        ocean
            .zones
            .extend(std::iter::repeat_n(ocean.zones[0].clone(), 30));
        assert!(matches!(
            validate_ocean_contexts(&ocean),
            Err(LegacySaveError::StateProjection(message))
                if message == "ocean has 113 live contexts; AI state supports at most 112"
        ));

        let mut flags = [0; AI_ZONE_TARGET_CAPACITY];
        flags[0] = 3;
        assert!(matches!(
            ai_zone_targets(&flags, 83, 0),
            Err(LegacySaveError::StateProjection(message))
                if message == "AI nation 0 ocean context 0 has invalid target state 3"
        ));
        flags[0] = 0;
        flags[83] = 1;
        assert!(matches!(
            ai_zone_targets(&flags, 83, 0),
            Err(LegacySaveError::StateProjection(message))
                if message == "AI nation 0 unused ocean context 83 has nonzero target state 1"
        ));
    }

    #[test]
    fn port_owner_projection_uses_port_tile_former_owner_and_newest_order() {
        let mut save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
        let newest = save.ocean.port_zones.len() - 1;
        let next_newest = newest - 1;
        let newest_zone = save.ocean.port_zones[newest].context_ordinal;
        let next_newest_zone = save.ocean.port_zones[next_newest].context_ordinal;
        let newest_tile = save.ocean.port_zones[newest].port_tile_index.unwrap() as usize;
        let next_newest_tile = save.ocean.port_zones[next_newest].port_tile_index.unwrap() as usize;
        save.ocean.port_zones[newest].seed_nation_id = 6;
        save.ocean.port_zones[next_newest].seed_nation_id = 5;
        save.map.tiles[newest_tile].former_owner_nation = 0;
        save.map.tiles[next_newest_tile].former_owner_nation = 0;

        let owners = port_zone_owners(&save.ocean, &save.map).unwrap();
        assert_eq!(
            &owners[..2],
            &[
                PortZoneOwner {
                    zone: OceanZoneId::new(newest_zone as u16),
                    former_owner: NationId::new(0),
                },
                PortZoneOwner {
                    zone: OceanZoneId::new(next_newest_zone as u16),
                    former_owner: NationId::new(0),
                },
            ]
        );
    }

    #[test]
    fn retail_projection_preserves_minister_identity_and_direct_state() {
        let save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
        let state = save.game_state(game_context()).unwrap();
        assert_eq!(
            save.simulation.game_setup.foreign_minister_policy_ids,
            [1, 4, 2, 4, 3, 5, 3]
        );
        assert_eq!(
            state
                .nations
                .majors()
                .map(|nation| nation.economy().foreign_minister_personality)
                .collect::<Vec<_>>(),
            [
                ForeignMinisterPersonality::Trader,
                ForeignMinisterPersonality::Bill,
                ForeignMinisterPersonality::Textile,
                ForeignMinisterPersonality::Bill,
                ForeignMinisterPersonality::Diplomat,
                ForeignMinisterPersonality::Ted,
                ForeignMinisterPersonality::Base,
            ]
        );
        assert_eq!(
            state
                .nations
                .majors()
                .map(|nation| nation.economy().foreign_minister_skill_index)
                .collect::<Vec<_>>(),
            [0, 4, 0, 4, 0, 5, 0]
        );
        assert!(state.nations.majors().all(|nation| {
            nation.economy().development_grant_by_nation == NationTable::<i16>::default()
                && nation.economy().defense_minister_skill_index == 0
        }));
        assert_eq!(
            state
                .nations
                .major(MajorNationId::new(6))
                .economy()
                .foreign_minister_personality,
            ForeignMinisterPersonality::Base,
            "the human constructs the base minister even though setup policy 3 names Diplomat"
        );
    }

    #[test]
    fn retail_projection_preserves_country_and_province_semantics() {
        let save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
        let state = save.game_state(game_context()).unwrap();

        let nation_zero = state.nations.major(MajorNationId::new(0)).common();
        assert_eq!(nation_zero.status, CountryStatus::Independent);
        assert_eq!(
            nation_zero.owned_regions,
            [79, 80, 89, 90, 91, 100, 101, 111]
                .map(ProvinceId::new)
                .to_vec()
        );

        let province_zero = &state.provinces[ProvinceId::new(0)];
        assert_eq!(province_zero.owner(), Some(NationId::new(12)));
        assert_eq!(province_zero.former_owner(), Some(NationId::new(12)));
        assert_eq!(province_zero.adjacency(), [8, 1, 17].map(ProvinceId::new));
        assert_eq!(province_zero.region_class(), Some(0));

        let province_seventy_nine = &state.provinces[ProvinceId::new(79)];
        assert_eq!(province_seventy_nine.owner(), Some(NationId::new(0)));
        assert_eq!(
            province_seventy_nine.adjacency(),
            [71, 72, 80, 78, 89, 90].map(ProvinceId::new)
        );
        assert_eq!(province_seventy_nine.region_class(), Some(4));

        for province in 120..PROVINCE_COUNT {
            assert_eq!(
                state.provinces[ProvinceId::new(province as u16)],
                ProvinceState::default()
            );
        }

        assert!(
            state.do_nation_territories_share_region_class(NationId::new(0), NationId::new(19))
        );
        assert!(
            !state.do_nation_territories_share_region_class(NationId::new(0), NationId::new(1))
        );
        assert!(state.are_nations_border_linked(NationId::new(0), NationId::new(19)));
        assert!(!state.are_nations_border_linked(NationId::new(0), NationId::new(1)));
    }

    #[test]
    fn country_status_projection_accepts_only_retail_encodings() {
        for (encoded, expected) in [
            (-1, CountryStatus::Independent),
            (100, CountryStatus::ProtectorateOf(NationId::new(0))),
            (122, CountryStatus::ProtectorateOf(NationId::new(22))),
            (200, CountryStatus::ColonyOf(NationId::new(0))),
            (222, CountryStatus::ColonyOf(NationId::new(22))),
        ] {
            assert_eq!(country_status_from_retail(encoded).unwrap(), expected);
        }
        for encoded in [-2, 0, 99, 123, 199, 223] {
            assert!(country_status_from_retail(encoded).is_err());
        }
    }

    #[test]
    fn semantic_projection_rejects_malformed_territory_inputs() {
        for count in [-1, 13] {
            let save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
            let mut province = save.map.provinces[0].clone();
            province.adjacent_region_count = count;
            assert!(province_state(0, &province).is_err());
        }
        for adjacent in [-1, 384] {
            let save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
            let mut province = save.map.provinces[0].clone();
            province.adjacent_region_count = 1;
            province.adjacent_region_ids[0] = adjacent;
            assert!(province_state(0, &province).is_err());
        }

        let save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
        let mut province = save.map.provinces[0].clone();
        province.owner_nation = 23;
        assert!(province_state(0, &province).is_err());
        province.owner_nation = 0;
        province.former_owner_nation = 23;
        assert!(province_state(0, &province).is_err());
        province.former_owner_nation = 0;
        province.region_class = 24;
        assert!(province_state(0, &province).is_err());

        for owned_region in [-1, 384] {
            let mut save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
            first_great_power_mut(&mut save).country.owned_regions[0] = owned_region;
            assert!(save.game_state(game_context()).is_err());
        }
        for encoded_status in [-2, 0, 99, 123, 199, 223] {
            let mut save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
            first_great_power_mut(&mut save).country.encoded_nation_slot = encoded_status;
            assert!(save.game_state(game_context()).is_err());
        }

        let mut too_short = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
        too_short.map.provinces.pop();
        assert!(too_short.game_state(game_context()).is_err());
        let mut too_long = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
        too_long
            .map
            .provinces
            .push(too_long.map.provinces[0].clone());
        assert!(too_long.game_state(game_context()).is_err());

        let mut stale_tail = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
        stale_tail.map.provinces[120].adjacent_region_ids[0] = 384;
        assert!(stale_tail.game_state(game_context()).is_ok());
    }

    #[test]
    fn retail_river_sprites_project_to_canonical_connection_codes() {
        for (sprite, connection_code) in [
            (0x0b, 1),
            (0x0d, 3),
            (0x0e, 3),
            (0x1a, 9),
            (0x1b, 1),
            (0x2a, 9),
            (0x2b, 0x0a),
            (0x2c, 0x0b),
            (0x2d, 0x0b),
            (0x32, 0x0f),
            (0x33, 0x13),
            (0x37, 0x10),
            (0x38, 0x11),
            (0x39, 0x11),
            (0x3a, 0x12),
        ] {
            assert_eq!(
                river_segment_from_retail_sprite(sprite, 7)
                    .unwrap()
                    .unwrap()
                    .connection_code(),
                connection_code
            );
        }
        assert_eq!(river_segment_from_retail_sprite(0, 7).unwrap(), None);
        assert!(river_segment_from_retail_sprite(1, 7).is_err());
    }

    #[test]
    fn normalizes_the_one_based_scenario_map_while_reading_game_setup() {
        const SCENARIO_MAP_OFFSET: usize = 60;
        let mut bytes = [0_u8; SCENARIO_MAP_OFFSET + std::mem::size_of::<i16>()];

        bytes[SCENARIO_MAP_OFFSET..].copy_from_slice(&1_i16.to_le_bytes());
        let setup = read_game_setup(&mut LegacyStream::new(&bytes)).unwrap();
        assert_eq!(setup.scenario_map, Some(ScenarioMapId::new(0)));

        bytes[SCENARIO_MAP_OFFSET..].copy_from_slice(&(-1_i16).to_le_bytes());
        let setup = read_game_setup(&mut LegacyStream::new(&bytes)).unwrap();
        assert_eq!(setup.scenario_map, None);
    }

    #[test]
    fn rejects_negative_army_mission_unit_counts_as_invalid_counts() {
        let mut bytes = [0_u8; 2 + 5 * 4 + 2];
        bytes[22..].copy_from_slice(&(-1_i16).to_le_bytes());

        let error = read_army_mission(&mut LegacyStream::new(&bytes)).unwrap_err();
        let LegacySaveError::InvalidCount {
            context,
            value,
            maximum,
        } = error
        else {
            panic!("expected invalid count, got {error:?}");
        };
        assert_eq!(context, "army mission units");
        assert_eq!(value, -1);
        assert_eq!(maximum, MAX_MILITARY_UNITS);
    }

    #[test]
    fn parses_the_retail_beginning_of_game_prefix() {
        let save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
        assert_eq!(save.header.format_version, 62);
        assert_eq!(save.header.save_label, "- Autosave -");
        assert_eq!(save.header.preview_owner_nation_by_tile.len(), 6480);
        assert_eq!(save.header.preview_difficulty, 1);
        assert_eq!(save.header.preview_active_nation, 6);
        assert_eq!(save.simulation.economic_turn, 1);
        assert_eq!(save.simulation.active_nation, 6);
        assert_eq!(save.simulation.turn_state_code, 5);
        assert_eq!(save.simulation.nation_count, 7);
        assert_eq!(save.simulation.minor_nation_count, 16);
        assert_eq!(save.simulation.diplomacy_year_term_raw, 1914);
        assert_eq!(save.simulation.nation_names[0], "Zimm");
        assert_eq!(save.simulation.nation_names[6], " Testland");
        assert_eq!(save.simulation.nation_names[22], "Sindel");
        assert_eq!(save.animator_idle_frequency, 2);
        assert_eq!(
            save.market.rows[TradeCommodity::Cotton],
            TradeMarketRow {
                previous_price: 100,
                price: 100,
                base_price: 100,
                request_count: 0,
                offer_count: 0,
                amount_offered: 0,
                adjusted_offer_count: 0.0,
                maximum_offer_by_nation: NationTable::default(),
            }
        );
        assert_eq!(save.market.rows[TradeCommodity::Arms].base_price, 900);
        assert_eq!(save.technology, TechnologyState::default());
        assert_eq!(
            save.diplomacy.standings[NationId::new(0)][NationId::new(0)],
            0x100
        );
        assert_eq!(
            save.diplomacy.relationships[NationId::new(0)][NationId::new(1)],
            DiplomaticRelationship::Peace
        );
        assert_eq!(
            save.diplomacy.relationship_turns[NationId::new(0)][NationId::new(1)],
            None
        );
        assert_eq!(
            save.diplomacy.mission_levels[NationId::new(0)][NationId::new(1)],
            DiplomaticMissionLevel::Embassy
        );
        assert_eq!(save.diplomacy.congress.chairman, None);
        assert_eq!(save.minor_nations[0].diplomacy_save_fields, [7, 8, 9, 10]);
        assert_eq!(save.map.tiles.len(), 6480);
        assert_eq!(save.map.provinces.len(), 384);
        assert_eq!(save.map.no_horizontal_wrap, 0);
        assert_eq!(save.map.tiles[0].terrain_kind, 5);
        assert_eq!(save.map.tiles[0].owner_nation, 82);
        let world = save.world_state().unwrap();
        assert_eq!(world.topology(), MapTopology::Wrapping);
        assert_eq!(world[TileId::new(0)].terrain, TerrainKind::Water);
        assert_eq!(
            world[TileId::new(0)].owner_nation,
            Some(TileOwnerTag::new(82))
        );
        assert!(!save.ocean.zones.is_empty());
        assert!(save.navy.ships.is_empty());
        assert!(save.navy.admirals.is_empty());
        assert!(save.navy.task_forces.is_empty());
        assert_eq!(save.army_report_count, 0);
        assert_eq!(save.remaining_manager_chain_offset, 0x4dc51);

        let (country, suffix_offset) =
            parse_country_base_at(RETAIL_FIXTURE, save.remaining_manager_chain_offset).unwrap();
        assert_eq!(country.identity, "Zimm");
        assert_eq!(country.alternate_identity, "Zimm");
        assert_eq!(country.nation_slot, 0);
        assert_eq!(country.encoded_nation_slot, -1);
        assert_eq!(country.treasury, 10_000);
        assert_eq!(country.home_tile, 3_494);
        assert_eq!(country.overlay_anchor_tile, -1);
        assert_eq!(country.need_level_by_nation, [100; NATION_COUNT]);
        assert_eq!(country.military_units.len(), 27);
        assert_eq!(country.military_units[0].name, "1st Minutemen");
        assert_eq!(country.military_units[0].persistent_id, 0x113);
        assert_eq!(country.military_units[0].stationed_province, 79);
        assert_eq!(country.military_units[0].strength, 500);
        let unit_states = country.military_unit_states(NationId::new(0)).unwrap();
        assert_eq!(unit_states.len(), 27);
        assert_eq!(unit_states[0].id().get(), 275);
        assert_eq!(unit_states[0].unit_type(), MilitaryUnitKind::Minutemen);
        assert_eq!(
            *unit_states[0].order().targets(),
            [Some(ProvinceId::new(79)); 3]
        );
        assert_eq!(unit_states[26].id().get(), 301);
        assert_eq!(suffix_offset, 0x4e2a3);

        let (great_power, optional_payload_offset) =
            parse_great_power_prefix_at(RETAIL_FIXTURE, suffix_offset).unwrap();
        assert_eq!(great_power.capacities, [0, 0, 15, 11]);
        assert_eq!(great_power.relationship_lists.len(), 19);
        assert_eq!(great_power.relationship_lists[0].record_size, 4);
        assert_eq!(great_power.relationship_lists[2].record_size, 12);
        assert_eq!(great_power.minister_presence_mask, 0x0f);
        assert_eq!(optional_payload_offset, 0x4eae0);

        let (ministers, city_offset) = parse_great_power_ministers_at(
            RETAIL_FIXTURE,
            optional_payload_offset,
            great_power.minister_presence_mask,
            save.simulation.game_setup.foreign_minister_policy_ids[0],
        )
        .unwrap();
        assert!(ministers.foreign.is_some());
        assert_eq!(
            ministers.interior.as_ref().unwrap().integer_lists[0].len(),
            8
        );
        assert_eq!(
            ministers.interior.as_ref().unwrap().integer_lists[1].len(),
            20
        );
        assert!(ministers.defense.is_some());
        assert_eq!(city_offset, 0x4edd0);

        let (city, city_suffix_offset) = parse_city_at(RETAIL_FIXTURE, city_offset).unwrap();
        assert_eq!(city.orders, CityOrders::default());
        assert!(city.tasks.is_empty());
        assert_eq!(city.transport_requests.record_size, 4);
        assert!(city.transport_requests.records.is_empty());
        assert_eq!(city.population.count, 7);
        assert_eq!(city.population.strength, 12);
        assert_eq!(city.population.baseline_labor, [4, 2, 1]);
        assert_eq!(city.stockpile[7..16], [20, 10, 24, 8, 19, 0, 5, 5, 0]);
        assert_eq!(
            city.production_orders[7..16],
            [999, 999, 999, 999, 0, 0, 999, 999, 0]
        );
        assert_eq!(city_suffix_offset, 0x4fbf6);

        let city_state = city.city_state(Some(TileId::new(3_494))).unwrap();
        assert_eq!(city_state.home_town_tile, Some(TileId::new(3_494)));
        assert_eq!(*city_state.orders, CityOrders::default());
        assert_eq!(
            city_state.population.accumulator().get().to_bits(),
            1_088_421_888
        );

        let (post_city, auto_offset) =
            parse_great_power_post_city_at(RETAIL_FIXTURE, city_suffix_offset).unwrap();
        assert_eq!(post_city.towns.len(), 1);
        assert_eq!(post_city.towns[0].name, "FrogCity");
        assert_eq!(post_city.towns[0].tile_index, 3_494);
        assert_eq!(post_city.civilian_units.len(), 2);
        assert_eq!(post_city.diplomacy_budget_base, 50_000);
        assert_eq!(post_city.special_resource_trade_balance, 0);
        assert_eq!(auto_offset, 0x4fcc1);

        let (auto, first_mission_offset) =
            parse_auto_great_power_prefix_at(RETAIL_FIXTURE, auto_offset).unwrap();
        assert_eq!(auto.mission_count, 11);
        assert_eq!(first_mission_offset, 0x4fec1);

        let mut archive = LegacyMfcArchiveState::default();
        let (missions, second_nation_offset) = parse_missions_at(
            RETAIL_FIXTURE,
            first_mission_offset,
            auto.mission_count,
            &mut archive,
        )
        .unwrap();
        assert_eq!(missions.len(), 11);
        assert_eq!(second_nation_offset, 0x500be);
        assert_eq!(missions[0].class, "TDefendProvinceMission");
        assert_eq!(missions[0].army.as_ref().unwrap().present_location, 79);
        assert_eq!(missions[7].army.as_ref().unwrap().present_location, 111);
        assert_eq!(missions[8].class, "TControlSeaZoneMission");
        assert_eq!(missions[8].navy.as_ref().unwrap().target_zone, 22);
        assert_eq!(missions[9].class, "TEscortMission");
        assert_eq!(missions[9].navy.as_ref().unwrap().target_zone, 66);
        assert_eq!(missions[10].class, "TScatteredShipsMission");
        assert_eq!(missions[10].importance_bits, 981_668_463);

        let mission_states = missions
            .iter()
            .enumerate()
            .map(|(queue_index, mission)| {
                mission
                    .mission_state(NationId::new(0), queue_index, &country.military_units)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let MissionData::DefendProvince { province, army } = &mission_states[0].data else {
            panic!("first mission is not defend province");
        };
        assert_eq!(*province, ProvinceId::new(79));
        assert!(army.units.is_empty());
        let MissionData::ControlSeaZone(navy) = &mission_states[8].data else {
            panic!("ninth mission is not control sea zone");
        };
        assert_eq!(navy.target_zone, Some(OceanZoneId::new(22)));
        assert_eq!(mission_states[0].path_nation, None);
        assert_eq!(mission_states[10].importance_bits, 981_668_463);

        let mut archive = LegacyMfcArchiveState::default();
        let mut nation_offset = save.remaining_manager_chain_offset;
        let mut global_mission_index = 0;
        for nation in 0..6 {
            let (major, next_offset) = parse_auto_great_power_record_at(
                RETAIL_FIXTURE,
                nation_offset,
                save.simulation.game_setup.foreign_minister_policy_ids[nation],
                &mut archive,
            )
            .unwrap();
            assert_eq!(major.great_power.country.nation_slot, nation as i16);
            assert_eq!(major.missions.len(), 11);
            for (queue_index, mission) in major.missions.iter().enumerate() {
                let state = mission
                    .mission_state(
                        NationId::new(nation as u8),
                        queue_index,
                        &major.great_power.country.military_units,
                    )
                    .unwrap();
                assert_eq!(state.nation, NationId::new(nation as u8));
                global_mission_index += 1;
            }
            nation_offset = next_offset;
        }
        assert_eq!(global_mission_index, 66);

        // The seventh major is player-controlled and therefore has no
        // TAutoGreatPower suffix or mission queue.
        let (player_major, minor_nations_offset) = parse_great_power_record_at(
            RETAIL_FIXTURE,
            nation_offset,
            save.simulation.game_setup.foreign_minister_policy_ids[6],
        )
        .unwrap();
        assert_eq!(player_major.country.nation_slot, 6);
        assert_eq!(player_major.country.identity, " Testland");
        assert!(minor_nations_offset > nation_offset);

        let mut minor_offset = minor_nations_offset;
        for nation in 7..NATION_COUNT {
            let (minor, next_offset) = parse_minor_record_at(RETAIL_FIXTURE, minor_offset).unwrap();
            assert_eq!(minor.country.nation_slot, nation as i16);
            assert_eq!(minor.diplomacy_save_extension.len(), RESOURCE_KIND_COUNT);
            minor_offset = next_offset;
        }
        assert_eq!(minor_offset, 0x62503);
        let (help, end_offset) = parse_help_manager_at(RETAIL_FIXTURE, minor_offset).unwrap();
        assert_eq!(help.index_records.record_size, 14);
        assert_eq!(help.index_records.records.len(), 30);
        assert_eq!(end_offset, RETAIL_FIXTURE.len());

        assert_eq!(save.major_nations.len(), 7);
        assert_eq!(save.minor_nations.len(), 16);
        assert_eq!(save.help, help);
        assert_eq!(save.end_offset, RETAIL_FIXTURE.len());

        let mut game = save
            .game_state(LegacyGameStateContext {
                crt_rand_state: 1,
                map_generation_lcg: 0,
                zone_status_lcg: 3_916_827_792,
                selected_nation: NationId::new(6),
            })
            .unwrap();
        assert_eq!(game.market, save.market);
        let expected_civilian_count = save
            .major_nations
            .iter()
            .map(|nation| nation.great_power().post_city.civilian_units.len())
            .sum::<usize>();
        assert_eq!(game.military_units.len(), 461);
        assert!(expected_civilian_count > 0);
        assert_eq!(game.civilian_units.len(), expected_civilian_count);
        assert_eq!(game.civilian_units[0].nation(), NationId::new(0));
        assert_eq!(
            game.civilian_units[0].id().get(),
            save.major_nations[0].great_power().post_city.civilian_units[0].persistent_id
        );
        assert_eq!(game.missions.len(), 66);
        assert_eq!(game.unit_ids.current(), 950);
        assert_eq!(
            game.nations
                .minor(MinorNationId::new(7))
                .unwrap()
                .consortium_members
                .map(MinorNationId::get),
            [7, 8, 9, 10]
        );
        assert_eq!(game.civilian_units.len(), expected_civilian_count);
        assert!(game.all_humans_finished());
        assert!(!game.turn.in_linear_phase());
        game.reset_turn_flags();
        assert!(
            game.nations
                .majors()
                .take(6)
                .all(|nation| nation.economy().turn_finished)
        );
        assert!(
            !game
                .nations
                .major(MajorNationId::new(6))
                .economy()
                .turn_finished
        );
        game.turn.advance_season();
        assert_eq!(game.turn.economic_turn, 2);
    }

    #[test]
    fn semantic_projection_rejects_missing_major_aggregates() {
        let context = game_context();

        let mut missing_major = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
        missing_major.major_nations.pop();
        assert!(matches!(
            missing_major.game_state(context),
            Err(LegacySaveError::StateProjection(message))
                if message == "major nation slot 6 is absent"
        ));

        let mut missing_city = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
        match &mut missing_city.major_nations[0] {
            LegacyMajorNationState::Auto(nation) => nation.great_power.city = None,
            LegacyMajorNationState::Other(nation) => nation.city = None,
        }
        assert!(matches!(
            missing_city.game_state(context),
            Err(LegacySaveError::StateProjection(message))
                if message == "major nation slot 0 has no city"
        ));
    }

    #[test]
    fn semantic_projection_rejects_nonfinite_population_accumulator() {
        let context = game_context();
        let mut save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
        let city = first_great_power_mut(&mut save).city.as_mut().unwrap();
        city.population.count_float_bits = f32::NAN.to_bits();

        assert!(matches!(
            save.game_state(context),
            Err(LegacySaveError::StateProjection(message))
                if message == "population accumulator is not finite"
        ));
    }

    #[test]
    fn semantic_projection_rejects_unit_id_counter_overflow() {
        let context = game_context();
        let mut save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
        save.simulation.persistent_unit_id_counter = i32::MAX;

        assert!(matches!(
            save.game_state(context),
            Err(LegacySaveError::StateProjection(message))
                if message == "persistent unit ID counter overflows while loading units"
        ));
    }

    #[test]
    fn semantic_projection_preserves_inactive_pending_action_payload() {
        let mut save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
        let prefix = &mut first_great_power_mut(&mut save).prefix;
        prefix.pending_action_status[0] = 0;
        prefix.pending_action_payload_by_action[0] = 0;

        let state = save.game_state(game_context()).unwrap();
        assert_eq!(
            state
                .nations
                .majors()
                .next()
                .unwrap()
                .economy()
                .pending_actions[PendingActionKind::NavyGrowthReward]
                .payload(),
            Some(0)
        );
    }

    #[test]
    fn semantic_projection_rejects_pending_action_payload_below_sentinel() {
        let mut save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
        let prefix = &mut first_great_power_mut(&mut save).prefix;
        prefix.pending_action_payload_by_action[0] = -2;

        assert!(matches!(
            save.game_state(game_context()),
            Err(LegacySaveError::StateProjection(message))
                if message == "pending-action payload -2 is below the -1 sentinel"
        ));
    }

    #[test]
    fn semantic_projection_rejects_invalid_diplomacy_grant_flags() {
        let mut save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
        first_great_power_mut(&mut save)
            .prefix
            .diplomacy_grant_by_nation[0] = -2;

        assert!(matches!(
            save.game_state(game_context()),
            Err(LegacySaveError::UnsupportedDiplomacyGrantFlags {
                nation: 0,
                target: 0,
                entry: -2,
            })
        ));
    }

    #[test]
    fn semantic_projection_rejects_invalid_mission_province_ids() {
        let mut save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
        let LegacyMajorNationState::Auto(nation) = &mut save.major_nations[0] else {
            panic!("first fixture nation is computer-controlled");
        };
        nation.missions[0].army.as_mut().unwrap().present_location = -2;

        assert!(matches!(
            save.game_state(game_context()),
            Err(LegacySaveError::StateProjection(message))
                if message == "province ID -2 is out of range"
        ));
    }

    #[test]
    fn semantic_projection_rejects_unimplemented_serialized_payloads() {
        let mut save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
        save.navy.admirals.push(LegacyAdmiral {
            nation: 0,
            name: String::new(),
            experience: 0,
            ship_index: 0,
        });
        assert!(matches!(
            save.game_state(game_context()),
            Err(LegacySaveError::StateProjection(message))
                if message == "semantic projection of non-empty retail navy relationships is not implemented"
        ));

        let mut save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
        let LegacyMajorNationState::Auto(nation) = &mut save.major_nations[0] else {
            panic!("first fixture nation is computer-controlled");
        };
        nation.missions[8]
            .navy
            .as_mut()
            .unwrap()
            .ship_ordinals
            .push(0);
        assert!(matches!(
            save.game_state(game_context()),
            Err(LegacySaveError::StateProjection(message))
                if message == "semantic projection of navy mission ship ordinal 0 is not implemented"
        ));

        let mut save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
        let city = first_great_power_mut(&mut save).city.as_mut().unwrap();
        city.tasks.push(LegacyCityTask {
            kind: 1,
            payload: vec![0; 8],
        });
        assert!(matches!(
            save.game_state(game_context()),
            Err(LegacySaveError::StateProjection(message))
                if message == "semantic projection of city tasks is not implemented"
        ));

        let mut save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
        let city = first_great_power_mut(&mut save).city.as_mut().unwrap();
        let record_size = city.transport_requests.record_size;
        city.transport_requests
            .records
            .push(vec![0; usize::from(record_size)]);
        assert!(matches!(
            save.game_state(game_context()),
            Err(LegacySaveError::StateProjection(message))
                if message == "semantic projection of city transport requests is not implemented"
        ));

        let mut save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
        let towns = &mut first_great_power_mut(&mut save).post_city.towns;
        let duplicate = towns[0].clone();
        towns.push(duplicate);
        assert!(matches!(
            save.game_state(game_context()),
            Err(LegacySaveError::StateProjection(message))
                if message == "major nation slot 0 has 2 towns; semantic projection supports one city"
        ));
    }

    #[test]
    fn deal_book_projection_reconstructs_retail_sorted_load_order() {
        let mut save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
        let list = &mut first_great_power_mut(&mut save).prefix.relationship_lists[2];
        let record = |kind: i16, nation: i16, amount: i16, eligibility: i16, price: i32| {
            let mut bytes = Vec::with_capacity(12);
            bytes.extend_from_slice(&kind.to_le_bytes());
            bytes.extend_from_slice(&nation.to_le_bytes());
            bytes.extend_from_slice(&amount.to_le_bytes());
            bytes.extend_from_slice(&eligibility.to_le_bytes());
            bytes.extend_from_slice(&price.to_le_bytes());
            bytes
        };
        list.records = vec![record(1, 8, 11, 1, 123), record(0, 0, 22, 0, 456)];

        let state = save.game_state(game_context()).unwrap();
        assert_eq!(
            state
                .nations
                .major(MajorNationId::new(0))
                .economy()
                .deal_book[TradeCommodity::Cotton],
            vec![
                TradeDealBookEntry {
                    kind: DealBookEntryKind::Accept,
                    nation: NationId::new(0),
                    amount: 22,
                    unit_price: 456,
                },
                TradeDealBookEntry {
                    kind: DealBookEntryKind::Offer,
                    nation: NationId::new(8),
                    amount: 11,
                    unit_price: 123,
                },
            ]
        );
    }

    #[test]
    fn rejects_bad_magic_old_versions_and_truncation() {
        let mut bad_magic = RETAIL_FIXTURE.to_vec();
        bad_magic[0] = 0;
        assert!(matches!(
            LegacySaveV62::parse(&bad_magic),
            Err(LegacySaveError::InvalidMagic(_))
        ));

        let mut old = RETAIL_FIXTURE.to_vec();
        old[4..8].copy_from_slice(&0x22_u32.to_le_bytes());
        assert!(matches!(
            LegacySaveV62::parse(&old),
            Err(LegacySaveError::UnsupportedVersion(0x22))
        ));
        assert!(matches!(
            LegacySaveV62::parse(&RETAIL_FIXTURE[..100]),
            Err(LegacySaveError::Truncated { .. })
        ));
        assert!(matches!(
            LegacySaveV62::parse(&[]),
            Err(LegacySaveError::Truncated {
                offset: 0,
                requested: 4,
                remaining: 0,
            })
        ));
    }

    #[test]
    fn rejects_unsupported_tile_transport_link_bits() {
        for (field, bits) in [("transport_links", 0x40), ("pending_rail_links", 0x80)] {
            assert!(matches!(
                decode_tile_transport_links(7, field, bits),
                Err(LegacySaveError::UnsupportedTileTransportLinkBits {
                    tile: 7,
                    field: actual_field,
                    bits: actual_bits,
                }) if actual_field == field && actual_bits == bits
            ));
        }
    }
}
