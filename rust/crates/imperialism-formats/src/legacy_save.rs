use crate::legacy_stream::{LegacyStream, StreamError};
use imperialism_core::{
    ArmyMissionState, AttackMissionState, CityState, CivilianUnitId, CivilianUnitKind,
    CivilianUnitState, CivilianUnitTable, CivilianWorkOrder, DevelopmentLevel, Difficulty,
    DiplomacyGrant, DiplomacyGrantFlags, DiplomacyPolicy, GameState, IndustryActionTable,
    LaborPool, MAJOR_NATION_COUNT, MINOR_NATION_COUNT, MajorNation, MajorNationId,
    MajorNationState, MajorNationTable, MilitaryUnitId, MilitaryUnitKind, MilitaryUnitState,
    MilitaryUnitTable, MinorNation, MinorNationId, MinorNationTable, MissionData, MissionState,
    NATION_COUNT, NationCapacityTable, NationCommonState, NationId, NationPendingWork, NationTable,
    Nations, NavyMissionState, PENDING_ACTION_COUNT, PendingActionTable, PendingWorkState,
    PopulationState, ProductionTable, ProvinceId, ResourceTable, RetailCrtRng, RetailLcg, RngState,
    STRATEGIC_TILE_COUNT, SelectedShip, ShipState, TaskForceState, TileDevelopment, TileId,
    TileOwnerTag, TileState, TileTransportLinks, TradeCommodityTable, TradeMarketRow,
    TradeMarketState, TradePolicyScore, TurnState, WorldState,
};

const SAVE_MAGIC: [u8; 4] = *b"IBMA";
const CURRENT_RETAIL_VERSION: u32 = 0x3e;
const SAVE_LABEL_LENGTH: usize = 0x20;
const ACTIVE_NATION_NAME_LENGTH: usize = 0x20;
const RESOURCE_KIND_COUNT: usize = 23;
const CITY_PRODUCTION_SLOT_COUNT: usize = 16;
const CITY_ORDER_SLOT_COUNT: usize = 61;
const TRADE_CATEGORY_COUNT: usize = 17;
const DIPLOMACY_SERIALIZED_SIZE_V62: usize = 5_460;
const TECH_SERIALIZED_SIZE_V62: usize = 1_914;
const TERRAIN_TILE_SERIALIZED_SIZE: usize = 0x24;
const PROVINCE_COUNT: usize = 0x180;
const PROVINCE_FIXED_SERIALIZED_SIZE: usize = 0xa4;
/// Format-specific ceilings for externally supplied collection lengths.
const MAX_MISSIONS: usize = 1_024;
const MAX_OCEAN_ZONES: usize = 4_096;
const MAX_OCEAN_ROUTES: usize = 4_096;
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
    pub scenario_map_index_plus_one: i16,
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
    pub scenario_map_index_plus_one: i32,
    pub persistent_unit_id_counter: i32,
    pub nation_availability: [u8; NATION_COUNT],
    pub saved_multiplayer_role: i32,
    pub preference_slot_10: i16,
    pub selected_asset_set: i16,
    pub starting_year: i16,
    pub phase_state_by_decade: [u8; 12],
    pub nation_names: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct LegacySaveV62 {
    header: LegacySaveHeader,
    simulation: LegacySimulationPrefix,
    animator_idle_frequency: i32,
    market: TradeMarketState,
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
                Ok(MilitaryUnitState {
                    id: MilitaryUnitId::new(unit.persistent_id),
                    nation,
                    unit_type,
                    stationed_province: unit.stationed_province,
                    order: unit.order,
                    order_target: unit.order_target,
                    owner_nation: nation_id_from_retail_i16(unit.owner_nation)?,
                    roster_id: unit.roster_id,
                    registered: unit.registered != 0,
                    order_target_tiles: unit.order_target_tiles,
                    order_target_mirrors: unit.order_target_mirrors,
                    name: unit.name.clone(),
                    strength: unit.strength,
                    era: unit.era,
                    experience: unit.experience,
                    battle_flags: unit.battle_flags,
                })
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
    pub stock_by_type: [i16; RESOURCE_KIND_COUNT],
    pub production_orders: [i16; CITY_PRODUCTION_SLOT_COUNT],
    pub production_accum: [i16; CITY_PRODUCTION_SLOT_COUNT],
    pub unmet_resource_retries: [i16; RESOURCE_KIND_COUNT],
    pub reserved_by_type: [i16; RESOURCE_KIND_COUNT],
    pub production_current: [i16; CITY_PRODUCTION_SLOT_COUNT],
    pub production_progress: [i16; CITY_PRODUCTION_SLOT_COUNT],
    pub consumed_production_input_by_type: [i16; RESOURCE_KIND_COUNT],
    pub rolling_item_production_score: i32,
    pub population: LegacyPopulationState,
    /// Serialized payloads for the 47 constructed entries in the 61-slot table.
    pub production_order_payloads: Vec<(u8, Vec<u8>)>,
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
                Ok(CivilianUnitState {
                    id: CivilianUnitId::new(unit.persistent_id),
                    nation,
                    unit_type,
                    tile: optional_tile_id(i32::from(unit.tile_index)),
                    order: civilian_work_order(unit.order)?,
                    order_target: optional_tile_id(i32::from(unit.order_target)),
                    owner_nation: nation_id_from_retail_i16(unit.owner_nation)?,
                    roster_id: unit.roster_id,
                    registered: unit.registered != 0,
                    remaining_turns: unit.remaining_turns,
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
        queue_index: u32,
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
                units.push(MilitaryUnitId::new(unit.persistent_id));
            }
            Some(ArmyMissionState {
                present_location: army.present_location,
                required_equipage_bits: army.required_equipage_bits,
                units,
            })
        } else {
            None
        };
        let navy = self.navy.as_ref().map(navy_mission_state);
        let beachhead = self.beachhead.as_ref().map(navy_mission_state);
        let attack = self
            .target_province
            .zip(self.amassing_province)
            .zip(army.clone())
            .map(
                |((target_province, amassing_province), army)| AttackMissionState {
                    army,
                    target_province,
                    amassing_province,
                },
            );
        let data = match self.class.as_str() {
            "TDefendProvinceMission" => {
                MissionData::DefendProvince(required_state(army, "defend-province army mission")?)
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
            "TBlockadePortMission" => MissionData::BlockadePort {
                navy: required_state(navy, "blockade-port navy mission")?,
                port_zone: required_state(self.blockade_port_zone, "blockade port zone")?,
            },
            "TBeachheadMission" => {
                MissionData::Beachhead(required_state(navy, "beachhead navy mission")?)
            }
            class => {
                return Err(LegacySaveError::StateProjection(format!(
                    "unsupported mission class {class}"
                )));
            }
        };
        Ok(MissionState {
            nation,
            queue_index,
            data,
            source_nation: self.source_nation,
            path_marker: self.path_marker,
            state: self.state,
            importance_bits: self.importance_bits,
            marker: self.marker,
        })
    }
}

fn navy_mission_state(mission: &LegacyNavyMission) -> NavyMissionState {
    NavyMissionState {
        target_zone: mission.target_zone,
        resolved_port_zone: mission.resolved_port_zone,
        // These two fields are deliberately rebuilt as null by TNavyMission::ReadFrom.
        selected_ship: None,
        task_force: None,
        state: mission.state,
        required_equipage_bits: mission.required_equipage_bits,
        ships: mission
            .ship_ordinals
            .iter()
            .map(|ordinal| SelectedShip {
                ship: imperialism_core::ShipId::new(*ordinal as u32),
                selected: false,
            })
            .collect(),
    }
}

impl LegacyCityState {
    fn city_state(&self, home_town_tile: Option<TileId>) -> CityState {
        CityState {
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
            order_count_by_type: IndustryActionTable::from_array(self.order_count_by_type),
            rolling_item_production_score: self.rolling_item_production_score,
            low_production: self.low_production != 0,
            low_stock: self.low_stock != 0,
            reserved_by_type: ResourceTable::from_array(self.reserved_by_type),
            home_town_tile,
            power_available: self.power_available,
            stock_by_type: ResourceTable::from_array(self.stock_by_type),
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
            population: PopulationState {
                count: self.population.count,
                count_float_bits: self.population.count_float_bits,
                strength: self.population.strength,
                extra: self.population.extra,
                phase_value: self.population.phase_value,
                baseline_labor: LaborPool::from(self.population.baseline_labor),
                production_labor: LaborPool::from(self.population.production_labor),
                pending_labor_delta: LaborPool::from(self.population.pending_labor_delta),
                predicted_need_by_resource: ResourceTable::from_array(
                    self.population.predicted_need_by_resource,
                ),
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LegacyTerrainTile {
    pub terrain_kind: i8,
    pub owner_nation: i8,
    pub former_owner_nation: i8,
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
            terrain_kind: self.terrain_kind,
            owner_nation: optional_tile_owner_tag(self.owner_nation),
            former_owner_nation: optional_tile_owner_tag(self.former_owner_nation),
            province: optional_province_id(self.city_or_province_index),
            development: TileDevelopment {
                surface: DevelopmentLevel::new((self.development_classes as u8) & 0x0f),
                extractive: DevelopmentLevel::new((self.development_classes as u8) >> 4),
                resource_visible_to_majors: MajorNationTable::from_fn(|nation| {
                    self.pending_development_visibility & (1 << nation.get()) != 0
                }),
            },
            edge_resources: self
                .edge_resources
                .map(|resource| (resource >= 0).then_some(resource)),
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
            action_state: i16::from(self.action_state),
            active_flags: self.active_flags,
            region_marker: -1,
            river_sprite_code: 0,
        })
    }
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

fn optional_tile_owner_tag(value: i8) -> Option<TileOwnerTag> {
    u8::try_from(value).ok().map(TileOwnerTag::new)
}

fn optional_province_id(value: i16) -> Option<ProvinceId> {
    u16::try_from(value).ok().map(ProvinceId::new)
}

fn optional_tile_id(value: i32) -> Option<TileId> {
    u16::try_from(value).ok().map(TileId::new)
}

fn civilian_work_order(value: i32) -> Result<CivilianWorkOrder, LegacySaveError> {
    let order = match value {
        0 => CivilianWorkOrder::Idle,
        1 => CivilianWorkOrder::Redeploy,
        2 => CivilianWorkOrder::Sleep,
        5 => CivilianWorkOrder::LayRail,
        6 => CivilianWorkOrder::BuildDepot,
        7 => CivilianWorkOrder::BuildPort,
        8 => CivilianWorkOrder::Prospect,
        10 => CivilianWorkOrder::DevelopResource,
        12 => CivilianWorkOrder::BuildFort,
        13 => CivilianWorkOrder::PurchaseLand,
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
    fn world_state(&self) -> Result<WorldState, LegacySaveError> {
        Ok(WorldState {
            wraps_horizontally: self.no_horizontal_wrap == 0,
            tiles: self
                .tiles
                .iter()
                .copied()
                .enumerate()
                .map(|(tile, terrain)| terrain.tile_state(tile))
                .collect::<Result<_, _>>()?,
        })
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
    #[error("{context}: count {value} exceeds maximum {maximum}")]
    InvalidCount {
        context: &'static str,
        value: i32,
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
                value: i32::try_from(value).unwrap_or(i32::MAX),
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
            value,
            maximum,
        });
    };
    if count > maximum {
        return Err(LegacySaveError::InvalidCount {
            context,
            value,
            maximum,
        });
    }
    Ok(count)
}

fn bounded_usize(
    value: usize,
    maximum: usize,
    context: &'static str,
) -> Result<usize, LegacySaveError> {
    if value > maximum {
        return Err(LegacySaveError::InvalidCount {
            context,
            value: i32::try_from(value).unwrap_or(i32::MAX),
            maximum,
        });
    }
    Ok(value)
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
        let scenario_map_index_plus_one = i32::from(game_setup.scenario_map_index_plus_one);
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
        let starting_year = stream.read_le_i16()?;
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
            scenario_map_index_plus_one,
            persistent_unit_id_counter,
            nation_availability,
            saved_multiplayer_role,
            preference_slot_10,
            selected_asset_set,
            starting_year,
            phase_state_by_decade,
            nation_names,
        };
        let animator_idle_frequency = stream.read_le_i32()?;
        let market = read_trade_market(&mut stream)?;
        stream.skip(DIPLOMACY_SERIALIZED_SIZE_V62)?;
        stream.skip(TECH_SERIALIZED_SIZE_V62)?;
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
    pub fn world_state(&self) -> Result<WorldState, LegacySaveError> {
        self.map.world_state()
    }

    /// Projects the fully decoded save directly into live semantic state.
    /// Runtime-only RNG and selection state must be supplied by the process that loaded
    /// the save because the retail stream does not contain them.
    pub fn game_state(
        &self,
        context: LegacyGameStateContext,
    ) -> Result<GameState, LegacySaveError> {
        if !self.navy.ships.is_empty() || !self.navy.task_forces.is_empty() {
            return Err(LegacySaveError::StateProjection(
                "semantic projection of non-empty retail navy relationships is not implemented"
                    .to_owned(),
            ));
        }

        let mut majors = MajorNationTable::default();
        let mut minors = MinorNationTable::default();
        let mut military_units = Vec::new();
        let mut civilian_units = Vec::new();
        let mut missions = Vec::new();
        for slot in 0..7 {
            let major_id = MajorNationId::new(slot as u8);
            let nation_id = major_id.nation();
            let nation = self
                .major_nations
                .iter()
                .find(|nation| nation.great_power().country.nation_slot == slot as i16);
            let Some(nation) = nation else {
                continue;
            };
            let great_power = nation.great_power();
            let city = great_power.city.as_ref().map(|city| {
                let home_town = great_power
                    .post_city
                    .towns
                    .first()
                    .map_or(great_power.country.home_tile, |town| {
                        i32::from(town.tile_index)
                    });
                city.city_state(optional_tile_id(home_town))
            });
            majors[major_id] = Some(MajorNation {
                common: country_common(&great_power.country),
                state: major_nation_rule_state(great_power)?,
                city,
            });
            military_units.extend(great_power.country.military_unit_states(nation_id)?);
            civilian_units.extend(great_power.post_city.civilian_unit_states(nation_id)?);
            if let LegacyMajorNationState::Auto(auto) = nation {
                for (queue_index, mission) in auto.missions.iter().enumerate() {
                    missions.push(mission.mission_state(
                        nation_id,
                        queue_index as u32,
                        &great_power.country.military_units,
                    )?);
                }
            }
        }
        for slot in 7..NATION_COUNT {
            let minor_id = MinorNationId::new(slot as u8);
            if let Some(nation) = self
                .minor_nations
                .iter()
                .find(|nation| nation.country.nation_slot == slot as i16)
            {
                minors[minor_id] = Some(MinorNation {
                    common: country_common(&nation.country),
                });
                military_units.extend(
                    nation
                        .country
                        .military_unit_states(NationId::new(slot as u8))?,
                );
            }
        }

        for nation in &self.major_nations {
            let slot = nation.great_power().country.nation_slot;
            let lists = &nation.great_power().prefix.relationship_lists;
            if !lists[0].records.is_empty() || !lists[1].records.is_empty() {
                return Err(LegacySaveError::StateProjection(format!(
                    "pending event projection is not implemented for nation {slot}"
                )));
            }
        }
        let pending_nations = MajorNationTable::from_fn(|_nation| NationPendingWork {
            turn_events: Vec::new(),
            proposals: Vec::new(),
            turn_summary: Vec::new(),
            turn_start_events: Vec::new(),
        });

        // The retail load path restores this counter before deserializing units.
        // Every TUnit constructor increments it once, even though ReadFrom then
        // replaces the unit's generated ID with the persisted ID.
        let loaded_unit_count = military_units.len() + civilian_units.len();
        let persistent_unit_id_counter = self.simulation.persistent_unit_id_counter
            + i32::try_from(loaded_unit_count).expect("loaded unit count fits the game counter");

        Ok(GameState {
            turn: TurnState {
                scenario_map_index_plus_one: self.simulation.scenario_map_index_plus_one,
                economic_turn: i32::from(self.simulation.economic_turn),
                phase_code: i32::from(self.simulation.turn_state_code),
                difficulty: Difficulty::try_from(self.simulation.difficulty).map_err(|_| {
                    LegacySaveError::StateProjection(format!(
                        "invalid difficulty {}",
                        self.simulation.difficulty
                    ))
                })?,
                active_nation: nation_id_from_retail_i16(self.simulation.active_nation)?,
                selected_nation: context.selected_nation,
            },
            persistent_unit_id_counter,
            world: self.map.world_state()?,
            rng: RngState {
                crt_rand: RetailCrtRng::from_state(context.crt_rand_state),
                map_generation: RetailLcg::from_state(context.map_generation_lcg),
                zone_status: RetailLcg::from_state(context.zone_status_lcg),
            },
            market: self.market.clone(),
            nations: Nations { majors, minors },
            military_units,
            civilian_units,
            ships: Vec::<ShipState>::new(),
            task_forces: Vec::<TaskForceState>::new(),
            missions,
            pending: PendingWorkState {
                nations: pending_nations,
                war_transitions: Vec::new(),
            },
        })
    }
}

fn major_nation_rule_state(
    nation: &LegacyGreatPowerState,
) -> Result<MajorNationState, LegacySaveError> {
    let prefix = &nation.prefix;
    let post = &nation.post_city;
    Ok(MajorNationState {
        diplomacy_eligible: prefix.diplomacy_eligible != 0,
        capacities: NationCapacityTable::from_array(prefix.capacities),
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
        pending_action_status: PendingActionTable::from_array(prefix.pending_action_status),
        pending_action_payload_by_action: PendingActionTable::from_array(
            prefix.pending_action_payload_by_action,
        ),
        diplomacy_budget_base: post.diplomacy_budget_base,
        escalation_counter: i16::from(post.escalation_counter),
        pending_commitment_cost: post.pending_commitment_cost,
        pressure_counter: i16::from(post.pressure_counter),
        aid_allocation_total: post.aid_allocation_total,
        colony_boycott_flags: NationTable::from_array(post.colony_boycott_flags),
        military_expenses: post.military_expenses,
    })
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
            let flags = if entry & 0x4000 != 0 {
                DiplomacyGrantFlags::RECURRING
            } else {
                DiplomacyGrantFlags::empty()
            };
            Some(DiplomacyGrant {
                amount: i32::from(entry & 0x3fff),
                flags,
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
            0x12d => Some(DiplomacyPolicy::JoinEmpire),
            0x12e => Some(DiplomacyPolicy::Alliance),
            0x12f => Some(DiplomacyPolicy::NonAggressionPact),
            0x130 => Some(DiplomacyPolicy::PeaceTreaty),
            0x131 => Some(DiplomacyPolicy::DeclareWar),
            0x132 => Some(DiplomacyPolicy::JoinEmpireWithWarEntanglements),
            0x133 => Some(DiplomacyPolicy::BuildConsulate),
            0x134 => Some(DiplomacyPolicy::BuildEmbassy),
            _ => {
                return Err(LegacySaveError::UnsupportedDiplomacyPolicy {
                    nation,
                    target,
                    entry,
                });
            }
        };
    }
    Ok(policies)
}

fn country_common(country: &LegacyCountryBase) -> NationCommonState {
    NationCommonState {
        treasury: country.treasury,
        home_tile: optional_tile_id(country.home_tile),
        trade_policy_by_nation: NationTable::from_array(
            country
                .need_level_by_nation
                .map(|score| TradePolicyScore::new(i32::from(score))),
        ),
    }
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
    let count = bounded_usize(count as usize, MAX_MISSIONS, "AI mission queue")?;
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

fn read_trade_market(stream: &mut LegacyStream<'_>) -> Result<TradeMarketState, LegacySaveError> {
    let rows: [TradeMarketRow; TRADE_CATEGORY_COUNT] = (0..TRADE_CATEGORY_COUNT)
        .map(|_| read_trade_market_row(stream))
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .expect("one market row per trade commodity");
    for _ in 0..TRADE_CATEGORY_COUNT {
        let record_size = usize::from(stream.read_le_u16()?);
        let record_count = bounded_usize(
            stream.read_le_u32()? as usize,
            MAX_TRADE_HISTORY_RECORDS,
            "trade history",
        )?;
        let byte_len =
            record_size
                .checked_mul(record_count)
                .ok_or(LegacySaveError::InvalidCount {
                    context: "trade history byte length",
                    value: i32::MAX,
                    maximum: MAX_TRADE_HISTORY_RECORDS,
                })?;
        stream.skip(byte_len)?;
    }
    Ok(TradeMarketState {
        rows: TradeCommodityTable::from_array(rows),
    })
}

fn read_trade_market_row(stream: &mut LegacyStream<'_>) -> Result<TradeMarketRow, StreamError> {
    let previous_price = i32::from(stream.read_le_i16()?);
    let price = i32::from(stream.read_le_i16()?);
    let request_count = i32::from(stream.read_le_i16()?);
    let offer_count = i32::from(stream.read_le_i16()?);
    let adjusted_offer_count = f64::from_le_bytes(stream.read_bytes(8)?.try_into().unwrap());
    let amount_offered = i32::from(stream.read_le_i16()?);
    let base_price = i32::from(stream.read_le_i16()?);
    // The three per-nation offer-history cells are not represented by the price slice.
    for _ in 0..3 {
        stream.skip(RESOURCE_KIND_COUNT * std::mem::size_of::<i16>())?;
    }
    Ok(TradeMarketRow {
        previous_price,
        price,
        base_price,
        request_count,
        offer_count,
        amount_offered,
        adjusted_offer_count,
    })
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
    let zone_count = bounded_usize(
        usize::from(stream.read_le_u16()?),
        MAX_OCEAN_ZONES,
        "ocean zones",
    )?;
    let zones = (0..zone_count)
        .map(|_| read_zone(stream, false))
        .collect::<Result<Vec<_>, _>>()?;
    let port_zone_count = bounded_usize(
        usize::from(stream.read_le_u16()?),
        MAX_OCEAN_ZONES,
        "ocean port zones",
    )?;
    let port_zones = (0..port_zone_count)
        .map(|_| read_zone(stream, true))
        .collect::<Result<Vec<_>, _>>()?;
    let route_count = bounded_usize(
        usize::from(stream.read_le_u16()?),
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
    let ship_count = bounded_usize(usize::from(stream.read_le_u16()?), MAX_SHIPS, "navy ships")?;
    let mut ships = (0..ship_count)
        .map(|_| read_ship(stream))
        .collect::<Result<Vec<_>, _>>()?;
    ships.reverse();
    let admiral_count = bounded_usize(
        usize::from(stream.read_le_u16()?),
        MAX_ADMIRALS,
        "navy admirals",
    )?;
    let admirals = (0..admiral_count)
        .map(|_| read_admiral(stream))
        .collect::<Result<Vec<_>, _>>()?;
    let task_force_count = bounded_usize(
        usize::from(stream.read_le_u16()?),
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
    let child_count = bounded_usize(
        usize::from(stream.read_le_u16()?),
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
    bounded_usize(usize::from(report_count), MAX_ARMY_REPORTS, "army reports")?;
    for _ in 0..report_count {
        stream.skip(8)?;
        for _ in 0..2 {
            stream.skip(1 + 0x20 + 0xff)?;
            let child_count = bounded_usize(
                usize::from(stream.read_le_u16()?),
                MAX_MILITARY_UNITS,
                "army report children",
            )?;
            let byte_len = child_count
                .checked_mul(42)
                .ok_or(LegacySaveError::InvalidCount {
                    context: "army report children byte length",
                    value: i32::MAX,
                    maximum: MAX_MILITARY_UNITS,
                })?;
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
    let military_unit_count = bounded_usize(
        stream.read_le_u32()? as usize,
        MAX_MILITARY_UNITS,
        "country military units",
    )?;
    let military_units = (0..military_unit_count)
        .map(|_| read_military_unit(stream))
        .collect::<Result<Vec<_>, _>>()?;

    // TLongintList::NoOpReadFrom is likewise a no-op.
    let owned_region_count = bounded_usize(
        stream.read_le_u32()? as usize,
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

fn read_city(stream: &mut LegacyStream<'_>) -> Result<LegacyCityState, StreamError> {
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
    let stock_by_type = read_be_short_array(stream)?;
    let production_orders = read_be_short_array(stream)?;
    let production_accum = read_be_short_array(stream)?;
    let unmet_resource_retries = read_be_short_array(stream)?;
    let reserved_by_type = read_be_short_array(stream)?;
    let production_current = read_be_short_array(stream)?;
    let production_progress = read_be_short_array(stream)?;
    let consumed_production_input_by_type = read_be_short_array(stream)?;
    let rolling_item_production_score = stream.read_le_i32()?;
    let population = read_population(stream)?;

    let mut production_order_payloads = Vec::new();
    for slot in 0..CITY_ORDER_SLOT_COUNT {
        if let Some(length) = city_order_payload_size(slot) {
            production_order_payloads.push((slot as u8, stream.read_bytes(length)?.to_vec()));
        }
    }

    // TTaskList's inherited TSortedList stream hook is a no-op.
    let task_count = stream.read_le_u32()? as usize;
    if task_count > MAX_CITY_TASKS {
        return Err(StreamError::InvalidCount {
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
        stock_by_type,
        production_orders,
        production_accum,
        unmet_resource_retries,
        reserved_by_type,
        production_current,
        production_progress,
        consumed_production_input_by_type,
        rolling_item_production_score,
        population,
        production_order_payloads,
        tasks,
        transport_requests,
    })
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

const fn city_order_payload_size(slot: usize) -> Option<usize> {
    match slot {
        7 | 23 | 24 | 43..=50 | 60 => Some(58),
        8..=16 | 51 | 53..=59 => Some(66),
        25..=32 | 34..=42 => Some(71),
        52 => Some(60),
        _ => None,
    }
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

fn read_army_mission(stream: &mut LegacyStream<'_>) -> Result<LegacyArmyMission, StreamError> {
    let present_location = stream.read_le_i16()?;
    let required_equipage_bits = read_be_u32_array(stream)?;
    let count = stream.read_le_i16()?;
    if count < 0 {
        return Err(StreamError::Truncated {
            offset: stream.position() - 2,
            requested: count.unsigned_abs() as usize,
            remaining: 0,
        });
    }
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
        former_owner_nation: bytes[3] as i8,
        owner_nation: bytes[4] as i8,
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
    let scenario_map_index_plus_one = stream.read_le_i16()?;
    Ok(LegacyGameSetup {
        multiplayer_game_active,
        nation_control_modes,
        city_minister_policy_ids,
        foreign_minister_policy_ids,
        defense_minister_policy_ids,
        reload_political_map_state,
        scenario_map_index_plus_one,
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
        assert_eq!(save.simulation.starting_year, 1914);
        assert_eq!(imperialism_core::TurnCalendar::new(1914, 1).year(), 1914);
        assert_eq!(imperialism_core::TurnCalendar::new(1914, 1).quarter(), 1);
        assert_eq!(save.simulation.nation_names[0], "Zimm");
        assert_eq!(save.simulation.nation_names[6], " Testland");
        assert_eq!(save.simulation.nation_names[22], "Sindel");
        assert_eq!(save.animator_idle_frequency, 2);
        assert_eq!(
            save.market.rows[imperialism_core::TradeCommodity::Cotton],
            TradeMarketRow {
                previous_price: 100,
                price: 100,
                base_price: 100,
                request_count: 0,
                offer_count: 0,
                amount_offered: 0,
                adjusted_offer_count: 0.0,
            }
        );
        assert_eq!(
            save.market.rows[imperialism_core::TradeCommodity::Arms].base_price,
            900
        );
        assert_eq!(save.map.tiles.len(), 6480);
        assert_eq!(save.map.provinces.len(), 384);
        assert_eq!(save.map.no_horizontal_wrap, 0);
        assert_eq!(save.map.tiles[0].terrain_kind, 5);
        assert_eq!(save.map.tiles[0].owner_nation, 82);
        let world = save.world_state().unwrap();
        assert_eq!(world.tiles.len(), 6480);
        assert!(world.wraps_horizontally);
        assert_eq!(world.tiles[0].terrain_kind, 5);
        assert_eq!(world.tiles[0].owner_nation, Some(TileOwnerTag::new(82)));
        assert!(!save.ocean.zones.is_empty());
        assert!(save.navy.ships.is_empty());
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
        assert_eq!(unit_states[0].id.get(), 275);
        assert_eq!(unit_states[0].unit_type, MilitaryUnitKind::Minutemen);
        assert_eq!(unit_states[0].order_target_tiles, [79; 3]);
        assert_eq!(unit_states[26].id.get(), 301);
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
        assert_eq!(city.production_order_payloads.len(), 47);
        assert!(city.tasks.is_empty());
        assert_eq!(city.transport_requests.record_size, 4);
        assert_eq!(city.population.count, 7);
        assert_eq!(city.population.strength, 12);
        assert_eq!(city.population.baseline_labor, [4, 2, 1]);
        assert_eq!(city.stock_by_type[7..16], [20, 10, 24, 8, 19, 0, 5, 5, 0]);
        assert_eq!(
            city.production_orders[7..16],
            [999, 999, 999, 999, 0, 0, 999, 999, 0]
        );
        assert_eq!(city_suffix_offset, 0x4fbf6);

        let city_state = city.city_state(Some(TileId::new(3_494)));
        assert_eq!(city_state.home_town_tile, Some(TileId::new(3_494)));
        assert_eq!(city_state.population.count_float_bits, 1_088_421_888);

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
                    .mission_state(
                        NationId::new(0),
                        queue_index as u32,
                        &country.military_units,
                    )
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let MissionData::DefendProvince(army) = &mission_states[0].data else {
            panic!("first mission is not defend province");
        };
        assert!(army.units.is_empty());
        let MissionData::ControlSeaZone(navy) = &mission_states[8].data else {
            panic!("ninth mission is not control sea zone");
        };
        assert_eq!(navy.selected_ship, None);
        assert_eq!(mission_states[10].importance_bits, 981_668_463);

        let mut archive = LegacyMfcArchiveState::default();
        let mut nation_offset = save.remaining_manager_chain_offset;
        let mut global_mission_index = 0_u32;
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
                        queue_index as u32,
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
        assert_eq!(game.civilian_units[0].nation, NationId::new(0));
        assert_eq!(
            game.civilian_units[0].id.get(),
            save.major_nations[0].great_power().post_city.civilian_units[0].persistent_id
        );
        assert_eq!(game.missions.len(), 66);
        assert_eq!(game.persistent_unit_id_counter, 950);
        assert_eq!(game.civilian_units.len(), expected_civilian_count);
        assert!(game.all_humans_finished().unwrap());
        assert!(!game.turn.in_linear_phase());
        game.reset_turn_flags().unwrap();
        assert!(
            game.nations
                .majors
                .iter()
                .take(6)
                .all(|nation| { nation.as_ref().unwrap().state.turn_finished })
        );
        assert!(
            !game
                .nations
                .major(MajorNationId::new(6))
                .unwrap()
                .state
                .turn_finished
        );
        game.turn.advance_season();
        assert_eq!(game.turn.economic_turn, 2);
        assert_eq!(
            game.request_next_phase().events,
            vec![imperialism_core::GameEvent::PhaseAdvanceRequested]
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
