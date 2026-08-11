use super::*;
use imperialism_core::*;

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
    pub turn_flow_status_flags: u32,
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
    /// Decoded from retail's packed status word at read time.
    pub status: CountryStatus,
    pub unit_name_ordinal_by_type: [i16; 30],
    pub unit_name_counter: i16,
    pub treasury: i32,
    pub home_tile: i32,
    pub overlay_anchor_tile: i32,
    pub need_level_by_nation: [i16; NATION_COUNT],
    pub military_units: Vec<LegacyMilitaryUnit>,
    pub owned_regions: Vec<i32>,
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
    pub pending_actions: PendingActionTable<PendingActionState>,
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
    pub army_movement_budget: i32,
    pub turn_finished_flag: u8,
    pub special_resource_trade_balance: i32,
    pub aid_allocation_total: i32,
    pub colony_boycott_flags: [u8; NATION_COUNT],
    pub military_expenses: i32,
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
    pub(super) const fn great_power(&self) -> &LegacyGreatPowerState {
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
    pub(super) entries: Vec<Option<String>>,
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LegacyTerrainTile {
    pub terrain_kind: i8,
    pub sprite_variant: u8,
    pub region_tile_subtype: i8,
    pub river_sprite: u8,
    pub owner_nation: i8,
    pub former_owner_nation: i8,
    pub secondary_owner_nation: i8,
    pub region: i8,
    pub adjacency_bits: u8,
    pub adjacency_mask_a: u8,
    pub adjacency_mask_b: u8,
    pub city_or_province_index: i16,
    pub development_classes: i8,
    pub pending_development_visibility: u8,
    pub edge_resources: [i8; 2],
    pub rail_flags: u8,
    pub action_state: i8,
    pub active_flags: u16,
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
    pub resource_development_by_type: [i16; 10],
    pub city_score: i32,
    pub explored_by_nation_mask: u8,
    pub region_class: i8,
    pub name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LegacyMapState {
    pub view_origin_tile: i16,
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
