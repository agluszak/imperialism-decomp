#![allow(dead_code)]

use super::*;
use imperialism_core::*;

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

pub(crate) struct LegacyGameSetup {
    pub multiplayer_game_active: u8,
    pub nation_control_modes: [i16; 7],
    pub city_minister_policy_ids: [i16; 7],
    pub foreign_minister_policy_ids: [i16; 7],
    pub defense_minister_policy_ids: [i16; 7],
    pub reload_political_map_state: u8,
    /// Retail stores zero for no scenario and otherwise a one-based scenario index.
    pub scenario_map_index_plus_one: i16,
}

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

pub(crate) struct LegacyTradeMarketRow {
    pub previous_price: i16,
    pub price: i16,
    pub request_count: i16,
    pub offer_count: i16,
    pub adjusted_offer_count: f64,
    pub amount_offered: i16,
    pub base_price: i16,
    pub current_offer_by_nation: [i16; NATION_COUNT],
    pub accumulated_offer_by_nation: [i16; NATION_COUNT],
    pub maximum_offer_by_nation: [i16; NATION_COUNT],
}

pub(crate) struct LegacyTradeMarketState {
    pub rows: [LegacyTradeMarketRow; TRADE_CATEGORY_COUNT],
    pub history: [LegacyFixedRecordList; TRADE_CATEGORY_COUNT],
}

pub(crate) struct LegacyDiplomacyState {
    pub relation_standing_scores: [i16; NATION_COUNT * NATION_COUNT],
    pub relation_propagation_matrix: [i16; NATION_COUNT * NATION_COUNT],
    pub relation_turn_stamp_matrix: [i16; NATION_COUNT * NATION_COUNT],
    pub relation_code_matrix: [i16; super::PROVINCE_COUNT],
    pub pending_policy_code_matrix: [i8; super::PROVINCE_COUNT],
    pub last_diplomatic_effort_turn: i16,
    pub relation_side_effect_matrix: [i16; NATION_COUNT * NATION_COUNT],
    pub congress_leadership: [i16; 2],
    pub congress_support: [i16; 3],
    pub special_relation_source_slots: [i16; MINOR_NATION_COUNT],
    pub special_relation_target_slots: [i16; MINOR_NATION_COUNT],
}

pub(crate) struct LegacyTechnologyState {
    pub priority_slots: [i16; TECHNOLOGY_COUNT],
    pub initial_capability_value_by_nation_and_resource:
        [[i16; RESOURCE_KIND_COUNT]; MAJOR_NATION_COUNT],
    pub tech_selector: i16,
    pub active_zone_index: i16,
    pub per_technology_unlock_flags: [u8; TECHNOLOGY_COUNT],
    pub resource_type_enabled: [u8; 14],
    pub init_flags_1ab: [u8; 30],
    pub init_flags_1c9: [u8; 9],
    pub active_prerequisite_pair: [i16; 2],
    pub nation_capability_slots: [[i16; 10]; MAJOR_NATION_COUNT],
    pub research_status_by_nation: [[u8; TECHNOLOGY_COUNT]; MAJOR_NATION_COUNT],
    pub selected_resource_type_by_nation: [[u8; 14]; MAJOR_NATION_COUNT],
    pub ability_active_by_nation: [[u8; 30]; MAJOR_NATION_COUNT],
    pub university_recruitment_availability: [[u8; 9]; MAJOR_NATION_COUNT],
    pub completion_year_offsets: [[i16; TECHNOLOGY_COUNT]; MAJOR_NATION_COUNT],
    pub capability_value_by_nation_and_resource: [[i16; RESOURCE_KIND_COUNT]; MAJOR_NATION_COUNT],
    pub marker: i16,
}

pub(crate) struct LegacyZone {
    pub display_name: String,
    pub status_code: i16,
    pub tile_or_terrain_id: i32,
    pub seed_nation_id: i16,
    pub active_tile_index: i16,
    pub context_ordinal: i16,
}

pub(crate) struct LegacyPortZone {
    pub zone: LegacyZone,
    pub port_tile_index: i16,
}

pub(crate) struct LegacyOceanState {
    pub zones: Vec<LegacyZone>,
    pub port_zones: Vec<LegacyPortZone>,
    pub route_segments: Vec<[i32; 4]>,
}

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

pub(crate) struct LegacyAdmiral {
    pub nation: i16,
    pub name: String,
    pub experience: i16,
    pub ship_index: i16,
}

pub(crate) struct LegacyTaskForce {
    pub aggression: i32,
    pub order: i32,
    pub target_ordinal: i16,
    pub location_ordinal: i16,
    pub nation: i16,
    pub defeated: u8,
    pub ingot_tile: i16,
    pub ships: Vec<[i16; 2]>,
}

pub(crate) struct LegacyNavyState {
    /// Head-first runtime order, matching canonical snapshot IDs.
    pub ships: Vec<LegacyShip>,
    pub admirals: Vec<LegacyAdmiral>,
    pub task_forces: Vec<LegacyTaskForce>,
}

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

pub(crate) struct LegacyCountryBase {
    pub identity: String,
    pub alternate_identity: String,
    pub nation_slot: i16,
    pub encoded_country_status: i16,
    pub unit_name_ordinal_by_type: [i16; 30],
    pub unit_name_counter: i16,
    pub treasury: i32,
    pub home_tile: i32,
    pub overlay_anchor_tile: i32,
    pub need_level_by_nation: [i16; NATION_COUNT],
    pub military_units: Vec<LegacyMilitaryUnit>,
    pub owned_regions: Vec<i32>,
}
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
    pub turn_event_queue: LegacyFixedRecordList,
    pub proposal_queue: LegacyFixedRecordList,
    pub diplomacy_tracked_slots: [LegacyFixedRecordList; TRADE_CATEGORY_COUNT],
}

pub(crate) struct LegacyFixedRecordList {
    pub record_size: u16,
    pub records: Vec<Vec<u8>>,
}

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

pub(crate) struct LegacyCityTask {
    pub kind: u8,
    pub payload: Vec<u8>,
}

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
    pub orders: LegacyCityOrders,
    pub tasks: Vec<LegacyCityTask>,
    pub transport_requests: LegacyFixedRecordList,
}

pub(crate) struct LegacyProductionOrder {
    pub resource_type_index: i16,
    pub quantity: i16,
    pub limiting_constraint: i16,
    pub tracking_slots: [i16; RESOURCE_KIND_COUNT],
    pub accumulated_value: i32,
}

pub(crate) struct LegacyItemOrder {
    pub order: LegacyProductionOrder,
    pub requested_quantity: i16,
    pub primary_input_resource_id: i16,
    pub secondary_input_resource_id: i16,
    pub production_slot: i16,
}

pub(crate) struct LegacyUnitOrder {
    pub order: LegacyProductionOrder,
    pub primary_input_resource_id: i16,
    pub secondary_input_resource_id: i16,
    pub primary_input_per_unit: i16,
    pub secondary_input_per_unit: i16,
    pub cash_cost_per_unit: i16,
    pub workforce_mode: i16,
    pub specialist_mode: u8,
}

pub(crate) struct LegacyPowerPlantOrder {
    pub order: LegacyProductionOrder,
    pub desired_quantity: i16,
}

pub(crate) struct LegacyCityOrders {
    pub food_processing: LegacyProductionOrder,
    pub items: [LegacyItemOrder; 9],
    pub training: [LegacyProductionOrder; 2],
    pub military_recruitment: [LegacyUnitOrder; 8],
    pub civilian_recruitment: [LegacyUnitOrder; 9],
    pub ships: [LegacyProductionOrder; 8],
    pub transport_capacity: LegacyItemOrder,
    pub power_plant: LegacyPowerPlantOrder,
    pub expansions: [LegacyItemOrder; 7],
    pub population_growth: LegacyProductionOrder,
}

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

pub(crate) struct LegacyDefenseMinisterState {
    pub skill_index: i16,
    pub scalar_fields: [i16; 2],
    pub recruit_order_count_by_type: [i16; 30],
    pub order_weight_by_type: [i16; 30],
    pub thresholds: [i16; 4],
}

pub(crate) struct LegacyGreatPowerMinisters {
    pub foreign: Option<LegacyForeignMinisterState>,
    pub interior: Option<LegacyInteriorMinisterState>,
    pub defense: Option<LegacyDefenseMinisterState>,
}

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

pub(crate) struct LegacyGreatPowerPostCity {
    pub towns: Vec<LegacyTown>,
    pub civilian_units: Vec<LegacyCivilianUnit>,
    /// Unrecovered per-nation bytes. Kept for save layout; not projected into GameState.
    pub candidate_nation_flags: [u8; NATION_COUNT],
    pub diplomacy_budget_base: i32,
    pub escalation_counter: i8,
    pub pending_commitment_cost: i32,
    pub pressure_counter: i8,
    pub army_movement_budget: i32,
    pub turn_finished_flag: u8,
    pub special_resource_trade_balance: i32,
    pub aid_allocation_total: i32,
    /// Unrecovered per-nation bytes. Kept for save layout; not projected into GameState.
    pub colony_boycott_flags: [u8; NATION_COUNT],
    pub military_expenses: i32,
}
pub(crate) struct LegacyAutoGreatPowerPrefix {
    pub action_metric_by_quarter: [i16; 6],
    pub map_node_state_flags: [u8; 0x180],
    pub port_zone_state_flags: [u8; 0x70],
}

pub(crate) struct LegacyGreatPowerState {
    pub country: LegacyCountryBase,
    pub prefix: LegacyGreatPowerPrefix,
    pub ministers: LegacyGreatPowerMinisters,
    pub city: Option<LegacyCityState>,
    pub post_city: LegacyGreatPowerPostCity,
}

pub(crate) struct LegacyAutoGreatPowerState {
    pub great_power: LegacyGreatPowerState,
    pub auto_prefix: LegacyAutoGreatPowerPrefix,
    pub missions: Vec<LegacyMission>,
}

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

pub(crate) struct LegacyHelpState {
    pub index_records: LegacyFixedRecordList,
    pub civilian_completion_counters: [i16; 5],
    pub help_index_ready: i16,
}

pub(crate) struct LegacyArmyMission {
    pub present_location: i16,
    pub required_equipage_bits: [u32; 5],
    /// One-based ordinals in the owning nation's military-unit list.
    pub unit_ordinals: Vec<i16>,
}

pub(crate) struct LegacyNavyMission {
    pub target_zone: i16,
    pub resolved_port_zone: i16,
    pub required_equipage_bits: [u32; 4],
    /// Zero-based ordinals in the global ship list.
    pub ship_ordinals: Vec<i16>,
    pub state: i32,
}

pub(crate) struct LegacyMissionCommon {
    pub source_nation: i16,
    pub state: u8,
    pub importance_bits: u32,
    pub flag: u8,
    pub path_marker: i16,
    pub marker: u8,
}

pub(crate) enum LegacyMission {
    DefendProvince {
        common: LegacyMissionCommon,
        army: LegacyArmyMission,
    },
    AttackProvince {
        common: LegacyMissionCommon,
        army: LegacyArmyMission,
        target_province: i16,
        amassing_province: i16,
    },
    Invade {
        common: LegacyMissionCommon,
        army: LegacyArmyMission,
        target_province: i16,
        amassing_province: i16,
        beachhead: LegacyNavyMission,
    },
    ControlSeaZone {
        common: LegacyMissionCommon,
        navy: LegacyNavyMission,
    },
    Escort {
        common: LegacyMissionCommon,
        navy: LegacyNavyMission,
    },
    ScatteredShips {
        common: LegacyMissionCommon,
        navy: LegacyNavyMission,
    },
    Beachhead {
        common: LegacyMissionCommon,
        navy: LegacyNavyMission,
    },
    BlockadePort {
        common: LegacyMissionCommon,
        navy: LegacyNavyMission,
        blockade_port_zone: i16,
    },
}
pub(crate) struct LegacyTerrainTile {
    pub terrain_kind: i8,
    pub sprite_variant: u8,
    pub river_sprite: u8,
    pub owner_nation: i8,
    pub former_owner_nation: i8,
    pub secondary_owner_nation: i8,
    pub owner_border_mask: u8,
    pub city_border_mask: u8,
    pub water_adjacency_mask: u8,
    pub region: i8,
    pub adjacency_bits: u8,
    pub adjacency_mask_a: u8,
    pub adjacency_mask_b: u8,
    pub city_record_index: i16,
    pub development_classes: i8,
    pub pending_development_visibility: u8,
    pub recruit_search_visited: u8,
    pub per_tile_visited: i8,
    pub marker_slot_index: i8,
    pub edge_resources: [i8; 2],
    pub gate: i8,
    pub rail_flags: u8,
    pub action_state: i8,
    pub tile_action_ordinal: i16,
    pub active_flags: u16,
}
pub(crate) struct LegacyProvince {
    pub owner_nation: i8,
    pub former_owner_nation: i8,
    pub development_stage: i8,
    pub fort_level: i8,
    pub city_tile: i16,
    pub last_turn_tick: i16,
    pub adjacent_region_count: i8,
    pub adjacent_region_ids: [i16; 12],
    pub adjacent_region_anchor_tiles: [i16; 12],
    pub linked_region_count: i8,
    pub secondary_neighbor_tile: i16,
    pub primary_neighbor_tile: i16,
    pub linked_tile_indices: [i16; 32],
    pub resource_development_by_type: [i16; 10],
    pub city_score: i32,
    pub navy_order_reachable: u8,
    pub explored_by_nation_mask: u8,
    pub resource_presence_mask: i8,
    pub region_class: i8,
    pub name: String,
}

pub(crate) struct LegacyMapState {
    pub view_origin_tile: i16,
    pub map_data_ready: u8,
    pub recruit_search_active: u8,
    pub city_score_total: i32,
    pub scenario_tag: String,
    /// The original field is inverted: zero enables horizontal wrapping.
    pub no_horizontal_wrap: u8,
    pub tiles: Vec<LegacyTerrainTile>,
    pub provinces: Vec<LegacyProvince>,
    pub pending_river_mouth_tile: i16,
}
