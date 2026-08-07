use crate::legacy_stream::{LegacyStream, StreamError};
use imperialism_core::{
    STRATEGIC_MAP_HEIGHT, STRATEGIC_MAP_WIDTH, STRATEGIC_TILE_COUNT, SnapshotWorld, TileSnapshot,
    TurnCalendar,
};
use std::fmt;

const SAVE_MAGIC: [u8; 4] = *b"IBMA";
const MINIMUM_SUPPORTED_VERSION: u32 = 0x23;
const CURRENT_RETAIL_VERSION: u32 = 0x3e;
const SAVE_LABEL_LENGTH: usize = 0x20;
const ACTIVE_NATION_NAME_LENGTH: usize = 0x20;
const NATION_COUNT: usize = 23;
const RESOURCE_KIND_COUNT: usize = 23;
const AID_ALLOCATION_COUNT: usize = 0x170;
const PENDING_ACTION_COUNT: usize = 13;
const TRADE_CATEGORY_COUNT: usize = 17;
const TRADE_CATEGORY_SERIALIZED_SIZE: usize = 158;
const DIPLOMACY_SERIALIZED_SIZE_V62: usize = 5_460;
const TECH_SERIALIZED_SIZE_V62: usize = 1_914;
const TERRAIN_TILE_SERIALIZED_SIZE: usize = 0x24;
const PROVINCE_COUNT: usize = 0x180;
const PROVINCE_FIXED_SERIALIZED_SIZE: usize = 0xa4;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacySaveHeader {
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
pub struct LegacyGameSetup {
    pub multiplayer_game_active: u8,
    pub nation_control_modes: [i16; 7],
    pub city_minister_policy_ids: [i16; 7],
    pub foreign_minister_policy_ids: [i16; 7],
    pub defense_minister_policy_ids: [i16; 7],
    pub reload_political_map_state: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacySimulationPrefix {
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
    pub scenario_map_index_plus_one: i32,
    pub nation_availability: [u8; NATION_COUNT],
    pub saved_multiplayer_role: i32,
    pub preference_slot_10: i16,
    pub selected_asset_set: i16,
    pub starting_year: i16,
    pub phase_state_by_decade: [u8; 12],
    pub nation_names: Vec<String>,
}

impl LegacySimulationPrefix {
    pub const fn calendar(&self) -> TurnCalendar {
        TurnCalendar::new(self.starting_year, self.economic_turn)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacySaveV62 {
    pub header: LegacySaveHeader,
    pub simulation: LegacySimulationPrefix,
    pub animator_idle_frequency: i32,
    pub map: LegacyMapState,
    pub ocean: LegacyOceanState,
    pub navy: LegacyNavyState,
    pub army_report_count: u16,
    /// Byte position immediately after `TArmyMgr`; nation records start here.
    pub remaining_manager_chain_offset: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyZone {
    pub display_name: String,
    pub status_code: i16,
    pub tile_or_terrain_id: i32,
    pub seed_nation_id: i16,
    pub active_tile_index: i16,
    pub context_ordinal: i16,
    pub port_tile_index: Option<i16>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyOceanState {
    pub zones: Vec<LegacyZone>,
    pub port_zones: Vec<LegacyZone>,
    pub route_segments: Vec<[i32; 4]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyShip {
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
pub struct LegacyAdmiral {
    pub nation: i16,
    pub name: String,
    pub experience: i16,
    pub ship_index: i16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyTaskForce {
    pub aggression: i32,
    pub order: i32,
    pub target_ordinal: i16,
    pub location_ordinal: i16,
    pub nation: i16,
    pub ingot_tile: i16,
    pub ships: Vec<[i16; 2]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyNavyState {
    /// Head-first runtime order, matching canonical snapshot IDs.
    pub ships: Vec<LegacyShip>,
    pub admirals: Vec<LegacyAdmiral>,
    pub task_forces: Vec<LegacyTaskForce>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyMilitaryUnit {
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
pub struct LegacyCountryBase {
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyGreatPowerPrefix {
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
    pub aid_allocation_matrix: [i32; AID_ALLOCATION_COUNT],
    pub pending_action_status: [i8; PENDING_ACTION_COUNT],
    pub pending_action_payload_by_action: [i16; PENDING_ACTION_COUNT],
    pub relationship_lists: Vec<LegacyFixedRecordList>,
    pub minister_presence_mask: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyFixedRecordList {
    pub record_size: u16,
    pub records: Vec<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LegacyTerrainTile {
    pub terrain_kind: i8,
    pub owner_nation: i8,
    pub former_owner_nation: i8,
    pub city_or_province_index: i16,
    pub development_classes: i8,
    pub edge_resources: [i8; 2],
    pub rail_flags: u8,
    pub action_state: i8,
    pub active_flags: u16,
}

impl LegacyTerrainTile {
    fn snapshot(self) -> TileSnapshot {
        TileSnapshot([
            i64::from(self.terrain_kind),
            i64::from(self.owner_nation),
            i64::from(self.former_owner_nation),
            i64::from(self.city_or_province_index),
            i64::from(self.development_classes),
            i64::from(self.edge_resources[0]),
            i64::from(self.edge_resources[1]),
            i64::from(self.rail_flags),
            i64::from(self.action_state),
            i64::from(self.active_flags),
        ])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyProvince {
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
pub struct LegacyMapState {
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
    pub fn snapshot_world(&self) -> SnapshotWorld {
        SnapshotWorld {
            width: STRATEGIC_MAP_WIDTH,
            height: STRATEGIC_MAP_HEIGHT,
            wrap: i32::from(self.no_horizontal_wrap),
            tiles: self
                .tiles
                .iter()
                .copied()
                .map(LegacyTerrainTile::snapshot)
                .collect(),
        }
    }
}

#[derive(Debug)]
pub enum LegacySaveError {
    Stream(StreamError),
    InvalidMagic([u8; 4]),
    UnsupportedVersion(u32),
    UnsupportedMultiplayerRole(i32),
}

impl fmt::Display for LegacySaveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stream(error) => error.fmt(formatter),
            Self::InvalidMagic(magic) => {
                write!(formatter, "invalid Imperialism save magic {magic:?}")
            }
            Self::UnsupportedVersion(version) => write!(
                formatter,
                "unsupported Imperialism save version {version:#x}; expected {MINIMUM_SUPPORTED_VERSION:#x}..={CURRENT_RETAIL_VERSION:#x}"
            ),
            Self::UnsupportedMultiplayerRole(role) => write!(
                formatter,
                "multiplayer save role {role} requires the game-flow manager DTO before the simulation suffix can be located"
            ),
        }
    }
}

impl std::error::Error for LegacySaveError {}

impl From<StreamError> for LegacySaveError {
    fn from(value: StreamError) -> Self {
        Self::Stream(value)
    }
}

impl LegacySaveV62 {
    pub fn parse(bytes: &[u8]) -> Result<Self, LegacySaveError> {
        let mut stream = LegacyStream::new(bytes);
        let magic: [u8; 4] = stream.read_bytes(4)?.try_into().unwrap();
        if magic != SAVE_MAGIC {
            return Err(LegacySaveError::InvalidMagic(magic));
        }
        let format_version = stream.read_le_u32()?;
        if !(MINIMUM_SUPPORTED_VERSION..=CURRENT_RETAIL_VERSION).contains(&format_version) {
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
        let nation_count = stream.read_le_i32()?;
        let minor_nation_count = stream.read_le_i32()?;
        let turn_flow_status_flags = stream.read_le_u32()?;
        let difficulty = stream.read_u8()?;
        let game_setup = read_game_setup(&mut stream)?;
        let scenario_map_index_plus_one = stream.read_le_i32()?;
        let nation_availability = stream.read_bytes(NATION_COUNT)?.try_into().unwrap();
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
            nation_count,
            minor_nation_count,
            turn_flow_status_flags,
            difficulty,
            game_setup,
            scenario_map_index_plus_one,
            nation_availability,
            saved_multiplayer_role,
            preference_slot_10,
            selected_asset_set,
            starting_year,
            phase_state_by_decade,
            nation_names,
        };
        let animator_idle_frequency = stream.read_le_i32()?;
        skip_trade_manager(&mut stream)?;
        stream.skip(DIPLOMACY_SERIALIZED_SIZE_V62)?;
        stream.skip(TECH_SERIALIZED_SIZE_V62)?;
        let map = read_map(&mut stream)?;
        let ocean = read_ocean(&mut stream)?;
        let navy = read_navy(&mut stream)?;
        let army_report_count = skip_army_reports(&mut stream)?;
        Ok(Self {
            header,
            simulation,
            animator_idle_frequency,
            map,
            ocean,
            navy,
            army_report_count,
            remaining_manager_chain_offset: stream.position(),
        })
    }
}

/// Decodes the common `TCountry` prefix at an already-located nation record.
///
/// The returned offset is the first byte of the derived `TGreatPower` or `TMinor`
/// suffix. Keeping location separate from decoding lets the manager-chain parser
/// choose the concrete retail nation class without embedding C++ layout in the DTO.
pub fn parse_country_base_at(
    bytes: &[u8],
    offset: usize,
) -> Result<(LegacyCountryBase, usize), LegacySaveError> {
    let remaining = bytes.get(offset..).ok_or(StreamError {
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
pub fn parse_great_power_prefix_at(
    bytes: &[u8],
    offset: usize,
) -> Result<(LegacyGreatPowerPrefix, usize), LegacySaveError> {
    let remaining = bytes.get(offset..).ok_or(StreamError {
        offset,
        requested: 1,
        remaining: 0,
    })?;
    let mut stream = LegacyStream::new(remaining);
    let prefix = read_great_power_prefix(&mut stream)?;
    Ok((prefix, offset + stream.position()))
}

fn skip_trade_manager(stream: &mut LegacyStream<'_>) -> Result<(), StreamError> {
    stream.skip(TRADE_CATEGORY_COUNT * TRADE_CATEGORY_SERIALIZED_SIZE)?;
    for _ in 0..TRADE_CATEGORY_COUNT {
        let record_size = usize::from(stream.read_le_u16()?);
        let record_count = stream.read_le_u32()? as usize;
        stream.skip(record_size.saturating_mul(record_count))?;
    }
    Ok(())
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

fn read_ocean(stream: &mut LegacyStream<'_>) -> Result<LegacyOceanState, StreamError> {
    let zone_count = usize::from(stream.read_le_u16()?);
    let zones = (0..zone_count)
        .map(|_| read_zone(stream, false))
        .collect::<Result<Vec<_>, _>>()?;
    let port_zone_count = usize::from(stream.read_le_u16()?);
    let port_zones = (0..port_zone_count)
        .map(|_| read_zone(stream, true))
        .collect::<Result<Vec<_>, _>>()?;
    let route_count = usize::from(stream.read_le_u16()?);
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

fn read_navy(stream: &mut LegacyStream<'_>) -> Result<LegacyNavyState, StreamError> {
    let ship_count = usize::from(stream.read_le_u16()?);
    let mut ships = (0..ship_count)
        .map(|_| read_ship(stream))
        .collect::<Result<Vec<_>, _>>()?;
    ships.reverse();
    let admiral_count = usize::from(stream.read_le_u16()?);
    let admirals = (0..admiral_count)
        .map(|_| read_admiral(stream))
        .collect::<Result<Vec<_>, _>>()?;
    let task_force_count = usize::from(stream.read_le_u16()?);
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

fn read_task_force(stream: &mut LegacyStream<'_>) -> Result<LegacyTaskForce, StreamError> {
    let aggression = stream.read_le_i32()?;
    let order = stream.read_le_i32()?;
    let target_ordinal = stream.read_le_i16()?;
    let location_ordinal = stream.read_le_i16()?;
    let nation = stream.read_le_i16()?;
    stream.skip(1)?;
    let ingot_tile = stream.read_le_i16()?;
    let child_count = usize::from(stream.read_le_u16()?);
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

fn skip_army_reports(stream: &mut LegacyStream<'_>) -> Result<u16, StreamError> {
    let report_count = stream.read_le_u16()?;
    for _ in 0..report_count {
        stream.skip(8)?;
        for _ in 0..2 {
            stream.skip(1 + 0x20 + 0xff)?;
            let child_count = usize::from(stream.read_le_u16()?);
            stream.skip(child_count.saturating_mul(42))?;
        }
    }
    Ok(report_count)
}

fn read_country_base(stream: &mut LegacyStream<'_>) -> Result<LegacyCountryBase, StreamError> {
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
    let military_unit_count = stream.read_le_u32()? as usize;
    let military_units = (0..military_unit_count)
        .map(|_| read_military_unit(stream))
        .collect::<Result<Vec<_>, _>>()?;

    // TLongintList::NoOpReadFrom is likewise a no-op.
    let owned_region_count = stream.read_le_u32()? as usize;
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
    let mut aid_allocation_matrix = [0; AID_ALLOCATION_COUNT];
    for value in &mut aid_allocation_matrix {
        *value = stream.read_be_i32()?;
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
        aid_allocation_matrix,
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

fn read_terrain_tile(stream: &mut LegacyStream<'_>) -> Result<LegacyTerrainTile, StreamError> {
    let bytes = stream.read_bytes(TERRAIN_TILE_SERIALIZED_SIZE)?;
    Ok(LegacyTerrainTile {
        terrain_kind: bytes[0] as i8,
        former_owner_nation: bytes[3] as i8,
        owner_nation: bytes[4] as i8,
        development_classes: bytes[0x0c] as i8,
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
    stream.skip(3)?;
    Ok(LegacyGameSetup {
        multiplayer_game_active,
        nation_control_modes,
        city_minister_policy_ids,
        foreign_minister_policy_ids,
        defense_minister_policy_ids,
        reload_political_map_state,
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

fn fixed_text(bytes: &[u8]) -> String {
    let length = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    lossy_text(&bytes[..length])
}

fn lossy_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const RETAIL_FIXTURE: &[u8] =
        include_bytes!("../../../../tests/runtime/fixtures/beginning_of_game.imp");

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
        assert_eq!(save.simulation.turn_flow_status_flags, 0x40);
        assert_eq!(save.simulation.starting_year, 1914);
        assert_eq!(save.simulation.calendar().year(), 1914);
        assert_eq!(save.simulation.calendar().quarter(), 1);
        assert_eq!(save.simulation.nation_names[0], "Zimm");
        assert_eq!(save.simulation.nation_names[6], " Testland");
        assert_eq!(save.simulation.nation_names[22], "Sindel");
        assert_eq!(save.animator_idle_frequency, 2);
        assert_eq!(save.map.tiles.len(), 6480);
        assert_eq!(save.map.provinces.len(), 384);
        assert_eq!(save.map.no_horizontal_wrap, 0);
        assert_eq!(save.map.tiles[0].terrain_kind, 5);
        assert_eq!(save.map.tiles[0].owner_nation, 82);
        assert_eq!(
            save.map.snapshot_world().semantic_hash().unwrap(),
            "dbd2668d"
        );
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
        assert_eq!(suffix_offset, 0x4e2a3);

        let (great_power, optional_payload_offset) =
            parse_great_power_prefix_at(RETAIL_FIXTURE, suffix_offset).unwrap();
        assert_eq!(great_power.capacities, [0, 0, 15, 11]);
        assert_eq!(great_power.relationship_lists.len(), 19);
        assert_eq!(great_power.relationship_lists[0].record_size, 4);
        assert_eq!(great_power.relationship_lists[2].record_size, 12);
        assert_eq!(great_power.minister_presence_mask, 0x0f);
        assert_eq!(optional_payload_offset, 0x4eae0);
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
            Err(LegacySaveError::Stream(_))
        ));
    }
}
