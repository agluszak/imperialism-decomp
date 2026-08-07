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
    /// Byte position immediately after `TMapMgr`; the ocean manager starts here.
    pub remaining_manager_chain_offset: usize,
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
        Ok(Self {
            header,
            simulation,
            animator_idle_frequency,
            map,
            remaining_manager_chain_offset: stream.position(),
        })
    }
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
        assert!(save.remaining_manager_chain_offset > 0x3d1bd);
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
