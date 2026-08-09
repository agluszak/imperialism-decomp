use crate::*;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::ops::{Index, IndexMut};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct GameState {
    pub turn: TurnState,
    pub unit_ids: UnitIdAllocator,
    pub world: StrategicMap,
    pub provinces: ProvinceTable<ProvinceState>,
    pub port_zone_owners: Vec<PortZoneOwner>,
    pub rng: RngState,
    pub market: TradeMarketState,
    pub technology: TechnologyState,
    pub diplomacy: DiplomacyState,
    pub nations: Nations,
    pub military_units: Vec<MilitaryUnitState>,
    pub civilian_units: Vec<CivilianUnitState>,
    pub ships: Vec<ShipState>,
    pub task_forces: Vec<TaskForceState>,
    pub missions: Vec<MissionState>,
    pub pending: PendingWorkState,
}

/// A port zone and the nation that owned its port tile before scenario setup.
///
/// The owning [`GameState`] vector preserves retail's newest-to-oldest port
/// chain order.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PortZoneOwner {
    pub zone: OceanZoneId,
    pub former_owner: NationId,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct UnitIdAllocator(i32);
impl UnitIdAllocator {
    pub const fn from_retail(value: i32) -> Self {
        Self(value)
    }
    pub const fn current(self) -> i32 {
        self.0
    }
    pub(crate) fn next_civilian(&mut self) -> CivilianUnitId {
        self.0 += 1;
        CivilianUnitId::new(self.0)
    }
    pub(crate) fn next_military(&mut self) -> MilitaryUnitId {
        self.0 += 1;
        MilitaryUnitId::new(self.0)
    }
}

/// Every nation slot, split into the two populations that carry different
/// domain state. Every major slot is a complete major nation; minor slots may
/// still be absent until their save projection is normalized separately.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Nations {
    pub(crate) majors: MajorNationTable<MajorNation>,
    pub(crate) minors: MinorNationTable<Option<MinorNation>>,
}

impl Nations {
    pub const fn new(
        majors: MajorNationTable<MajorNation>,
        minors: MinorNationTable<Option<MinorNation>>,
    ) -> Self {
        Self { majors, minors }
    }

    pub fn major(&self, nation: crate::MajorNationId) -> &MajorNation {
        &self.majors[nation]
    }

    pub(crate) fn major_mut(&mut self, nation: crate::MajorNationId) -> &mut MajorNation {
        &mut self.majors[nation]
    }

    pub(crate) fn city(&self, nation: crate::MajorNationId) -> &CityState {
        &self.majors[nation].city
    }

    pub(crate) fn city_mut(&mut self, nation: crate::MajorNationId) -> &mut CityState {
        &mut self.majors[nation].city
    }

    pub fn majors(&self) -> impl ExactSizeIterator<Item = &MajorNation> {
        self.majors.iter()
    }

    pub fn minor(&self, nation: MinorNationId) -> Option<&MinorNation> {
        self.minors[nation].as_ref()
    }

    pub fn minor_count(&self) -> usize {
        self.minors.iter().flatten().count()
    }

    pub(crate) fn common(&self, nation: NationId) -> Option<&NationCommonState> {
        if let Some(nation) = MajorNationId::from_nation(nation) {
            Some(&self.majors[nation].common)
        } else {
            self.minors[MinorNationId::new(nation.get())]
                .as_ref()
                .map(|nation| &nation.common)
        }
    }

    pub(crate) fn common_mut(&mut self, nation: NationId) -> Option<&mut NationCommonState> {
        if let Some(nation) = MajorNationId::from_nation(nation) {
            Some(&mut self.majors[nation].common)
        } else {
            self.minors[MinorNationId::new(nation.get())]
                .as_mut()
                .map(|nation| &mut nation.common)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MajorNation {
    pub(crate) common: NationCommonState,
    pub(crate) economy: GreatPowerState,
    pub(crate) city: CityState,
}

impl MajorNation {
    pub const fn from_parts(
        common: NationCommonState,
        economy: GreatPowerState,
        city: CityState,
    ) -> Self {
        Self {
            common,
            economy,
            city,
        }
    }

    /// Builds a random-game start major nation from the resolved starting
    /// `treasury`, whether the slot is the `human` player, and its scenario
    /// `city`. Homes are unset until capital selection places them.
    pub(crate) fn for_random_start(
        treasury: i32,
        human: bool,
        foreign_minister_personality: ForeignMinisterPersonality,
        city: CityState,
    ) -> Self {
        Self {
            common: NationCommonState {
                status: crate::CountryStatus::Independent,
                owned_regions: Vec::new(),
                treasury,
                home_tile: None,
                trade_policy_by_nation: NationTable::default(),
            },
            economy: GreatPowerState::for_random_start(human, foreign_minister_personality),
            city,
        }
    }

    pub const fn common(&self) -> &NationCommonState {
        &self.common
    }

    pub const fn economy(&self) -> &GreatPowerState {
        &self.economy
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MinorNation {
    pub common: NationCommonState,
    pub consortium_members: [MinorNationId; 4],
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TurnState {
    pub scenario_map: Option<ScenarioMapId>,
    pub economic_turn: i32,
    /// Raw persisted `TSimMgr` term consumed by diplomacy scaling.
    ///
    /// This is not the 1815-based display calendar.
    pub diplomacy_year_term_raw: i16,
    pub phase: PhaseCode,
    pub difficulty: Difficulty,
    pub active_nation: NationId,
    pub selected_nation: NationId,
}

/// Global technology flags that currently affect authoritative simulation rules.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct TechnologyState {
    pub advanced_iron_working: bool,
    pub marine_engineering: bool,
}

impl TechnologyState {
    /// Selects the production-capacity term used by retail's naval-force score.
    pub const fn naval_production_capacity(
        self,
        lumber_mill_capacity: i32,
        steel_mill_capacity: i32,
    ) -> i32 {
        if self.marine_engineering {
            steel_mill_capacity
        } else if self.advanced_iron_working {
            (lumber_mill_capacity + steel_mill_capacity) / 2
        } else {
            lumber_mill_capacity
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ScenarioMapId(u16);
impl ScenarioMapId {
    pub const fn new(index: u16) -> Self {
        Self(index)
    }

    pub const fn index(self) -> u16 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct PhaseCode(i32);
impl PhaseCode {
    pub const CAPITAL_SELECTION: Self = Self(2);
    pub const PRE_MAP: Self = Self(3);
    pub const HOME_PLACEMENT: Self = Self(4);
    pub const STRATEGIC_MAP: Self = Self(5);
    pub const TURN: Self = Self(6);
    pub const fn from_retail(value: i32) -> Self {
        Self(value)
    }
    pub const fn retail(self) -> i32 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StrategicMap {
    topology: MapTopology,
    tiles: Box<[TileState]>,
}

impl<'de> Deserialize<'de> for StrategicMap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct SerializedStrategicMap {
            topology: MapTopology,
            tiles: Box<[TileState]>,
        }

        let map = SerializedStrategicMap::deserialize(deserializer)?;
        Self::new(map.topology, map.tiles).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("strategic map has {actual} tiles; expected {STRATEGIC_TILE_COUNT}")]
pub struct StrategicMapSizeError {
    pub actual: usize,
}

impl StrategicMap {
    pub fn new(
        topology: MapTopology,
        tiles: impl Into<Box<[TileState]>>,
    ) -> Result<Self, StrategicMapSizeError> {
        let tiles = tiles.into();
        if tiles.len() != STRATEGIC_TILE_COUNT {
            return Err(StrategicMapSizeError {
                actual: tiles.len(),
            });
        }
        Ok(Self { topology, tiles })
    }

    /// Accepts tiles derived one-for-one from an already validated generated map.
    pub(crate) fn from_generated_tiles(topology: MapTopology, tiles: Box<[TileState]>) -> Self {
        debug_assert_eq!(tiles.len(), STRATEGIC_TILE_COUNT);
        Self { topology, tiles }
    }

    pub const fn geometry(&self) -> crate::MapGeometry {
        crate::MapGeometry::new(self.topology)
    }

    pub const fn topology(&self) -> MapTopology {
        self.topology
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &TileState> {
        self.tiles.iter()
    }
}

impl Index<TileId> for StrategicMap {
    type Output = TileState;

    fn index(&self, index: TileId) -> &Self::Output {
        &self.tiles[usize::from(index.get())]
    }
}

impl IndexMut<TileId> for StrategicMap {
    fn index_mut(&mut self, index: TileId) -> &mut Self::Output {
        &mut self.tiles[usize::from(index.get())]
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TileState {
    pub terrain: TerrainKind,
    pub owner_nation: Option<TileOwnerTag>,
    pub former_owner_nation: Option<TileOwnerTag>,
    pub province: Option<ProvinceId>,
    pub development: TileDevelopment,
    pub edge_resources: [Option<crate::ResourceKind>; 2],
    /// Completed directional transport links from this tile.
    pub transport_links: TileTransportLinks,
    /// Directional rail sections that have been ordered but not yet completed.
    pub pending_rail_links: TileTransportLinks,
    pub action: Option<TileAction>,
    pub flags: TileFlags,
    pub region: Option<RegionId>,
    pub river: Option<RiverSegment>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum TerrainKind {
    Plains,
    Forest,
    Hills,
    Mountain,
    Swamp,
    Water,
    Desert,
    Farmland,
}

impl TerrainKind {
    pub const fn from_retail(value: i8) -> Option<Self> {
        match value {
            0 => Some(Self::Plains),
            1 => Some(Self::Forest),
            2 => Some(Self::Hills),
            3 => Some(Self::Mountain),
            4 => Some(Self::Swamp),
            5 => Some(Self::Water),
            6 => Some(Self::Desert),
            7 => Some(Self::Farmland),
            _ => None,
        }
    }

    pub const fn retail(self) -> i8 {
        self as i8
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct TileAction(i16);

impl<'de> Deserialize<'de> for TileAction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = i16::deserialize(deserializer)?;
        Self::try_from_retail(value)
            .ok_or_else(|| serde::de::Error::custom("tile action -1 is represented by None"))
    }
}

impl TileAction {
    pub const fn try_from_retail(value: i16) -> Option<Self> {
        if value == -1 { None } else { Some(Self(value)) }
    }

    pub const fn retail(self) -> i16 {
        self.0
    }
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
    #[serde(transparent)]
    pub struct TileFlags: u16 {
        /// Set by `ResetTileToBaseTransportFlag`; consumers use this as the base-transport test.
        const BASE_TRANSPORT = 1 << 0;
        const RECRUITMENT_RESERVED = 1 << 1;
        /// Set by `SetProvinceCapitalTileFlagBit08`, which also advances the province fort level.
        const PROVINCE_CAPITAL_FORTIFICATION = 1 << 3;
        /// The city marker bit tested independently by map and unit consumers.
        const CITY_MARKER = 1 << 5;

        /// Complete state written for a fallback or re-anchored province capital.
        const PROVINCE_ANCHOR_STATE = 0x22;
        /// Complete state written for a minor nation's home tile.
        const MINOR_HOME_STATE = 0x21;
        /// Complete state written by `PlaceCity`.
        const PLACED_CITY_STATE = 0x37;
    }
}

impl TileFlags {
    pub(crate) fn has_base_transport(self) -> bool {
        self.contains(Self::BASE_TRANSPORT)
    }

    pub fn is_city(self) -> bool {
        self.contains(Self::CITY_MARKER)
    }

    pub(crate) fn clear_city_marker(&mut self) {
        self.remove(Self::CITY_MARKER);
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RegionId(u8);

impl RegionId {
    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u8 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct RiverSegment {
    connection_code: u8,
}

impl<'de> Deserialize<'de> for RiverSegment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct SerializedRiverSegment {
            connection_code: u8,
        }

        let segment = SerializedRiverSegment::deserialize(deserializer)?;
        if !(1..=0x15).contains(&segment.connection_code) {
            return Err(serde::de::Error::custom(
                "river connection code must be between 1 and 0x15",
            ));
        }
        Ok(Self {
            connection_code: segment.connection_code,
        })
    }
}

impl RiverSegment {
    /// Constructs the canonical river-connection code produced by retail map
    /// generation. Zero is the no-river sentinel; 1 through 0x15 are the
    /// interior, source, and water-mouth connection forms.
    pub const fn from_connection_code(connection_code: u8) -> Option<Self> {
        if connection_code == 0 {
            None
        } else {
            assert!(connection_code <= 0x15, "invalid river connection code");
            Some(Self { connection_code })
        }
    }

    pub const fn connection_code(self) -> u8 {
        self.connection_code
    }

    pub(crate) const fn flow_type(self) -> Option<usize> {
        if self.connection_code >= 1 && self.connection_code <= 9 {
            Some((self.connection_code - 1) as usize)
        } else {
            None
        }
    }
}

impl Default for TileState {
    fn default() -> Self {
        Self {
            terrain: TerrainKind::Plains,
            owner_nation: None,
            former_owner_nation: None,
            province: None,
            development: TileDevelopment::default(),
            edge_resources: [None; 2],
            transport_links: TileTransportLinks::default(),
            pending_rail_links: TileTransportLinks::default(),
            action: None,
            flags: TileFlags::empty(),
            region: None,
            river: None,
        }
    }
}

bitflags::bitflags! {
    /// The six directional links that may leave a strategic-map tile.
    #[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
    pub struct TileTransportLinks: u8 {
        const NORTH_EAST = 1 << 0;
        const EAST = 1 << 1;
        const SOUTH_EAST = 1 << 2;
        const SOUTH_WEST = 1 << 3;
        const WEST = 1 << 4;
        const NORTH_WEST = 1 << 5;
    }
}

impl TileTransportLinks {
    pub(crate) const fn for_direction(direction: HexDirection) -> Self {
        match direction {
            HexDirection::NorthEast => Self::NORTH_EAST,
            HexDirection::East => Self::EAST,
            HexDirection::SouthEast => Self::SOUTH_EAST,
            HexDirection::SouthWest => Self::SOUTH_WEST,
            HexDirection::West => Self::WEST,
            HexDirection::NorthWest => Self::NORTH_WEST,
        }
    }

    pub(crate) fn insert_direction(&mut self, direction: HexDirection) {
        self.insert(Self::for_direction(direction));
    }
}

/// One independently-progressed resource-development channel on a map tile.
///
/// Retail stores both channels in one byte, but game rules operate on them as
/// separate levels.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct DevelopmentLevel(u8);

impl DevelopmentLevel {
    pub const ZERO: Self = Self(0);

    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u8 {
        self.0
    }

    pub(crate) fn advance(&mut self) {
        self.0 += 1;
    }
}

impl Default for DevelopmentLevel {
    fn default() -> Self {
        Self::ZERO
    }
}

/// The two resource-development channels and their discovery visibility.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TileDevelopment {
    pub surface: DevelopmentLevel,
    pub extractive: DevelopmentLevel,
    /// Major nations that can see the tile's resource information.
    pub resource_visible_to_majors: MajorNationTable<bool>,
}

impl Default for TileDevelopment {
    fn default() -> Self {
        Self {
            surface: DevelopmentLevel::ZERO,
            extractive: DevelopmentLevel::ZERO,
            resource_visible_to_majors: MajorNationTable::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RngState {
    pub crt_rand: RetailCrtRng,
    pub map_generation: RetailLcg,
    pub zone_status: RetailLcg,
}

/// The authoritative bilateral relationship stored by retail diplomacy state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiplomaticRelationship {
    Alliance,
    NonAggressionPact,
    Peace,
    JoinedEmpire,
    War,
}

impl DiplomaticRelationship {
    pub const fn try_from_retail(value: i16) -> Option<Self> {
        match value {
            2 => Some(Self::Alliance),
            3 => Some(Self::NonAggressionPact),
            4 => Some(Self::Peace),
            5 => Some(Self::JoinedEmpire),
            6 => Some(Self::War),
            _ => None,
        }
    }

    pub const fn retail(self) -> i16 {
        match self {
            Self::Alliance => 2,
            Self::NonAggressionPact => 3,
            Self::Peace => 4,
            Self::JoinedEmpire => 5,
            Self::War => 6,
        }
    }
}

/// The bilateral diplomatic mission level stored by retail diplomacy state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiplomaticMissionLevel {
    None,
    TradeConsulate,
    Embassy,
}

impl DiplomaticMissionLevel {
    pub const fn try_from_retail(value: i16) -> Option<Self> {
        match value {
            0 => Some(Self::None),
            1 => Some(Self::TradeConsulate),
            2 => Some(Self::Embassy),
            _ => None,
        }
    }

    pub const fn retail(self) -> i16 {
        match self {
            Self::None => 0,
            Self::TradeConsulate => 1,
            Self::Embassy => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DiplomaticCongressState {
    pub chairman: Option<MajorNationId>,
    pub counterpart: Option<MajorNationId>,
    pub chairman_support: i16,
    pub counterpart_support: i16,
    pub neutral_support: i16,
}

/// Persistent `TDiplomacyMgr` state plus its two constructor-restored runtime values.
///
/// Retail deliberately does not persist the pending-policy tier matrix, relation baseline copy,
/// or comparative-power rows. At the beginning-save/phase-6 boundary, the tier and power rows are
/// rebuilt before their later consumers, while the baseline belongs to multiplayer delta sync.
/// They must be represented when a modeled checkpoint can stop between those writes and reads;
/// the v62 payload alone cannot reconstruct them.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DiplomacyState {
    pub standings: NationTable<NationTable<i16>>,
    pub relationships: NationTable<NationTable<DiplomaticRelationship>>,
    pub relationship_turns: NationTable<NationTable<Option<i16>>>,
    pub influence_thresholds: ProvinceTable<i16>,
    pub influence_sides: ProvinceTable<Option<MajorNationId>>,
    pub last_diplomatic_effort_turn: i16,
    pub mission_levels: NationTable<NationTable<DiplomaticMissionLevel>>,
    pub congress: DiplomaticCongressState,
    pub special_relation_sources: MinorNationTable<Option<MajorNationId>>,
    pub special_relation_targets: MinorNationTable<Option<MajorNationId>>,
    pub last_processed_nation: Option<MajorNationId>,
    /// UI action-validation discriminator. Its meanings are recovered, but core rules do not
    /// interpret it yet, so the retail numeric domain remains visible.
    pub proposal_mode_raw: i16,
}

impl DiplomacyState {
    /// `InitializeTDiplomacyTurnStateManagerDefaults` followed by
    /// `RebuildCivilianOrderCompatibilityMatrices` for a complete random-game nation table.
    pub(crate) fn for_random_start(
        human_nation: MajorNationId,
        difficulty: Difficulty,
        rng: &mut RetailCrtRng,
    ) -> Self {
        let human_slot = human_nation.get();
        let mut standings = NationTable::from_array(std::array::from_fn(|source| {
            NationTable::from_array(std::array::from_fn(|target| {
                let source = source as u8;
                let target = target as u8;
                if source == target {
                    0xff
                } else if source >= MinorNationId::FIRST && target >= MinorNationId::FIRST {
                    if (source - MinorNationId::FIRST) / 4 == (target - MinorNationId::FIRST) / 4 {
                        0x96
                    } else {
                        0x6e
                    }
                } else if source < MajorNationId::COUNT
                    && source != human_slot
                    && difficulty > Difficulty::Normal
                {
                    if difficulty == Difficulty::NighOnImpossible {
                        0x69
                    } else {
                        0x64
                    }
                } else {
                    0x5a
                }
            }))
        }));
        let mut mission_levels = NationTable::from_array(std::array::from_fn(|source| {
            NationTable::from_array(std::array::from_fn(|target| {
                if source < MajorNationId::COUNT as usize
                    && target < MajorNationId::COUNT as usize
                    && source != target
                {
                    DiplomaticMissionLevel::Embassy
                } else {
                    DiplomaticMissionLevel::None
                }
            }))
        }));

        if difficulty == Difficulty::Introductory {
            let first_minor = (rng.next_rand() as u8 % 4) * 4 + MinorNationId::FIRST;
            for target in first_minor..first_minor + 4 {
                let target = NationId::new(target);
                let human = human_nation.nation();
                mission_levels[human][target] = DiplomaticMissionLevel::TradeConsulate;
                mission_levels[target][human] = DiplomaticMissionLevel::TradeConsulate;
                standings[human][target] = 0x6e;
                standings[target][human] = 0x6e;
            }
        }

        if difficulty > Difficulty::Normal {
            for source in 0..MajorNationId::COUNT {
                if source == human_slot {
                    continue;
                }
                let target = NationId::new(
                    rng.next_rand() as u8 % MinorNationId::COUNT + MinorNationId::FIRST,
                );
                let source = NationId::new(source);
                mission_levels[source][target] = DiplomaticMissionLevel::TradeConsulate;
                mission_levels[target][source] = DiplomaticMissionLevel::TradeConsulate;
                standings[source][target] = 0x6e;
                standings[target][source] = 0x6e;
            }
        }

        if difficulty == Difficulty::NighOnImpossible {
            for source in 0..MajorNationId::COUNT {
                if source == human_slot {
                    continue;
                }
                for target in 0..MajorNationId::COUNT {
                    if target == human_slot {
                        continue;
                    }
                    let source = NationId::new(source);
                    let target = NationId::new(target);
                    standings[source][target] = 0x6e;
                    standings[target][source] = 0x6e;
                }
            }
        }

        Self {
            standings,
            relationships: NationTable::from_array(std::array::from_fn(|_| {
                NationTable::from_array([DiplomaticRelationship::Peace; crate::NATION_COUNT])
            })),
            relationship_turns: NationTable::default(),
            influence_thresholds: ProvinceTable::default(),
            influence_sides: ProvinceTable::default(),
            last_diplomatic_effort_turn: 0,
            mission_levels,
            congress: DiplomaticCongressState {
                chairman: None,
                counterpart: None,
                chairman_support: 0,
                counterpart_support: 0,
                neutral_support: 0,
            },
            special_relation_sources: MinorNationTable::default(),
            special_relation_targets: MinorNationTable::default(),
            last_processed_nation: None,
            proposal_mode_raw: 0,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NationCommonState {
    pub status: crate::CountryStatus,
    pub owned_regions: Vec<ProvinceId>,
    pub treasury: i32,
    pub home_tile: Option<TileId>,
    pub trade_policy_by_nation: NationTable<TradePolicyScore>,
}

/// A bilateral trade-preference score.
///
/// Retail recognizes several named steps, but save data can carry other
/// scores, so this is deliberately not a closed enum.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct TradePolicyScore(i32);

impl TradePolicyScore {
    pub const NEUTRAL: Self = Self(100);
    pub const BOYCOTT: Self = Self(300);

    pub const fn new(score: i32) -> Self {
        Self(score)
    }

    pub(crate) const fn decrement_step(self, treasury: i32) -> Self {
        match self.0 {
            100 => Self(95),
            95 => Self(90),
            90 => Self(75),
            75 if treasury > 10_000 => Self(50),
            _ => self,
        }
    }
}

impl Default for TradePolicyScore {
    fn default() -> Self {
        Self::NEUTRAL
    }
}

/// A current diplomatic grant to one nation.
///
/// `None` in the owning table means no grant. A present zero-valued grant is
/// retained because it still participates in retail diplomacy processing.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DiplomacyGrant {
    pub amount: i32,
    pub recurring: bool,
}

/// A proposed diplomatic relationship with one nation.
///
/// The retail save stores these as numeric proposal codes. The core keeps the
/// relationship meaning; absent entries have no current policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiplomacyPolicy {
    JoinEmpire,
    Alliance,
    NonAggressionPact,
    PeaceTreaty,
    DeclareWar,
    JoinEmpireWithWarEntanglements,
    BuildConsulate,
    BuildEmbassy,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GreatPowerState {
    pub controller: MajorNationController,
    pub ai_zone_targets: Option<Vec<AiZoneTargetState>>,
    pub foreign_minister_personality: ForeignMinisterPersonality,
    pub foreign_minister_skill_index: i16,
    pub development_grant_by_nation: NationTable<i16>,
    pub defense_minister_skill_index: i16,
    pub capacities: NationCapacities,
    pub grant_total_cost: i32,
    pub unfilled_trade_offer_count: i16,
    pub diplomacy_policy_by_nation: NationTable<Option<DiplomacyPolicy>>,
    pub diplomacy_grants_by_nation: NationTable<Option<DiplomacyGrant>>,
    pub need_current_by_type: ResourceTable<i16>,
    pub need_target_by_type: ResourceTable<i16>,
    pub relation_delta_current: ResourceTable<i16>,
    pub purchased_items_by_resource: ResourceTable<i16>,
    pub item_potentials: ResourceTable<i16>,
    pub unfilled_trade_turns_by_resource: ResourceTable<i16>,
    pub transported_items_by_resource: ResourceTable<i16>,
    pub remembered_trade_offers_by_resource: ResourceTable<i16>,
    pub aid_allocation_by_minor_nation: MinorNationTable<ResourceTable<i32>>,
    pub budget_pool_base: i32,
    pub budget_pool_delta: i32,
    pub special_resource_trade_balance: i32,
    pub candidate_nation_flags: NationTable<u8>,
    pub scenario_initialized: bool,
    pub turn_finished: bool,
    pub pending_actions: PendingActionTable<PendingActionState>,
    pub diplomacy_budget_base: i32,
    pub escalation_counter: i16,
    pub pending_commitment_cost: i32,
    pub pressure_counter: i16,
    pub aid_allocation_total: i32,
    pub colony_boycott_flags: NationTable<u8>,
    pub military_expenses: i32,
}

impl GreatPowerState {
    /// The post-`IGreatPower`/`IAutoGreatPower` construction state a major nation
    /// carries at the random-game start boundary. Only the human is diplomacy
    /// eligible before capital selection.
    pub(crate) fn for_random_start(
        human: bool,
        foreign_minister_personality: ForeignMinisterPersonality,
    ) -> Self {
        let controller = if human {
            MajorNationController::Human
        } else {
            MajorNationController::Computer
        };
        Self {
            controller,
            ai_zone_targets: match controller {
                MajorNationController::Human => None,
                MajorNationController::Computer => Some(Vec::new()),
            },
            foreign_minister_personality,
            foreign_minister_skill_index: foreign_minister_personality.initial_skill_index(),
            development_grant_by_nation: NationTable::default(),
            defense_minister_skill_index: 0,
            capacities: NationCapacities::from_array([0, 0, 0x0f, 0]),
            grant_total_cost: 0,
            unfilled_trade_offer_count: 0,
            diplomacy_policy_by_nation: NationTable::default(),
            diplomacy_grants_by_nation: NationTable::default(),
            need_current_by_type: ResourceTable::default(),
            need_target_by_type: ResourceTable::default(),
            relation_delta_current: ResourceTable::default(),
            purchased_items_by_resource: ResourceTable::default(),
            item_potentials: ResourceTable::default(),
            unfilled_trade_turns_by_resource: ResourceTable::default(),
            transported_items_by_resource: ResourceTable::default(),
            remembered_trade_offers_by_resource: ResourceTable::default(),
            aid_allocation_by_minor_nation: MinorNationTable::default(),
            budget_pool_base: 0,
            budget_pool_delta: 0,
            special_resource_trade_balance: 0,
            candidate_nation_flags: NationTable::default(),
            scenario_initialized: false,
            turn_finished: true,
            pending_actions: PendingActionTable::default(),
            diplomacy_budget_base: 20_000,
            escalation_counter: 0,
            pending_commitment_cost: 0,
            pressure_counter: 0,
            aid_allocation_total: 0,
            colony_boycott_flags: NationTable::default(),
            military_expenses: 0,
        }
    }
}

/// An AI major's current use of one live sea or port-zone context.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AiZoneTargetState {
    #[default]
    Unmarked,
    Candidate,
    MissionQueued,
}

/// The exact foreign-minister behavior selected for a major nation.
///
/// Retail constructs the base minister for human and proxy nations. AI nations
/// receive one of the six personality implementations selected by map setup.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ForeignMinisterPersonality {
    Base,
    Arms,
    Trader,
    Textile,
    Diplomat,
    Bill,
    Ted,
}

impl ForeignMinisterPersonality {
    const fn initial_skill_index(self) -> i16 {
        match self {
            Self::Base | Self::Arms => 0,
            Self::Trader => 1,
            Self::Textile => 2,
            Self::Diplomat => 3,
            Self::Bill => 4,
            Self::Ted => 5,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum MajorNationController {
    Human,
    Computer,
}
impl MajorNationController {
    pub(crate) const fn is_human(self) -> bool {
        matches!(self, Self::Human)
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct PendingActionState {
    status: PendingActionStatus,
    payload: Option<i16>,
}

impl PendingActionState {
    pub const fn new(status: PendingActionStatus, payload: Option<i16>) -> Self {
        Self { status, payload }
    }
    pub(crate) const fn status(self) -> PendingActionStatus {
        self.status
    }
    pub const fn payload(self) -> Option<i16> {
        self.payload
    }
    pub(crate) fn queue(&mut self, payload: i16) {
        self.status = PendingActionStatus::Queued;
        self.payload = Some(payload);
    }
    pub(crate) const fn level(self) -> Option<i16> {
        match self.status {
            PendingActionStatus::Queued => None,
            PendingActionStatus::None | PendingActionStatus::Level3 => Some(0),
            PendingActionStatus::Level4 => Some(1),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingActionStatus {
    #[default]
    None,
    Queued,
    Level3,
    Level4,
}
impl PendingActionStatus {
    pub(crate) fn has_reached(self, other: Self) -> bool {
        self >= other
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CityState {
    pub power_plant_upgrade_queued: bool,
    pub food_substitution_count: i16,
    pub starvation_population_loss: i16,
    pub serialized_state: i16,
    pub phase_counter: i16,
    /// Cumulative military recruit deltas by [`MilitaryUnitKind`].
    #[serde(
        serialize_with = "crate::units::serialize_military_unit_table",
        deserialize_with = "crate::units::deserialize_military_unit_table"
    )]
    pub military_recruit_count_by_kind: MilitaryUnitTable<i16>,
    /// Cumulative civilian recruit deltas by [`CivilianUnitKind`].
    #[serde(
        serialize_with = "crate::units::serialize_civilian_unit_table",
        deserialize_with = "crate::units::deserialize_civilian_unit_table"
    )]
    pub civilian_recruit_count_by_kind: CivilianUnitTable<i16>,
    pub ship_order_count_by_type: ShipTypeTable<i16>,
    pub rolling_item_production_score: i32,
    pub low_production: bool,
    pub low_stock: bool,
    pub reserved_by_type: ResourceTable<i16>,
    pub home_town_tile: Option<TileId>,
    pub power_available: i16,
    pub stockpile: Stockpile,
    pub production_orders: ProductionTable<i16>,
    pub production_accum: ProductionTable<i16>,
    pub production_flags: ProductionTable<u8>,
    pub production_current: ProductionTable<i16>,
    pub production_progress: ProductionTable<i16>,
    pub population_growth_penalty_ticks: i16,
    pub unmet_resource_retries: ResourceTable<i16>,
    pub consumed_production_input_by_type: ResourceTable<i16>,
    pub population: PopulationState,
}

impl CityState {
    /// Builds the scenario start city. `stockpile` and `production` come from
    /// the difficulty presets, `labor` is the `SetPopulation` triple, and only
    /// the human capital gets the Frog City marker at tile 0.
    pub(crate) fn for_random_start(
        stockpile: ResourceTable<i16>,
        production: ProductionTable<i16>,
        labor: LaborPool,
        human: bool,
    ) -> Self {
        Self {
            power_plant_upgrade_queued: false,
            food_substitution_count: 0,
            starvation_population_loss: 0,
            serialized_state: 0,
            phase_counter: 0,
            military_recruit_count_by_kind: MilitaryUnitTable::default(),
            civilian_recruit_count_by_kind: CivilianUnitTable::default(),
            ship_order_count_by_type: ShipTypeTable::default(),
            rolling_item_production_score: 0,
            low_production: false,
            low_stock: false,
            reserved_by_type: ResourceTable::default(),
            home_town_tile: human.then(|| TileId::new(0)),
            // Human Frog City marker sits at tile 0 without PlaceCity. AI
            // capitals are placed later once tile post-passes and frog-city
            // scoring land.
            power_available: 0,
            stockpile: Stockpile::from_table(stockpile),
            production_orders: production.clone(),
            production_accum: production,
            production_flags: ProductionTable::default(),
            production_current: ProductionTable::default(),
            production_progress: ProductionTable::default(),
            population_growth_penalty_ticks: 0,
            unmet_resource_retries: ResourceTable::default(),
            consumed_production_input_by_type: ResourceTable::default(),
            population: PopulationState::from_labor(labor),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct Stockpile(ResourceTable<i16>);

impl<'de> Deserialize<'de> for Stockpile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(Self::from_table(ResourceTable::deserialize(deserializer)?))
    }
}

impl Stockpile {
    pub fn from_table(mut amounts: ResourceTable<i16>) -> Self {
        amounts
            .values_mut()
            .for_each(|amount| *amount = (*amount).max(0));
        Self(amounts)
    }
    pub(crate) fn credit(&mut self, resource: crate::ResourceKind, amount: i16) {
        self.0[resource] = self.0[resource].saturating_add(amount).max(0);
    }
    pub(crate) fn debit_clamped(&mut self, resource: crate::ResourceKind, amount: i16) {
        self.0[resource] = self.0[resource].saturating_sub(amount).max(0);
    }
    pub(crate) fn set_nonnegative(&mut self, resource: crate::ResourceKind, amount: i16) {
        self.0[resource] = amount.max(0);
    }
}

impl std::ops::Index<crate::ResourceKind> for Stockpile {
    type Output = i16;
    fn index(&self, resource: crate::ResourceKind) -> &Self::Output {
        &self.0[resource]
    }
}

#[cfg(test)]
impl std::ops::IndexMut<crate::ResourceKind> for Stockpile {
    fn index_mut(&mut self, resource: crate::ResourceKind) -> &mut Self::Output {
        &mut self.0[resource]
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PopulationState {
    pub(crate) count: i16,
    pub(crate) accumulator: PopulationAccumulator,
    pub(crate) strength: i16,
    pub(crate) extra: i16,
    pub(crate) strike_phase: StrikePhase,
    pub(crate) baseline_labor: LaborPool,
    pub(crate) production_labor: LaborPool,
    pub(crate) pending_labor_delta: LaborPool,
    pub(crate) predicted_need_by_resource: ResourceTable<i16>,
}

impl PopulationState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        count: i16,
        accumulator: PopulationAccumulator,
        strength: i16,
        extra: i16,
        strike_phase: StrikePhase,
        baseline_labor: LaborPool,
        production_labor: LaborPool,
        pending_labor_delta: LaborPool,
        predicted_need_by_resource: ResourceTable<i16>,
    ) -> Self {
        Self {
            count,
            accumulator,
            strength,
            extra,
            strike_phase,
            baseline_labor,
            production_labor,
            pending_labor_delta,
            predicted_need_by_resource,
        }
    }

    /// Builds a fresh population whose baseline and production bands both equal
    /// `labor`, with no pending reassignment. Mirrors the retail
    /// `SetPopulation`-time state used when a city first appears.
    pub(crate) fn from_labor(labor: LaborPool) -> Self {
        let count = labor.low + labor.medium + labor.high;
        Self::new(
            count,
            PopulationAccumulator::from_count(count),
            labor.strength(),
            0,
            StrikePhase::default(),
            labor,
            labor,
            LaborPool::default(),
            ResourceTable::default(),
        )
    }

    pub const fn count(&self) -> i16 {
        self.count
    }

    pub const fn accumulator(&self) -> PopulationAccumulator {
        self.accumulator
    }

    pub const fn strength(&self) -> i16 {
        self.strength
    }

    pub const fn baseline_labor(&self) -> LaborPool {
        self.baseline_labor
    }
}

/// A finite semantic population total.
///
/// The retail save stores its IEEE-754 bits, but core state exposes the value
/// itself. The retained bits preserve exact arithmetic between rule steps.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PopulationAccumulator(u32);

impl PopulationAccumulator {
    pub fn new(value: f32) -> Option<Self> {
        value.is_finite().then_some(Self(value.to_bits()))
    }

    #[cfg(test)]
    pub(crate) fn from_bits(bits: u32) -> Self {
        Self::new(f32::from_bits(bits)).expect("population accumulator stays finite")
    }

    pub(crate) fn from_count(count: i16) -> Self {
        Self(f32::from(count).to_bits())
    }

    pub fn get(self) -> f32 {
        f32::from_bits(self.0)
    }
    pub(crate) fn remove(&mut self, amount: i16) {
        self.0 = (self.get() - f32::from(amount)).to_bits();
    }
}

impl Serialize for PopulationAccumulator {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.get().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PopulationAccumulator {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = f32::deserialize(deserializer)?;
        Self::new(value)
            .ok_or_else(|| serde::de::Error::custom("population accumulator must be finite"))
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[repr(u8)]
pub enum StrikePhase {
    #[default]
    Clothing,
    Furniture,
    Hardware,
    Arms,
}

impl StrikePhase {
    pub const fn from_retail(value: i16) -> Option<Self> {
        match value {
            0 => Some(Self::Clothing),
            1 => Some(Self::Furniture),
            2 => Some(Self::Hardware),
            3 => Some(Self::Arms),
            _ => None,
        }
    }
    pub const fn retail(self) -> i16 {
        self as i16
    }
    pub(crate) const fn index(self) -> usize {
        self as usize
    }
    pub(crate) const fn next(self) -> Self {
        match self {
            Self::Clothing => Self::Furniture,
            Self::Furniture => Self::Hardware,
            Self::Hardware => Self::Arms,
            Self::Arms => Self::Clothing,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MilitaryUnitState {
    pub(crate) id: MilitaryUnitId,
    pub(crate) nation: NationId,
    pub(crate) unit_type: MilitaryUnitKind,
    pub(crate) stationed_province: Option<ProvinceId>,
    pub(crate) order: MilitaryOrder,
    pub(crate) owner_nation: NationId,
    pub(crate) roster_id: i16,
    pub(crate) registered: bool,
    pub(crate) name: String,
    pub(crate) strength: i16,
    pub(crate) era: i16,
    pub(crate) experience: i16,
    pub(crate) battle_flags: i16,
}

impl MilitaryUnitState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
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
        era: i16,
        experience: i16,
        battle_flags: i16,
    ) -> Self {
        Self {
            id,
            nation,
            unit_type,
            stationed_province,
            order,
            owner_nation,
            roster_id,
            registered,
            name,
            strength,
            era,
            experience,
            battle_flags,
        }
    }

    pub const fn id(&self) -> MilitaryUnitId {
        self.id
    }

    pub const fn nation(&self) -> NationId {
        self.nation
    }

    pub const fn unit_type(&self) -> MilitaryUnitKind {
        self.unit_type
    }

    pub const fn order(&self) -> &MilitaryOrder {
        &self.order
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MilitaryOrder {
    Idle {
        targets: [Option<ProvinceId>; 3],
        target_mirrors: [Option<ProvinceId>; 3],
    },
    Retail {
        code: MilitaryOrderCode,
        target: Option<ProvinceId>,
        targets: [Option<ProvinceId>; 3],
        target_mirrors: [Option<ProvinceId>; 3],
    },
}

impl MilitaryOrder {
    pub const fn idle(
        targets: [Option<ProvinceId>; 3],
        target_mirrors: [Option<ProvinceId>; 3],
    ) -> Self {
        Self::Idle {
            targets,
            target_mirrors,
        }
    }

    pub const fn retail(
        code: MilitaryOrderCode,
        target: Option<ProvinceId>,
        targets: [Option<ProvinceId>; 3],
        target_mirrors: [Option<ProvinceId>; 3],
    ) -> Self {
        Self::Retail {
            code,
            target,
            targets,
            target_mirrors,
        }
    }

    pub const fn targets(&self) -> &[Option<ProvinceId>; 3] {
        match self {
            Self::Idle { targets, .. } | Self::Retail { targets, .. } => targets,
        }
    }

    pub const fn target_mirrors(&self) -> &[Option<ProvinceId>; 3] {
        match self {
            Self::Idle { target_mirrors, .. } | Self::Retail { target_mirrors, .. } => {
                target_mirrors
            }
        }
    }
}

/// An unrecovered retail military order discriminator retained only inside an
/// otherwise data-carrying order.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct MilitaryOrderCode(i32);
impl MilitaryOrderCode {
    pub const fn from_retail(value: i32) -> Self {
        Self(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CivilianUnitState {
    pub(crate) id: CivilianUnitId,
    pub(crate) nation: NationId,
    pub(crate) unit_type: CivilianUnitKind,
    pub(crate) location: CivilianLocation,
    pub(crate) order: CivilianWorkOrder,
    pub(crate) owner_nation: NationId,
    pub(crate) roster_id: i16,
    pub(crate) registered: bool,
}

impl<'de> Deserialize<'de> for CivilianUnitState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct SerializedCivilianUnit {
            id: CivilianUnitId,
            nation: NationId,
            unit_type: CivilianUnitKind,
            location: CivilianLocation,
            order: CivilianWorkOrder,
            owner_nation: NationId,
            roster_id: i16,
            registered: bool,
        }

        let unit = SerializedCivilianUnit::deserialize(deserializer)?;
        Self::new(
            unit.id,
            unit.nation,
            unit.unit_type,
            unit.location,
            unit.order,
            unit.owner_nation,
            unit.roster_id,
            unit.registered,
        )
        .ok_or_else(|| serde::de::Error::custom("civilian order is inconsistent with location"))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum CivilianLocation {
    OnMap(TileId),
    OffMap,
}
impl CivilianLocation {
    pub(crate) const fn tile(self) -> Option<TileId> {
        match self {
            Self::OnMap(tile) => Some(tile),
            Self::OffMap => None,
        }
    }
}

impl CivilianUnitState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: CivilianUnitId,
        nation: NationId,
        unit_type: CivilianUnitKind,
        location: CivilianLocation,
        order: CivilianWorkOrder,
        owner_nation: NationId,
        roster_id: i16,
        registered: bool,
    ) -> Option<Self> {
        let valid_location = match order {
            CivilianWorkOrder::Idle
            | CivilianWorkOrder::Sleep
            | CivilianWorkOrder::Redeploy { .. } => true,
            CivilianWorkOrder::LayRail { segment, .. } => {
                location.tile() == Some(segment.destination())
            }
            _ => location.tile().is_some(),
        };
        valid_location.then_some(Self {
            id,
            nation,
            unit_type,
            location,
            order,
            owner_nation,
            roster_id,
            registered,
        })
    }
    pub const fn id(&self) -> CivilianUnitId {
        self.id
    }
    pub const fn nation(&self) -> NationId {
        self.nation
    }
    pub const fn location(&self) -> CivilianLocation {
        self.location
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
    /// Open retail mission-status byte; bit zero is consumed by current retail AI logic.
    pub marker: u8,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct PendingWorkState {
    pub nations: MajorNationTable<NationPendingWork>,
    pub newspaper_events: Vec<PendingNewspaperEvent>,
    pub war_transitions: Vec<WarTransition>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InterNationNewsKind {
    WarDeclaredBySubject,
    WarDeclaredAgainstSubject,
    PeaceTreatyAccepted,
    JoinEmpireAccepted,
    AllianceAccepted,
    NonAggressionPactAccepted,
    PeaceTreatyRejected,
    JoinEmpireRejected,
    AllianceRejected,
    NonAggressionPactRejected,
    TradeConsulateEstablished,
    EmbassyEstablished,
    MinorEmpireAffiliationChanged,
    MinorTerritoryRelationshipAffected,
    PeaceRelationshipPropagated,
    WarWithIndependentMinor,
    AllianceRelationshipEstablished,
    NationJoinedEmpire,
    NationJoinedWar,
    NationTransferred,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PendingNewspaperEvent {
    InterNation {
        event: InterNationNewsKind,
        subject: MajorNationId,
        related_nations: NationTable<bool>,
    },
    Shortage {
        subject: MajorNationId,
        affected_nations: NationTable<bool>,
        resource: crate::ResourceKind,
    },
    Miscellaneous {
        audience: Option<MajorNationId>,
        story_code: i32,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WarTransition {
    pub first: NationId,
    pub second: NationId,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct NationPendingWork {
    pub turn_events: Vec<DiplomacyNotice>,
    pub proposals: Vec<DiplomacyProposal>,
    pub turn_summary: Vec<TurnSummary>,
    pub turn_start_events: Vec<TurnStartEvent>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DiplomacyNotice {
    pub source: NationId,
    pub code: i16,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DiplomacyProposal {
    pub source: NationId,
    pub policy: DiplomacyPolicy,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TurnSummary {
    MilitaryRecruit {
        turn_tick: i32,
        unit_type: MilitaryUnitKind,
        count: i16,
    },
    /// A recovered queue record whose presentation meaning has not yet been
    /// interpreted by a Rust rule.
    Retail {
        turn_tick: i32,
        order_kind: i16,
        payload: i16,
        flags: i16,
    },
}
impl TurnSummary {
    pub(crate) const fn order_key(self) -> i16 {
        match self {
            Self::MilitaryRecruit { .. } => 3,
            Self::Retail { order_kind, .. } => order_kind,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TurnStartEvent {
    LandSale { tag: i32, sale: LandSale },
    Tagged { class: String, tag: i32 },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LandSale {
    pub tile: TileId,
    pub nation: NationId,
}

#[cfg(test)]
mod tests {
    use super::{
        DiplomacyState, DiplomaticMissionLevel, PendingActionState, PendingActionStatus,
        PopulationAccumulator, RiverSegment, Stockpile, TechnologyState, TileAction, TileFlags,
        TurnStartEvent,
    };
    use crate::{Difficulty, MajorNationId, NationId, ResourceKind, ResourceTable, RetailCrtRng};

    #[test]
    fn naval_production_capacity_follows_the_technology_priority_order() {
        for (advanced_iron_working, marine_engineering, expected) in [
            (false, false, 7),
            (true, false, 5),
            (false, true, 4),
            (true, true, 4),
        ] {
            let technology = TechnologyState {
                advanced_iron_working,
                marine_engineering,
            };
            assert_eq!(technology.naval_production_capacity(7, 4), expected);
        }
    }

    #[test]
    fn random_start_diplomacy_preserves_retail_matrix_order_and_consortiums() {
        let mut rng = RetailCrtRng::from_state(1);
        let state =
            DiplomacyState::for_random_start(MajorNationId::new(6), Difficulty::Normal, &mut rng);

        assert_eq!(state.standings[NationId::new(0)][NationId::new(0)], 0xff);
        assert_eq!(state.standings[NationId::new(0)][NationId::new(1)], 0x5a);
        assert_eq!(state.standings[NationId::new(7)][NationId::new(10)], 0x96);
        assert_eq!(state.standings[NationId::new(7)][NationId::new(11)], 0x6e);
        assert_eq!(
            state.mission_levels[NationId::new(0)][NationId::new(1)],
            DiplomaticMissionLevel::Embassy
        );
        assert_eq!(
            state.mission_levels[NationId::new(0)][NationId::new(7)],
            DiplomaticMissionLevel::None
        );
        assert_eq!(rng.state(), 1, "Normal initialization consumes no CRT draw");
    }

    #[test]
    fn introductory_and_hard_diplomacy_consume_only_the_recovered_consulate_draws() {
        let mut introductory_rng = RetailCrtRng::from_state(1);
        let introductory = DiplomacyState::for_random_start(
            MajorNationId::new(6),
            Difficulty::Introductory,
            &mut introductory_rng,
        );
        assert_eq!(introductory_rng.state(), 2_745_024);
        for target in 11..15 {
            assert_eq!(
                introductory.mission_levels[NationId::new(6)][NationId::new(target)],
                DiplomaticMissionLevel::TradeConsulate
            );
        }

        let mut hard_rng = RetailCrtRng::from_state(1);
        let hard = DiplomacyState::for_random_start(
            MajorNationId::new(6),
            Difficulty::Hard,
            &mut hard_rng,
        );
        let mut expected_rng = RetailCrtRng::from_state(1);
        for _ in 0..MajorNationId::COUNT - 1 {
            expected_rng.next_rand();
        }
        assert_eq!(hard_rng, expected_rng);
        assert_eq!(
            hard.mission_levels[NationId::new(0)][NationId::new(16)],
            DiplomaticMissionLevel::TradeConsulate
        );
    }

    #[test]
    fn nigh_on_impossible_overwrites_ai_diagonal_standings_like_retail() {
        let mut rng = RetailCrtRng::from_state(1);
        let state = DiplomacyState::for_random_start(
            MajorNationId::new(6),
            Difficulty::NighOnImpossible,
            &mut rng,
        );

        assert_eq!(state.standings[NationId::new(0)][NationId::new(0)], 0x6e);
        assert_eq!(state.standings[NationId::new(6)][NationId::new(6)], 0xff);
    }

    #[test]
    fn population_accumulator_exposes_a_finite_semantic_value() {
        let accumulator = PopulationAccumulator::new(7.5).unwrap();

        assert_eq!(accumulator.get(), 7.5);
        assert_eq!(serde_json::to_string(&accumulator).unwrap(), "7.5");
        assert!(PopulationAccumulator::new(f32::NAN).is_none());
        assert!(PopulationAccumulator::new(f32::INFINITY).is_none());
    }

    #[test]
    fn stockpile_deserialization_normalizes_each_resource_once() {
        let serialized = serde_json::to_string(&ResourceTable::from_array([-1; 23])).unwrap();
        let stockpile: Stockpile = serde_json::from_str(&serialized).unwrap();

        assert_eq!(stockpile[ResourceKind::Paper], 0);
        assert!(crate::all_resources().all(|resource| stockpile[resource] >= 0));
    }

    #[test]
    fn pending_action_deserialization_preserves_payload_independently_of_status() {
        let state: PendingActionState =
            serde_json::from_str(r#"{"status":"none","payload":0}"#).unwrap();

        assert_eq!(state.status(), PendingActionStatus::None);
        assert_eq!(state.payload(), Some(0));
    }

    #[test]
    fn pending_action_level_is_derived_from_status_not_payload() {
        assert_eq!(
            PendingActionState::new(PendingActionStatus::None, None).level(),
            Some(0)
        );
        assert_eq!(
            PendingActionState::new(PendingActionStatus::Queued, Some(6)).level(),
            None
        );
        assert_eq!(
            PendingActionState::new(PendingActionStatus::Level3, Some(6)).level(),
            Some(0)
        );
        assert_eq!(
            PendingActionState::new(PendingActionStatus::Level4, Some(6)).level(),
            Some(1)
        );
    }

    #[test]
    fn tile_action_deserialization_does_not_restore_the_no_action_sentinel() {
        assert!(serde_json::from_str::<TileAction>("-1").is_err());
    }

    #[test]
    fn land_sale_event_uses_a_strategic_tile_id() {
        let event: TurnStartEvent =
            serde_json::from_str(r#"{"kind":"land_sale","tag":4,"sale":{"tile":500,"nation":0}}"#)
                .unwrap();

        assert!(matches!(
            event,
            TurnStartEvent::LandSale { sale, .. } if sale.tile.get() == 500
        ));
    }

    #[test]
    fn ship_location_is_a_required_zone_id() {
        let ship = r#"{"ship_type":"frigate","location":-1,"task_force":null,"aggression":0,"nation":0,"name":"","strength":1,"experience":0,"selection":0}"#;

        assert!(serde_json::from_str::<super::ShipState>(ship).is_err());
    }

    #[test]
    fn tile_flags_keep_city_marker_and_complete_state_writes_separate() {
        assert!(TileFlags::PROVINCE_ANCHOR_STATE.is_city());
        assert!(TileFlags::MINOR_HOME_STATE.is_city());
        assert!(TileFlags::PLACED_CITY_STATE.is_city());
        assert!(!TileFlags::PROVINCE_ANCHOR_STATE.has_base_transport());
        assert!(TileFlags::MINOR_HOME_STATE.has_base_transport());

        let mut sibling = TileFlags::PLACED_CITY_STATE | TileFlags::PROVINCE_CAPITAL_FORTIFICATION;
        sibling.clear_city_marker();
        assert_eq!(sibling.bits(), 0x1f);
    }

    #[test]
    fn river_connection_codes_index_only_two_ended_flows() {
        assert_eq!(
            RiverSegment::from_connection_code(1).unwrap().flow_type(),
            Some(0)
        );
        assert_eq!(
            RiverSegment::from_connection_code(9).unwrap().flow_type(),
            Some(8)
        );
        assert_eq!(
            RiverSegment::from_connection_code(0x0a)
                .unwrap()
                .flow_type(),
            None
        );
        assert_eq!(
            RiverSegment::from_connection_code(0x15)
                .unwrap()
                .flow_type(),
            None
        );
        assert_eq!(RiverSegment::from_connection_code(0), None);
        assert!(serde_json::from_str::<RiverSegment>(r#"{"connection_code":0}"#).is_err());
        assert!(serde_json::from_str::<RiverSegment>(r#"{"connection_code":22}"#).is_err());
    }
}
