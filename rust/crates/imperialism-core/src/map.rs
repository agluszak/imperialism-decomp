use crate::*;
use serde::{Deserialize, Deserializer, Serialize};
use std::ops::Index;

/// A port zone and the nation that owned its port tile before scenario setup.
///
/// The owning [`GameState`] vector preserves retail's newest-to-oldest port
/// chain order.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PortZoneOwner {
    pub zone: OceanZoneId,
    pub former_owner: NationId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StrategicMap {
    topology: MapTopology,
    view_origin: TileId,
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
            view_origin: TileId,
            tiles: Box<[TileState]>,
        }

        let map = SerializedStrategicMap::deserialize(deserializer)?;
        let mut world = Self::new(map.topology, map.tiles).map_err(serde::de::Error::custom)?;
        world.view_origin = map.view_origin;
        Ok(world)
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
        Ok(Self {
            topology,
            view_origin: TileId::new(1),
            tiles,
        })
    }

    /// Accepts tiles derived one-for-one from an already validated generated map.
    pub(crate) fn from_generated_tiles(topology: MapTopology, tiles: Box<[TileState]>) -> Self {
        debug_assert_eq!(tiles.len(), STRATEGIC_TILE_COUNT);
        Self {
            topology,
            view_origin: TileId::new(1),
            tiles,
        }
    }

    pub const fn geometry(&self) -> crate::MapGeometry {
        crate::MapGeometry::new(self.topology)
    }

    pub const fn topology(&self) -> MapTopology {
        self.topology
    }

    pub const fn view_origin(&self) -> TileId {
        self.view_origin
    }

    pub fn set_view_origin(&mut self, view_origin: TileId) {
        self.view_origin = view_origin;
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

impl StrategicMap {
    /// Mutable tile access for authoritative map operations inside core.
    pub(crate) fn tile_mut(&mut self, index: TileId) -> &mut TileState {
        &mut self.tiles[usize::from(index.get())]
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TileState {
    pub terrain: TerrainKind,
    pub rendering: TileRendering,
    pub region_tile_subtype: RegionTileSubtype,
    pub owner_nation: Option<TileOwnerTag>,
    pub former_owner_nation: Option<TileOwnerTag>,
    pub secondary_owner_nation: Option<MajorNationId>,
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

/// The resolved per-tile picture choices consumed by retail's strategic-map renderer.
///
/// These values are stable observable state: retail saves and restores them instead of
/// rerunning the random picture-assignment pass when a game is loaded.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct TileRendering {
    pub sprite_variant: u8,
    pub river_sprite: Option<RiverSprite>,
    pub transition_mask: u8,
    pub coast_or_secondary_mask: u8,
}

impl TileRendering {
    pub const fn from_retail(
        sprite_variant: u8,
        river_sprite: u8,
        transition_mask: u8,
        coast_or_secondary_mask: u8,
    ) -> Option<Self> {
        if sprite_variant > 0x3f || transition_mask > 0x3f || coast_or_secondary_mask > 0x3f {
            return None;
        }
        let river_sprite = if river_sprite == 0 {
            None
        } else {
            match RiverSprite::from_retail(river_sprite) {
                Some(sprite) => Some(sprite),
                None => return None,
            }
        };
        Some(Self {
            sprite_variant,
            river_sprite,
            transition_mask,
            coast_or_secondary_mask,
        })
    }
}

impl<'de> Deserialize<'de> for TileRendering {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct SerializedTileRendering {
            sprite_variant: u8,
            river_sprite: Option<RiverSprite>,
            transition_mask: u8,
            coast_or_secondary_mask: u8,
        }

        let rendering = SerializedTileRendering::deserialize(deserializer)?;
        if rendering.sprite_variant > 0x3f
            || rendering.transition_mask > 0x3f
            || rendering.coast_or_secondary_mask > 0x3f
        {
            return Err(serde::de::Error::custom(
                "tile rendering variant and masks must be between 0 and 0x3f",
            ));
        }
        Ok(Self {
            sprite_variant: rendering.sprite_variant,
            river_sprite: rendering.river_sprite,
            transition_mask: rendering.transition_mask,
            coast_or_secondary_mask: rendering.coast_or_secondary_mask,
        })
    }
}

/// One finalized retail `TTerrainStateRecord::riverSpriteCode` picture choice.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RiverSprite(u8);

impl RiverSprite {
    pub const fn from_retail(value: u8) -> Option<Self> {
        if value >= 0x0b && value <= 0x3a {
            Some(Self(value))
        } else {
            None
        }
    }

    pub const fn retail(self) -> u8 {
        self.0
    }
}

impl<'de> Deserialize<'de> for RiverSprite {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u8::deserialize(deserializer)?;
        Self::from_retail(value)
            .ok_or_else(|| serde::de::Error::custom("river sprite must be between 0x0b and 0x3a"))
    }
}

/// Retail's open numeric tile-profile domain (`TTerrainStateRecord::gateFlag`).
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RegionTileSubtype(i8);

impl RegionTileSubtype {
    pub const fn from_retail(value: i8) -> Self {
        Self(value)
    }

    pub const fn retail(self) -> i8 {
        self.0
    }
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
            rendering: TileRendering::default(),
            region_tile_subtype: RegionTileSubtype::default(),
            owner_nation: None,
            former_owner_nation: None,
            secondary_owner_nation: None,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tile_action_deserialization_does_not_restore_the_no_action_sentinel() {
        assert!(serde_json::from_str::<TileAction>("-1").is_err());
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
